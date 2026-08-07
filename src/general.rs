use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use futures_util::stream::TryStreamExt;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use netlink_packet_route::address::AddressAttribute;
use pnet::datalink::{self, NetworkInterface};
use rand::Rng;
use rand::distributions::Alphanumeric;
use rtnetlink::packet_route::link::{
    InfoKind, LinkAttribute, LinkInfo, LinkMessage, MacVlanMode,
};
use rtnetlink::{AddressMessageBuilder, Handle, LinkMacVlan, new_connection};

use crate::config::Config;
use crate::error::NetworkError;
use crate::packet::VrrpPacket;
use crate::router::{VirtualRouter, VirtualRouterParams};
use crate::{AddressAction, NetResult};

pub(crate) fn get_interface(name: &str) -> NetResult<NetworkInterface> {
    let interface_names_match = |iface: &NetworkInterface| iface.name == name;
    let interfaces = datalink::linux::interfaces();

    // check if interface name exists, if not create it
    match interfaces.into_iter().find(interface_names_match) {
        Some(interface) => Ok(interface),
        None => Err(NetworkError::InterfaceNotFound(name.to_string())),
    }
}

/// The first IPv4 address configured on `interface`.
/// Used as the source address for VRRP advertisements.
pub(crate) fn primary_ipv4(
    interface: &NetworkInterface,
) -> NetResult<Ipv4Addr> {
    interface
        .ips
        .iter()
        .find_map(|ip| match ip.ip() {
            IpAddr::V4(addr) => Some(addr),
            IpAddr::V6(_) => None,
        })
        .ok_or_else(|| NetworkError::NoIpv4Address(interface.name.clone()))
}

/// First non-loopback IPv6 address on `interface`, if any. Used as the
/// source for v3 IPv6 advertisements; unlike `primary_ipv4`, absence isn't
/// fatal -- v3 just holds off sending v6 adverts until one shows up.
pub(crate) fn primary_ipv6(interface: &NetworkInterface) -> Option<Ipv6Addr> {
    interface.ips.iter().find_map(|ip| match ip.ip() {
        IpAddr::V6(addr) if !addr.is_loopback() => Some(addr),
        _ => None,
    })
}

/// Takes the configs that have been received and converts them into a virtual
///  router instance.
pub fn config_to_vr(conf: Config) -> VirtualRouter {
    let max_ip_count = VrrpPacket::MAX_IP_COUNT;
    let raw_addresses = conf.ip_addresses;
    if raw_addresses.len() > max_ip_count {
        log::warn!(
            "({})  More than {max_ip_count} IP addresses(max for VRRP) have been configured. Only first {max_ip_count} addresses will be used..",
            conf.name
        );
    }

    let addresses = if raw_addresses.len() <= max_ip_count {
        raw_addresses
    } else {
        raw_addresses[0..max_ip_count].to_vec()
    };

    let mut ipv4_addresses: Vec<Ipv4Net> = vec![];
    let mut ipv6_addresses: Vec<Ipv6Net> = vec![];
    for ip_config in addresses.iter() {
        match IpNet::from_str(ip_config) {
            Ok(IpNet::V4(net)) => ipv4_addresses.push(net),
            Ok(IpNet::V6(net)) => ipv6_addresses.push(net),
            Err(err) => {
                log::error!(
                    "({}) invalid IP address {ip_config:?}: {err}",
                    conf.name
                );
            }
        }
    }

    let vr = VirtualRouter::new(VirtualRouterParams {
        name: conf.name,
        vrid: conf.vrid,
        version: conf.version,
        ipv4_addresses,
        ipv6_addresses,
        priority: conf.priority,
        advert_interval: conf.advert_interval,
        preempt_mode: conf.preempt_mode,
        network_interface: conf.interface_name,
    });
    log::info!("({}) Entered {:?} state.", vr.name, vr.fsm.state);
    vr
}

/// Adds/removes the given virtual IP addresses (IPv4 or IPv6, inferred per
/// address) on `interface_name` via Netlink (equivalent to
/// `ip address add/delete <addr> dev <iface>`).
///
/// Bridges into async rtnetlink code from what is otherwise a synchronous
/// call chain, so this must be invoked from within a multi-threaded tokio
/// runtime.
pub(crate) fn virtual_address_action(
    action: AddressAction,
    addresses: &[String],
    interface_name: &str,
) {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(apply_address_action(
            action,
            addresses,
            interface_name,
        ));
    });
}

async fn apply_address_action(
    action: AddressAction,
    addresses: &[String],
    interface_name: &str,
) {
    let (connection, handle, _) = match new_connection() {
        Ok(conn) => conn,
        Err(err) => {
            log::error!("Unable to open netlink connection: {err}");
            return;
        }
    };
    tokio::spawn(connection);

    let mut links = handle
        .link()
        .get()
        .match_name(interface_name.to_string())
        .execute();
    let index = match links.try_next().await {
        Ok(Some(link)) => link.header.index,
        Ok(None) => {
            log::error!(
                "Unable to find interface {interface_name} for virtual address action"
            );
            return;
        }
        Err(err) => {
            log::error!("Problem fetching interface {interface_name}: {err}");
            return;
        }
    };

    for addr in addresses {
        let net = match IpNet::from_str(addr) {
            Ok(net) => net,
            Err(err) => {
                log::error!("Invalid virtual address {addr}: {err}");
                continue;
            }
        };

        let result = match (&action, net) {
            (AddressAction::Add, net) => {
                handle
                    .address()
                    .add(index, net.addr(), net.prefix_len())
                    .replace()
                    .execute()
                    .await
            }
            (AddressAction::Delete, IpNet::V4(net)) => {
                let message = AddressMessageBuilder::<Ipv4Addr>::new()
                    .index(index)
                    .address(net.addr(), net.prefix_len())
                    .build();
                handle.address().del(message).execute().await
            }
            (AddressAction::Delete, IpNet::V6(net)) => {
                let message = AddressMessageBuilder::<Ipv6Addr>::new()
                    .index(index)
                    .address(net.addr(), net.prefix_len())
                    .build();
                handle.address().del(message).execute().await
            }
        };

        if let Err(err) = result {
            log::trace!(
                "Problem performing netlink '{action}' for {addr} on {interface_name}: {err}"
            );
        }
    }
}

fn fnv1a_hash(input: &str) -> u32 {
    const FNV_OFFSET_BASIS: u32 = 0x811c_9dc5;
    const FNV_PRIME: u32 = 0x0100_0193;

    let mut hash = FNV_OFFSET_BASIS;
    for byte in input.bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AddressFamily {
    V4,
    V6,
}

impl AddressFamily {
    fn name_prefix(self) -> &'static str {
        match self {
            Self::V4 => "fover4",
            Self::V6 => "fover6",
        }
    }

    /// The well-known VRRP virtual MAC for this family:
    /// `00-00-5E-00-01-{VRID}` for IPv4, `00-00-5E-00-02-{VRID}` for IPv6.
    fn virtual_mac(self, vrid: u8) -> [u8; 6] {
        match self {
            Self::V4 => [0x00, 0x00, 0x5e, 0x00, 0x01, vrid],
            Self::V6 => [0x00, 0x00, 0x5e, 0x00, 0x02, vrid],
        }
    }
}

/// mvlan interface name:
///     `fover4-{vrid}-{4 hex digit hash of the parent name}` (or `fover6-`
///     for the IPv6 side). Kept to 4 hex digits (rather than 5) so that,
///     with a 3-digit vrid, the name stays within Linux's 15-character
///     `IFNAMSIZ` limit once the family digit is included.
fn mac_vlan_name(
    parent_ifname: &str,
    vrid: u8,
    family: AddressFamily,
) -> String {
    let hash = fnv1a_hash(parent_ifname) & 0xFFFF;
    format!("{}-{vrid}-{hash:04x}", family.name_prefix())
}

/// Whether a failed netlink link lookup failed specifically because the
/// requested interface doesn't exist (ENODEV), as opposed to some other,
/// genuine failure.
fn is_no_such_device(err: &rtnetlink::Error) -> bool {
    matches!(
        err,
        rtnetlink::Error::NetlinkError(msg)
            if msg.code == std::num::NonZeroI32::new(-libc::ENODEV)
    )
}

fn link_is_mac_vlan(link: &LinkMessage) -> bool {
    for attr in &link.attributes {
        if let LinkAttribute::LinkInfo(infos) = attr {
            for info in infos {
                if let LinkInfo::Kind(InfoKind::MacVlan) = info {
                    return true;
                }
            }
        }
    }
    false
}

fn link_mac_address(link: &LinkMessage) -> Option<Vec<u8>> {
    link.attributes.iter().find_map(|attr| match attr {
        LinkAttribute::Address(mac) => Some(mac.clone()),
        _ => None,
    })
}

fn link_parent_index(link: &LinkMessage) -> Option<u32> {
    link.attributes.iter().find_map(|attr| match attr {
        LinkAttribute::Link(idx) => Some(*idx),
        _ => None,
    })
}

/// Creates (or reuses) the mac-vlan interface for `family` on this
/// instance's vrid/parent interface.
///
/// An existing interface with the target name is reused, not treated as
/// stale -- a v2 and v3 instance sharing the same name/vrid/parent are
/// expected to share the same `fover4-...` mac-vlan. Reuse requires it
/// actually be a mac-vlan, carry this family's virtual MAC, and hang off
/// the same parent; any mismatch is a hard error. Only ever deleted on
/// teardown (`delete_mac_vlan`), once no addresses remain on it.
pub(crate) async fn create_mac_vlan(
    parent_ifname: &str,
    vrid: u8,
    family: AddressFamily,
) -> NetResult<String> {
    let name = mac_vlan_name(parent_ifname, vrid, family);
    let virtual_mac = family.virtual_mac(vrid);

    let (connection, handle, _) =
        new_connection().map_err(NetworkError::NetlinkConnect)?;
    tokio::spawn(connection);

    let mut parents = handle
        .link()
        .get()
        .match_name(parent_ifname.to_string())
        .execute();
    let parent_index = match parents.try_next().await {
        Ok(Some(link)) => link.header.index,
        Ok(None) => {
            return Err(NetworkError::InterfaceNotFound(
                parent_ifname.to_string(),
            ));
        }
        Err(source) => {
            return Err(NetworkError::InterfaceLookup {
                name: parent_ifname.to_string(),
                source,
            });
        }
    };

    // Check if an interface with the name already exists.
    let mut existing = handle.link().get().match_name(name.clone()).execute();
    match existing.try_next().await {
        Ok(Some(link)) => {
            if !link_is_mac_vlan(&link) {
                return Err(NetworkError::NotMacVlan(name));
            }

            if link_mac_address(&link).as_deref()
                != Some(virtual_mac.as_slice())
            {
                return Err(NetworkError::MacVlanMismatch {
                    name,
                    reason:
                        "its MAC address doesn't match this instance's virtual MAC"
                            .to_string(),
                });
            }

            if link_parent_index(&link) != Some(parent_index) {
                return Err(NetworkError::MacVlanMismatch {
                    name,
                    reason: format!(
                        "it belongs to a different parent interface than {parent_ifname}"
                    ),
                });
            }

            log::info!(
                "Reusing existing mac-vlan {name} (parent {parent_ifname}, vrid {vrid})"
            );
            return Ok(name);
        }
        Ok(None) => {}
        Err(err) if is_no_such_device(&err) => {}
        Err(source) => {
            return Err(NetworkError::InterfaceLookup { name, source });
        }
    }

    let message = LinkMacVlan::new(&name, parent_index, MacVlanMode::Bridge)
        .up()
        .address(virtual_mac.to_vec())
        .build();

    if let Err(source) = handle.link().add(message).execute().await {
        return Err(NetworkError::MacVlanCreate { name, source });
    }

    if family == AddressFamily::V4 {
        let arp_ignore_path =
            format!("/proc/sys/net/ipv4/conf/{name}/arp_ignore");
        if let Err(err) = tokio::fs::write(&arp_ignore_path, b"8").await {
            log::warn!(
                "Unable to disable kernel ARP replies on {name} ({arp_ignore_path}): {err}"
            );
        }
    }

    log::info!("Created mac-vlan {name} (parent {parent_ifname}, vrid {vrid})");
    Ok(name)
}

/// Tears down the mac-vlan interface created by [`create_mac_vlan`], but only
/// if there are no addresses on the interface.
pub(crate) fn delete_mac_vlan(name: &str) {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(apply_delete_mac_vlan(name));
    });
}

async fn apply_delete_mac_vlan(name: &str) {
    let (connection, handle, _) = match new_connection() {
        Ok(conn) => conn,
        Err(err) => {
            log::error!("Unable to open netlink connection: {err}");
            return;
        }
    };
    tokio::spawn(connection);

    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let index = match links.try_next().await {
        Ok(Some(link)) => link.header.index,
        Ok(None) => {
            log::warn!(
                "mac-vlan interface {name} not found; nothing to delete"
            );
            return;
        }
        Err(err) => {
            log::error!(
                "Problem fetching mac-vlan interface {name} for deletion: {err}"
            );
            return;
        }
    };

    match remaining_address_count(&handle, index).await {
        Ok(0) => {}
        Ok(remaining) => {
            log::info!(
                "mac-vlan {name} still has {remaining} address(es) assigned (likely still in use by another instance); leaving it up"
            );
            return;
        }
        Err(err) => {
            log::error!(
                "Unable to check remaining addresses on {name} before deletion: {err}"
            );
            return;
        }
    }

    if let Err(err) = handle.link().del(index).execute().await {
        log::error!("Problem deleting mac-vlan interface {name}: {err}");
    }
}

async fn remaining_address_count(
    handle: &Handle,
    link_index: u32,
) -> Result<usize, rtnetlink::Error> {
    let mut addrs = handle
        .address()
        .get()
        .set_link_index_filter(link_index)
        .execute();
    let mut count = 0usize;

    'link_local: while let Some(msg) = addrs.try_next().await? {
        for attr in msg.attributes {
            if let AddressAttribute::Address(addr) = attr {
                if let IpAddr::V6(addr) = addr
                    && addr.is_unicast_link_local()
                {
                    continue 'link_local;
                }
                count += 1;
            }
        }
    }

    Ok(count)
}

pub(crate) fn random_vr_name() -> String {
    let val: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();

    log::info!("Name for Virtual Router not given. generated name VR_{val}");
    format!("VR_{val}")
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroI32;

    use netlink_packet_core::ErrorMessage;

    use super::*;

    // Golden values below pin down the current hash/naming scheme. If this
    // test starts failing after an intentional change to `fnv1a_hash` or
    // `mac_vlan_name`, remember that upgrades won't find the mac-vlan
    // interface a prior run created under the old name -- that's the actual
    // failure mode being guarded against, not just this assertion.
    #[test]
    fn fnv1a_hash_is_stable_for_known_inputs() {
        assert_eq!(fnv1a_hash(""), 0x811c_9dc5);
        assert_eq!(fnv1a_hash("eth0"), 0x67b1_9724);
    }

    #[test]
    fn fnv1a_hash_differs_for_different_inputs() {
        assert_ne!(fnv1a_hash("eth0"), fnv1a_hash("eth1"));
    }

    #[test]
    fn mac_vlan_name_is_stable_and_deterministic() {
        let first = mac_vlan_name("eth0", 51, AddressFamily::V4);
        let second = mac_vlan_name("eth0", 51, AddressFamily::V4);
        assert_eq!(first, second);
        assert_eq!(first, "fover4-51-9724");
    }

    #[test]
    fn mac_vlan_name_varies_with_vrid_parent_and_family() {
        assert_ne!(
            mac_vlan_name("eth0", 51, AddressFamily::V4),
            mac_vlan_name("eth0", 52, AddressFamily::V4)
        );
        assert_ne!(
            mac_vlan_name("eth0", 51, AddressFamily::V4),
            mac_vlan_name("eth1", 51, AddressFamily::V4)
        );
        assert_ne!(
            mac_vlan_name("eth0", 51, AddressFamily::V4),
            mac_vlan_name("eth0", 51, AddressFamily::V6)
        );
    }

    #[test]
    fn mac_vlan_name_fits_within_ifnamsiz() {
        // Worst case: 3-digit vrid, either family prefix.
        let v4 = mac_vlan_name("eth0", 255, AddressFamily::V4);
        let v6 = mac_vlan_name("eth0", 255, AddressFamily::V6);
        assert!(v4.len() <= 15, "{v4} is {} chars", v4.len());
        assert!(v6.len() <= 15, "{v6} is {} chars", v6.len());
    }

    #[test]
    fn same_vrid_and_parent_shares_the_v4_name_across_versions() {
        // v2 and v3 instances with the same name/vrid/parent are expected
        // to share the v4 mac-vlan -- naming is keyed by
        // (parent, vrid, family) only, version plays no part in it.
        let a = mac_vlan_name("eth0", 51, AddressFamily::V4);
        let b = mac_vlan_name("eth0", 51, AddressFamily::V4);
        assert_eq!(a, b);
    }

    #[test]
    fn virtual_mac_differs_by_family() {
        assert_eq!(
            AddressFamily::V4.virtual_mac(51),
            [0x00, 0x00, 0x5e, 0x00, 0x01, 51]
        );
        assert_eq!(
            AddressFamily::V6.virtual_mac(51),
            [0x00, 0x00, 0x5e, 0x00, 0x02, 51]
        );
    }

    fn netlink_error_with_code(code: i32) -> rtnetlink::Error {
        let mut msg = ErrorMessage::default();
        msg.code = NonZeroI32::new(code);
        rtnetlink::Error::NetlinkError(msg)
    }

    #[test]
    fn is_no_such_device_true_for_enodev() {
        let err = netlink_error_with_code(-libc::ENODEV);
        assert!(is_no_such_device(&err));
    }

    #[test]
    fn is_no_such_device_false_for_other_codes() {
        let err = netlink_error_with_code(-libc::EPERM);
        assert!(!is_no_such_device(&err));
    }

    #[test]
    fn is_no_such_device_false_for_non_netlink_errors() {
        let err = rtnetlink::Error::RequestFailed;
        assert!(!is_no_such_device(&err));
    }
}
