use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use futures_util::stream::TryStreamExt;
use ipnet::Ipv4Net;
use pnet::datalink::{self, NetworkInterface};
use rand::Rng;
use rand::distributions::Alphanumeric;
use rtnetlink::packet_route::link::{
    InfoKind, LinkAttribute, LinkInfo, LinkMessage, MacVlanMode,
};
use rtnetlink::{AddressMessageBuilder, LinkMacVlan, new_connection};

use crate::config::VrrpConfig;
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

// Takes the configs that have been received and converts them into a virtual
//  router instance.
pub fn config_to_vr(conf: VrrpConfig) -> VirtualRouter {
    let mut ips: Vec<Ipv4Net> = vec![];
    let max_ip_count = VrrpPacket::MAX_IP_COUNT;
    if conf.ip_addresses().len() > max_ip_count {
        log::warn!(
            "({})  More than {max_ip_count} IP addresses(max for VRRP) have been configured. Only first {max_ip_count} addresses will be used..",
            conf.name()
        );
    }

    let addresses = if conf.ip_addresses().len() <= max_ip_count {
        conf.ip_addresses()
    } else {
        conf.ip_addresses()[0..max_ip_count].to_vec()
    };
    for ip_config in addresses.iter() {
        // TODO: have error logging if this is Err.
        if let Ok(ip_addr) = Ipv4Net::from_str(ip_config) {
            ips.push(ip_addr);
        }
    }

    let vr = VirtualRouter::new(VirtualRouterParams {
        name: conf.name(),
        vrid: conf.vrid(),
        ip_addresses: ips,
        priority: conf.priority(),
        advert_interval: conf.advert_interval(),
        preempt_mode: conf.preempt_mode(),
        network_interface: conf.interface_name(),
    });
    log::info!("({}) Entered {:?} state.", vr.name, vr.fsm.state);
    vr
}

/// Adds/removes the given virtual IP addresses on `interface_name` via
/// Netlink (equivalent to `ip address add/delete <addr> dev <iface>`).
///
/// Bridges into async rtnetlink code from what is otherwise a synchronous
/// call chain, so this must be invoked from within a multi-threaded tokio
/// runtime.
pub fn virtual_address_action(
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
        let net = match Ipv4Net::from_str(addr) {
            Ok(net) => net,
            Err(err) => {
                log::error!("Invalid virtual address {addr}: {err}");
                continue;
            }
        };

        let result = match action {
            AddressAction::Add => {
                handle
                    .address()
                    .add(index, IpAddr::V4(net.addr()), net.prefix_len())
                    .replace()
                    .execute()
                    .await
            }
            AddressAction::Delete => {
                let message = AddressMessageBuilder::<Ipv4Addr>::new()
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

/// mvlan interface name:
///     `fover-{vrid}-{5 hex digit hash of the parent name}`.
fn mac_vlan_name(parent_ifname: &str, vrid: u8) -> String {
    let hash = fnv1a_hash(parent_ifname) & 0xF_FFFF;
    format!("fover-{vrid}-{hash:05x}")
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

pub(crate) async fn create_mac_vlan(
    parent_ifname: &str,
    vrid: u8,
) -> NetResult<String> {
    let name = mac_vlan_name(parent_ifname, vrid);

    let (connection, handle, _) =
        new_connection().map_err(NetworkError::NetlinkConnect)?;
    tokio::spawn(connection);

    // Check if an interface with the name exists.
    let mut existing = handle.link().get().match_name(name.clone()).execute();

    match existing.try_next().await {
        Ok(Some(link)) => {
            if !link_is_mac_vlan(&link) {
                return Err(NetworkError::NotAMacVlan(name));
            }
            log::warn!(
                "Removing stale mac-vlan {name} left over from a prior run"
            );
            if let Err(source) =
                handle.link().del(link.header.index).execute().await
            {
                return Err(NetworkError::StaleMacVlanRemoval { name, source });
            }
        }
        Ok(None) => {}
        Err(err) if is_no_such_device(&err) => {}
        Err(source) => {
            return Err(NetworkError::InterfaceLookup { name, source });
        }
    }

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

    let virtual_mac = vec![0x00, 0x00, 0x5e, 0x00, 0x01, vrid];
    let message = LinkMacVlan::new(&name, parent_index, MacVlanMode::Bridge)
        .up()
        .address(virtual_mac)
        .build();

    if let Err(source) = handle.link().add(message).execute().await {
        return Err(NetworkError::MacVlanCreate { name, source });
    }

    let arp_ignore_path = format!("/proc/sys/net/ipv4/conf/{name}/arp_ignore");
    if let Err(err) = tokio::fs::write(&arp_ignore_path, b"8").await {
        log::warn!(
            "Unable to disable kernel ARP replies on {name} ({arp_ignore_path}): {err}"
        );
    }

    log::info!("Created mac-vlan {name} (parent {parent_ifname}, vrid {vrid})");
    Ok(name)
}

/// Deletes the mac-vlan interface created by [`create_mac_vlan`]. Deleting
/// the link removes any address(es) still assigned to it in one shot.
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
    match links.try_next().await {
        Ok(Some(link)) => {
            if let Err(err) =
                handle.link().del(link.header.index).execute().await
            {
                log::error!(
                    "Problem deleting mac-vlan interface {name}: {err}"
                );
            }
        }
        Ok(None) => {
            log::warn!(
                "mac-vlan interface {name} not found; nothing to delete"
            );
        }
        Err(err) => {
            log::error!(
                "Problem fetching mac-vlan interface {name} for deletion: {err}"
            );
        }
    }
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
