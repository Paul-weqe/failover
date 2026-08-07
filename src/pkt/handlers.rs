/// Defines how each different type of packet should be handled.
/// Depending on the current state of the machine.
/// The packets anticipated are:
///     - VRRP packets (IPv4 and, for v3, IPv6)
///     - ARP packets (IPv4's neighbor resolution)
///     - NDP packets (IPv6's neighbor resolution, ARP has no v6 equivalent)
///
/// The actions on each of the above are specified in section 6 of RFC 3768
/// (v2) and section 6 of RFC 5798 (v3).
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use pnet::datalink;
use pnet::packet::Packet;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;

use crate::error::{NetworkError, PacketError};
use crate::general::{get_interface, virtual_address_action};
use crate::observer::EventObserver;
use crate::packet::{
    ARPframe, ArpPacket, EthernetFrame, NdpNeighborAdvertisement,
    NdpNeighborSolicitation, VRRP_V6_MCAST_ADDR, VrrpPacket,
};
use crate::router::VirtualRouter;
use crate::state_machine::{Event, State};
use crate::{AddressAction, NetResult, VrrpAddresses, network};

pub(crate) fn handle_incoming_arp_pkt(
    eth_packet: &EthernetPacket<'_>,
    vrouter: Arc<Mutex<VirtualRouter>>,
) -> NetResult<()> {
    let vrouter = match vrouter.lock() {
        Ok(vr) => vr,
        Err(_) => {
            log::error!("Unable to create mutex lock for vrouter");
            return Err(NetworkError::LockPoisoned);
        }
    };
    let interface = get_interface(&vrouter.mac_vlan_interface_v4)?;
    let arp_packet = match ArpPacket::decode(eth_packet.payload()) {
        Some(arp_packet) => arp_packet,
        None => return Ok(()),
    };

    let interface_mac = match interface.clone().mac {
        Some(mac) => mac,
        None => {
            log::warn!(
                "interface {} does not have mac address. Unable to continue with incoming VRRP packet checks",
                &interface.name
            );
            return Ok(());
        }
    };

    match vrouter.fsm.state {
        State::Init => {}
        State::Backup => {
            // MUST NOT respond to ARP requests for the IP address(s) associated
            // with the virtual router.
            for ip in &vrouter.ipv4_addresses {
                if ip.addr().octets() == arp_packet.target_proto_address {
                    return Ok(());
                }
            }

            // !TODO
            // MUST discard packets with a destination link layer MAC address
            // equal to the virtual router MAC address.
            if arp_packet.target_hw_address == interface_mac.octets() {
                return Ok(());
            }
        }

        State::Master => {
            // Ignore anything that isn't an ARP request, and ignore
            // packets we sent ourselves (e.g. our own gratuitous ARPs
            // looped back by the raw socket), otherwise we end up
            // replying to our own reply forever.
            if arp_packet.operation != 1
                || arp_packet.sender_hw_address == interface_mac.octets()
            {
                return Ok(());
            }

            // MUST respond to ARP requests for the IP address(s) associated
            // with the virtual router.
            for ip in &vrouter.ipv4_addresses {
                if ip.addr().octets() == arp_packet.target_proto_address {
                    let eth_frame = EthernetFrame {
                        dst_mac: eth_packet.get_source().octets(),
                        src_mac: interface_mac.octets(),
                        ethertype: 0x806,
                    };

                    let arp_packet = ArpPacket {
                        hw_type: 1,
                        proto_type: 0x0800,
                        hw_length: 6,
                        proto_length: 4,
                        operation: 2,
                        sender_hw_address: interface_mac.octets(),
                        sender_proto_address: arp_packet.target_proto_address,
                        target_hw_address: arp_packet.sender_hw_address,
                        target_proto_address: arp_packet.sender_proto_address,
                    };

                    let arp_frame = ARPframe::new(eth_frame, arp_packet);
                    network::send_packet_arp(
                        interface.name.as_str(),
                        arp_frame,
                    );
                }
            }
        }
    }

    Ok(())
}

/// IPv6's equivalent of `handle_incoming_arp_pkt`: only ever called for a
/// v3 instance's Neighbor Solicitation traffic on its `fover6-...`
/// mac-vlan. Only handles the MASTER-replies-to-solicitations case --
/// unlike ARP, IPv6 raw sockets don't hand us a full link-layer frame to
/// mirror the BACKUP-side "don't respond"/"discard for our own mac"
/// bookkeeping against, so this is intentionally the minimal behaviour
/// needed for failover to still work: announce ownership when asked.
pub(crate) fn handle_incoming_ndp_pkt(
    payload: &[u8],
    _src_ip: Ipv6Addr,
    vrouter: Arc<Mutex<VirtualRouter>>,
) -> NetResult<()> {
    let vrouter = match vrouter.lock() {
        Ok(vr) => vr,
        Err(_) => {
            log::error!("Unable to create mutex lock for vrouter");
            return Err(NetworkError::LockPoisoned);
        }
    };

    let Some(v6_iface) = vrouter.mac_vlan_interface_v6.clone() else {
        return Ok(());
    };

    if vrouter.fsm.state != State::Master {
        return Ok(());
    }

    let Some(ns) = NdpNeighborSolicitation::decode(payload) else {
        return Ok(());
    };

    if !vrouter
        .ipv6_addresses
        .iter()
        .any(|ip| ip.addr() == ns.target_address)
    {
        return Ok(());
    }

    let interface = get_interface(&v6_iface)?;
    let Some(interface_mac) = interface.mac else {
        return Ok(());
    };

    let na = NdpNeighborAdvertisement {
        target_address: ns.target_address,
        target_link_addr: interface_mac.octets(),
        override_flag: true,
    };
    network::send_neighbor_advertisement(&v6_iface, ns.target_address, na);

    Ok(())
}

/// Logs why an incoming VRRP packet is being dropped
fn log_drop(vrouter_name: &str, reason: PacketError) {
    match reason {
        PacketError::VridMismatch { .. } => {
            log::trace!("({vrouter_name}) dropping VRRP packet: {reason}");
        }
        PacketError::BadTtl(_) | PacketError::BadChecksum => {
            log::warn!("({vrouter_name}) dropping VRRP packet: {reason}");
        }
        _ => {
            log::error!("({vrouter_name}) dropping VRRP packet: {reason}");
        }
    }
}

pub(crate) fn handle_incoming_vrrp_v4_pkt(
    ip_packet: &Ipv4Packet<'_>,
    vrouter_mutex: Arc<Mutex<VirtualRouter>>,
) -> NetResult<()> {
    for interface in datalink::interfaces().iter() {
        if interface
            .ips
            .iter()
            .any(|ip| ip.ip() == ip_packet.get_source())
        {
            return Ok(());
        }
    }

    process_vrrp_packet(
        ip_packet.payload(),
        IpAddr::V4(ip_packet.get_source()),
        IpAddr::V4(ip_packet.get_destination()),
        ip_packet.get_ttl(),
        vrouter_mutex,
    )
}

/// IPv6 counterpart of `handle_incoming_vrrp_v4_pkt`. `payload` is already
/// just the VRRP message (an IPv6 raw socket doesn't hand us the IP
/// header the way an IPv4 one does), so there's no header to strip and no
/// hop-limit to check here -- see `network::VrrpListenerV6` for why.
pub(crate) fn handle_incoming_vrrp_v6_pkt(
    payload: &[u8],
    src_ip: Ipv6Addr,
    vrouter_mutex: Arc<Mutex<VirtualRouter>>,
) -> NetResult<()> {
    for interface in datalink::interfaces().iter() {
        if interface.ips.iter().any(|ip| ip.ip() == IpAddr::V6(src_ip)) {
            return Ok(());
        }
    }

    process_vrrp_packet(
        payload,
        IpAddr::V6(src_ip),
        IpAddr::V6(VRRP_V6_MCAST_ADDR),
        255,
        vrouter_mutex,
    )
}

fn process_vrrp_packet(
    payload: &[u8],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    ttl: u8,
    vrouter_mutex: Arc<Mutex<VirtualRouter>>,
) -> NetResult<()> {
    let mut vrouter = match vrouter_mutex.lock() {
        Ok(vr) => vr,
        Err(err) => {
            log::warn!("problem fetching vrouter mutex");
            log::warn!("{err}");
            return Ok(());
        }
    };

    let vrrp_packet = match VrrpPacket::decode(payload, src_ip, dst_ip) {
        Ok(pkt) => pkt,
        Err(err) => {
            log_drop(&vrouter.name, err);
            return Ok(());
        }
    };

    // MUST DO verifications(rfc3768 section 7.1 / rfc5798 section 5.2.x).
    {
        // 1. Verify IP TTL/hop-limit is 255.
        if ttl != 255 {
            log_drop(&vrouter.name, PacketError::BadTtl(ttl));
            return Ok(());
        }

        // The VRRP checksum is now verified inside `VrrpPacket::decode`
        // itself (it needs the IPv6 pseudo-header for a v6 packet, which
        // only the caller has), so a bad checksum already surfaced as a
        // decode error above.

        // 5. MUST verify that the VRID is configured on the receiving
        //      interface and the local router is not the IP Address owner.
        if vrrp_packet.vrid != vrouter.vrid {
            log_drop(
                &vrouter.name,
                PacketError::VridMismatch {
                    expected: vrouter.vrid,
                    received: vrrp_packet.vrid,
                },
            );
            return Ok(());
        }

        // 7. MUST verify that the Adver Interval in the packet is the same as
        //      the locally configured for this virtual router.
        let expected_adver_int_cs = vrouter.advert_interval as u16 * 100;
        if vrrp_packet.adver_int_cs != expected_adver_int_cs {
            log_drop(
                &vrouter.name,
                PacketError::AdvertIntervalMismatch {
                    expected: vrouter.advert_interval,
                    received: (vrrp_packet.adver_int_cs / 100) as u8,
                },
            );
            return Ok(());
        }
    }

    // MAY DO verifications (rfc3768 section 7.1): count and address list
    // must match what's locally configured *for this packet's family*.
    let (count_check, addr_check, expected_count) = match &vrrp_packet.addresses
    {
        VrrpAddresses::V4(addrs) => {
            let local = vrouter.ipv4_addrs();
            (
                addrs.len() == vrouter.ipv4_addresses.len(),
                addrs.iter().all(|a| local.contains(a)),
                vrouter.ipv4_addresses.len() as u8,
            )
        }
        VrrpAddresses::V6(addrs) => {
            let local = vrouter.ipv6_addrs();
            (
                addrs.len() == vrouter.ipv6_addresses.len(),
                addrs.iter().all(|a| local.contains(a)),
                vrouter.ipv6_addresses.len() as u8,
            )
        }
    };

    if !count_check {
        log_drop(
            &vrouter.name,
            PacketError::IpCountMismatch {
                expected: expected_count,
                received: vrrp_packet.addresses.len() as u8,
            },
        );
        if vrrp_packet.priority != 255 {
            return Ok(());
        }
    }

    if !addr_check && vrrp_packet.priority != 255 {
        log_drop(&vrouter.name, PacketError::IpListMismatch);
        return Ok(());
    }

    // Which mac-vlan/address list this packet's family maps to, for the
    // state-transition actions below.
    let (mac_vlan_iface, str_addresses) = match &vrrp_packet.addresses {
        VrrpAddresses::V4(_) => (
            vrouter.mac_vlan_interface_v4.clone(),
            vrouter.str_ipv4_addresses(),
        ),
        VrrpAddresses::V6(_) => match &vrouter.mac_vlan_interface_v6 {
            Some(iface) => (iface.clone(), vrouter.str_ipv6_addresses()),
            // A v2 instance has no v6 side, so it should never have
            // reached this branch (only the v6 listener decodes V6
            // addresses, and only a v3 instance runs one).
            None => return Ok(()),
        },
    };

    match vrouter.fsm.state {
        State::Backup => {
            if vrrp_packet.priority == 0 {
                let skew_time = vrouter.skew_time;
                vrouter.fsm.set_master_down_timer(skew_time);
            } else if !vrouter.preempt_mode
                || vrrp_packet.priority >= vrouter.priority
            {
                let m_down_interval = vrouter.master_down_interval;
                vrouter.fsm.set_master_down_timer(m_down_interval);
            } else if vrouter.priority > vrrp_packet.priority {
                virtual_address_action(
                    AddressAction::Add,
                    &str_addresses,
                    &mac_vlan_iface,
                );
                vrouter.fsm.state = State::Master;
                let advert_interval = vrouter.advert_interval as f32;
                vrouter.fsm.set_advert_timer(advert_interval);
                log::info!("({}) transitioned to MASTER", vrouter.name);
            }
            Ok(())
        }

        State::Master => {
            let adv_priority_gt_local_priority =
                vrrp_packet.priority > vrouter.priority;
            let adv_priority_eq_local_priority =
                vrrp_packet.priority == vrouter.priority;

            // If an ADVERTISEMENT is received, then
            if vrrp_packet.priority == 0 {
                // send ADVERTISEMENT
                vrouter.send_advertisement();
                let advert_interval = vrouter.advert_interval as f32;
                vrouter.fsm.set_advert_timer(advert_interval);

                Ok(())
            } else if adv_priority_gt_local_priority {
                // delete virtual IP address
                virtual_address_action(
                    AddressAction::Delete,
                    &str_addresses,
                    &mac_vlan_iface,
                );
                let m_down_interval = vrouter.master_down_interval;
                vrouter.fsm.set_master_down_timer(m_down_interval);
                vrouter.fsm.state = State::Backup;
                log::info!("({}) transitioned to BACKUP", vrouter.name);
                EventObserver::notify_mut(vrouter, Event::Null)?;
                Ok(())
            } else if adv_priority_eq_local_priority {
                // delete virtual IP address
                virtual_address_action(
                    AddressAction::Delete,
                    &str_addresses,
                    &mac_vlan_iface,
                );
                let m_down_interval = vrouter.master_down_interval;
                vrouter.fsm.set_master_down_timer(m_down_interval);
                vrouter.fsm.state = State::Backup;
                vrouter.fsm.event = Event::Null;
                log::info!("({}) transitioned to BACKUP", vrouter.name);
                EventObserver::notify_mut(vrouter, Event::Null)?;
                Ok(())
            } else {
                Ok(())
            }
        }
        _ => Ok(()),
    }
}
