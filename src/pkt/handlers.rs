/// Defines how each different type of packet should be handled.
/// Depending on the current state of the machine.
/// The two main packets being anticipated are:
///     - VRRP packets
///     - ARP packets
///
/// The actions on each of the above are specified in section
/// 6 of RFC 3768.
use core::f32;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use internet_checksum::Checksum;
use ipnet::Ipv4Net;
use pnet::datalink;
use pnet::packet::Packet;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;

use crate::error::{NetworkError, PacketError};
use crate::general::{get_interface, virtual_address_action};
use crate::observer::EventObserver;
use crate::packet::{ARPframe, ArpPacket, EthernetFrame, VrrpPacket};
use crate::router::VirtualRouter;
use crate::state_machine::{Event, State};
use crate::{AddressAction, NetResult, network};

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
    let interface = get_interface(&vrouter.mac_vlan_interface)?;
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
            for ip in &vrouter.ip_addresses {
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
            for ip in &vrouter.ip_addresses {
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

pub(crate) fn handle_incoming_vrrp_pkt(
    ip_packet: &Ipv4Packet<'_>,
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

    let vrrp_packet = match VrrpPacket::decode(ip_packet.payload()) {
        Ok(pkt) => pkt,
        Err(err) => {
            log_drop(&vrouter.name, err);
            return Ok(());
        }
    };

    for interface in datalink::interfaces().iter() {
        if interface
            .ips
            .iter()
            .any(|ip| ip.ip() == ip_packet.get_source())
        {
            return Ok(());
        }
    }

    // MUST DO verifications(rfc3768 section 7.1).
    {
        // 1. Verify IP TTL is 255.
        let ttl = ip_packet.get_ttl();
        if ttl != 255 {
            log_drop(&vrouter.name, PacketError::BadTtl(ttl));
            return Ok(());
        }

        // 3. MUST verify that the received packet contains the complete VRRP
        //      packet (including fixed fields, IP Address(es), and Authentication
        //      Data)

        // 4. MUST verify the VRRP checksum.
        let mut check = Checksum::new();
        check.add_bytes(ip_packet.payload());
        if check.checksum() != [0, 0] {
            log_drop(&vrouter.name, PacketError::BadChecksum);
            return Ok(());
        }

        // 5. MUST verify that the VRID is configured on the receiving interface
        //      and the local router is not the IP Address owner (Priority equals
        //      255 (decimal)).
        //      TODO: Once implemented multiple interfaces
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

        // 6. Auth Type must be same.
        //      TODO: once multiple authentication types are configured

        // 7. MUST verify that the Adver Interval in the packet is the same as
        //      the locally configured for this virtual router
        //      If the above check fails, the receiver MUST discard the packet,
        //      SHOULD log the event and MAY indicate via network management that a
        //      misconfiguration was detected.
        if vrrp_packet.adver_int != vrouter.advert_interval {
            log_drop(
                &vrouter.name,
                PacketError::AdvertIntervalMismatch {
                    expected: vrouter.advert_interval,
                    received: vrrp_packet.adver_int,
                },
            );
            return Ok(());
        }
    }

    // MAY DO verifications (rfc3768 section 7.1)
    {
        // 1. MAY verify that "Count IP Addrs" and the list of IP Address
        //      matches the IP_Addresses configured for the VRID
        //
        //      If the packet was not generated by the address owner (Priority does
        //      not equal 255 (decimal)), the receiver MUST drop the packet,
        //      otherwise continue processing.
        let count_check =
            vrrp_packet.count_ip == vrouter.ip_addresses.len() as u8;
        let mut addr_check = true;

        let mut addr: Vec<u8> = vec![];
        for (counter, ip_ad) in vrrp_packet.ip_addresses.iter().enumerate() {
            ip_ad.octets().iter().for_each(|oc| {
                addr.push(*oc);
            });
            if (counter + 1) % 4 == 0 {
                let ip = match Ipv4Net::new(
                    Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]),
                    24,
                ) {
                    Ok(ip) => ip.addr(),
                    Err(err) => {
                        log::error!(
                            "Invalid IP on incoming VRRP packet: {:?}",
                            addr
                        );
                        log::error!("{err}");
                        return Ok(());
                    }
                };
                if !vrouter.ipv4_addresses().contains(&ip) {
                    log::error!(
                        "({}) IP address {:?} for incoming VRRP packet not found in local config",
                        vrouter.name,
                        ip
                    );
                    addr_check = false;
                }
            }
        }

        if !count_check {
            log_drop(
                &vrouter.name,
                PacketError::IpCountMismatch {
                    expected: vrouter.ip_addresses.len() as u8,
                    received: vrrp_packet.count_ip,
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
    }

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
                    &vrouter.str_ipv4_addresses(),
                    &vrouter.mac_vlan_interface,
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
            let _send_ip_gt_local_ip =
                ip_packet.get_source() > ip_packet.get_destination();

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
                    &vrouter.str_ipv4_addresses(),
                    &vrouter.mac_vlan_interface,
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
                    &vrouter.str_ipv4_addresses(),
                    &vrouter.mac_vlan_interface,
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
