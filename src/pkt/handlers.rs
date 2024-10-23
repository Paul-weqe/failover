use crate::network;
use crate::packet::{ARPframe, ArpPacket, EthernetFrame, VrrpPacket};
use crate::{
    error::NetError, general::virtual_address_action, observer::EventObserver,
    state_machine::Event, NetResult,
};
use crate::{general::get_interface, router::VirtualRouter, state_machine::States};

/// Defines how each different type of packet should be handled.
/// Depending on the current state of the machine.
/// The two main packets being anticipated are:
///     - VRRP packets
///     - ARP packets
///
/// The actions on each of the above are specified in section
/// 6 of RFC 3768.
///
use core::f32;
use ipnet::Ipv4Net;
use pnet::{
    datalink,
    packet::{ethernet::EthernetPacket, ipv4::Ipv4Packet, Packet},
};
use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};
//use vrrp_packet::VrrpPacket;

pub(crate) fn handle_incoming_arp_pkt(
    eth_packet: &EthernetPacket<'_>,
    vrouter: Arc<Mutex<VirtualRouter>>,
) -> NetResult<()> {
    let vrouter = match vrouter.lock() {
        Ok(vr) => vr,
        Err(err) => {
            log::error!("Unable to create mutex lock for vrouter");
            return Err(NetError(format!(
                "Unable to create mutex lock for vrouter\n\n {err}"
            )));
        }
    };
    let interface = get_interface(&vrouter.network_interface)?;
    let arp_packet = match ArpPacket::decode(eth_packet.payload()) {
        Some(arp_packet) => arp_packet,
        None => return Ok(()),
    };

    let interface_mac = match interface.clone().mac {
        Some(mac) => mac,
        None => {
            log::warn!("interface {} does not have mac address. Unable to continue with incoming VRRP packet checks", &interface.name);
            return Ok(());
        }
    };

    match vrouter.fsm.state {
        States::Init => {}
        States::Backup => {
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

        States::Master => {
            // MUST respond to ARP requests for the IP address(es) associated
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
                    network::send_packet_arp(interface.name.as_str(), arp_frame);
                }
            }
        }
    }

    Ok(())
}

pub(crate) fn handle_incoming_vrrp_pkt(
    eth_packet: &EthernetPacket<'_>,
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
    let ip_packet = match Ipv4Packet::new(eth_packet.payload()) {
        Some(pkt) => pkt,
        None => {
            log::warn!("Unable to read incoming IP packet");
            return Ok(());
        }
    };

    let vrrp_packet = match VrrpPacket::decode(ip_packet.payload()) {
        Some(pkt) => pkt,
        None => {
            log::warn!("Unable to read incoming VRRP packet");
            return Ok(());
        }
    };

    let mut error;

    // TODO {
    //      - currently we are looking at the first IP address of the interface that is sending the data.
    //      - this should be changed to looking through all the IP addresses in the device.
    // }
    // received packets from the same device
    for interface in datalink::interfaces().iter() {
        if let Some(ip) = interface.ips.first() {
            if ip.ip() == ip_packet.get_source() {
                return Ok(());
            }
        };
    }

    // MUST DO verifications(rfc3768 section 7.1)
    {
        // 1. Verify IP TTL is 255
        if ip_packet.get_ttl() != 255 {
            error = format!("({}) TTL of incoming VRRP packet != 255", vrouter.name);
            log::warn!("{error}");
            return Result::Err(NetError(error));
        }

        // 2. MUST verify the VRRP version is 2.
        if vrrp_packet.version != 2 {
            error = format!("({}) Incoming VRRP packet Version != 2", vrouter.name);
            log::error!("{error}");
            return Result::Err(NetError(error));
        }

        // 3. MUST verify that the received packet contains the complete VRRP
        //      packet (including fixed fields, IP Address(es), and Authentication
        //      Data)

        // 4. MUST verify the VRRP checksum.
        //      rfc1071() function should return value with all 1's

        // 5. MUST verify that the VRID is configured on the receiving interface
        //      and the local router is not the IP Address owner (Priority equals
        //      255 (decimal)).
        //      TODO Once implemented multiple interfaces
        if vrrp_packet.vrid != vrouter.vrid {
            return Ok(());
        }

        // 6. Auth Type must be same.
        //      TODO once multiple authentication types are configured

        // 7. MUST verify that the Adver Interval in the packet is the same as
        //      the locally configured for this virtual router
        //      If the above check fails, the receiver MUST discard the packet,
        //      SHOULD log the event and MAY indicate via network management that a
        //      misconfiguration was detected.
        if vrrp_packet.adver_int != vrouter.advert_interval {
            error = format!(
                "({}) Incoming VRRP packet has advert interval {} while configured advert interval is {}",
                vrouter.name, vrrp_packet.adver_int, vrouter.advert_interval);

            log::error!("{error}");
            return Result::Err(NetError(error));
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
        let count_check = vrrp_packet.count_ip == vrouter.ip_addresses.len() as u8;
        let mut addr_check = true;

        if vrrp_packet.ip_addresses.clone().len() % 4 != 0 {
            error = format!("({}) Invalid Ip Addresses in vrrp packet", vrouter.name);
            log::error!("{error}");
            return Result::Err(NetError(error));
        }

        let mut addr: Vec<u8> = vec![];
        for (counter, ip_ad) in vrrp_packet.ip_addresses.iter().enumerate() {
            //addr.push(ip_ad.octets());
            ip_ad.octets().iter().for_each(|oc| {
                addr.push(*oc);
            });
            if (counter + 1) % 4 == 0 {
                let ip = match Ipv4Net::new(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]), 24) {
                    Ok(ip) => ip.addr(),
                    Err(err) => {
                        log::error!("Invalid IP on incoming VRRP packet: {:?}", addr);
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
            error =
                format!(
                "({}) ip count check({}) does not match with local configuration of ip count {}",
                vrouter.name, vrrp_packet.count_ip, vrouter.ip_addresses.len()
            );
            log::error!("{error}");
            if vrrp_packet.priority != 255 {
                return Result::Err(NetError(error));
            }
        }

        if !addr_check && vrrp_packet.priority != 255 {
            error = format!(
                "({}) IP addresses for incoming vrrp don't match ",
                vrouter.name
            );
            log::error!("{error}");
            if vrrp_packet.priority != 255 {
                return Result::Err(NetError(error));
            }
        }
    }

    match vrouter.fsm.state {
        States::Backup => {
            if vrrp_packet.priority == 0 {
                let skew_time = vrouter.skew_time;
                vrouter.fsm.set_master_down_timer(skew_time);
            } else if !vrouter.preempt_mode || vrrp_packet.priority >= vrouter.priority {
                let m_down_interval = vrouter.master_down_interval;
                vrouter.fsm.set_master_down_timer(m_down_interval);
            } else if vrouter.priority > vrrp_packet.priority {
                virtual_address_action(
                    "add",
                    &vrouter.str_ipv4_addresses(),
                    &vrouter.network_interface,
                );
                vrouter.fsm.state = States::Master;
                let advert_interval = vrouter.advert_interval as f32;
                vrouter.fsm.set_advert_timer(advert_interval);
                log::info!("({}) transitioned to MASTER", vrouter.name);
            }
            Ok(())
        }

        States::Master => {
            let incoming_ip_pkt = match Ipv4Packet::new(eth_packet.payload()) {
                Some(pkt) => pkt,
                None => {
                    let err = "Problem processing incoming IP packet";
                    log::warn!("{err}");
                    return Err(NetError(err.to_string()));
                }
            };
            let adv_priority_gt_local_priority = vrrp_packet.priority > vrouter.priority;
            let adv_priority_eq_local_priority = vrrp_packet.priority == vrouter.priority;
            let _send_ip_gt_local_ip =
                incoming_ip_pkt.get_source() > incoming_ip_pkt.get_destination();

            // If an ADVERTISEMENT is received, then
            if vrrp_packet.priority == 0 {
                // send ADVERTISEMENT
                let mut ips: Vec<Ipv4Addr> = vec![];
                for addr in vrouter.ip_addresses.clone() {
                    ips.push(addr.addr());
                }

                let pkt = VrrpPacket {
                    version: 2,
                    hdr_type: 1,
                    vrid: vrouter.vrid,
                    priority: vrouter.priority,
                    count_ip: vrouter.ip_addresses.len() as u8,
                    auth_type: 0,
                    adver_int: vrouter.advert_interval,
                    checksum: 0,
                    ip_addresses: ips,
                    auth_data: 0,
                    auth_data2: 0,
                };
                let _ = network::send_vrrp_packet(&vrouter.network_interface, pkt);
                let advert_interval = vrouter.advert_interval as f32;
                vrouter.fsm.set_advert_timer(advert_interval);

                Ok(())
            } else if adv_priority_gt_local_priority {
                // delete virtual IP address
                virtual_address_action(
                    "delete",
                    &vrouter.str_ipv4_addresses(),
                    &vrouter.network_interface,
                );
                let m_down_interval = vrouter.master_down_interval;
                vrouter.fsm.set_master_down_timer(m_down_interval);
                vrouter.fsm.state = States::Backup;
                log::info!("({}) transitioned to BACKUP", vrouter.name);
                EventObserver::notify_mut(vrouter, Event::Null)?;
                Ok(())
            } else if adv_priority_eq_local_priority {
                // delete virtual IP address
                virtual_address_action(
                    "delete",
                    &vrouter.str_ipv4_addresses(),
                    &vrouter.network_interface,
                );
                let m_down_interval = vrouter.master_down_interval;
                vrouter.fsm.set_master_down_timer(m_down_interval);
                vrouter.fsm.state = States::Backup;
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
