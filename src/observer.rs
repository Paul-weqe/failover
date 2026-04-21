use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::error::NetError;
use crate::general::{get_interface, virtual_address_action};
use crate::packet::{ARPframe, ArpPacket, EthernetFrame, VrrpPacket};
use crate::router::VirtualRouter;
use crate::state_machine::{Event, State};
use crate::{NetResult, checksum, network};

/// Listens for when any Event occurs in the Virtual Router.
/// Events that can occur are: Startup,  Shutdown, MasterDown, Null  
/// Actions happening on when each of these Events is fired are
/// Specified in RFC 3768 section 6.3, 6.4 and 6.5
#[derive(Debug, Clone)]
pub(crate) struct EventObserver;

impl EventObserver {
    pub(crate) fn notify(
        vrouter: Arc<Mutex<VirtualRouter>>,
        event: Event,
    ) -> NetResult<()> {
        let vrouter = match vrouter.lock() {
            Ok(vrouter) => vrouter,
            Err(_) => {
                return Err(NetError(
                    "Unable to fetch vrouter mutex".to_string(),
                ));
            }
        };
        EventObserver::notify_mut(vrouter, event)?;
        Ok(())
    }

    pub(crate) fn notify_mut(
        mut vrouter: MutexGuard<'_, VirtualRouter>,
        event: Event,
    ) -> NetResult<()> {
        let interface = get_interface(&vrouter.network_interface)?;

        match event {
            Event::Startup if vrouter.fsm.state == State::Init => {
                if vrouter.priority == 255 {
                    // Send VRRP advertisement.
                    let mut addresses: Vec<Ipv4Addr> = vec![];
                    vrouter.ip_addresses.iter().for_each(|ip| {
                        addresses.push(ip.addr());
                    });

                    let mut pkt = VrrpPacket {
                        vrid: vrouter.vrid,
                        priority: vrouter.priority,
                        count_ip: vrouter.ip_addresses.len() as u8,
                        adver_int: vrouter.advert_interval,
                        checksum: 0,
                        ip_addresses: addresses,
                    };

                    // Confirm checksum. checksum position is the third item
                    // in 16 bit words.
                    pkt.checksum = checksum::calculate(&pkt.encode(), 3);

                    let _ = network::send_vrrp_packet(
                        &vrouter.network_interface,
                        pkt,
                    );

                    for ip in &vrouter.ip_addresses {
                        let eth_frame = EthernetFrame {
                            dst_mac: [0xff; 6],
                            src_mac: interface.mac.unwrap().octets(),
                            ethertype: 0x0806,
                        };
                        let arp_pkt = ArpPacket {
                            hw_type: 1,
                            proto_type: 0x0800,
                            hw_length: 6,
                            proto_length: 4,
                            operation: 1,
                            sender_hw_address: interface.mac.unwrap().octets(),
                            sender_proto_address: ip.addr().octets(),
                            target_hw_address: [0xff; 6],
                            target_proto_address: ip.addr().octets(),
                        };
                        let arp_frame = ARPframe::new(eth_frame, arp_pkt);
                        network::send_packet_arp(&interface.name, arp_frame);
                    }

                    // Bring virtual IP back up.
                    virtual_address_action(
                        "add",
                        &vrouter.str_ipv4_addresses(),
                        &vrouter.network_interface,
                    );
                    let advert_time = vrouter.advert_interval as f32;
                    vrouter.fsm.set_advert_timer(advert_time);
                    vrouter.fsm.state = State::Master;
                    log::info!(
                        "({}) transitioned to MASTER (init)",
                        vrouter.name
                    );
                } else {
                    // Delete virtual IP.
                    virtual_address_action(
                        "delete",
                        &vrouter.str_ipv4_addresses(),
                        &vrouter.network_interface,
                    );
                    let m_down_interval = vrouter.master_down_interval;
                    vrouter.fsm.set_master_down_timer(m_down_interval);
                    vrouter.fsm.state = State::Backup;
                    log::info!(
                        "({}) transitioned to BACKUP (init)",
                        vrouter.name
                    );
                }
            }
            Event::Shutdown => {
                match vrouter.fsm.state {
                    State::Backup => {
                        vrouter.fsm.disable_timer();
                        vrouter.fsm.state = State::Init;
                    }
                    State::Master => {
                        vrouter.fsm.disable_timer();
                        // Send ADVERTIEMENT.
                        let mut addresses: Vec<Ipv4Addr> = vec![];
                        vrouter.ip_addresses.iter().for_each(|ip| {
                            addresses.push(ip.addr());
                        });

                        let mut pkt = VrrpPacket {
                            vrid: vrouter.vrid,
                            priority: vrouter.priority,
                            count_ip: vrouter.ip_addresses.len() as u8,
                            adver_int: vrouter.advert_interval,
                            checksum: 0,
                            ip_addresses: addresses,
                        };
                        // Confirm checksum. checksum position is the third
                        // item in 16 bit words.
                        pkt.checksum = checksum::calculate(&pkt.encode(), 3);

                        let _ = network::send_vrrp_packet(
                            &vrouter.network_interface,
                            pkt,
                        );
                        vrouter.fsm.state = State::Init;
                    }
                    State::Init => {}
                }
            }
            Event::MasterDown if vrouter.fsm.state == State::Backup => {
                // Send ADVERTIEMENT then send gratuitous ARP.

                // VRRP advertisement.
                {
                    let mut ips: Vec<Ipv4Addr> = vec![];
                    for addr in vrouter.ip_addresses.clone() {
                        ips.push(addr.addr());
                    }
                    let mut pkt = VrrpPacket {
                        vrid: vrouter.vrid,
                        priority: vrouter.priority,
                        count_ip: vrouter.ip_addresses.len() as u8,
                        checksum: 0,
                        adver_int: vrouter.advert_interval,
                        ip_addresses: ips,
                    };
                    // Confirm checksum. checksum position is the third item
                    // in 16 bit words.
                    pkt.checksum = checksum::calculate(&pkt.encode(), 3);

                    let _ = network::send_vrrp_packet(
                        vrouter.network_interface.as_str(),
                        pkt,
                    );
                }

                // Gratuitous ARP.
                {
                    for ip in &vrouter.ip_addresses {
                        let eth_frame = EthernetFrame {
                            dst_mac: [0xff; 6],
                            src_mac: interface.mac.unwrap().octets(),
                            ethertype: 0x0806,
                        };
                        let arp_pkt = ArpPacket {
                            hw_type: 1,
                            proto_type: 0x0800,
                            hw_length: 6,
                            proto_length: 4,
                            operation: 1,
                            sender_hw_address: interface.mac.unwrap().octets(),
                            sender_proto_address: ip.addr().octets(),
                            target_hw_address: [0xff; 6],
                            target_proto_address: ip.addr().octets(),
                        };
                        let arp_frame = ARPframe::new(eth_frame, arp_pkt);
                        network::send_packet_arp(&interface.name, arp_frame);
                    }
                }

                // Add virtual IP address.
                virtual_address_action(
                    "add",
                    &vrouter.str_ipv4_addresses(),
                    &vrouter.network_interface,
                );
                let advert_interval = vrouter.advert_interval as f32;
                vrouter.fsm.set_advert_timer(advert_interval);
                vrouter.fsm.state = State::Master;
                log::info!("({}) Transitioned to MASTER", vrouter.name);
            }
            _ => {}
        }
        Ok(())
    }
}
