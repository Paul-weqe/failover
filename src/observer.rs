use pnet::packet::Packet;
use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex, MutexGuard},
};

use crate::{
    checksum,
    error::NetError,
    general::{create_datalink_channel, get_interface, virtual_address_action},
    network,
    packet::VrrpPacket,
    pkt::generators::MutablePktGenerator,
    router::VirtualRouter,
    state_machine::{Event, States},
    NetResult,
};

/// Listens for when any Event occurs in the Virtual Router.
/// Events that can occur are: Startup,  Shutdown, MasterDown, Null  
/// Actions happening on when each of these Events is fired are
/// Specified in RFC 3768 section 6.3, 6.4 and 6.5
#[derive(Debug, Clone)]
pub(crate) struct EventObserver;

impl EventObserver {
    pub(crate) fn notify(vrouter: Arc<Mutex<VirtualRouter>>, event: Event) -> NetResult<()> {
        let vrouter = match vrouter.lock() {
            Ok(vrouter) => vrouter,
            Err(_) => return Err(NetError("Unable to fetch vrouter mutex".to_string())),
        };
        EventObserver::notify_mut(vrouter, event)?;
        Ok(())
    }

    pub(crate) fn notify_mut(
        mut vrouter: MutexGuard<'_, VirtualRouter>,
        event: Event,
    ) -> NetResult<()> {
        let interface = get_interface(&vrouter.network_interface)?;
        let generator = MutablePktGenerator::new(interface.clone());
        let (mut sender, _receiver) = create_datalink_channel(&interface)?;

        match event {
            Event::Startup => {
                if vrouter.fsm.state == States::Init {
                    if vrouter.priority == 255 {
                        // send VRRP advertisement.
                        let mut addresses: Vec<Ipv4Addr> = vec![];
                        vrouter.ip_addresses.iter().for_each(|ip| {
                            addresses.push(ip.addr());
                        });

                        let pkt = VrrpPacket {
                            version: 2,
                            hdr_type: 1,
                            vrid: vrouter.vrid,
                            priority: vrouter.priority,
                            count_ip: vrouter.ip_addresses.len() as u8,
                            auth_type: 0,
                            adver_int: vrouter.advert_interval,
                            checksum: 0,
                            ip_addresses: addresses,
                            auth_data: 0,
                            auth_data2: 0,
                        };
                        let _ = network::send_vrrp_packet(&vrouter.network_interface, pkt);

                        for ip in &vrouter.ip_addresses {
                            let mut e_buff = [0u8; 42];
                            let mut a_buff = [0u8; 28];
                            let (mut grat_eth, grat_arp) = generator.gen_gratuitous_arp_packet(
                                &mut e_buff,
                                &mut a_buff,
                                ip.addr(),
                            );
                            grat_eth.set_payload(grat_arp.packet());
                            sender.send_to(grat_eth.packet(), None);
                        }

                        // bring virtual IP back up.
                        virtual_address_action(
                            "add",
                            &vrouter.str_ipv4_addresses(),
                            &vrouter.network_interface,
                        );
                        let advert_time = vrouter.advert_interval as f32;
                        vrouter.fsm.set_advert_timer(advert_time);
                        vrouter.fsm.state = States::Master;
                        //log::info!("({}) transitioned to MASTER (init)", vrouter.name);
                    } else {
                        // delete virtual IP.
                        virtual_address_action(
                            "delete",
                            &vrouter.str_ipv4_addresses(),
                            &vrouter.network_interface,
                        );
                        let m_down_interval = vrouter.master_down_interval;
                        vrouter.fsm.set_master_down_timer(m_down_interval);
                        vrouter.fsm.state = States::Backup;
                        //log::info!("({}) transitioned to BACKUP (init)", vrouter.name);
                    }
                }
            }
            Event::Shutdown => {
                match vrouter.fsm.state {
                    States::Backup => {
                        vrouter.fsm.disable_timer();
                        vrouter.fsm.state = States::Init;
                    }
                    States::Master => {
                        vrouter.fsm.disable_timer();
                        // send ADVERTIEMENT
                        /*
                        // VRRP pakcet
                        let mut vrrp_buff: Vec<u8> = vec![0; 16 + (4 * vrouter.ip_addresses.len())];
                        let mut vrrp_packet = generator.gen_vrrp_header(&mut vrrp_buff, &vrouter);
                        vrrp_packet.set_checksum(checksum::one_complement_sum(
                            vrrp_packet.packet(),
                            Some(6),
                        ));

                        // IP packet
                        let ip_len = vrrp_packet.packet().len() + 20;
                        let mut ip_buff: Vec<u8> = vec![0; ip_len];
                        let mut ip_packet = generator.gen_vrrp_ip_header(&mut ip_buff);
                        ip_packet.set_payload(vrrp_packet.packet());

                        // Ethernet packet
                        let mut eth_buffer: Vec<u8> = vec![0; 14 + ip_packet.packet().len()];
                        let mut ether_packet = generator.gen_vrrp_eth_packet(&mut eth_buffer);
                        ether_packet.set_payload(ip_packet.packet());
                        sender.send_to(ether_packet.packet(), None);
                        */
                        let mut addresses: Vec<Ipv4Addr> = vec![];
                        vrouter.ip_addresses.iter().for_each(|ip| {
                            addresses.push(ip.addr());
                        });

                        let pkt = VrrpPacket {
                            version: 2,
                            hdr_type: 1,
                            vrid: vrouter.vrid,
                            priority: vrouter.priority,
                            count_ip: vrouter.ip_addresses.len() as u8,
                            auth_type: 0,
                            adver_int: vrouter.advert_interval,
                            checksum: 0,
                            ip_addresses: addresses,
                            auth_data: 0,
                            auth_data2: 0,
                        };
                        let _ = network::send_vrrp_packet(&vrouter.network_interface, pkt);
                        vrouter.fsm.state = States::Init;
                    }
                    States::Init => {}
                }
            }
            Event::MasterDown => {
                if vrouter.fsm.state == States::Backup {
                    // send ADVERTIEMENT then send gratuitous ARP

                    // VRRP advertisement
                    {
                        // VRRP pakcet
                        let mut vrrp_buff: Vec<u8> = vec![0; 16 + (4 * vrouter.ip_addresses.len())];
                        let mut vrrp_packet = generator.gen_vrrp_header(&mut vrrp_buff, &vrouter);
                        vrrp_packet.set_checksum(checksum::one_complement_sum(
                            vrrp_packet.packet(),
                            Some(6),
                        ));

                        // IP packet
                        let ip_len = vrrp_packet.packet().len() + 20;
                        let mut ip_buff: Vec<u8> = vec![0; ip_len];
                        let mut ip_packet = generator.gen_vrrp_ip_header(&mut ip_buff);
                        ip_packet.set_payload(vrrp_packet.packet());

                        // Ethernet packet
                        let mut eth_buffer: Vec<u8> = vec![0; 14 + ip_packet.packet().len()];
                        let mut ether_packet = generator.gen_vrrp_eth_packet(&mut eth_buffer);
                        ether_packet.set_payload(ip_packet.packet());
                        sender.send_to(ether_packet.packet(), None);
                    }

                    // gratuitous ARP
                    {
                        for ip in &vrouter.ip_addresses {
                            let mut e_buff = [0u8; 42];
                            let mut a_buff = [0u8; 28];
                            let (mut grat_eth, grat_arp) = generator.gen_gratuitous_arp_packet(
                                &mut e_buff,
                                &mut a_buff,
                                ip.addr(),
                            );
                            grat_eth.set_payload(grat_arp.packet());
                            sender.send_to(grat_eth.packet(), None);
                        }
                    }

                    // add virtual IP address
                    virtual_address_action(
                        "add",
                        &vrouter.str_ipv4_addresses(),
                        &vrouter.network_interface,
                    );
                    let advert_interval = vrouter.advert_interval as f32;
                    vrouter.fsm.set_advert_timer(advert_interval);
                    vrouter.fsm.state = States::Master;
                    //log::info!("({}) Transitioned to MASTER", vrouter.name);
                }
            }
            _ => {}
        }
        Ok(())
    }
}
