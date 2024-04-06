use std::{sync::Arc, time::Duration};
use pnet::packet::{
    ethernet::{ EtherTypes, EthernetPacket }, icmp::IcmpPacket, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, Packet
};
use tokio::sync::Mutex;
use crate::{
    general::{create_datalink_channel, get_interface}, 
    pkt::{generators, handlers::{handle_incoming_arp_pkt, handle_incoming_vrrp_pkt}}, 
    router::VirtualRouter, state_machine::{Event, States},
    error::NetError
};
use crate::checksum;


/// initiates the network functions across the board. 
/// from interfaces, channels, packet handling etc...
pub async fn run_vrrp(vrouter: VirtualRouter) -> Result<(), NetError>{

    let interface = get_interface(&vrouter.network_interface);
    let vrouter_mutex = Arc::new(Mutex::new(vrouter));

    // mutexes to be used in the Network, Event and Timer listeners 
    let net_vrouter_mutex = Arc::clone(&vrouter_mutex);
    let event_vrouter_mutex = Arc::clone(&vrouter_mutex);
    let timer_vrouter_mutex = Arc::clone(&vrouter_mutex);

    // we will have already added our second IP address
    if interface.ips.len() <= 1 {
        log::error!("Interface {} does not have any valid IP addresses", interface.name);
        return Result::Err(
            NetError(format!("Interface {} does not have any valid IP addresses", interface.name))
        );
    }

    let mutable_pkt_generator = generators::MutablePktGenerator::new( interface.clone() );
    let event_pkt_generator = mutable_pkt_generator.clone();
    let timer_pkt_generator = mutable_pkt_generator.clone();


    let (mut event_sender, _event_receiver) = create_datalink_channel(&interface);
    let (mut timer_sender, _timer_receiver) = create_datalink_channel(&interface);

    // thread to listen for any incoming network requests
    // subprocess listens for any incoming network requests
    let network_receiver_process = tokio::spawn( async move {
        let (mut _tx, mut rx) = create_datalink_channel(&interface);
        
        loop {
            let buf = rx.next().unwrap();
            let incoming_eth_pkt = EthernetPacket::new(buf).unwrap();
            match incoming_eth_pkt.get_ethertype() {

                EtherTypes::Ipv4 => {
                    // println!("IPV4!!!");
                    
                    let incoming_ip_pkt = Ipv4Packet::new(incoming_eth_pkt.payload()).unwrap();
                    if incoming_ip_pkt.get_next_level_protocol() == IpNextHeaderProtocols::Vrrp {
                        match handle_incoming_vrrp_pkt(&incoming_eth_pkt, Arc::clone(&net_vrouter_mutex)).await {
                            Ok(_) => {}
                            Err(_) => {
                                continue;
                            }
                        }
                    }
                    
                    else if incoming_ip_pkt.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                        println!("ICMP!!!");
                        let icmp = IcmpPacket::new(incoming_ip_pkt.payload()).unwrap();
                        println!("{:#?}", icmp);
                    }
                }
                
                EtherTypes::Arp => {
                    handle_incoming_arp_pkt( &incoming_eth_pkt, Arc::clone(&net_vrouter_mutex)).await;
                }

                _ => {
                    let net_vr = &net_vrouter_mutex.lock().await;
                    
                    // if we are master, we forward the packet. 
                    // otherwise we leave the packet be
                    if net_vr.fsm.state == States::Master {

                    }
                }
            }
        }

    });

    let timers_counter_process = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        
        loop {
            let mut timer_vrouter = timer_vrouter_mutex.lock().await;
            interval.tick().await;
            let timer = timer_vrouter.fsm.timer;

            match timer.t_type {
                crate::state_machine::TimerType::MasterDown => {
                    if timer_vrouter.fsm.timer.remaining_time > 0.0 {
                        timer_vrouter.fsm.reduce_timer();
                    } 
                    else {
                        timer_vrouter.fsm.state = States::Master;
                        log::info!("({}) transitioned to MASTER", timer_vrouter.name);
                        let advert_interval = timer_vrouter.advert_interval as f32;
                        timer_vrouter.fsm.set_advert_timer(advert_interval);
                    }
                }

                crate::state_machine::TimerType::Adver => {

                    if timer_vrouter.fsm.timer.remaining_time <= 0.0 {
                        // VRRP pakcet
                        let mut vrrp_buff: Vec<u8> = vec![0; 16 + (4 * timer_vrouter.ip_addresses.len())];
                        let mut vrrp_packet = timer_pkt_generator.gen_vrrp_header(&mut vrrp_buff, &timer_vrouter).await;
                        vrrp_packet.set_checksum(checksum::one_complement_sum(vrrp_packet.packet(), Some(6)));
                        
                        // // IP packet
                        let ip_len = vrrp_packet.packet().len() + 20;
                        let mut ip_buff: Vec<u8> = vec![0; ip_len];
                        let mut ip_packet = timer_pkt_generator.gen_vrrp_ip_header(&mut ip_buff);
                        ip_packet.set_payload(vrrp_packet.packet());

                        // // Ethernet packet
                        let mut eth_buffer: Vec<u8> = vec![0; 14 + ip_packet.packet().len()];
                        let mut ether_packet = timer_pkt_generator.gen_vrrp_eth_packet(&mut eth_buffer);
                        ether_packet.set_payload(ip_packet.packet());  
                        timer_sender
                            .send_to(ether_packet.packet(), None)
                            .unwrap()
                            .unwrap();
                    }
                    timer_vrouter.fsm.reduce_timer();
                }

                crate::state_machine::TimerType::Null =>  {

                }
            }
        }
    });

    // listens to any event as it comes in
    let event_listener_process = tokio::spawn(async move {

        loop {

            let mut event_vrouter = event_vrouter_mutex.lock().await;
            match &event_vrouter.fsm.event {
                
                Event::Startup => {
                    if event_vrouter.fsm.state == States::Init {
                        if event_vrouter.priority == 255 {

                            //   ________________________________________________
                            //  |                _______________________________|
                            //  |               |                               |
                            //  |               |            ______________     |
                            //  |  ETH HEADER   | IP HEADER |  VRRP PACKET |    |
                            //  |               |           |______________|    |  
                            //  |               |_______________________________|
                            //  |_______________________________________________|
                
                            // VRRP pakcet
                            let no_of_ips = event_vrouter.ip_addresses.len();

                            let mut vrrp_buff: Vec<u8> = vec![0; 16 + (4 * no_of_ips)];
                            let mut vrrp_packet = event_pkt_generator.gen_vrrp_header(&mut vrrp_buff, &event_vrouter).await;
                            vrrp_packet.set_checksum(checksum::one_complement_sum(vrrp_packet.packet(), Some(6)));
                            
                            // IP packet
                            let ip_len = vrrp_packet.packet().len() + 20;
                            let mut ip_buff: Vec<u8> = vec![0; ip_len];
                            let mut ip_packet = event_pkt_generator.gen_vrrp_ip_header(&mut ip_buff);
                            ip_packet.set_payload(vrrp_packet.packet());

                            // Ethernet packet
                            let mut eth_buffer: Vec<u8> = vec![0; 14 + ip_packet.packet().len()];
                            let mut ether_packet = event_pkt_generator.gen_vrrp_eth_packet(&mut eth_buffer);
                            ether_packet.set_payload(ip_packet.packet());            
                            event_sender
                                .send_to(ether_packet.packet(), None)
                                .unwrap()
                                .unwrap();
                
                            for ip in &event_vrouter.ip_addresses {
                                let mut e_buff = [0u8; 42];
                                let mut a_buff = [0u8; 28];
                                let (mut grat_eth, grat_arp) = event_pkt_generator.gen_gratuitous_arp_packet(
                                    &mut e_buff, &mut a_buff, ip.addr()
                                );
                                grat_eth.set_payload(grat_arp.packet());
                                event_sender
                                    .send_to(grat_eth.packet(), None)
                                    .unwrap()
                                    .unwrap();
                            }
                
                            let advert_time = event_vrouter.advert_interval as f32;
                            event_vrouter.fsm.set_advert_timer(advert_time);
                            event_vrouter.fsm.state = States::Master;
                            log::info!("({}) transitioned to MASTER (init)", event_vrouter.name);
                        }
                
                        else {
                            let m_down_interval = event_vrouter.master_down_interval;
                            event_vrouter.fsm.set_master_down_timer(m_down_interval);
                            event_vrouter.fsm.state = States::Backup;
                            log::info!("({}) transitioned to BACKUP (init)", event_vrouter.name);
                        }
                    }
                }

                Event::Shutdown => {
                    match event_vrouter.fsm.state {
                        States::Backup => {
                            event_vrouter.fsm.disable_timer();
                            event_vrouter.fsm.state = States::Init;
                        }
                        States::Master => {
                            event_vrouter.fsm.disable_timer();
                            // send ADVERTIEMENT 
                            // VRRP pakcet
                            let mut vrrp_buff: Vec<u8> = vec![0; 16 + (4 * event_vrouter.ip_addresses.len())];
                            let mut vrrp_packet = event_pkt_generator.gen_vrrp_header(&mut vrrp_buff, &event_vrouter).await;
                            vrrp_packet.set_checksum(checksum::one_complement_sum(vrrp_packet.packet(), Some(6)));
                            
                            // IP packet
                            let ip_len = vrrp_packet.packet().len() + 20;
                            let mut ip_buff: Vec<u8> = vec![0; ip_len];
                            let mut ip_packet = event_pkt_generator.gen_vrrp_ip_header(&mut ip_buff);
                            ip_packet.set_payload(vrrp_packet.packet());

                            // Ethernet packet
                            let mut eth_buffer: Vec<u8> = vec![0; 14 + ip_packet.packet().len()];
                            let mut ether_packet = event_pkt_generator.gen_vrrp_eth_packet(&mut eth_buffer);
                            ether_packet.set_payload(ip_packet.packet());  
                            event_sender
                                .send_to(ether_packet.packet(), None)
                                .unwrap()
                                .unwrap();

                            event_vrouter.fsm.state = States::Init;
                        }
                        States::Init => {}
                    }
                }

                Event::MasterDown => {
                    if event_vrouter.fsm.state == States::Backup {
                        // send ADVERTIEMENT then send gratuitous ARP 

                        // VRRP advertisement
                        {
                            // VRRP pakcet
                            let mut vrrp_buff: Vec<u8> = vec![0; 16 + (4 * event_vrouter.ip_addresses.len())];
                            let mut vrrp_packet = event_pkt_generator.gen_vrrp_header(&mut vrrp_buff, &event_vrouter).await;
                            vrrp_packet.set_checksum(checksum::one_complement_sum(vrrp_packet.packet(), Some(6)));
                            
                            // IP packet
                            let ip_len = vrrp_packet.packet().len() + 20;
                            let mut ip_buff: Vec<u8> = vec![0; ip_len];
                            let mut ip_packet = event_pkt_generator.gen_vrrp_ip_header(&mut ip_buff);
                            ip_packet.set_payload(vrrp_packet.packet());

                            // Ethernet packet
                            let mut eth_buffer: Vec<u8> = vec![0; 14 + ip_packet.packet().len()];
                            let mut ether_packet = event_pkt_generator.gen_vrrp_eth_packet(&mut eth_buffer);
                            ether_packet.set_payload(ip_packet.packet());  
                            event_sender
                                .send_to(ether_packet.packet(), None)
                                .unwrap()
                                .unwrap();
                        }

                        // gratuitous ARP 
                        {
                            for ip in &event_vrouter.ip_addresses {
                                let mut e_buff = [0u8; 42];
                                let mut a_buff = [0u8; 28];
                                let (mut grat_eth, grat_arp) = event_pkt_generator.gen_gratuitous_arp_packet(
                                    &mut e_buff, &mut a_buff, ip.addr()
                                );
                                grat_eth.set_payload(grat_arp.packet());
                                event_sender
                                    .send_to(grat_eth.packet(), None)
                                    .unwrap()
                                    .unwrap();
                            }
                        }

                        let advert_interval = event_vrouter.advert_interval as f32;
                        event_vrouter.fsm.set_advert_timer(advert_interval);
                        event_vrouter.fsm.state = States::Master;
                        log::info!("({}) Transitioned to MASTER", event_vrouter.name);

                    }
                    log::info!("({}) Master Down Event", &event_vrouter.name);
                }

                Event::Null => { }

            }
        }
    });

    let _ = tokio::join!(
        network_receiver_process, 
        event_listener_process,
        timers_counter_process
    );
    Ok(())
}
