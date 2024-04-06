use std::{sync::Arc, time::Duration};
use pnet::{datalink::{DataLinkReceiver, DataLinkSender}, packet::{
    ethernet::{ EtherTypes, EthernetPacket }, icmp::IcmpPacket, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, Packet
}};
use tokio::sync::Mutex;
use crate::{
    error::NetError, general::{create_datalink_channel, get_interface}, 
    pkt::{generators::{self, MutablePktGenerator}, 
    handlers::{handle_incoming_arp_pkt, handle_incoming_vrrp_pkt}}, 
    router::VirtualRouter, state_machine::{Event, States}
};
use crate::checksum;


/// initiates the network functions across the board. 
/// from interfaces, channels, packet handling etc...
pub async fn run_vrrp(vrouter: VirtualRouter) -> Result<(), NetError>{

    let interface = get_interface(&vrouter.network_interface);
    let vrouter = Arc::new(Mutex::new(vrouter));
    let pkt_generator = generators::MutablePktGenerator::new( interface.clone() );


    // wait for when either MasterDownTimer or AdvertTimer is reached to 
    // carry out necessary actions. 
    let timers_process = tokio::spawn(
        timers_listener(
            pkt_generator.clone(), 
            create_datalink_channel(&interface), 
            Arc::clone(&vrouter)
        )
    );

    // async process listens for any incoming network requests
    let network_process = tokio::spawn(
        network_listener(
            create_datalink_channel(&interface), 
        Arc::clone(&vrouter)
        )
    );

    // listen for any events happening to the vrouter
    let event_process = tokio::spawn(
        event_listener(
            pkt_generator.clone(), 
            create_datalink_channel(&interface), 
            Arc::clone(&vrouter)
        )
    );
    
    let _ = tokio::join!(
        event_process,
        network_process, 
        timers_process
    );
    Ok(())
}


/// Listens for when any Event occurs in the Virtual Router. 
/// Events that can occur are: Startup,  Shutdown, MasterDown, Null  
/// Actions happening on when each of these Events is fired are
/// Specified in RFC 3768 section 6.3, 6.4 and 6.5
async fn event_listener(
    generator: MutablePktGenerator, 
    (mut sender, _receiver): (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>),
    vrouter: Arc<Mutex<VirtualRouter>>
){
    loop {
        
        let mut vrouter = vrouter.lock().await;
        match &vrouter.fsm.event {
            
            // Startup actions specified in section 6.4.1 of RFC 3768
            // this Event is called when the router is initialized and 
            // the state machine is in Init mode. Is default when Vrouter is 
            // started. 
            Event::Startup => {
                if vrouter.fsm.state == States::Init {
                    if vrouter.priority == 255 {

                        //   ________________________________________________
                        //  |                _______________________________|
                        //  |               |                               |
                        //  |               |            ______________     |
                        //  |  ETH HEADER   | IP HEADER |  VRRP PACKET |    |
                        //  |               |           |______________|    |  
                        //  |               |_______________________________|
                        //  |_______________________________________________|
            
                        // VRRP pakcet
                        let no_of_ips = vrouter.ip_addresses.len();

                        let mut vrrp_buff: Vec<u8> = vec![0; 16 + (4 * no_of_ips)];
                        let mut vrrp_packet = generator.gen_vrrp_header(&mut vrrp_buff, &vrouter).await;
                        vrrp_packet.set_checksum(checksum::one_complement_sum(vrrp_packet.packet(), Some(6)));
                        
                        // IP packet
                        let ip_len = vrrp_packet.packet().len() + 20;
                        let mut ip_buff: Vec<u8> = vec![0; ip_len];
                        let mut ip_packet = generator.gen_vrrp_ip_header(&mut ip_buff);
                        ip_packet.set_payload(vrrp_packet.packet());

                        // Ethernet packet
                        let mut eth_buffer: Vec<u8> = vec![0; 14 + ip_packet.packet().len()];
                        let mut ether_packet = generator.gen_vrrp_eth_packet(&mut eth_buffer);
                        ether_packet.set_payload(ip_packet.packet());            
                        sender
                            .send_to(ether_packet.packet(), None)
                            .unwrap()
                            .unwrap();
            
                        for ip in &vrouter.ip_addresses {
                            let mut e_buff = [0u8; 42];
                            let mut a_buff = [0u8; 28];
                            let (mut grat_eth, grat_arp) = generator.gen_gratuitous_arp_packet(
                                &mut e_buff, &mut a_buff, ip.addr()
                            );
                            grat_eth.set_payload(grat_arp.packet());
                            sender
                                .send_to(grat_eth.packet(), None)
                                .unwrap()
                                .unwrap();
                        }
            
                        let advert_time = vrouter.advert_interval as f32;
                        vrouter.fsm.set_advert_timer(advert_time);
                        vrouter.fsm.state = States::Master;
                        log::info!("({}) transitioned to MASTER (init)", vrouter.name);
                    }
            
                    else {
                        let m_down_interval = vrouter.master_down_interval;
                        vrouter.fsm.set_master_down_timer(m_down_interval);
                        vrouter.fsm.state = States::Backup;
                        log::info!("({}) transitioned to BACKUP (init)", vrouter.name);
                    }
                }
            }

            // Can be called when the Virtual Rotuer is in the Backup Mode.
            // Actions covered in RFC 3768 section 6.4.2
            Event::Shutdown => {
                match vrouter.fsm.state {
                    States::Backup => {
                        vrouter.fsm.disable_timer();
                        vrouter.fsm.state = States::Init;
                    }
                    States::Master => {
                        vrouter.fsm.disable_timer();
                        // send ADVERTIEMENT 
                        // VRRP pakcet
                        let mut vrrp_buff: Vec<u8> = vec![0; 16 + (4 * vrouter.ip_addresses.len())];
                        let mut vrrp_packet = generator.gen_vrrp_header(&mut vrrp_buff, &vrouter).await;
                        vrrp_packet.set_checksum(checksum::one_complement_sum(vrrp_packet.packet(), Some(6)));
                        
                        // IP packet
                        let ip_len = vrrp_packet.packet().len() + 20;
                        let mut ip_buff: Vec<u8> = vec![0; ip_len];
                        let mut ip_packet = generator.gen_vrrp_ip_header(&mut ip_buff);
                        ip_packet.set_payload(vrrp_packet.packet());

                        // Ethernet packet
                        let mut eth_buffer: Vec<u8> = vec![0; 14 + ip_packet.packet().len()];
                        let mut ether_packet = generator.gen_vrrp_eth_packet(&mut eth_buffer);
                        ether_packet.set_payload(ip_packet.packet());  
                        sender
                            .send_to(ether_packet.packet(), None)
                            .unwrap()
                            .unwrap();

                        vrouter.fsm.state = States::Init;
                    }
                    States::Init => {}
                }
            }
            
            // Is when the router is in Backup mode and the master has not sent 
            // any VRRP ADVERTISEMENT for the period set by the 'Master Down Timer'. 
            //  
            Event::MasterDown => {
                if vrouter.fsm.state == States::Backup {
                    // send ADVERTIEMENT then send gratuitous ARP 

                    // VRRP advertisement
                    {
                        // VRRP pakcet
                        let mut vrrp_buff: Vec<u8> = vec![0; 16 + (4 * vrouter.ip_addresses.len())];
                        let mut vrrp_packet = generator.gen_vrrp_header(&mut vrrp_buff, &vrouter).await;
                        vrrp_packet.set_checksum(checksum::one_complement_sum(vrrp_packet.packet(), Some(6)));
                        
                        // IP packet
                        let ip_len = vrrp_packet.packet().len() + 20;
                        let mut ip_buff: Vec<u8> = vec![0; ip_len];
                        let mut ip_packet = generator.gen_vrrp_ip_header(&mut ip_buff);
                        ip_packet.set_payload(vrrp_packet.packet());

                        // Ethernet packet
                        let mut eth_buffer: Vec<u8> = vec![0; 14 + ip_packet.packet().len()];
                        let mut ether_packet = generator.gen_vrrp_eth_packet(&mut eth_buffer);
                        ether_packet.set_payload(ip_packet.packet());  
                        sender
                            .send_to(ether_packet.packet(), None)
                            .unwrap()
                            .unwrap();
                    }

                    // gratuitous ARP 
                    {
                        for ip in &vrouter.ip_addresses {
                            let mut e_buff = [0u8; 42];
                            let mut a_buff = [0u8; 28];
                            let (mut grat_eth, grat_arp) = generator.gen_gratuitous_arp_packet(
                                &mut e_buff, &mut a_buff, ip.addr()
                            );
                            grat_eth.set_payload(grat_arp.packet());
                            sender
                                .send_to(grat_eth.packet(), None)
                                .unwrap()
                                .unwrap();
                        }
                    }

                    let advert_interval = vrouter.advert_interval as f32;
                    vrouter.fsm.set_advert_timer(advert_interval);
                    vrouter.fsm.state = States::Master;
                    log::info!("({}) Transitioned to MASTER", vrouter.name);

                }
                log::info!("({}) Master Down Event", &vrouter.name);
            }

            Event::Null => { }

        }
    }
}


async fn timers_listener(
    generator: MutablePktGenerator, 
    (mut sender, _receiver): (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>),
    vrouter: Arc<Mutex<VirtualRouter>>
) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        let mut timer_vrouter = vrouter.lock().await;
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
                    let mut vrrp_packet = generator.gen_vrrp_header(&mut vrrp_buff, &timer_vrouter).await;
                    vrrp_packet.set_checksum(checksum::one_complement_sum(vrrp_packet.packet(), Some(6)));
                    
                    // // IP packet
                    let ip_len = vrrp_packet.packet().len() + 20;
                    let mut ip_buff: Vec<u8> = vec![0; ip_len];
                    let mut ip_packet = generator.gen_vrrp_ip_header(&mut ip_buff);
                    ip_packet.set_payload(vrrp_packet.packet());

                    // // Ethernet packet
                    let mut eth_buffer: Vec<u8> = vec![0; 14 + ip_packet.packet().len()];
                    let mut ether_packet = generator.gen_vrrp_eth_packet(&mut eth_buffer);
                    ether_packet.set_payload(ip_packet.packet());  
                    sender
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
}

async fn network_listener(
    (_sender, mut receiver): (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>),
    vrouter: Arc<Mutex<VirtualRouter>>
) {
    loop {
        let buf = receiver.next().unwrap();
        let incoming_eth_pkt = EthernetPacket::new(buf).unwrap();
        match incoming_eth_pkt.get_ethertype() {

            EtherTypes::Ipv4 => {
                // println!("IPV4!!!");
                
                let incoming_ip_pkt = Ipv4Packet::new(incoming_eth_pkt.payload()).unwrap();
                if incoming_ip_pkt.get_next_level_protocol() == IpNextHeaderProtocols::Vrrp {
                    match handle_incoming_vrrp_pkt(&incoming_eth_pkt, Arc::clone(&vrouter)).await {
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
                handle_incoming_arp_pkt( &incoming_eth_pkt, Arc::clone(&vrouter)).await;
            }

            _ => {
                let net_vr = &vrouter.lock().await;
                
                // if we are master, we forward the packet. 
                // otherwise we leave the packet be
                if net_vr.fsm.state == States::Master {

                }
            }
        }
    }
}
