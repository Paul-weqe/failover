/// This is the main file for the processes being run. 
/// There are three functions holding these processes 
/// functions that are to be run:
///     - Network Process (pub(crate) fn network_process)
///     - Event Process (pub(crate) fn event_process)
///     - Timer Process (pub(crate) fn timer_process)
/// 
/// Each of the above will be run on a thread of their own. 
/// Avoided using async since they were only three separate threads needed. 
/// 
/// 

use std::{sync::Arc, time::Instant};
use pnet::packet::{
    ethernet::{ EtherTypes, EthernetPacket }, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, Packet
};
use crate::{
    general::create_datalink_channel, observer::EventObserver, pkt::handlers::{handle_incoming_arp_pkt, handle_incoming_vrrp_pkt},
    state_machine::{Event, States}
};
use crate::checksum;


/// Waits for network connections and does the necessary actions. 
/// Acts on the queries mostly described from the state machine 
/// in chapter 6.3 onwards ofRFC 3768
pub(crate) fn network_process(items: crate::TaskItems) {
    // NetworkInterface
    let interface = items.generator.interface;
    let (_sender, mut receiver) = create_datalink_channel(&interface);
    let vrouter = items.vrouter;

    loop {
        let buff = receiver.next().unwrap();
        
        let incoming_eth_pkt = EthernetPacket::new(buff).unwrap();
        match incoming_eth_pkt.get_ethertype() {

            EtherTypes::Ipv4 => {

                let incoming_ip_pkt = Ipv4Packet::new(incoming_eth_pkt.payload()).unwrap();
                if incoming_ip_pkt.get_next_level_protocol() == IpNextHeaderProtocols::Vrrp {
                    match handle_incoming_vrrp_pkt(&incoming_eth_pkt, Arc::clone(&vrouter)) {
                        Ok(_) => {}
                        Err(_) => {
                            continue
                        }
                    }
                }
                
            }
            
            EtherTypes::Arp => {
                handle_incoming_arp_pkt( &incoming_eth_pkt, Arc::clone(&vrouter));
            }

            _ => {
                let net_vr = &vrouter.lock().unwrap();
                
                // if we are master, we forward the packet. 
                // otherwise we leave the packet be
                if net_vr.fsm.state == States::Master {

                }
            }
        }

    }
}


/// Used to track the various timers: (MasterDownTimer and Advertimer)
/// Has been explained in RFC 3768 section 6.2
pub(crate) fn timer_process(items: crate::TaskItems) {

    let generator = items.generator;
    let (mut sender, _receiver) = create_datalink_channel(&generator.interface);
    let vrouter = items.vrouter;

    loop {
        let mut vrouter = vrouter.lock().unwrap();
        let timer = vrouter.fsm.timer;

        match timer.t_type {
            crate::state_machine::TimerType::MasterDown => {

                if Instant::now() > vrouter.fsm.timer.waiting_for.unwrap() {
                    EventObserver::notify_mut(vrouter, Event::MasterDown);
                }

            }

            crate::state_machine::TimerType::Adver => {
                
                if Instant::now() > vrouter.fsm.timer.waiting_for.unwrap() {
                    // VRRP pakcet
                    let mut vrrp_buff: Vec<u8> = vec![0; 16 + (4 * vrouter.ip_addresses.len())];
                    let mut vrrp_packet = generator.gen_vrrp_header(&mut vrrp_buff, &vrouter);
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

                    let advert_time = vrouter.advert_interval as f32;
                    vrouter.fsm.set_advert_timer(advert_time);
                }
                // timer_vrouter.fsm.reduce_timer();
            }

            crate::state_machine::TimerType::Null =>  {
                
            }
        }
    }
}
