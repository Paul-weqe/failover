use std::sync::Arc;
use tokio::sync::Mutex;
use crate::{network, pkt::generators, state_machine::Event};
use pnet::packet::{
    arp::{ ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket }, 
    ethernet::{ EtherTypes, EthernetPacket, MutableEthernetPacket }, 
    ipv4::Ipv4Packet, Packet
};
use vrrp_packet::VrrpPacket;
use crate::{ 
    router::VirtualRouter, 
    state_machine::States,
    base_functions::{create_datalink_channel, get_interface}
};

// pub fn handle_incoming_arp_pkt(packet: &ArpPacket, vrouter: &VirtualRouter) {
pub async fn handle_incoming_arp_pkt<'a>(eth_packet: &EthernetPacket<'a>, vrouter: Arc<Mutex<VirtualRouter>>) {

    let mut_router = vrouter.lock().await;
    let interface = get_interface(&mut_router.network_interface);
    let arp_packet = ArpPacket::new(eth_packet.payload()).unwrap();

    match mut_router.fsm.state {
        States::INIT => {}
        States::BACKUP => {
            // MUST NOT respond to ARP requests for the IP address(s) associated 
            // with the virtual router.
            for ip in &mut_router.ip_addresses {
                if ip.addr() == arp_packet.get_target_proto_addr() {
                    return 
                }
            }
            
            // MUST discard packets with a destination link layer MAC address
            // equal to the virtual router MAC address.
            if arp_packet.get_target_hw_addr() == interface.mac.unwrap() {
                return
            }
        }

        States::MASTER => {
            // MUST respond to ARP requests for the IP address(es) associated
            // with the virtual router.
            for ip in &mut_router.ip_addresses {
                if ip.addr() == arp_packet.get_target_proto_addr() {
                    let (mut sender, _) = create_datalink_channel(&interface);

                    // respond to arp request
                    let mut ethernet_buffer = [0u8; 42];
                    let mut arp_buffer = [0u8; 28];
                    let mut outgoing_ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
                    outgoing_ethernet_packet.set_destination(eth_packet.get_source());
                    outgoing_ethernet_packet.set_source(interface.clone().mac.unwrap());

                    let mut outgoing_arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
                    outgoing_arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
                    outgoing_arp_packet.set_protocol_type(EtherTypes::Ipv4);
                    outgoing_arp_packet.set_hw_addr_len(6);
                    outgoing_arp_packet.set_proto_addr_len(4);
                    outgoing_arp_packet.set_operation(ArpOperations::Reply);
                    outgoing_arp_packet.set_target_hw_addr(arp_packet.get_sender_hw_addr());
                    outgoing_arp_packet.set_sender_hw_addr(interface.clone().mac.unwrap());
                    outgoing_arp_packet.set_target_proto_addr(arp_packet.get_sender_proto_addr());
                    outgoing_arp_packet.set_sender_proto_addr(arp_packet.get_target_proto_addr());
                    outgoing_ethernet_packet.set_payload(outgoing_arp_packet.packet());

                    sender
                        .send_to(outgoing_ethernet_packet.packet(), Some(interface.clone()))
                        .unwrap()
                        .unwrap();
                }
            }
        }
    }
}

// pub fn handle_incoming_vrrp_pkt(eth_packet: &EthernetPacket, vrouter: Arc<Mutex<VirtualRouter>>)
pub async fn handle_incoming_vrrp_pkt<'a>(eth_packet: &EthernetPacket<'a>, vrouter_mutex: Arc<Mutex<VirtualRouter>>) 
{

    let mut vrouter = vrouter_mutex.lock().await;
    let interface = get_interface(&vrouter.network_interface);
    let ip_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();
    let vrrp_packet = VrrpPacket::new(ip_packet.payload()).unwrap();
    

    if interface.ips.first().unwrap().ip() != ip_packet.get_source() {
        match vrouter.fsm.state {
            
            States::BACKUP => {
                if vrrp_packet.get_priority() == 0 {
                    let skew_time = vrouter.skew_time;
                    vrouter.fsm.set_master_down_timer(skew_time);
                }
                else if !vrouter.preempt_mode || vrrp_packet.get_priority() >= vrouter.priority {
                    let m_down_interval = vrouter.master_down_interval;
                    vrouter.fsm.set_master_down_timer(m_down_interval);   
                }
                else if vrouter.priority > vrrp_packet.get_priority() {
                    vrouter.fsm.state = States::MASTER;
                    let advert_interval = vrouter.advert_interval as f32;
                    vrouter.fsm.set_advert_timer(advert_interval);
                    log::info!("({}) transitioned to MASTER", vrouter.name);
                    
                } 
                else {
                    return 
                }
            }
            
            States::MASTER => {
                let incoming_ip_pkt = Ipv4Packet::new(eth_packet.payload()).unwrap(); 
                let adv_priority_gt_local_priority = vrrp_packet.get_priority() > vrouter.priority;
                let adv_priority_eq_local_priority = vrrp_packet.get_priority() == vrouter.priority;
                let send_ip_gt_local_ip = incoming_ip_pkt.get_source() > incoming_ip_pkt.get_destination();
                
                // If an ADVERTISEMENT is received, then
                if vrrp_packet.get_priority() == 0 {

                    // send ADVERTISEMENT
                    let mut_pkt_generator = generators::MutablePktGenerator::new(interface.clone());
                    let (mut sender, _) = create_datalink_channel(&interface);

                    let mut vrrp_buff: Vec<u8> = vec![0; 16 + (4 * vrouter.ip_addresses.len())];
                    let mut outgoing_vrrp_packet = mut_pkt_generator.gen_vrrp_header(&mut vrrp_buff, &vrouter).await;
                    outgoing_vrrp_packet.set_checksum(network::checksum::one_complement_sum(outgoing_vrrp_packet.packet(), Some(6)));

                    let ip_len = vrrp_packet.packet().len() + 20;
                    let mut ip_buff: Vec<u8> = vec![0; ip_len];
                    let mut ip_packet = mut_pkt_generator.gen_vrrp_ip_header(&mut ip_buff);
                    ip_packet.set_payload(vrrp_packet.packet());

                    let mut eth_buff: Vec<u8> = vec![0; 14 + ip_packet.packet().len()];
                    let mut eth_packet = mut_pkt_generator.gen_vrrp_eth_packet(&mut eth_buff);
                    eth_packet.set_payload(ip_packet.packet());

                    sender
                        .send_to(eth_packet.packet(), None)
                        .unwrap()
                        .unwrap();
                    let advert_interval = vrouter.advert_interval as f32;
                    vrouter.fsm.set_advert_timer(advert_interval);
                    vrouter.fsm.event = Event::NoEvent;

                }
                
                else if adv_priority_gt_local_priority || ( adv_priority_eq_local_priority && adv_priority_eq_local_priority) 
                {
                    let m_down_interval = vrouter.master_down_interval as f32;
                    vrouter.fsm.set_master_down_timer(m_down_interval);
                    vrouter.fsm.state = States::BACKUP;
                    vrouter.fsm.event = Event::NoEvent;
                    log::info!("({}) transitioned to BACKUP", vrouter.name);
                }

                else {
                    return
                }

            }
            _ => {}
        }
    }

}
