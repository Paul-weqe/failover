use pnet::packet::{
    arp::{ ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket }, 
    ethernet::{ EtherTypes, EthernetPacket, MutableEthernetPacket },
    Packet
};
use crate::{ router::VirtualRouter, state_machine::States };



// pub fn handle_incoming_arp_pkt(packet: &ArpPacket, vrouter: &VirtualRouter) {
pub fn handle_incoming_arp_pkt(eth_packet: &EthernetPacket, vrouter: &VirtualRouter) {
    let interface = crate::get_interface(&vrouter.name);
    let arp_packet = ArpPacket::new(eth_packet.payload()).unwrap();

    match vrouter.fsm.state {
        States::INIT => {}
        States::BACKUP => {
            // MUST NOT respond to ARP requests for the IP address(s) associated 
            // with the virtual router.
            for ip in &vrouter.ip_addresses {
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
            for ip in &vrouter.ip_addresses {
                if ip.addr() == arp_packet.get_target_proto_addr() {
                    let (mut sender, _) = crate::create_datalink_channel(&interface);

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

pub fn handle_incoming_vrrp_pkt(eth_packet: &EthernetPacket, vrouter: &VirtualRouter) {}
