use core::f32;
use std::{net::Ipv4Addr, sync::Arc};
use ipnet::Ipv4Net;
use tokio::sync::Mutex;
use crate::{checksum, error::NetError, pkt::generators, state_machine::Event};
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


pub(crate) async fn handle_incoming_arp_pkt<'a>(eth_packet: &EthernetPacket<'a>, vrouter: Arc<Mutex<VirtualRouter>>) {

    let vrouter = vrouter.lock().await;
    let interface = get_interface(&vrouter.network_interface);
    let arp_packet = ArpPacket::new(eth_packet.payload()).unwrap();
    
    match vrouter.fsm.state {
        States::Init => {}
        States::Backup => {
            // MUST NOT respond to ARP requests for the IP address(s) associated 
            // with the virtual router.
            for ip in &vrouter.ip_addresses {
                if ip.addr() == arp_packet.get_target_proto_addr() {
                    return 
                }
            }
            
            // !TODO
            // MUST discard packets with a destination link layer MAC address
            // equal to the virtual router MAC address.
            if arp_packet.get_target_hw_addr() == interface.mac.unwrap() {
                return
            }
        }

        States::Master => {
            // MUST respond to ARP requests for the IP address(es) associated
            // with the virtual router.
            for ip in &vrouter.ip_addresses {
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

pub(crate) async fn handle_incoming_vrrp_pkt<'a>(eth_packet: &EthernetPacket<'a>, vrouter_mutex: Arc<Mutex<VirtualRouter>>) -> Result<(), NetError>{

    let mut vrouter = vrouter_mutex.lock().await;
    let interface = get_interface(&vrouter.network_interface);
    let ip_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();
    let vrrp_packet = VrrpPacket::new(ip_packet.payload()).unwrap();
    let mut error ;
    // MUST DO verifications(rfc3768 section 7.1)
    {
        
        // 1. Verify IP TTL is 255
        if ip_packet.get_ttl() != 255 {
            error = format!("({}) TTL of incoming VRRP packet != 255", vrouter.name);
            log::error!("{error}");
            return Result::Err(NetError(error));
        }

        // 2. MUST verify the VRRP version is 2.
        if vrrp_packet.get_version() != 2 {
            error = format!("({}) Incoming VRRP packet Version != 2", vrouter.name);
            log::error!("{error}");
            return Result::Err(NetError(error));
        }

        // 3. MUST verify that the received packet contains the complete VRRP
        //      packet (including fixed fields, IP Address(es), and Authentication
        //      Data)


        // 4. MUST verify the VRRP checksum.
        //      rfc1071() function should return value with all 1's
        let check = checksum::confirm_checksum(vrrp_packet.packet());
        if format!("{:b}", check).contains("0") {
            error = format!("({}) invalid checksum from {:?}", vrouter.name, ip_packet.get_source());
            log::error!("{error}");
            return Result::Err(NetError(error));
        }

        
        // 5. MUST verify that the VRID is configured on the receiving interface
        //      and the local router is not the IP Address owner (Priority equals
        //      255 (decimal)).
        //      TODO Once implemented multiple interfaces

        // 6. Auth Type must be same. 
        //      TODO once multiple authentication types are configured

        // 7. MUST verify that the Adver Interval in the packet is the same as
        //      the locally configured for this virtual router
        //      If the above check fails, the receiver MUST discard the packet,
        //      SHOULD log the event and MAY indicate via network management that a
        //      misconfiguration was detected.
        if vrrp_packet.get_advert_int() != vrouter.advert_interval {
            error = format!(
                "({}) Incoming VRRP packet has advert interval {} while configured advert interval is {}",
                vrouter.name, vrrp_packet.get_advert_int(), vrouter.advert_interval 
            );
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
        let count_check = vrrp_packet.get_count_ip() == vrouter.ip_addresses.len() as u8;
        let mut addr_check = true;

        if vrrp_packet.get_ip_addresses().clone().len() % 4 != 0 {
            error = format!("({}) Invalid Ip Addresses in vrrp packet", vrouter.name);
            log::error!("{error}");
            return Result::Err(NetError(error));
        }

        let mut addr: Vec<u8> = vec![];
        for (counter, octet) in vrrp_packet.get_ip_addresses().iter().enumerate() {
            addr.push(*octet);
            if counter + 1 % 4 == 0 {
                let ip = Ipv4Net::new(
                    Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]), 24
                ).unwrap().addr();
                if !vrouter.ipv4_addresses().contains(&ip) {
                    log::error!("({}) IP address {:?} for incoming VRRP packet not found in local config", vrouter.name, ip);
                    addr_check = false;
                }
            }
        }
        
        if !count_check {
            error = format!(
                "({}) ip count check({}) does not match with local configuration of ip count {}",
                vrouter.name, vrrp_packet.get_count_ip(), vrouter.ip_addresses.len()
            );
            log::error!("{error}");
            if vrrp_packet.get_priority() != 255{
                return Result::Err(NetError(error));
            }
        }

        if !addr_check && vrrp_packet.get_priority() != 255 {
            error = format!("({}) IP addresses for incoming vrrp don't match ", vrouter.name);
            log::error!("{error}");
            if vrrp_packet.get_priority() != 255 {
                return Result::Err(NetError(error));
            }
        }

    }

    if interface.ips.first().unwrap().ip() != ip_packet.get_source() {
        match vrouter.fsm.state {
            
            States::Backup => {
                if vrrp_packet.get_priority() == 0 {
                    let skew_time = vrouter.skew_time;
                    vrouter.fsm.set_master_down_timer(skew_time);
                }
                else if !vrouter.preempt_mode || vrrp_packet.get_priority() >= vrouter.priority {
                    let m_down_interval = vrouter.master_down_interval;
                    vrouter.fsm.set_master_down_timer(m_down_interval);
                }
                else if vrouter.priority > vrrp_packet.get_priority() {
                    vrouter.fsm.state = States::Master;
                    let advert_interval = vrouter.advert_interval as f32;
                    vrouter.fsm.set_advert_timer(advert_interval);
                    log::info!("({}) transitioned to MASTER", vrouter.name);
                } 
                Ok(())
            }
            
            States::Master => {
                let incoming_ip_pkt = Ipv4Packet::new(eth_packet.payload()).unwrap(); 
                let adv_priority_gt_local_priority = vrrp_packet.get_priority() > vrouter.priority;
                let adv_priority_eq_local_priority = vrrp_packet.get_priority() == vrouter.priority;
                let _send_ip_gt_local_ip = incoming_ip_pkt.get_source() > incoming_ip_pkt.get_destination();
                
                // If an ADVERTISEMENT is received, then
                if vrrp_packet.get_priority() == 0 {

                    // send ADVERTISEMENT
                    let mut_pkt_generator = generators::MutablePktGenerator::new(interface.clone());
                    let (mut sender, _) = create_datalink_channel(&interface);

                    let mut vrrp_buff: Vec<u8> = vec![0; 16 + (4 * vrouter.ip_addresses.len())];
                    let mut outgoing_vrrp_packet = mut_pkt_generator.gen_vrrp_header(&mut vrrp_buff, &vrouter).await;
                    outgoing_vrrp_packet.set_checksum(checksum::one_complement_sum(outgoing_vrrp_packet.packet(), Some(6)));

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
                    vrouter.fsm.event = Event::Null;
                    Ok(())

                }
                
                else if adv_priority_gt_local_priority 
                {
                    let m_down_interval = vrouter.master_down_interval as f32;
                    vrouter.fsm.set_master_down_timer(m_down_interval);
                    vrouter.fsm.state = States::Backup;
                    vrouter.fsm.event = Event::Null;
                    log::info!("({}) transitioned to BACKUP", vrouter.name);
                    Ok(())
                }
                else if adv_priority_eq_local_priority {

                    let m_down_interval = vrouter.master_down_interval as f32;
                    vrouter.fsm.set_master_down_timer(m_down_interval);
                    vrouter.fsm.state = States::Backup;
                    vrouter.fsm.event = Event::Null;
                    log::info!("({}) transitioned to BACKUP", vrouter.name);
                    Ok(())
                }
                else {Ok(()) 
                }

            }
            _ => {
                Ok(())
            }
        }
    } else {
        Result::Err(NetError(
            format!("")
        ))
    }

}
