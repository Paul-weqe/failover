use std::{net::Ipv4Addr, str::FromStr};
use pnet::{
    datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface}, 
    packet::{
        arp::{
            ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket
        }, 
        ethernet::{
            EtherTypes, EthernetPacket, MutableEthernetPacket
        }, 
        ip::IpNextHeaderProtocols, ipv4::{checksum, Ipv4Flags, Ipv4Packet, MutableIpv4Packet}, 
        Packet
    }, util::MacAddr
};
use vrrp_packet::{MutableVrrpPacket, VrrpPacket};
use crate::{defaults, router::VirtualRouter, system::{States, Timers}};



pub fn send_advertisement(mut vrouter: VirtualRouter)  
{
    let interface_names_match = |iface: &NetworkInterface| iface.name == vrouter.network_interface;
    let interfaces = datalink::linux::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    // build VRRP header
    // length = 32 + (8 * no_ip)
    log::info!("({}) Setting up advertisement packet", vrouter.name);
    let mut vrrp_buffer: Vec<u8> = vec![0; 16 + (4 * vrouter.ip_addresses.len())];
    let mut vrrp_packet: MutableVrrpPacket = MutableVrrpPacket::new(&mut vrrp_buffer[..]).unwrap();
    {
        let mut addresses: Vec<u8> = Vec::new();
        for addr in &vrouter.ip_addresses {
            for octet in addr.addr().octets() {
                addresses.push(octet);
            }
        }

        vrrp_packet.set_version(2);
        vrrp_packet.set_header_type(1);
        vrrp_packet.set_advert_int(vrouter.advert_interval);
        vrrp_packet.set_vrid(vrouter.vrid);
        vrrp_packet.set_priority(vrouter.priority);
        vrrp_packet.set_count_ip(vrouter.ip_addresses.len() as u8);
        vrrp_packet.set_checksum(0);
        vrrp_packet.set_auth_type(0);
        vrrp_packet.set_auth_data(0);
        vrrp_packet.set_auth_data2(0);
        vrrp_packet.set_ip_addresses(&addresses);
        vrrp_packet.set_checksum(checksum::one_complement_sum(vrrp_packet.packet(), Some(6)));

        if vrrp_packet.get_ip_addresses().len() > 20 {
            log::error!("VRRP packet cannot have more than 20 IP addresses");
            panic!("VRRP configuration VRID={} has more than 20 IP addresses", vrrp_packet.get_vrid());
        }
        if vrrp_packet.get_ip_addresses().len() == 0 {
            log::error!("VRRP packet must have a virtual ip address");
            panic!("VRRP configuration VRID={} does not have an ip address", vrrp_packet.get_vrid());
        }
    }
    
    // build IP packet
    // let mut ip_buffer: [u8; 212] = [0u8; 212];
    // let ip_len = vrrp_buffer.len() + 20;
    let ip = interface.ips.first().unwrap().ip();
    let ip_len = vrrp_packet.packet().len() + 20;
    let mut ip_buffer: Vec<u8> = vec![0; ip_len];
    let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer[..]).unwrap();
    {
        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_dscp(4);
        ip_packet.set_ecn(1);
        ip_packet.set_total_length(ip_len as u16);
        ip_packet.set_identification(2118);
        ip_packet.set_flags(Ipv4Flags::DontFragment);
        ip_packet.set_fragment_offset(0);
        ip_packet.set_ttl(255);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Vrrp);
        ip_packet.set_source(Ipv4Addr::from_str(&ip.to_string()).unwrap());
        ip_packet.set_destination(defaults::DESTINATION_MULTICAST_IP_ADDRESS);
        ip_packet.set_checksum(checksum(&ip_packet.to_immutable()));
        ip_packet.set_payload(&vrrp_packet.packet());
    }

    // build ethernet packet
    // let mut ether_buffer: [u8; 292] = [0u8; 292];
    let mut ether_buffer: Vec<u8> = vec![0; 14 + ip_packet.packet().len()];
    let mut ether_packet = MutableEthernetPacket::new(&mut ether_buffer).unwrap();
    {
        ether_packet.set_source(interface.mac.unwrap());
        ether_packet.set_destination(defaults::DESTINATION_MULTICAST_MAC_ADDRESS);
        ether_packet.set_ethertype(EtherTypes::Ipv4);
        ether_packet.set_payload(ip_packet.packet());
    }


    let (mut sender, mut receiver) = create_datalink_channel(&interface);
    
    loop {

        let buf = receiver.next().unwrap();
    
        match vrouter.system.state{

            // Initialize STATE
            States::INIT => {
                if vrouter.priority == 255 {
                    // send ADVERTISEMENT
                    log::info!("({}) VRRP ADVERTISEMENT sent", vrouter.name);
                    sender
                        .send_to(ether_packet.packet(), None)
                        .unwrap()
                        .unwrap();

                    // TODO: add code for gratuitous ARP request with Virtual Router MAC and each of the 
                    // IP addresses associated with the Virtual Router
                    {
                        let mut eth_arp_buffer = [0u8; 42];
                        let mut eth_arp_packet = MutableEthernetPacket::new(&mut eth_arp_buffer).unwrap();
                        eth_arp_packet.set_destination(MacAddr::broadcast());
                        eth_arp_packet.set_source(interface.mac.unwrap());
                        eth_arp_packet.set_ethertype(EtherTypes::Arp);
                        
                        let mut arp_buffer = [0u8; 28];
                        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
                        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
                        arp_packet.set_protocol_type(EtherTypes::Ipv4);
                        arp_packet.set_hw_addr_len(6);
                        arp_packet.set_proto_addr_len(4);
                        arp_packet.set_operation(ArpOperations::Request);
                        arp_packet.set_sender_hw_addr(interface.mac.unwrap());
                        arp_packet.set_sender_proto_addr(vrouter.ip_addresses[0].addr());
                        arp_packet.set_target_hw_addr(MacAddr::broadcast());
                        arp_packet.set_target_proto_addr(vrouter.ip_addresses[0].addr());
                        eth_arp_packet.set_payload(arp_packet.packet());

                        sender
                            .send_to(eth_arp_packet.packet(), None)
                            .unwrap()
                            .unwrap();
                        log::info!("({}) Sending ARP packet", vrouter.name);

                    }

                    // adding ARP
                    vrouter.system.timers = Timers::AdverTimer(vrouter.advert_interval);
                    vrouter.system.state = States::MASTER;
                    log::info!("({}) Entered the MASTER state", vrouter.name);
                }

                else {
                    vrouter.system.timers = Timers::MasterDownTimer(vrouter.master_down_interval);
                    vrouter.system.state = States::BACKUP;
                    log::info!("({}) Entering the BACKUP state", vrouter.name);
                    
                }
            },


            // Backup STATE
            States::BACKUP => {

                let buf = receiver.next().unwrap();
                // While in Backup State:
                let eth = EthernetPacket::new(&buf).unwrap();
                
                if eth.get_destination() == vrouter.mac() { continue; }

                // - MUST NOT respond to ARP requests for the IP address(s) associated
                // with the virtual router.
                let condition_1 = if eth.get_ethertype() == EtherTypes::Arp { true } else { false };

                // - MUST discard packets with a destination link layer MAC address
                // equal to the virtual router MAC address.
                let condition_2 = if eth.get_destination() == vrouter.mac() { true } else { false };

                // - MUST NOT accept packets addressed to the IP address(es) associated
                // with the virtual router.
                let mut condition_3 = false;
                
                if eth.get_ethertype() == EtherTypes::Ipv4 {
                    let ip = Ipv4Packet::new(eth.payload()).unwrap();
                    for addr in &vrouter.ip_addresses {
                        if addr.addr().octets() == ip.get_destination().octets() {
                            condition_3 = true;
                            break;
                        }
                    }
                }

                if condition_1 || condition_2 || condition_3 {
                    continue;
                }

                // check if advertisement has been received
                if eth.get_ethertype() == EtherTypes::Ipv4 {
                    let ip = Ipv4Packet::new(eth.payload()).unwrap();
                    if ip.get_next_level_protocol() == IpNextHeaderProtocols::Vrrp {
                        let received_vrrp_pkt = VrrpPacket::new(ip.payload()).unwrap();
                        if received_vrrp_pkt.get_header_type() == 1 {
                            if received_vrrp_pkt.get_priority() == 0 { 
                                vrouter.system.timers = Timers::MasterDownTimer(vrouter.skew_time);
                            } else {
                                if vrouter.preempt_mode == false || received_vrrp_pkt.get_priority() >= vrouter.priority {
                                    vrouter.system.timers = Timers::MasterDownTimer(vrouter.master_down_interval);
                                } else {
                                    continue;
                                }
                            }
                        }
                    }
                }
            },

            // Master STATE
            States::MASTER => {

                log::info!("I AM MASTER!!");
                loop  {

                    let rec_eth = EthernetPacket::new(buf).unwrap();
                    if rec_eth.get_ethertype() == EtherTypes::Arp {
                        let rec_arp = ArpPacket::new(rec_eth.payload()).unwrap();
                        println!("gotten ARP");
                        println!("{:?}......", rec_arp);
                    }

                }
            }
        }
    }

}


fn create_datalink_channel(interface: &NetworkInterface)  -> (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>){
    match pnet::datalink::channel(interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => return (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened: {}", e)
    }
}


pub mod checksum 
{
    //! checksums related functions module
    //! This module is dedicated to internet checksums functions.
    //!
    //! credit for rfc1071, propagate_carries and one_complement_sum 
    //! calculation to ref. impl. https://github.com/m-labs/smoltcp/blob/master/src/wire/ip.rs
    //! and rust's rVVRP github 
    use byteorder::{ByteOrder, NetworkEndian};
    const _RFC1071_CHUNK_SIZE: usize = 32;
    

    // rfc1071() function
    /// compute rfc1071 internet checksum
    /// returns all-ones if carried checksum is valid
    pub fn _rfc1071(mut data: &[u8]) -> u16 
    {
        
        let mut acc = 0;

        // for each 32 bytes chunk
        while data.len() >= _RFC1071_CHUNK_SIZE {
            let mut d = &data[.._RFC1071_CHUNK_SIZE];
            while d.len() >= 2 {
                // sum adjacent pairs converted to 16 bits integer
                acc += NetworkEndian::read_u16(d) as u32;
                // take the next 2 bytes for the next iteration
                d = &d[2..];
            }
            data = &data[_RFC1071_CHUNK_SIZE..];
        }

        // if it does not fit a 32 bytes chunk
        while data.len() >= 2 {
            acc += NetworkEndian::read_u16(data) as u32;
            data = &data[2..];
        }

        // add odd byte is present
        if let Some(&v) = data.first() {
            acc += (v as u32) << 8;
        }

        _propagate_carries(acc)
    }

    // propagate final complement?
    pub fn _propagate_carries(word: u32) -> u16 
    {
        let sum = (word >> 16) + (word & 0xffff);
        ((sum >> 16) as u16) + (sum as u16)
    }

    // one_complement_sum() function
    /// returns all-zeros if checksum is valid
    pub fn one_complement_sum(data: &[u8], pos: Option<usize>) -> u16 
    {
        let mut sum = 0u32;
        let mut idx = 0;

        while idx < data.len() {
            match pos {
                // if a position is given:
                Some(p) => {
                    if idx == p {
                        idx = p + 2; // skip 2 bytes
                    }
                    // if we reach the end of slice, we are done
                    if idx == data.len() {
                        break;
                    }
                }
                None => (),
            }
            let word = (data[idx] as u32) << 8 | data[idx + 1] as u32;
            sum = sum + word;
            idx = idx + 2;
        }

        while sum >> 16 != 0 {
            sum = (sum >> 16) + (sum & 0xFFFF);
        }

        !sum as u16
    }

}
