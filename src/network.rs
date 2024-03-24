use std::thread;

use pnet::{
    datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface}, 
    packet::{
        arp::ArpPacket, ethernet::{
            EtherType, EtherTypes, EthernetPacket, MutableEthernetPacket
        }, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, Packet
    }
};
use vrrp_packet::VrrpPacket;
use crate::{pkt_generators, pkt_handlers::{handle_incoming_arp_pkt, handle_incoming_vrrp_pkt}, router::VirtualRouter};



pub fn send_advertisement<'a>(mut vrouter: VirtualRouter)  
{
    let interface_names_match = |iface: &NetworkInterface| iface.name == vrouter.network_interface;
    let interfaces = datalink::linux::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();
    
    if interface.ips.len() == 0 {
        log::error!("Interface {} does not have any valid IP addresses", interface.name);
        panic!("Interface {} does not have any valid IP addresses", interface.name);
    }

    let mutable_pkt_generator = pkt_generators::MutablePktGenerator::new(vrouter.clone(), interface.clone());
    
    
    //   ________________________________________________
    //  |                _______________________________|
    //  |               |                               |
    //  |               |            ______________     |
    //  |  ETH HEADER   | IP HEADER |  VRRP PACKET |    |
    //  |               |           |______________|    |  
    //  |               |_______________________________|
    //  |_______________________________________________|

    // VRRP pakcet
    let mut vrrp_buff: Vec<u8> = vec![0; 16 + (4 * vrouter.ip_addresses.len())];
    let mut vrrp_packet = mutable_pkt_generator.gen_vrrp_header(&mut vrrp_buff);
    vrrp_packet.set_checksum(checksum::one_complement_sum(vrrp_packet.packet(), Some(6)));
    
    // IP packet
    let ip_len = vrrp_packet.packet().len() + 20;
    let mut ip_buff: Vec<u8> = vec![0; ip_len];
    let mut ip_packet = mutable_pkt_generator.gen_vrrp_ip_header(&mut ip_buff);
    ip_packet.set_payload(vrrp_packet.packet());

    // Ethernet packet
    let mut eth_buffer: Vec<u8> = vec![0; 14 + ip_packet.packet().len()];
    let mut ether_packet = mutable_pkt_generator.gen_vrrp_eth_packet(&mut eth_buffer);
    ether_packet.set_payload(ip_packet.packet());
    
    let (mut _sender, mut receiver) = create_datalink_channel(&interface);
    
    // listen for any incoming requests
    let receiver_thread = thread::spawn( move || {
        loop {
            let buf = receiver.next().unwrap();
            let incoming_eth_pkt = EthernetPacket::new(&buf).unwrap();
            
            match incoming_eth_pkt.get_ethertype() {
                EtherTypes::Ipv4 => {
                    let incoming_ip_pkt = Ipv4Packet::new(incoming_eth_pkt.payload()).unwrap();
                    if incoming_ip_pkt.get_next_level_protocol() == IpNextHeaderProtocols::Vrrp {
                        let incoming_vrrp_pkt = VrrpPacket::new(incoming_ip_pkt.payload()).unwrap();
                        handle_incoming_vrrp_pkt(&incoming_vrrp_pkt, &vrouter);
                    }
                }

                EtherTypes::Arp => {
                    let incoming_arp_pkt = ArpPacket::new(incoming_eth_pkt.payload()).unwrap();
                    handle_incoming_arp_pkt(&incoming_arp_pkt, &vrouter);
                }

                _ => continue
            }

        }
        
    });

    let _ = receiver_thread.join();

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
