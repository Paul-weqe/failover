//! checksums related functions module
//! This module is dedicated to internet checksums functions.
//!
//! credit for rfc1071, propagate_carries and one_complement_sum 
//! calculation to ref. impl. https://github.com/m-labs/smoltcp/blob/master/src/wire/ip.rs
//! and rust's rVVRP github 

use std::{net::Ipv4Addr, str::FromStr, time::Duration};
use pnet::{
    datalink::{self, Channel, NetworkInterface}, 
    packet::{
        ethernet::{EtherTypes, MutableEthernetPacket}, 
        ip::IpNextHeaderProtocols, 
        ipv4::{checksum, Ipv4Flags, MutableIpv4Packet}, 
        Packet
    }, 
    util::MacAddr
};
use vrrp_packet::MutableVrrpPacket;
use crate::router::VirtualRouter;

pub fn send_multicast(vrouter: VirtualRouter, interface_name: &str)  
{
    let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;
    let interfaces = datalink::linux::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    // build VRRP header
    // length = 32 + (8 * no_ip)
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
        vrrp_packet.set_checksum(checksum::rfc1071(&vrrp_packet.packet()));


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
        ip_packet.set_destination(Ipv4Addr::new(224, 0, 0, 18));
        ip_packet.set_checksum(checksum(&ip_packet.to_immutable()));
        ip_packet.set_payload(&vrrp_packet.packet());
    }

    // build ethernet packet
    // let mut ether_buffer: [u8; 292] = [0u8; 292];
    let mut ether_buffer: Vec<u8> = vec![0; 14 + ip_packet.packet().len()];
    let mut ether_packet = MutableEthernetPacket::new(&mut ether_buffer).unwrap();
    {
        // ether_packet.set_source(MacAddr(0x00, 0x00, 0x5E, 0x00, 0x01, vrouter.vrid));
        ether_packet.set_source(interface.mac.unwrap());
        ether_packet.set_destination(MacAddr(0x01, 0x00, 0x5E, 0x00, 0x00, 0x12));
        ether_packet.set_ethertype(EtherTypes::Ipv4);
        ether_packet.set_payload(ip_packet.packet());
    }
    
    let (mut sender, _receiver) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened: {}", e)  
    };

    loop {
        std::thread::sleep(Duration::from_secs(2));
        log::debug!("VRRP advert: {:#?}", &vrrp_packet);
        sender
            .send_to(ether_packet.packet(), None)
            .unwrap()
            .unwrap();
    }

}


pub mod checksum {
    use byteorder::{ByteOrder, NetworkEndian};
    const RFC1071_CHUNK_SIZE: usize = 32;


    // rfc1071() function
    /// compute rfc1071 internet checksum
    /// returns all-ones if carried checksum is valid
    pub fn rfc1071(mut data: &[u8]) -> u16 {
        let mut acc = 0;

        // for each 32 bytes chunk
        while data.len() >= RFC1071_CHUNK_SIZE {
            let mut d = &data[..RFC1071_CHUNK_SIZE];
            while d.len() >= 2 {
                // sum adjacent pairs converted to 16 bits integer
                acc += NetworkEndian::read_u16(d) as u32;
                // take the next 2 bytes for the next iteration
                d = &d[2..];
            }
            data = &data[RFC1071_CHUNK_SIZE..];
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

        propagate_carries(acc)
    }

    // propagate final complement?
    pub fn propagate_carries(word: u32) -> u16 {
        let sum = (word >> 16) + (word & 0xffff);
        ((sum >> 16) as u16) + (sum as u16)
    }

    // one_complement_sum() function
    /// returns all-zeros if checksum is valid
    pub fn one_complement_sum(data: &[u8], pos: Option<usize>) -> u16 {
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
