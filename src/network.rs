

//! checksums related functions module
//! This module is dedicated to internet checksums functions.
//!
//! credit for rfc1071, propagate_carries and one_complement_sum 
//! calculation to ref. impl. https://github.com/m-labs/smoltcp/blob/master/src/wire/ip.rs
//! and rust's rVVRP github 

use std::net::{IpAddr, Ipv4Addr};
use pnet::{packet::{ip::{IpNextHeaderProtocol, IpNextHeaderProtocols}, ipv4::{checksum, Ipv4Flags, MutableIpv4Packet}, Packet}, transport::transport_channel};
use vrrp_packet::MutableVrrpPacket;
use crate::router::VirtualRouter;
use pnet::transport::TransportSender;
use pnet::transport::TransportChannelType::Layer3;

pub fn send_multicast(vrouter: VirtualRouter)  
{
    // build VRRP header
    let mut vrrp_buffer = [0u8; 192];
    let mut vrrp_packet: MutableVrrpPacket = MutableVrrpPacket::new(&mut vrrp_buffer).unwrap();
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
    let mut ip_buffer: [u8; 212] = [0u8; 212];
    let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();
    {
        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_dscp(4);
        ip_packet.set_ecn(1);
        ip_packet.set_total_length(212);
        ip_packet.set_identification(257);
        ip_packet.set_flags(Ipv4Flags::DontFragment);
        ip_packet.set_fragment_offset(257);
        ip_packet.set_ttl(255);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Vrrp);
        ip_packet.set_source(vrouter.ip_addresses[0].addr());
        ip_packet.set_destination(Ipv4Addr::new(224, 0, 0, 18));
        ip_packet.set_checksum(checksum(&ip_packet.to_immutable()));
        ip_packet.set_payload(&vrrp_packet.packet());
    }

    let protocol = Layer3(IpNextHeaderProtocols::Vrrp);
    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "An error occured while creating the transport channel: {}",
            e
        )  
    };

    match tx.send_to(ip_packet, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))) {
        Ok(n) => {
            println!("Packet of size {n} sent");
        },
        Err(e) => {
            log::error!("Error occured: \n {:?}", e);
            panic!("Unable to send multicast packet");
        }
    };

}

pub mod networkinterface {
    use ipnet::Ipv4Net;


    /*
    * Creates a tun_tap interface on our device. 
    * This will have the ip address of Ipv4Net 
    * and mac address will be in the format 00-00-5E-00-01-{vrid}
    */
    #[cfg(target_os="linux")]
    pub fn create_network_interface(
        iname: &str,
        ip_address: &Ipv4Net,
        vrid: u8
    ) {
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
