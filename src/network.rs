

//! checksums related functions module
//! This module is dedicated to internet checksums functions.
//!
//! credit for rfc1071, propagate_carries and one_complement_sum 
//! calculation to ref. impl. https://github.com/m-labs/smoltcp/blob/master/src/wire/ip.rs
//! and rust's rVVRP github 

use std::net::Ipv4Addr;

use byteorder::{ByteOrder, NetworkEndian};
use pnet::packet::{ip::IpNextHeaderProtocols, ipv4::{checksum, Ipv4Flags, MutableIpv4Packet}, Packet};
use vrrp_packet::MutableVrrpPacket;
use crate::router::VirtualRouter;

const RFC1071_CHUNK_SIZE: usize = 32;


pub fn send_multicast(vrouter: VirtualRouter)  
{
    
    // build VRRP header
    let mut vrrp_buffer = [0u8; 20];
    let mut vrrp_packet: MutableVrrpPacket = MutableVrrpPacket::new(&mut vrrp_buffer).unwrap();
    {
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
        vrrp_packet.set_ip_addresses(vrouter.ip_addresses[0].addr());
        vrrp_packet.set_checksum(rfc1071(&vrrp_packet.packet()));
    }

    // build IP packet
    let mut ip_buffer: [u8; 200] = [0u8; 200];
    let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();
    {
        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_dscp(4);
        ip_packet.set_ecn(1);
        ip_packet.set_total_length(25);
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

}


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
