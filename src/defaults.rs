use std::net::Ipv4Addr;
use pnet::util::MacAddr;


pub fn priority() -> u8 { 100 }
pub fn advert_int() -> u8 { 1 }
pub fn preempt_mode() -> bool { true }


pub const DESTINATION_MULTICAST_MAC_ADDRESS: MacAddr = MacAddr(0x01, 0x00, 0x5E, 0x00, 0x00, 0x12);
pub const DESTINATION_MULTICAST_IP_ADDRESS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 18);
