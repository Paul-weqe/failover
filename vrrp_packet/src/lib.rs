use pnet_macros::packet;
use pnet_macros_support::types::*;


/// 
/// header of VRRP packet
/// as described in RFC 3768 (5.1)
/// 
#[packet]
pub struct Vrrp {
    version: u4,  
    header_type: u4, 
    vrid: u8,
    priority: u8,
    count_ip: u8,
    auth_type: u8,
    advert_int: u8,
    checksum: u16be,
    
    #[length="(count_ip * 4)"]
    ip_addresses: Vec<u8>,

    // the following two are only used for backward compatibility. 
    auth_data: u32be,
    auth_data2: u32be,
    #[length="0"]
    #[payload]
    pub payload: Vec<u8>
}


