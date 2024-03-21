use std::net::Ipv4Addr;

use pnet_macros::packet;
use pnet_macros_support::types::*;

/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Version| Type  | Virtual Rtr ID|   Priority    | Count IP Addrs|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Auth Type   |   Adver Int   |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         IP Address (1)                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                            .                                  |
/// |                            .                                  |
/// |                            .                                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         IP Address (n)                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     Authentication Data (1)                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     Authentication Data (2)                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 
/// NOTE: The checksum is the 16-bit one’s complement of the 
/// one’s complement sum of the entire VRRP message starting with 
/// the version field. For computing the checksum, the checksum 
/// field is set to zero. See RFC 1071 for more detail [CKSM]. 
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


