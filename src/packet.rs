use std::net::Ipv4Addr;

use bytes::{Buf, BufMut, Bytes, BytesMut};

//
// VRRP Packet Format.
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version| Type  | Virtual Rtr ID|   Priority    | Count IP Addrs|
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Auth Type   |   Adver Int   |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         IP Address (1)                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                            .                                  |
// |                            .                                  |
// |                            .                                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         IP Address (n)                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Authentication Data (1)                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Authentication Data (2)                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug)]
pub struct VrrpPacket {
    pub version: u8,
    pub hdr_type: u8,
    pub vrid: u8,
    pub priority: u8,
    pub count_ip: u8,
    pub auth_type: u8,
    pub adver_int: u8,
    pub checksum: u16,
    pub ip_addresses: Vec<Ipv4Addr>,

    // the following two are only used for backward compatibility.
    pub auth_data: u32,
    pub auth_data2: u32,
}

impl VrrpPacket {
    const MIN_PKT_LENGTH: usize = 16;
    const MAX_PKT_LENGTH: usize = 80;
    const MAX_IP_COUNT: usize = 16;

    // Encodes VRRP packet into a bytes buffer.
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(114);
        let ver_type = (self.version << 4) | self.hdr_type;
        buf.put_u8(ver_type);
        buf.put_u8(self.vrid);
        buf.put_u8(self.priority);
        buf.put_u8(self.count_ip);
        buf.put_u8(self.auth_type);
        buf.put_u8(self.adver_int);
        buf.put_u16(self.checksum);
        for addr in self.ip_addresses.clone() {
            let octets = addr.octets();
            octets.iter().for_each(|octet| buf.put_u8(*octet));
        }

        buf.put_u32(self.auth_data);
        buf.put_u32(self.auth_data2);
        buf
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        // 1. pkt length verification
        let pkt_size = data.len();

        let mut buf: Bytes = Bytes::copy_from_slice(data);
        let ver_type = buf.get_u8();
        let version = ver_type >> 4;
        let hdr_type = ver_type & 0x0F;
        let vrid = buf.get_u8();
        let priority = buf.get_u8();
        let count_ip = buf.get_u8();
        let auth_type = buf.get_u8();
        let adver_int = buf.get_u8();

        if !(Self::MIN_PKT_LENGTH..=Self::MAX_PKT_LENGTH).contains(&pkt_size)
            || count_ip as usize > Self::MAX_IP_COUNT
            || (count_ip * 4) + 16 != pkt_size as u8
        {
            return None;
        }

        let checksum = buf.get_u16();

        let mut ip_addresses: Vec<Ipv4Addr> = vec![];
        for _ in 0..count_ip {
            ip_addresses.push(Ipv4Addr::from_bits(buf.get_u32()));
        }

        let auth_data = buf.get_u32();
        let auth_data2 = buf.get_u32();

        return Some(Self {
            version,
            hdr_type,
            vrid,
            priority,
            count_ip,
            auth_type,
            adver_int,
            checksum,
            ip_addresses,
            auth_data,
            auth_data2,
        });
    }
}

#[repr(C)]
pub struct ARPframe {
    // Ethernet Header
    pub dst_mac: [u8; 6], // destination MAC address
    pub src_mac: [u8; 6], // source MAC address
    pub ethertype: u16,   // ether type

    // ARP
    pub hardware_type: u16,         // network link type (0x1=ethernet)
    pub protocol_type: u16,         // upper-layer protocol for resolution
    pub hw_addr_len: u8,            // length of hardware address (bytes)
    pub proto_addr_len: u8,         // upper-layer protocol address length
    pub opcode: u16,                // operation (0x1=request, 0x2=reply)
    pub sender_hw_addr: [u8; 6],    // sender hardware address
    pub sender_proto_addr: [u8; 4], // internetwork address of sender
    pub target_hw_addr: [u8; 6],    // hardware address of target
    pub target_proto_addr: [u8; 4], // internetwork address of target
}

impl ARPframe {
    pub fn new(eth_pkt: EthernetFrame, arp_pkt: ArpPacket) -> Self {
        Self {
            dst_mac: eth_pkt.dst_mac,
            src_mac: eth_pkt.src_mac,
            ethertype: eth_pkt.ethertype.to_be(),

            hardware_type: arp_pkt.hw_type.to_be(),
            protocol_type: arp_pkt.proto_type.to_be(),
            hw_addr_len: arp_pkt.hw_length,
            proto_addr_len: arp_pkt.proto_length,
            opcode: arp_pkt.operation.to_be(),

            sender_hw_addr: arp_pkt.sender_hw_address,
            sender_proto_addr: arp_pkt.sender_proto_address,
            target_hw_addr: arp_pkt.target_hw_address,
            target_proto_addr: arp_pkt.target_proto_address,
        }
    }
}

#[derive(Clone, Debug)]
pub struct EthernetFrame {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
}

#[derive(Clone, Debug)]
pub struct ArpPacket {
    pub hw_type: u16,
    pub proto_type: u16,
    pub hw_length: u8,
    pub proto_length: u8,
    pub operation: u16,
    pub sender_hw_address: [u8; 6],
    pub sender_proto_address: [u8; 4],
    pub target_hw_address: [u8; 6],
    pub target_proto_address: [u8; 4],
}

impl ArpPacket {
    pub fn decode(data: &[u8]) -> Option<ArpPacket> {
        if data.len() != 28 {
            return None;
        }
        let mut buf = Bytes::copy_from_slice(data);
        let hw_type = buf.get_u16();
        let proto_type = buf.get_u16();
        let hw_length = buf.get_u8();
        let proto_length = buf.get_u8();
        let operation = buf.get_u16();

        let sender_hw_address: [u8; 6] = [0_u8; 6];
        for mut _x in &sender_hw_address {
            _x = &buf.get_u8();
        }

        let sender_proto_address: [u8; 4] = [0_u8; 4];
        for mut _x in &sender_proto_address {
            _x = &buf.get_u8();
        }

        let target_hw_address: [u8; 6] = [0_u8; 6];
        for mut _x in &target_hw_address {
            _x = &buf.get_u8();
        }

        let target_proto_address: [u8; 4] = [0_u8; 4];
        for mut _x in &target_proto_address {
            _x = &buf.get_u8();
        }

        Some(Self {
            hw_type,
            proto_type,
            hw_length,
            proto_length,
            operation,
            sender_hw_address,
            sender_proto_address,
            target_hw_address,
            target_proto_address,
        })
    }
}
