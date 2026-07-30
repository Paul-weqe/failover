use std::net::Ipv4Addr;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use internet_checksum::Checksum;

use crate::error::PacketError;

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
    pub vrid: u8,
    pub priority: u8,
    pub count_ip: u8,
    pub adver_int: u8,
    pub ip_addresses: Vec<Ipv4Addr>,
}

impl VrrpPacket {
    const MIN_PKT_LENGTH: usize = 16;
    const MAX_PKT_LENGTH: usize = 80;
    pub(crate) const MAX_IP_COUNT: usize = 16;

    // Header elements that remain as const.
    const VRRP_VERSION: u8 = 2;
    const HDWR_TYPE: u8 = 1;

    // Encodes VRRP packet into a bytes buffer.
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(114);

        // Vrrp_version | hardware type.
        let ver_type = (Self::VRRP_VERSION << 4) | Self::HDWR_TYPE;
        buf.put_u8(ver_type);
        buf.put_u8(self.vrid);
        buf.put_u8(self.priority);
        buf.put_u8(self.count_ip);

        // Auth type.
        buf.put_u8(0);
        buf.put_u8(self.adver_int);

        // Checksum.
        buf.put_u16(0);
        for addr in &self.ip_addresses {
            let octets = addr.octets();
            octets.iter().for_each(|octet| buf.put_u8(*octet));
        }

        // Auth data1 & Auth Data2, only for backward compatibility.
        buf.put_u32(0);
        buf.put_u32(0);

        let mut check = Checksum::new();
        check.add_bytes(&buf);
        buf[6..8].copy_from_slice(&check.checksum());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, PacketError> {
        let pkt_size = data.len();
        if pkt_size < 1 {
            return Err(PacketError::Malformed);
        }

        let mut buf: Bytes = Bytes::copy_from_slice(data);
        let ver_type = buf.get_u8();
        let version = ver_type >> 4;
        let _hdr_type = ver_type & 0x0F;

        if version != Self::VRRP_VERSION {
            return Err(PacketError::UnsupportedVersion(version));
        }

        if !(Self::MIN_PKT_LENGTH..=Self::MAX_PKT_LENGTH).contains(&pkt_size) {
            return Err(PacketError::Malformed);
        }

        let vrid = buf.get_u8();
        let priority = buf.get_u8();
        let count_ip = buf.get_u8();
        let _auth_type = buf.get_u8();
        let adver_int = buf.get_u8();

        if count_ip as usize > Self::MAX_IP_COUNT
            || (count_ip * 4) + 16 != pkt_size as u8
        {
            return Err(PacketError::Malformed);
        }

        let _checksum = buf.get_u16();

        let mut ip_addresses: Vec<Ipv4Addr> = vec![];
        for _ in 0..count_ip {
            ip_addresses.push(Ipv4Addr::from_bits(buf.get_u32()));
        }

        let _auth_data = buf.get_u32();
        let _auth_data2 = buf.get_u32();

        Ok(Self {
            vrid,
            priority,
            count_ip,
            adver_int,
            ip_addresses,
        })
    }
}

#[repr(C)]
pub struct ARPframe {
    // Ethernet Header
    pub dst_mac: [u8; 6], // destination MAC address
    pub src_mac: [u8; 6], // source MAC address
    pub ethertype: u16,   // ether type

    // ARP
    pub hardware_type: u16, // Network link type (0x1=ethernet)
    pub protocol_type: u16, // Upper-layer protocol for resolution
    pub hw_addr_len: u8,    // Length of hardware address (bytes)
    pub proto_addr_len: u8, // Upper-layer protocol address length
    pub opcode: u16,        // Operation (0x1=request, 0x2=reply)
    pub sender_hw_addr: [u8; 6], // Sender hardware address
    pub sender_proto_addr: [u8; 4], // Internetwork address of sender
    pub target_hw_addr: [u8; 6], // Hardware address of target
    pub target_proto_addr: [u8; 4], // Internetwork address of target
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

        let sender_hw_address: [u8; 6] = std::array::from_fn(|_| buf.get_u8());
        let sender_proto_address: [u8; 4] =
            std::array::from_fn(|_| buf.get_u8());
        let target_hw_address: [u8; 6] = std::array::from_fn(|_| buf.get_u8());
        let target_proto_address: [u8; 4] =
            std::array::from_fn(|_| buf.get_u8());

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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_packet(count_ip: u8) -> VrrpPacket {
        let ip_addresses = (0..count_ip)
            .map(|i| Ipv4Addr::new(192, 168, 100, i))
            .collect();
        VrrpPacket {
            vrid: 51,
            priority: 100,
            count_ip,
            adver_int: 1,
            ip_addresses,
        }
    }

    #[test]
    fn encode_decode_roundtrip_various_ip_counts() {
        for count in [0u8, 1, 2, VrrpPacket::MAX_IP_COUNT as u8] {
            let pkt = sample_packet(count);
            let encoded = pkt.encode();
            let decoded = VrrpPacket::decode(&encoded).unwrap_or_else(|err| {
                panic!("decode failed for count_ip={count}: {err}")
            });

            assert_eq!(decoded.vrid, pkt.vrid);
            assert_eq!(decoded.priority, pkt.priority);
            assert_eq!(decoded.count_ip, pkt.count_ip);
            assert_eq!(decoded.adver_int, pkt.adver_int);
            assert_eq!(decoded.ip_addresses, pkt.ip_addresses);
        }
    }

    #[test]
    fn encode_produces_a_valid_internet_checksum() {
        let encoded = sample_packet(2).encode();
        let mut check = Checksum::new();
        check.add_bytes(&encoded);
        assert_eq!(check.checksum(), [0, 0]);
    }

    #[test]
    fn decode_rejects_empty_buffer() {
        assert!(matches!(
            VrrpPacket::decode(&[]),
            Err(PacketError::Malformed)
        ));
    }

    #[test]
    fn decode_rejects_buffer_shorter_than_min_length() {
        let encoded = sample_packet(0).encode();
        assert_eq!(encoded.len(), VrrpPacket::MIN_PKT_LENGTH);
        let truncated = &encoded[..encoded.len() - 1];
        assert!(matches!(
            VrrpPacket::decode(truncated),
            Err(PacketError::Malformed)
        ));
    }

    #[test]
    fn decode_rejects_buffer_longer_than_max_length() {
        let encoded = sample_packet(VrrpPacket::MAX_IP_COUNT as u8).encode();
        assert_eq!(encoded.len(), VrrpPacket::MAX_PKT_LENGTH);
        let mut padded = encoded.to_vec();
        padded.push(0);
        assert!(matches!(
            VrrpPacket::decode(&padded),
            Err(PacketError::Malformed)
        ));
    }

    #[test]
    fn decode_rejects_unsupported_version() {
        let mut encoded = sample_packet(1).encode();
        // High nibble is version; swap 2 -> 3.
        encoded[0] = (3 << 4) | (encoded[0] & 0x0F);
        assert!(matches!(
            VrrpPacket::decode(&encoded),
            Err(PacketError::UnsupportedVersion(3))
        ));
    }

    #[test]
    fn decode_rejects_count_ip_disagreeing_with_length() {
        let mut encoded = sample_packet(1).encode();
        // Byte 3 is count_ip; claim 2 addresses while the buffer only
        // carries the bytes for 1, so the length formula no longer holds.
        encoded[3] = 2;
        assert!(matches!(
            VrrpPacket::decode(&encoded),
            Err(PacketError::Malformed)
        ));
    }

    #[test]
    fn arp_decode_rejects_wrong_length() {
        assert!(ArpPacket::decode(&[0u8; 27]).is_none());
        assert!(ArpPacket::decode(&[0u8; 29]).is_none());
    }

    #[test]
    fn arp_decode_roundtrips_known_fields() {
        let pkt = ArpPacket {
            hw_type: 1,
            proto_type: 0x0800,
            hw_length: 6,
            proto_length: 4,
            operation: 2,
            sender_hw_address: [0x00, 0x00, 0x5e, 0x00, 0x01, 0x33],
            sender_proto_address: [192, 168, 100, 1],
            target_hw_address: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            target_proto_address: [192, 168, 100, 254],
        };

        let mut buf = BytesMut::with_capacity(28);
        buf.put_u16(pkt.hw_type);
        buf.put_u16(pkt.proto_type);
        buf.put_u8(pkt.hw_length);
        buf.put_u8(pkt.proto_length);
        buf.put_u16(pkt.operation);
        buf.put_slice(&pkt.sender_hw_address);
        buf.put_slice(&pkt.sender_proto_address);
        buf.put_slice(&pkt.target_hw_address);
        buf.put_slice(&pkt.target_proto_address);

        let decoded = ArpPacket::decode(&buf).expect("valid 28-byte frame");
        assert_eq!(decoded.hw_type, pkt.hw_type);
        assert_eq!(decoded.proto_type, pkt.proto_type);
        assert_eq!(decoded.hw_length, pkt.hw_length);
        assert_eq!(decoded.proto_length, pkt.proto_length);
        assert_eq!(decoded.operation, pkt.operation);
        assert_eq!(decoded.sender_hw_address, pkt.sender_hw_address);
        assert_eq!(decoded.sender_proto_address, pkt.sender_proto_address);
        assert_eq!(decoded.target_hw_address, pkt.target_hw_address);
        assert_eq!(decoded.target_proto_address, pkt.target_proto_address);
    }
}
