use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use internet_checksum::Checksum;

use crate::error::PacketError;
use crate::{VrrpAddresses, VrrpVersion};

// IANA-assigned IP protocol numbers used when building pseudo-headers for
// checksums that must cover them (IPv6 VRRP, and ICMPv6/NDP).
const VRRP_PROTO_NUM: u8 = 112;
const ICMPV6_PROTO_NUM: u8 = 58;

pub(crate) const VRRP_V6_MCAST_ADDR: Ipv6Addr =
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x12);
pub(crate) const ALL_NODES_V6_MCAST_ADDR: Ipv6Addr =
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

//
// VRRPv2 packet format (RFC 3768) over IPv4:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version| Type  | Virtual Rtr ID|   Priority    | Count IP Addrs|
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Auth Type   |   Adver Int   |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       IP Address(es)                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                  Authentication Data (1 & 2)                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// VRRPv3 (RFC 5798) keeps the same fixed header shape, but: the
// Auth Type/Adver Int bytes become a 4-bit Rsvd + 12-bit Max Adver Int
// (centiseconds) field, the trailing Authentication Data is dropped
// entirely, and the IP Address(es) may be IPv4 or IPv6.
#[derive(Clone, Debug)]
pub struct VrrpPacket {
    pub version: VrrpVersion,
    pub vrid: u8,
    pub priority: u8,
    pub adver_int_cs: u16,
    pub addresses: VrrpAddresses,
}

impl VrrpPacket {
    pub(crate) const MAX_IP_COUNT: usize = 16;
    const HDWR_TYPE: u8 = 1;
    // ver_type(1) + vrid(1) + priority(1) + count_ip(1) + interval-field(2)
    // + checksum(2). Identical width for v2 and v3 -- only the *trailing*
    // auth data (v2 only) and the address entry size (v4 vs v6) differ.
    const FIXED_HEADER_LEN: usize = 8;
    const V2_AUTH_TRAILER_LEN: usize = 8;

    /// Encodes this packet for the wire. `src_ip` is only used to build the
    /// IPv6 pseudo-header checksum when `addresses` is `V6`; it's ignored
    /// for IPv4 packets, which never need a pseudo-header.
    pub fn encode(&self, src_ip: IpAddr) -> BytesMut {
        match &self.addresses {
            VrrpAddresses::V4(addrs) => self.encode_v4(addrs),
            VrrpAddresses::V6(addrs) => {
                let src = match src_ip {
                    IpAddr::V6(v6) => v6,
                    IpAddr::V4(_) => Ipv6Addr::UNSPECIFIED,
                };
                self.encode_v6(src, addrs)
            }
        }
    }

    fn encode_v4(&self, addrs: &[Ipv4Addr]) -> BytesMut {
        let mut buf = BytesMut::with_capacity(
            Self::FIXED_HEADER_LEN
                + Self::V2_AUTH_TRAILER_LEN
                + addrs.len() * 4,
        );

        let ver_type = (self.version.as_u8() << 4) | Self::HDWR_TYPE;
        buf.put_u8(ver_type);
        buf.put_u8(self.vrid);
        buf.put_u8(self.priority);
        buf.put_u8(addrs.len() as u8);

        match self.version {
            VrrpVersion::V2 => {
                buf.put_u8(0); // Auth type.
                buf.put_u8((self.adver_int_cs / 100) as u8);
            }
            VrrpVersion::V3 => {
                buf.put_u16(self.adver_int_cs & 0x0FFF);
            }
        }
        buf.put_u16(0); // Checksum placeholder.

        for addr in addrs {
            buf.put_u32(addr.to_bits());
        }

        if self.version == VrrpVersion::V2 {
            buf.put_u32(0); // Auth data 1.
            buf.put_u32(0); // Auth data 2.
        }

        let mut check = Checksum::new();
        check.add_bytes(&buf);
        buf[6..8].copy_from_slice(&check.checksum());
        buf
    }

    fn encode_v6(&self, src_ip: Ipv6Addr, addrs: &[Ipv6Addr]) -> BytesMut {
        let mut buf =
            BytesMut::with_capacity(Self::FIXED_HEADER_LEN + addrs.len() * 16);

        let ver_type = (self.version.as_u8() << 4) | Self::HDWR_TYPE;
        buf.put_u8(ver_type);
        buf.put_u8(self.vrid);
        buf.put_u8(self.priority);
        buf.put_u8(addrs.len() as u8);
        buf.put_u16(self.adver_int_cs & 0x0FFF);
        buf.put_u16(0); // Checksum placeholder.

        for addr in addrs {
            buf.put_u128(addr.to_bits());
        }

        let mut check = Checksum::new();
        check.add_bytes(&src_ip.octets());
        check.add_bytes(&VRRP_V6_MCAST_ADDR.octets());
        check.add_bytes(&(buf.len() as u32).to_be_bytes());
        check.add_bytes(&[0, 0, 0, VRRP_PROTO_NUM]);
        check.add_bytes(&buf);
        buf[6..8].copy_from_slice(&check.checksum());
        buf
    }

    /// Decodes a VRRP message. `src_ip`/`dst_ip` are the outer IP header's
    /// addresses -- unused for IPv4 (whose checksum has no pseudo-header),
    /// required to verify an IPv6 packet's checksum.
    pub fn decode(
        data: &[u8],
        src_ip: IpAddr,
        dst_ip: IpAddr,
    ) -> Result<Self, PacketError> {
        match (src_ip, dst_ip) {
            (IpAddr::V4(_), _) => Self::decode_v4(data),
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                Self::decode_v6(data, src, dst)
            }
            (IpAddr::V6(_), IpAddr::V4(_)) => Err(PacketError::Malformed),
        }
    }

    fn decode_v4(data: &[u8]) -> Result<Self, PacketError> {
        if data.is_empty() {
            return Err(PacketError::Malformed);
        }

        let mut buf = Bytes::copy_from_slice(data);
        let ver_type = buf.get_u8();
        let version = VrrpVersion::try_from(ver_type >> 4)?;

        if data.len() < Self::FIXED_HEADER_LEN {
            return Err(PacketError::Malformed);
        }

        let vrid = buf.get_u8();
        let priority = buf.get_u8();
        let count_ip = buf.get_u8();

        let adver_int_cs = match version {
            VrrpVersion::V2 => {
                let _auth_type = buf.get_u8();
                let seconds = buf.get_u8();
                seconds as u16 * 100
            }
            VrrpVersion::V3 => {
                let field = buf.get_u16();
                field & 0x0FFF
            }
        };

        let trailing_auth_len = if version == VrrpVersion::V2 {
            Self::V2_AUTH_TRAILER_LEN
        } else {
            0
        };
        let expected_len = Self::FIXED_HEADER_LEN
            + trailing_auth_len
            + (count_ip as usize * 4);
        if count_ip as usize > Self::MAX_IP_COUNT || expected_len != data.len()
        {
            return Err(PacketError::Malformed);
        }

        if !Self::verify_checksum_v4(data) {
            return Err(PacketError::BadChecksum);
        }

        let _checksum = buf.get_u16();

        let mut addrs = Vec::with_capacity(count_ip as usize);
        for _ in 0..count_ip {
            addrs.push(Ipv4Addr::from_bits(buf.get_u32()));
        }

        if version == VrrpVersion::V2 {
            let _auth_data1 = buf.get_u32();
            let _auth_data2 = buf.get_u32();
        }

        Ok(Self {
            version,
            vrid,
            priority,
            adver_int_cs,
            addresses: VrrpAddresses::V4(addrs),
        })
    }

    fn decode_v6(
        data: &[u8],
        src_ip: Ipv6Addr,
        dst_ip: Ipv6Addr,
    ) -> Result<Self, PacketError> {
        if data.is_empty() {
            return Err(PacketError::Malformed);
        }

        let mut buf = Bytes::copy_from_slice(data);
        let ver_type = buf.get_u8();
        let version_raw = ver_type >> 4;
        let version = VrrpVersion::try_from(version_raw)?;
        if version != VrrpVersion::V3 {
            // VRRPv2 never runs over IPv6.
            return Err(PacketError::UnsupportedVersion(version_raw));
        }

        if data.len() < Self::FIXED_HEADER_LEN {
            return Err(PacketError::Malformed);
        }

        let vrid = buf.get_u8();
        let priority = buf.get_u8();
        let count_ip = buf.get_u8();
        let field = buf.get_u16();
        let adver_int_cs = field & 0x0FFF;

        let expected_len = Self::FIXED_HEADER_LEN + (count_ip as usize * 16);
        if count_ip as usize > Self::MAX_IP_COUNT || expected_len != data.len()
        {
            return Err(PacketError::Malformed);
        }

        if !Self::verify_checksum_v6(data, src_ip, dst_ip) {
            return Err(PacketError::BadChecksum);
        }

        let _checksum = buf.get_u16();

        let mut addrs = Vec::with_capacity(count_ip as usize);
        for _ in 0..count_ip {
            addrs.push(Ipv6Addr::from_bits(buf.get_u128()));
        }

        Ok(Self {
            version,
            vrid,
            priority,
            adver_int_cs,
            addresses: VrrpAddresses::V6(addrs),
        })
    }

    fn verify_checksum_v4(data: &[u8]) -> bool {
        let mut check = Checksum::new();
        check.add_bytes(data);
        check.checksum() == [0, 0]
    }

    fn verify_checksum_v6(data: &[u8], src: Ipv6Addr, dst: Ipv6Addr) -> bool {
        let mut check = Checksum::new();
        check.add_bytes(&src.octets());
        check.add_bytes(&dst.octets());
        check.add_bytes(&(data.len() as u32).to_be_bytes());
        check.add_bytes(&[0, 0, 0, VRRP_PROTO_NUM]);
        check.add_bytes(data);
        check.checksum() == [0, 0]
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

/// A hand-rolled ICMPv6 Neighbor Advertisement (RFC 4861 section 4.4) --
/// IPv6's equivalent of a gratuitous ARP reply. Sent over a raw ICMPv6
/// socket, so unlike `ARPframe` this carries no Ethernet header; the kernel
/// fills in the IPv6 header for a socket bound to `IPPROTO_ICMPV6`.
pub struct NdpNeighborAdvertisement {
    pub target_address: Ipv6Addr,
    pub target_link_addr: [u8; 6],
    /// Whether receivers should override an existing (stale) neighbor cache
    /// entry -- set for the gratuitous, "this address moved to me" case.
    pub override_flag: bool,
}

impl NdpNeighborAdvertisement {
    const TYPE: u8 = 136;
    const OPT_TARGET_LINK_ADDR: u8 = 2;

    pub fn encode(&self, src_ip: Ipv6Addr, dst_ip: Ipv6Addr) -> BytesMut {
        let mut msg = BytesMut::with_capacity(32);
        msg.put_u8(Self::TYPE);
        msg.put_u8(0); // Code.
        msg.put_u16(0); // Checksum placeholder.

        let flags: u8 = if self.override_flag { 0b0010_0000 } else { 0 };
        msg.put_u8(flags);
        msg.put_u8(0);
        msg.put_u8(0);
        msg.put_u8(0);

        msg.put_slice(&self.target_address.octets());

        msg.put_u8(Self::OPT_TARGET_LINK_ADDR);
        msg.put_u8(1); // Option length, in units of 8 bytes.
        msg.put_slice(&self.target_link_addr);

        let mut check = Checksum::new();
        check.add_bytes(&src_ip.octets());
        check.add_bytes(&dst_ip.octets());
        check.add_bytes(&(msg.len() as u32).to_be_bytes());
        check.add_bytes(&[0, 0, 0, ICMPV6_PROTO_NUM]);
        check.add_bytes(&msg);
        msg[2..4].copy_from_slice(&check.checksum());
        msg
    }
}

/// A hand-rolled ICMPv6 Neighbor Solicitation (RFC 4861 section 4.3),
/// decoded just far enough to answer "who is being asked about" so a
/// MASTER can reply the way it replies to ARP requests on IPv4.
pub struct NdpNeighborSolicitation {
    pub target_address: Ipv6Addr,
}

impl NdpNeighborSolicitation {
    const TYPE: u8 = 135;

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 24 || data[0] != Self::TYPE {
            return None;
        }
        let target_octets: [u8; 16] = data[8..24].try_into().ok()?;
        Some(Self {
            target_address: Ipv6Addr::from(target_octets),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_v4_packet(version: VrrpVersion, count_ip: u8) -> VrrpPacket {
        let addrs = (0..count_ip)
            .map(|i| Ipv4Addr::new(192, 168, 100, i))
            .collect();
        VrrpPacket {
            version,
            vrid: 51,
            priority: 100,
            adver_int_cs: 100,
            addresses: VrrpAddresses::V4(addrs),
        }
    }

    fn sample_v6_packet(count_ip: u8) -> VrrpPacket {
        let addrs = (0..count_ip)
            .map(|i| Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, i as u16))
            .collect();
        VrrpPacket {
            version: VrrpVersion::V3,
            vrid: 51,
            priority: 100,
            adver_int_cs: 250,
            addresses: VrrpAddresses::V6(addrs),
        }
    }

    const DUMMY_V4: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

    #[test]
    fn v2_encode_decode_roundtrip_various_ip_counts() {
        for count in [0u8, 1, 2, VrrpPacket::MAX_IP_COUNT as u8] {
            let pkt = sample_v4_packet(VrrpVersion::V2, count);
            let encoded = pkt.encode(DUMMY_V4);
            let decoded = VrrpPacket::decode(&encoded, DUMMY_V4, DUMMY_V4)
                .unwrap_or_else(|err| {
                    panic!("decode failed for count_ip={count}: {err}")
                });

            assert_eq!(decoded.version, VrrpVersion::V2);
            assert_eq!(decoded.vrid, pkt.vrid);
            assert_eq!(decoded.priority, pkt.priority);
            assert_eq!(decoded.adver_int_cs, pkt.adver_int_cs);
            assert_eq!(decoded.addresses, pkt.addresses);
        }
    }

    #[test]
    fn v3_v4_encode_decode_roundtrip_has_no_auth_trailer() {
        let pkt = sample_v4_packet(VrrpVersion::V3, 2);
        let encoded = pkt.encode(DUMMY_V4);
        // Fixed header (8) + 2 addresses * 4 bytes, no 8-byte auth trailer.
        assert_eq!(encoded.len(), 8 + 2 * 4);

        let decoded = VrrpPacket::decode(&encoded, DUMMY_V4, DUMMY_V4).unwrap();
        assert_eq!(decoded.version, VrrpVersion::V3);
        assert_eq!(decoded.addresses, pkt.addresses);
        assert_eq!(decoded.adver_int_cs, 100);
    }

    #[test]
    fn v3_v6_encode_decode_roundtrip_and_checksum_uses_pseudo_header() {
        let src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let dst = VRRP_V6_MCAST_ADDR;
        let pkt = sample_v6_packet(2);
        let encoded = pkt.encode(IpAddr::V6(src));

        let decoded =
            VrrpPacket::decode(&encoded, IpAddr::V6(src), IpAddr::V6(dst))
                .expect("valid v6 packet should decode");
        assert_eq!(decoded.addresses, pkt.addresses);
        assert_eq!(decoded.adver_int_cs, pkt.adver_int_cs);

        // Decoding with the wrong source address must fail: the checksum
        // covers the pseudo-header, so this proves it's actually used.
        let wrong_src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        assert!(matches!(
            VrrpPacket::decode(
                &encoded,
                IpAddr::V6(wrong_src),
                IpAddr::V6(dst)
            ),
            Err(PacketError::BadChecksum)
        ));
    }

    #[test]
    fn v3_interval_field_is_clamped_to_12_bits() {
        let mut pkt = sample_v4_packet(VrrpVersion::V3, 1);
        pkt.adver_int_cs = 0xFFFF; // way over 12 bits
        let encoded = pkt.encode(DUMMY_V4);
        let decoded = VrrpPacket::decode(&encoded, DUMMY_V4, DUMMY_V4).unwrap();
        assert_eq!(decoded.adver_int_cs, 0x0FFF);
    }

    #[test]
    fn v2_over_ipv6_is_rejected() {
        let pkt = sample_v4_packet(VrrpVersion::V2, 1);
        // v2's own encode() only knows IPv4, so build a v3-shaped v6 buffer
        // and hand-flip the version nibble to 2 to simulate a nonconformant
        // peer, rather than asserting on something encode() can't produce.
        let mut encoded =
            sample_v6_packet(1).encode(IpAddr::V6(Ipv6Addr::LOCALHOST));
        encoded[0] = (2 << 4) | (encoded[0] & 0x0F);
        let src = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let dst = IpAddr::V6(VRRP_V6_MCAST_ADDR);
        assert!(matches!(
            VrrpPacket::decode(&encoded, src, dst),
            Err(PacketError::UnsupportedVersion(2))
        ));
        let _ = pkt;
    }

    #[test]
    fn decode_rejects_empty_buffer() {
        assert!(matches!(
            VrrpPacket::decode(&[], DUMMY_V4, DUMMY_V4),
            Err(PacketError::Malformed)
        ));
    }

    #[test]
    fn decode_rejects_buffer_shorter_than_min_length() {
        let encoded = sample_v4_packet(VrrpVersion::V2, 0).encode(DUMMY_V4);
        let truncated = &encoded[..encoded.len() - 1];
        assert!(matches!(
            VrrpPacket::decode(truncated, DUMMY_V4, DUMMY_V4),
            Err(PacketError::Malformed)
        ));
    }

    #[test]
    fn decode_rejects_buffer_longer_than_max_length() {
        let encoded =
            sample_v4_packet(VrrpVersion::V2, VrrpPacket::MAX_IP_COUNT as u8)
                .encode(DUMMY_V4);
        let mut padded = encoded.to_vec();
        padded.push(0);
        assert!(matches!(
            VrrpPacket::decode(&padded, DUMMY_V4, DUMMY_V4),
            Err(PacketError::Malformed)
        ));
    }

    #[test]
    fn decode_rejects_unsupported_version() {
        let mut encoded = sample_v4_packet(VrrpVersion::V2, 1).encode(DUMMY_V4);
        encoded[0] = (7 << 4) | (encoded[0] & 0x0F);
        assert!(matches!(
            VrrpPacket::decode(&encoded, DUMMY_V4, DUMMY_V4),
            Err(PacketError::UnsupportedVersion(7))
        ));
    }

    #[test]
    fn decode_rejects_count_ip_disagreeing_with_length() {
        let mut encoded = sample_v4_packet(VrrpVersion::V2, 1).encode(DUMMY_V4);
        encoded[3] = 2;
        assert!(matches!(
            VrrpPacket::decode(&encoded, DUMMY_V4, DUMMY_V4),
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

    #[test]
    fn ndp_neighbor_advertisement_roundtrip_checksum() {
        let src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let dst = ALL_NODES_V6_MCAST_ADDR;
        let na = NdpNeighborAdvertisement {
            target_address: src,
            target_link_addr: [0x00, 0x00, 0x5e, 0x00, 0x02, 0x33],
            override_flag: true,
        };
        let encoded = na.encode(src, dst);

        let mut check = Checksum::new();
        check.add_bytes(&src.octets());
        check.add_bytes(&dst.octets());
        check.add_bytes(&(encoded.len() as u32).to_be_bytes());
        check.add_bytes(&[0, 0, 0, ICMPV6_PROTO_NUM]);
        check.add_bytes(&encoded);
        assert_eq!(check.checksum(), [0, 0]);
    }

    #[test]
    fn ndp_neighbor_solicitation_decode_extracts_target() {
        let target = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let mut data = vec![135u8, 0, 0, 0, 0, 0, 0, 0];
        data.extend_from_slice(&target.octets());
        let ns = NdpNeighborSolicitation::decode(&data).unwrap();
        assert_eq!(ns.target_address, target);
    }
}
