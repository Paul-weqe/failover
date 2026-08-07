use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};

use crate::packet::{
    ARPframe, ArpPacket, EthernetFrame, NdpNeighborAdvertisement, VrrpPacket,
};
use crate::state_machine::VirtualRouterMachine;
use crate::{VrrpAddresses, VrrpVersion, network};

#[derive(Debug, Clone)]
pub struct VirtualRouter {
    pub(crate) name: String,
    pub(crate) vrid: u8,
    pub(crate) version: VrrpVersion,
    pub(crate) ipv4_addresses: Vec<Ipv4Net>,
    pub(crate) ipv6_addresses: Vec<Ipv6Net>,
    pub(crate) priority: u8,
    pub(crate) skew_time: f32,
    pub(crate) advert_interval: u8,
    pub(crate) master_down_interval: f32,
    pub(crate) preempt_mode: bool,
    pub(crate) network_interface: String,
    pub(crate) mac_vlan_interface_v4: String,
    /// `Some` only for a v3 instance (v2 never creates a v6 mac-vlan).
    pub(crate) mac_vlan_interface_v6: Option<String>,
    pub(crate) primary_ip: Ipv4Addr,
    pub(crate) primary_ip_v6: Option<Ipv6Addr>,
    pub(crate) fsm: VirtualRouterMachine,
}

impl VirtualRouter {
    pub(crate) fn ipv4_addrs(&self) -> Vec<Ipv4Addr> {
        self.ipv4_addresses.iter().map(|a| a.addr()).collect()
    }

    pub(crate) fn str_ipv4_addresses(&self) -> Vec<String> {
        self.ipv4_addresses.iter().map(|a| a.to_string()).collect()
    }

    pub(crate) fn ipv6_addrs(&self) -> Vec<Ipv6Addr> {
        self.ipv6_addresses.iter().map(|a| a.addr()).collect()
    }

    pub(crate) fn str_ipv6_addresses(&self) -> Vec<String> {
        self.ipv6_addresses.iter().map(|a| a.to_string()).collect()
    }

    pub(crate) fn new(params: VirtualRouterParams) -> Self {
        let VirtualRouterParams {
            name,
            vrid,
            version,
            ipv4_addresses,
            ipv6_addresses,
            priority,
            advert_interval,
            preempt_mode,
            network_interface,
        } = params;

        let skew_time: f32 = match version {
            // v2 (RFC 3768 section 6.2): a flat sub-second tiebreaker,
            // independent of the advertisement interval.
            VrrpVersion::V2 => (256_f32 - priority as f32) / 256_f32,
            // v3 (RFC 5798 section 6.1): scales with the advertisement
            // interval now that the interval itself has sub-second
            // resolution. This is a real formula change, not just a unit
            // relabeling -- do not collapse this back into the v2 arm.
            VrrpVersion::V3 => {
                ((256_f32 - priority as f32) * advert_interval as f32) / 256_f32
            }
        };
        let master_down_interval: f32 =
            (3_f32 * advert_interval as f32) + skew_time;

        // Always create a mac-vlan interface reference for v3 (even before
        // it's actually built), so that "does this instance have a v6
        // side" is a plain Option check everywhere else.
        let mac_vlan_interface_v6 = match version {
            VrrpVersion::V3 => Some(String::new()),
            VrrpVersion::V2 => None,
        };

        Self {
            name,
            vrid,
            version,
            ipv4_addresses,
            ipv6_addresses,
            priority,
            skew_time,
            advert_interval,
            master_down_interval,
            preempt_mode,
            network_interface,
            mac_vlan_interface_v4: String::new(),
            mac_vlan_interface_v6,
            primary_ip: Ipv4Addr::UNSPECIFIED,
            primary_ip_v6: None,
            fsm: VirtualRouterMachine::default(),
        }
    }

    /// Builds, checksums and sends VRRP advertisement(s) for this router's
    /// current vrid/priority/addresses. Always sends an IPv4 advertisement
    /// over `mac_vlan_interface_v4`; a v3 instance additionally sends an
    /// IPv6 advertisement over `mac_vlan_interface_v6`.
    pub(crate) fn send_advertisement(&self) {
        let adver_int_cs = self.advert_interval as u16 * 100;

        let v4_pkt = VrrpPacket {
            version: self.version,
            vrid: self.vrid,
            priority: self.priority,
            adver_int_cs,
            addresses: VrrpAddresses::V4(self.ipv4_addrs()),
        };
        let _ = network::send_vrrp_packet_v4(
            &self.mac_vlan_interface_v4,
            self.primary_ip,
            v4_pkt,
        );

        if let (Some(v6_iface), Some(src_v6)) =
            (&self.mac_vlan_interface_v6, self.primary_ip_v6)
        {
            let v6_pkt = VrrpPacket {
                version: self.version,
                vrid: self.vrid,
                priority: self.priority,
                adver_int_cs,
                addresses: VrrpAddresses::V6(self.ipv6_addrs()),
            };
            let _ = network::send_vrrp_packet_v6(v6_iface, src_v6, v6_pkt);
        }
    }

    /// Sends a gratuitous ARP for each of this router's configured IPv4
    /// addresses, announcing `interface_mac` as their new owner.
    pub(crate) fn send_gratuitous_arps(&self, interface_mac: [u8; 6]) {
        for ip in &self.ipv4_addresses {
            let eth_frame = EthernetFrame {
                dst_mac: [0xff; 6],
                src_mac: interface_mac,
                ethertype: 0x0806,
            };
            let arp_pkt = ArpPacket {
                hw_type: 1,
                proto_type: 0x0800,
                hw_length: 6,
                proto_length: 4,
                operation: 1,
                sender_hw_address: interface_mac,
                sender_proto_address: ip.addr().octets(),
                target_hw_address: [0xff; 6],
                target_proto_address: ip.addr().octets(),
            };
            let arp_frame = ARPframe::new(eth_frame, arp_pkt);
            network::send_packet_arp(&self.mac_vlan_interface_v4, arp_frame);
        }
    }

    /// Sends an unsolicited (gratuitous) Neighbor Advertisement for each of
    /// this router's configured IPv6 addresses -- IPv6 has no ARP, so this
    /// is the equivalent of `send_gratuitous_arps` for the v6 side.
    pub(crate) fn send_neighbor_advertisements(&self, interface_mac: [u8; 6]) {
        let Some(v6_iface) = &self.mac_vlan_interface_v6 else {
            return;
        };
        for ip in &self.ipv6_addresses {
            let na = NdpNeighborAdvertisement {
                target_address: ip.addr(),
                target_link_addr: interface_mac,
                override_flag: true,
            };
            network::send_neighbor_advertisement(v6_iface, ip.addr(), na);
        }
    }
}

pub(crate) struct VirtualRouterParams {
    pub(crate) name: String,
    pub(crate) vrid: u8,
    pub(crate) version: VrrpVersion,
    pub(crate) ipv4_addresses: Vec<Ipv4Net>,
    pub(crate) ipv6_addresses: Vec<Ipv6Net>,
    pub(crate) priority: u8,
    pub(crate) advert_interval: u8,
    pub(crate) preempt_mode: bool,
    pub(crate) network_interface: String,
}
