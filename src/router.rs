use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::network;
use crate::packet::{ARPframe, ArpPacket, EthernetFrame, VrrpPacket};
use crate::state_machine::VirtualRouterMachine;

#[derive(Debug, Clone)]
pub struct VirtualRouter {
    pub name: String,
    pub vrid: u8,
    pub ip_addresses: Vec<Ipv4Net>,
    pub priority: u8,
    pub skew_time: f32,
    pub advert_interval: u8,
    pub master_down_interval: f32,
    pub preempt_mode: bool,
    pub network_interface: String,
    pub mac_vlan_interface: String,
    pub primary_ip: Ipv4Addr,
    pub fsm: VirtualRouterMachine,
}

impl VirtualRouter {
    pub(crate) fn ipv4_addresses(&self) -> Vec<Ipv4Addr> {
        let mut addrs: Vec<Ipv4Addr> = vec![];
        for a in self.ip_addresses.iter() {
            addrs.push(a.addr());
        }
        addrs
    }

    pub(crate) fn str_ipv4_addresses(&self) -> Vec<String> {
        let mut addrs: Vec<String> = vec![];
        for a in self.ip_addresses.iter() {
            addrs.push(a.to_string());
        }
        addrs
    }

    pub fn new(params: VirtualRouterParams) -> Self {
        let VirtualRouterParams {
            name,
            vrid,
            ip_addresses,
            priority,
            advert_interval,
            preempt_mode,
            network_interface,
        } = params;

        // SKEW TIME = (256 * priority) / 256
        let skew_time: f32 = (256_f32 - priority as f32) / 256_f32;
        // MASTER DOWN INTERVAL = (3 * ADVERTISEMENT INTERVAL ) + SKEW TIME
        let master_down_interval: f32 =
            (3_f32 * advert_interval as f32) + skew_time;

        Self {
            name,
            vrid,
            ip_addresses,
            priority,
            skew_time,
            advert_interval,
            master_down_interval,
            preempt_mode,
            network_interface,
            mac_vlan_interface: String::new(),
            primary_ip: Ipv4Addr::UNSPECIFIED,
            fsm: VirtualRouterMachine::default(),
        }
    }

    /// Builds, checksums and sends a VRRP advertisement for this router's
    /// current vrid/priority/ip_addresses over its configured interface.
    pub(crate) fn send_advertisement(&self) {
        let pkt = VrrpPacket {
            vrid: self.vrid,
            priority: self.priority,
            count_ip: self.ip_addresses.len() as u8,
            adver_int: self.advert_interval,
            checksum: 0,
            ip_addresses: self.ipv4_addresses(),
        };

        let _ = network::send_vrrp_packet(
            &self.mac_vlan_interface,
            self.primary_ip,
            pkt,
        );
    }

    /// Sends a gratuitous ARP for each of this router's configured IP
    /// addresses, announcing `interface_mac` as their new owner.
    pub(crate) fn send_gratuitous_arps(&self, interface_mac: [u8; 6]) {
        for ip in &self.ip_addresses {
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
            network::send_packet_arp(&self.mac_vlan_interface, arp_frame);
        }
    }
}

pub struct VirtualRouterParams {
    pub name: String,
    pub vrid: u8,
    pub ip_addresses: Vec<Ipv4Net>,
    pub priority: u8,
    pub advert_interval: u8,
    pub preempt_mode: bool,
    pub network_interface: String,
}
