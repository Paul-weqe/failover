use std::{net::Ipv4Addr, str::FromStr};
use tokio::sync::MutexGuard;
use pnet::{
    datalink::NetworkInterface, 
    packet::{arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket}, 
    ethernet::{EtherTypes, MutableEthernetPacket},
    ip::IpNextHeaderProtocols, 
    ipv4::{checksum, Ipv4Flags, MutableIpv4Packet}},
    util::MacAddr
};
use vrrp_packet::MutableVrrpPacket;
use crate::router::VirtualRouter;

#[derive(Clone)]
pub(crate) struct MutablePktGenerator {
    interface: NetworkInterface
}

impl MutablePktGenerator 
{
    pub(crate) fn new(interface: NetworkInterface) -> Self 
    {
        MutablePktGenerator {
            interface 
        }
    }

    pub(crate) async fn gen_vrrp_header<'a>(&self, buffer: &'a mut [u8], vrouter: &MutexGuard<'_, VirtualRouter>) -> MutableVrrpPacket<'a>
    {
        let mut addresses: Vec<u8> = Vec::new();
        for addr in &vrouter.ip_addresses {
            for octet in addr.addr().octets() {
                addresses.push(octet);
            }
        }
        let mut vrrp_pkt = MutableVrrpPacket::new(buffer).unwrap();
        vrrp_pkt.set_version(2);
        vrrp_pkt.set_header_type(1);
        vrrp_pkt.set_advert_int(vrouter.advert_interval);
        vrrp_pkt.set_vrid(vrouter.vrid);
        vrrp_pkt.set_priority(vrouter.priority);
        vrrp_pkt.set_count_ip(vrouter.ip_addresses.len() as u8);
        vrrp_pkt.set_checksum(0);
        vrrp_pkt.set_auth_type(0);
        vrrp_pkt.set_auth_data(0);
        vrrp_pkt.set_auth_data2(0);
        vrrp_pkt.set_ip_addresses(&addresses);
        
        if vrrp_pkt.get_ip_addresses().len() > 20 {
            log::error!("VRRP packet cannot have more than 20 IP addresses");
            panic!("VRRP configuration VRID={} has more than 20 IP addresses", vrrp_pkt.get_vrid());
        }
        if vrrp_pkt.get_ip_addresses().is_empty() {
            log::error!("VRRP packet must have a virtual ip address");
            panic!("VRRP configuration VRID={} does not have an ip address", vrrp_pkt.get_vrid());
        }
        vrrp_pkt
    }

    pub(crate) fn gen_vrrp_ip_header<'a>(&self, buffer: &'a mut [u8]) -> MutableIpv4Packet<'a>
    {
        let ip = self.interface.ips.first().unwrap().ip();
        let len = buffer.len();
        let mut ip_pkt = MutableIpv4Packet::new(&mut buffer[..]).unwrap();
        ip_pkt.set_version(4);
        ip_pkt.set_header_length(5);
        ip_pkt.set_dscp(4);
        ip_pkt.set_ecn(1);
        ip_pkt.set_total_length(len as u16);
        ip_pkt.set_identification(2118);
        ip_pkt.set_flags(Ipv4Flags::DontFragment);
        ip_pkt.set_fragment_offset(0);
        ip_pkt.set_ttl(255);
        ip_pkt.set_next_level_protocol(IpNextHeaderProtocols::Vrrp);
        ip_pkt.set_source(Ipv4Addr::from_str(&ip.to_string()).unwrap());
        ip_pkt.set_destination(Ipv4Addr::new(224, 0, 0, 18));
        ip_pkt.set_checksum(checksum(&ip_pkt.to_immutable()));
        
        ip_pkt
    }

    pub(crate) fn gen_vrrp_eth_packet<'a>(&self, buffer: &'a mut [u8]) -> MutableEthernetPacket<'a> 
    {
        let mut ether_pkt = MutableEthernetPacket::new(&mut buffer[..]).unwrap();
        ether_pkt.set_source(self.interface.mac.unwrap());
        ether_pkt.set_destination(MacAddr(0x01, 0x00, 0x5E, 0x00, 0x00, 0x12));
        ether_pkt.set_ethertype(EtherTypes::Ipv4);
        ether_pkt
    }

    pub(crate) fn gen_gratuitous_arp_packet<'a>(
        &self, eth_buffer: &'a mut [u8], arp_buffer: &'a mut [u8], ip: Ipv4Addr
    ) -> (MutableEthernetPacket<'a>, MutableArpPacket<'a>) 
    {
        let mut eth_arp_packet = MutableEthernetPacket::new(&mut eth_buffer[..]).unwrap();
        eth_arp_packet.set_destination(MacAddr::broadcast());
        eth_arp_packet.set_source(self.interface.mac.unwrap());
        eth_arp_packet.set_ethertype(EtherTypes::Arp);
        
        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer[..]).unwrap();
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(self.interface.mac.unwrap());
        arp_packet.set_sender_proto_addr(ip);
        arp_packet.set_target_hw_addr(MacAddr::broadcast());
        arp_packet.set_target_proto_addr(ip);
        (eth_arp_packet, arp_packet)
        
    }

}