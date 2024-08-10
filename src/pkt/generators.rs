use pnet::datalink::NetworkInterface;

/// PktGenerator is meant to create Network packets (header + body)
/// given specific parameters. The network interface together with the payload
/// help us with getting the necessary items.
///
/// Generating an ARP packet for example:
///
/// ```no_run
/// use pnet::packet::datalink::NetworkInterface;
/// use crate::general::create_datalink_channel;
/// use std::net::Ipv4Addr;
///
/// let interface: NetworkInterface = create_datalink_channel("wlo1");
/// let mut eth_buff = [0u8; 42];
/// let mut arp_buff = [0u8; 28];
///
/// let gen = MutablePktGenerator(interface: interface);
/// let arp_pkt = generator.gen_gratuitous_arp_packet(eth_buff, arp_buff, Ipv4Addr::from_str("192.168.100.12"));
/// ```
#[derive(Clone, Debug)]
pub(crate) struct MutablePktGenerator {
    pub(crate) interface: NetworkInterface,
}

impl MutablePktGenerator {
    pub(crate) fn new(interface: NetworkInterface) -> Self {
        MutablePktGenerator { interface }
    }
}
