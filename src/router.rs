
use ipnet::Ipv4Net;
use pnet::util::MacAddr;

use crate::system::VirtualRouterSystem;

#[derive(Debug)]
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
    pub system: VirtualRouterSystem
}

impl VirtualRouter {

    pub fn mac(&self) -> MacAddr {
        MacAddr::new(0x00, 0x00, 0x5E, 0x00, 0x01, self.vrid)
    }

}