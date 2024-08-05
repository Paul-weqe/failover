use ipnet::Ipv4Net;
use std::net::Ipv4Addr;

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

    pub fn new(
        name: String,
        vrid: u8,
        ip_addresses: Vec<Ipv4Net>,
        priority: u8,
        advert_interval: u8,
        preempt_mode: bool,
        network_interface: String,
    ) -> Self {
        // SKEW TIME = (256 * priority) / 256
        let skew_time: f32 = (256_f32 - priority as f32) / 256_f32;
        // MASTER DOWN INTERVAL = (3 * ADVERTISEMENT INTERVAL ) + SKEW TIME
        let master_down_interval: f32 = (3_f32 * advert_interval as f32) + skew_time;

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
            fsm: VirtualRouterMachine::default(),
        }
    }
}
