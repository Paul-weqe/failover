
use ipnet::Ipv4Net;

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
    pub fsm: VirtualRouterMachine
}