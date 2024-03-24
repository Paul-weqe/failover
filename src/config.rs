
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct VRConfig {
    pub name: String,
    pub vrid: u8,
    pub ip_addresses: Vec<String>,
    pub network_interface: String,


    #[serde(default = "priority")]
    pub priority: u8,

    #[serde(default = "advert_int")]
    pub advert_interval: u8,

    #[serde(default = "preempt_mode")]
    pub preempt_mode: bool,

}

pub fn advert_int() -> u8 { 1 }
pub fn priority() -> u8 { 100 }
pub fn preempt_mode() -> bool { true }
