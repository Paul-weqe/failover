
use crate::defaults;
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct VRConfig {
    pub name: String,
    pub vrid: u8,
    pub ip_addresses: Vec<String>,

    #[serde(default = "defaults::priority")]
    pub priority: u8,

    #[serde(default = "defaults::advert_int")]
    pub advert_interval: u8,

    #[serde(default = "defaults::preempt_mode")]
    pub preempt_mode: bool,

    #[serde(default = "defaults::network_interface")]
    pub network_interface: String

}