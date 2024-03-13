
use crate::{config, router};
use ipnet::Ipv4Net;
use std::f32;



/// 
/// Converts the `crate::config::VrConfig` to `crate::router::VirtualRouter`
/// This will help in usage accross the system
pub fn config_to_vr(conf: &config::VRConfig) -> router::VirtualRouter {

    // SKEW TIME = (256 * priority) / 256
    let skew_time: f32 = (256 as f32 - conf.priority as f32) / 256 as f32;

    // MASTER DOWN INTERVAL = (3 * ADVERTISEMENT INTERVAL ) + SKEW TIME 
    let master_down_interval: f32 = (3 as f32 * conf.advert_interval as f32) + skew_time as f32;
    
    let mut ips: Vec<Ipv4Net> = vec![];
    for ip_config in &conf.ip_addresses {
        ips.push(ip_config.as_str().parse().unwrap());
    }

    router::VirtualRouter {
        name: conf.name.clone(),
        vrid: conf.vrid,
        ip_addresses: ips,
        priority: conf.priority,
        skew_time: skew_time,
        advert_interval: conf.advert_interval,
        master_down_interval: master_down_interval,
        preempt_mode: conf.preempt_mode,
        network_interface: conf.network_interface.clone()
    }
}