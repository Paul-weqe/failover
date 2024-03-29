use ipnet::Ipv4Net;

use crate::{router::VirtualRouter, state_machine::VirtualRouterMachine};
use std::{f32, str::FromStr};


/// Converts the `crate::config::VrConfig` to `crate::router::VirtualRouter`
pub fn config_to_vr(conf: &crate::base_functions::FileConfig) -> VirtualRouter {

    // SKEW TIME = (256 * priority) / 256
    let skew_time: f32 = (256 as f32 - conf.priority as f32) / 256 as f32;
    
    // MASTER DOWN INTERVAL = (3 * ADVERTISEMENT INTERVAL ) + SKEW TIME 
    let master_down_interval: f32 = (3 as f32 * conf.advert_interval as f32) + skew_time as f32;
    
    let mut ips: Vec<Ipv4Net> = vec![];

    for ip_config in &conf.ip_addresses {
        match Ipv4Net::from_str(&ip_config) {
            Ok(ip_addr) => ips.push(ip_addr),
            Err(err) => {
                log::error!("Address '{:?}' not in the correct format", &ip_config);
                panic!("Error: {err}");
            }
        }
    }
    let vr = VirtualRouter {
        name: conf.name.clone(),
        vrid: conf.vrid,
        ip_addresses: ips,
        priority: conf.priority,
        skew_time: skew_time,
        advert_interval: conf.advert_interval,
        master_down_interval: master_down_interval,
        preempt_mode: conf.preempt_mode,
        network_interface: conf.network_interface.clone(),
        fsm: VirtualRouterMachine::default()
    };
    log::info!("({}) Setting up Router", vr.name);
    log::info!("({}) Entered {:?} state", vr.name, vr.fsm.state);
    vr

}

