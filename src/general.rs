
use std::{process::Command, str::FromStr};
use crate::{config::VrrpConfig, error::NetError, router::VirtualRouter, state_machine::VirtualRouterMachine, NetResult};
use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};
use ipnet::Ipv4Net;
use rand::{distributions::Alphanumeric, Rng};

pub(crate) fn get_interface(name: &str) -> NetworkInterface
{
    let interface_names_match = |iface: &NetworkInterface| iface.name == name;
    let interfaces = datalink::linux::interfaces();

    // check if interface name exists, if not create it
    interfaces.into_iter().find(interface_names_match).unwrap()
    
}

pub(crate) fn create_datalink_channel(interface: &NetworkInterface) -> NetResult<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)>
{

    match pnet::datalink::channel(interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => Ok((tx, rx)),
        Ok(_) => {
            Err(NetError("Unknown channel type".to_string()))
        }
        Err(err) => {
            log::error!("{err}");
            Err(NetError("Problem creating datalink channel".to_string()))
        }
    }

}

// takes the configs that have been received and converts them 
// into a virtual router instance. 
pub fn config_to_vr(conf: VrrpConfig) -> VirtualRouter
{

    // SKEW TIME = (256 * priority) / 256
    let skew_time: f32 = (256_f32 - conf.priority() as f32) / 256_f32;
    
    // MASTER DOWN INTERVAL = (3 * ADVERTISEMENT INTERVAL ) + SKEW TIME 
    let master_down_interval: f32 = (3_f32 * conf.advert_interval() as f32) + skew_time;
    
    let mut ips: Vec<Ipv4Net> = vec![];

    if conf.ip_addresses().len() > 20 {
        log::warn!("({})  More than 20 IP addresses(max for VRRP) have been configured. Only first 20 addresses will be considered. ", conf.name());
    }

    let addresses = if conf.ip_addresses().len() <= 20 { conf.ip_addresses() } else { conf.ip_addresses()[0..20].to_vec() }; 
    for ip_config in addresses.iter() {
        match Ipv4Net::from_str(ip_config) {
            Ok(ip_addr) => ips.push(ip_addr),
            Err(_) => {
                log::error!("({}) SKIPPING: Configured IP address '{:?}' not in the correct format. ", ip_config, conf.name());
            }
        }
    }
    
    let vr = VirtualRouter {
        name: conf.name().clone(),
        vrid: conf.vrid(),
        ip_addresses: ips,
        priority: conf.priority(),
        skew_time,
        advert_interval: conf.advert_interval(),
        master_down_interval,
        preempt_mode: conf.preempt_mode(),
        network_interface: conf.interface_name().clone(),
        fsm: VirtualRouterMachine::default()
    };
    log::info!("({}) Entered {:?} state.", vr.name, vr.fsm.state);
    vr

}


pub(crate) fn virtual_address_action(action: &str, addresses: &[String], interface_name: &str)
{
    for addr in addresses {
        let cmd_args = vec!["address", action, &addr, "dev", interface_name];
        let _ = Command::new("ip")
            .args(cmd_args)
            .output();
    }
}


pub(crate) fn random_string(length: usize) -> String 
{
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}