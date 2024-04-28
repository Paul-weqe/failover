
use std::{process::Command, str::FromStr};
use crate::{config::VrrpConfig, error::NetError, router::VirtualRouter, NetResult};
use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};
use ipnet::Ipv4Net;
use rand::{distributions::Alphanumeric, Rng};

pub(crate) fn get_interface(name: &str) -> NetResult<NetworkInterface>
{
    let interface_names_match = |iface: &NetworkInterface| iface.name == name;
    let interfaces = datalink::linux::interfaces();

    // check if interface name exists, if not create it
    match interfaces.into_iter().find(interface_names_match) {
        Some(interface) => Ok(interface),
        None => Err(NetError(format!("unable to find interface with name {name}")))
    } 
    
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
    let mut ips: Vec<Ipv4Net> = vec![];
    if conf.ip_addresses().len() > 20 {
        log::warn!("({})  More than 20 IP addresses(max for VRRP) have been configured. Only first 20 addresses will be used..", conf.name());
    }

    let addresses = if conf.ip_addresses().len() <= 20 { conf.ip_addresses() } else { conf.ip_addresses()[0..20].to_vec() }; 
    for ip_config in addresses.iter() {
        match Ipv4Net::from_str(ip_config) {
            Ok(ip_addr) => ips.push(ip_addr),
            Err(_) => {
                log::error!("({}) SKIPPING: Configured IP address '{:?}' not in the correct format ( oct[0].oct[1].oct[2].oct[3]/subnet )", ip_config, conf.name());
            }
        }
    }

    let vr = VirtualRouter::new(
        conf.name(), 
        conf.vrid(), 
        ips, 
        conf.priority(), 
        conf.advert_interval(),
        conf.preempt_mode(),
        conf.interface_name()
    );
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


pub(crate) fn random_vr_name() -> String 
{
    let val: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();

    log::info!("Name for Virtual Router not given. generated name VR_{val}");
    format!("VR_{val}")
}