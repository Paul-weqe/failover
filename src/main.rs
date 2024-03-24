mod config;
mod router;
mod converter;
mod network;
mod state_machine;
mod pkt;

use std::{error::Error, fs::File, io::BufReader, path::Path};
use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};
use simple_logger::SimpleLogger;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>>{
    
    SimpleLogger::new().with_colors(true).init().unwrap();
    let config = read_config_from_json_file("./vrrp-config.json")?;
    let vr = converter::config_to_vr(&config);
    network::send_advertisement(vr);

    Ok(())
}


fn read_config_from_json_file<P: AsRef<Path>>(path: P) -> Result<config::VRConfig, Box<dyn Error>> {
    log::info!("Reading from config file {:?}", path.as_ref().as_os_str());
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let u = serde_json::from_reader(reader)?;
    Ok(u)
}

pub fn get_interface(name: &str) -> NetworkInterface {
    let interface_names_match = |iface: &NetworkInterface| iface.name == name;
    let interfaces = datalink::linux::interfaces();
    interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap()
}

pub fn create_datalink_channel(interface: &NetworkInterface)  -> (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>){
    match pnet::datalink::channel(interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => return (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened: {}", e)
    }
}