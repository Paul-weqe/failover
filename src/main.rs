mod router;
mod converter;
mod network;
mod state_machine;
mod pkt;

use std::{error::Error, fs::File, io::BufReader, path::Path};
use simple_logger::SimpleLogger;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>>{
    
    SimpleLogger::new().with_colors(true).init().unwrap();
    let config = read_config_from_json_file("./vrrp-config.json")?;
    let vr = converter::config_to_vr(&config);
    network::init_network(vr);

    Ok(())
}


fn read_config_from_json_file<P: AsRef<Path>>(path: P) -> Result<base_functions::FileConfig, Box<dyn Error>> {
    log::info!("Reading from config file {:?}", path.as_ref().as_os_str());
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let u = serde_json::from_reader(reader)?;
    Ok(u)
}

pub mod base_functions {
    use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};
    use serde::{Deserialize, Serialize};

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


    #[derive(Debug, Serialize, Deserialize)]
    pub struct FileConfig {
        pub name: String,
        pub vrid: u8,
        pub ip_addresses: Vec<String>,
        pub network_interface: String,


        #[serde(default = "default_priority")]
        pub priority: u8,

        #[serde(default = "default_advert_int")]
        pub advert_interval: u8,

        #[serde(default = "default_preempt_mode")]
        pub preempt_mode: bool,

    }

    pub fn default_priority() -> u8 { 100 }
    pub fn default_advert_int() -> u8 { 1 }
    pub fn default_preempt_mode() -> bool { true }
}