mod pkt_generators;
mod pkt_handlers;
mod config;
mod router;
mod converter;
mod network;
mod system;

use std::{error::Error, fs::File, io::BufReader, path::Path};
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
