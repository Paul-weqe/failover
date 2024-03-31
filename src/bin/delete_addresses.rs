use std::{error::Error, fs::File, io::BufReader, path::Path, process::Command};

use serde::{Deserialize, Serialize};
use simple_logger::SimpleLogger;

fn main() {
    SimpleLogger::new().with_colors(true).init().unwrap();
    let config = read_config_from_json_file("./vrrp-config.json").unwrap();

    for addr in config.ip_addresses {
        let args = vec!["ip", "address", "delete", &addr, "dev", &config.network_interface];
        let cmd = Command::new("sudo")
            .args(args)
            .output();
        
        println!("{:?}", cmd);
        let _ = cmd.unwrap_or_else(|err| {
            log::error!("unable to add address {} to interface {}", &addr, &config.network_interface);
            panic!("{err}");
        });
    }
}

fn read_config_from_json_file<P: AsRef<Path>>(path: P) -> Result<FileConfig, Box<dyn Error>> {
    log::info!("Reading from config file {:?}", path.as_ref().as_os_str());
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let u = serde_json::from_reader(reader)?;
    Ok(u)
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