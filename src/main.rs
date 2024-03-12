use std::{error::Error, fs::File, io::BufReader, path::Path};

fn main() -> Result<(), Box<dyn Error>>{
    let config = read_config_from_json_file("./vrrp-config.json")?;
    println!("{:?}", config);
    Ok(())
}

fn read_config_from_json_file<P: AsRef<Path>>(path: P) -> Result<config::VRConfig, Box<dyn Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let u = serde_json::from_reader(reader)?;
    Ok(u)
}

pub mod defaults {
    use rand::{distributions::Alphanumeric, Rng};
    
    pub const DEFAULT_ADVERT_INTERVAL: u16 = 1;
    pub const DEFAULT_PRIORITY: u8 = 100;
    pub const DEFAULT_PREEMPT_MODE: bool = true;

    pub fn priority() -> u8 { 100 }
    pub fn advert_int() -> u16 { 1 }
    pub fn preempt_mode() -> bool { true }

    // create a name for a random network interface with name failnet-{random-5-letter-string}
    pub fn network_interface() -> String {
        let res = "failnet-".to_string();
        let s: String =  rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(5)
            .map(char::from)
            .collect();
        res + s.as_str()
    }

    pub fn network_mask() -> String { "255.255.255.0".to_string() }
}

pub mod config {
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
        pub advert_interval: u16,

        #[serde(default = "defaults::preempt_mode")]
        pub preempt_mode: bool,

        #[serde(default = "defaults::network_interface")]
        pub network_interface: String

    }

}

pub mod router {
    use ipnet::Ipv4Net;


    #[derive(Debug)]
    pub struct VirtualRouter {
        pub name: String,
        pub vrid: u8,
        pub ip_addresses: Vec<Ipv4Net>,
        pub priority: u8,
        pub skew_time: f32,
        pub advert_interval: u16,
        pub master_down_interval: f32,
        pub preempt_mode: bool,
        pub network_interface: String
    }
}

pub mod converter {
    use crate::{config, router};
    use ipnet::Ipv4Net;
    use std::f32;
    


    fn config_to_vr(conf: &config::VRConfig) -> router::VirtualRouter {
        let skew_time: f32 = (256 as f32 - conf.priority as f32) / 256 as f32;
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

}