mod config;

use config::VrrpConfig;
use std::fs;

fn main() {
    let raw_data = fs::read_to_string("vrrp-config.json").unwrap();
    let parsed_json_data: VrrpConfig = serde_json::from_str(raw_data.as_str()).unwrap();
    println!("{:?}", parsed_json_data)
}
