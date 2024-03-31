use std::process::Command;
use failover::base_functions::read_config_from_json_file;
use simple_logger::SimpleLogger;

/// bin used to create the "virtual" IP addresses for the 
/// interface that has been specified 
fn main() {
    SimpleLogger::new().with_colors(true).init().unwrap();
    let config = read_config_from_json_file("./vrrp-config.json").unwrap();
    
    for addr in config.ip_addresses {
        let args = vec!["ip", "address", "add", &addr, "dev", &config.interface_name];
        let cmd = Command::new("sudo")
            .args(args)
            .output();
        
        println!("{:?}", cmd);
        let _ = cmd.unwrap_or_else(|err| {
            log::error!("unable to add address {} to interface {}", &addr, &config.interface_name);
            panic!("{err}");
        });
    }
}