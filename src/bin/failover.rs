use failover::{config::parse_cli_opts, general::config_to_vr};

use std::env;
use simple_logger::SimpleLogger;

fn main(){

    SimpleLogger::new().with_colors(true).init().unwrap();
    
    let args: Vec<String> = env::args().collect();
    let config = match parse_cli_opts(&args) {
        Ok(config) => config,
        Err(err) => {
            log::error!("Error Reading config params");
            panic!("{err}");
        }
    };
    let vr = config_to_vr(config);

    failover::run(vr).unwrap_or_else(|err| {
        log::error!("Problem running VRRP process");
        panic!("{err}");
    });
    
}

