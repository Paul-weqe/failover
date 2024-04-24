use failover::{config::parse_cli_opts, general::config_to_vr};

use std::{env, thread};
use simple_logger::SimpleLogger;

fn main(){

    SimpleLogger::new().with_colors(true).init().unwrap();
    
    let args: Vec<String> = env::args().collect();

    let routers_config = match parse_cli_opts(&args) {
        Ok(config) => config,
        Err(err) => {
            log::error!("Error Reading config params");
            panic!("{err}");
        }
    };

    let mut thread_pool = vec![];
    for config in routers_config {
        let router_thread = thread::spawn(|| {
            let vrouter = config_to_vr(config);    
            failover::run(vrouter).unwrap_or_else(|err| {
                log::error!("Problem running VRRP process");
                panic!("{err}");
            });
        });
        thread_pool.push(router_thread);
    }
    
    for t in thread_pool { let _ = t.join(); }
}

