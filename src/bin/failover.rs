use failover::{
    base_functions::parse_cli_opts,
    converter, network
};
use std::env;
use simple_logger::SimpleLogger;

#[tokio::main]
async fn main(){

    SimpleLogger::new().with_colors(true).init().unwrap();
    
    let args: Vec<String> = env::args().collect();
    let config = match parse_cli_opts(&args) {
        Ok(config) => config,
        Err(err) => {
            log::error!("Error Reading config params");
            panic!("{err}");
        }
    };
    let vr = converter::config_to_vr(config);
    let init_network_process = network::run_vrrp(vr);
    init_network_process.await.unwrap_or_else(|err| {
        log::error!("Problem running VRRP process");
        panic!("{err}");
    });

}




