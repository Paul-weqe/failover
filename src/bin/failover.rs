use failover::{
    base_functions::read_config_from_json_file,
    converter, network
};
use simple_logger::SimpleLogger;
use failover::config::VrrpConfig;

#[tokio::main]
async fn main(){

    SimpleLogger::new().with_colors(true).init().unwrap();
    let config = read_config_from_json_file("./vrrp-config.json").unwrap();
    
    let vr = converter::config_to_vr(VrrpConfig::File(config));

    let init_network_ft = network::init_network(vr);
    init_network_ft.await.unwrap_or_else(|err| {
        log::error!("problem running VRRP process");
        panic!("{err}");
    });
    
}




