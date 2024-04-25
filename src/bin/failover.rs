use clap::Parser;
use failover::{config::{parse_cli_opts, CliArgs}, general::config_to_vr};
use tokio::task::JoinSet;
use simple_logger::SimpleLogger;

#[tokio::main]
async fn main(){

    SimpleLogger::new().with_colors(true).init().unwrap();
    let args = CliArgs::parse();
    let routers_config = match parse_cli_opts(args) {
        Ok(config) => config,
        Err(err) => {
            log::error!("Error reading config params");
            panic!("{err}")
        }
    };

    let mut routers_tasks = JoinSet::new();
    for config in routers_config {
        let vrouter = config_to_vr(config);
        routers_tasks.spawn(async {
            failover::run(vrouter).await
        });
    }


    while routers_tasks.join_next().await.is_some() {}
       
}