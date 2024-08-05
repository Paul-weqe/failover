use clap::Parser;
use failover_vr::{
    config::{parse_cli_opts, CliArgs},
    general::config_to_vr,
};
use tokio::task::JoinSet;

#[tokio::main]
async fn main() {
    let args = CliArgs::parse();
    let routers_config = match parse_cli_opts(args) {
        Ok(config) => config,
        Err(err) => {
            //log::error!("Error reading config params");
            panic!("{err}")
        }
    };

    let mut routers_tasks = JoinSet::new();
    for config in routers_config {
        let vrouter = config_to_vr(config);
        routers_tasks.spawn(async { failover_vr::run(vrouter).await });
    }

    while routers_tasks.join_next().await.is_some() {}
}
