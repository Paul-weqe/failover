use clap::Parser;
use failover_vr::config::{CliArgs, parse_cli_opts};
use failover_vr::general::config_to_vr;
use tokio::task::JoinSet;

#[tokio::main]
async fn main() {
    let args = CliArgs::parse();
    let routers_config = match parse_cli_opts(args) {
        Ok(config) => {
            log::debug!("Configs read successfully");
            config
        }
        Err(err) => {
            log::error!("Error reading configs {err}");
            std::process::exit(1);
        }
    };

    let mut routers_tasks = JoinSet::new();
    for config in routers_config {
        let vrouter = config_to_vr(config);
        routers_tasks.spawn(async { failover_vr::run(vrouter).await });
    }

    if routers_tasks.is_empty() {
        log::info!("failover shutting down. No VRRP instances to run");
        std::process::exit(0);
    }

    while routers_tasks.join_next().await.is_some() {}
}
