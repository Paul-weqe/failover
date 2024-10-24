use clap::Parser;
use failover_vr::{
    config::{parse_cli_opts, Action, CliArgs2},
    general::{config_to_vr, virtual_address_action},
};
use tokio::task::JoinSet;

#[tokio::main]
async fn main() {
    let args = CliArgs2::parse();
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
        match config.action() {
            Action::Run => {
                let vrouter = config_to_vr(config);
                routers_tasks.spawn(async { failover_vr::run(vrouter).await });
            }
            Action::Teardown => {
                log::info!("tearing down {:#?}", config.name());
                virtual_address_action("delete", &config.ip_addresses(), &config.interface_name());
                log::info!("{:#?} tear down complete", config.name());
            }
        }
    }

    if routers_tasks.is_empty() {
        log::info!("failover shutting down. No VRRP instances to run");
        std::process::exit(0);
    }

    while routers_tasks.join_next().await.is_some() {}
}
