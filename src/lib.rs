use std::sync::{Arc, Mutex};

use error::{FailoverError, NetworkError};
use general::get_interface;
use observer::EventObserver;
use pnet::datalink::NetworkInterface;
use router::VirtualRouter;
use state_machine::Event;
use tokio::signal;
use tokio::task::JoinSet;

pub mod config;
mod core_tasks;
pub mod error;
pub mod general;
mod network;
mod observer;
mod packet;
mod pkt;
pub mod router;
mod state_machine;

pub(crate) type NetResult<T> = Result<T, NetworkError>;
pub(crate) type ConfigResult<T> = Result<T, error::ConfigError>;

#[derive(Clone)]
pub(crate) struct TaskItems {
    vrouter: Arc<Mutex<VirtualRouter>>,
    interface: NetworkInterface,
    parent_interface: NetworkInterface,
}

#[derive(Debug)]
pub enum AddressAction {
    Add,
    Delete,
}

impl std::fmt::Display for AddressAction {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Add => write!(f, "add"),
            Self::Delete => write!(f, "delete"),
        }
    }
}

/// initiates the VRRP functions across the board.
/// from interfaces, channels, packet handling etc...
pub async fn run(mut vrouter: VirtualRouter) -> Result<(), FailoverError> {
    let parent_interface = get_interface(&vrouter.network_interface)?;
    vrouter.primary_ip = general::primary_ipv4(&parent_interface)?;

    vrouter.mac_vlan_interface =
        general::create_mac_vlan(&parent_interface.name, vrouter.vrid).await?;
    let interface = get_interface(&vrouter.mac_vlan_interface)?;

    let items = TaskItems {
        vrouter: Arc::new(Mutex::new(vrouter)),
        interface,
        parent_interface,
    };

    match EventObserver::notify(items.vrouter.clone(), Event::Startup) {
        Ok(_) => {}
        Err(err) => {
            log::error!("{err}");
            panic!("Problem running initial notify statement");
        }
    };
    let mut tasks_set = JoinSet::new();

    // Listens for incoming VRRP advertisements.
    let vrrp_items = items.clone();
    tasks_set.spawn(async { core_tasks::vrrp_process(vrrp_items).await });

    // Listens for incoming ARP requests/replies.
    let arp_items = items.clone();
    tasks_set.spawn(async { core_tasks::arp_process(arp_items).await });

    let timer_items = items.clone();
    tasks_set.spawn(async { core_tasks::timer_process(timer_items).await });

    // Wait for either a graceful shutdown signal, or all of the tasks above
    // finishing on their own (e.g. an unrecoverable bind error) -- whichever
    // happens first. Every VirtualRouter's `run()` registers its own signal
    // listeners independently; tokio fans a single incoming signal out to
    // all of them, so each session cleans up only its own mac-vlan.
    let mut sigterm =
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .map_err(NetworkError::SignalHandler)?;

    tokio::select! {
        _ = signal::ctrl_c() => {
            log::info!("({}) received SIGINT, shutting down", items.interface.name);
        }
        _ = sigterm.recv() => {
            log::info!("({}) received SIGTERM, shutting down", items.interface.name);
        }
        _ = async { while tasks_set.join_next().await.is_some() {} } => {}
    }

    if let Err(err) =
        EventObserver::notify(items.vrouter.clone(), Event::Shutdown)
    {
        log::error!("Problem tearing down virtual router: {err}");
    }

    tasks_set.abort_all();
    while tasks_set.join_next().await.is_some() {}

    Ok(())
}
