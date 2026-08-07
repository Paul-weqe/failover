use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use error::{FailoverError, NetworkError};
use general::AddressFamily;
use observer::EventObserver;
use pnet::datalink::NetworkInterface;
use router::VirtualRouter;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) enum VrrpVersion {
    V2 = 2,
    #[default]
    V3 = 3,
}

// ==== impl VrrpVersion ====

impl VrrpVersion {
    pub const fn as_u8(self) -> u8 {
        match self {
            VrrpVersion::V2 => 2,
            VrrpVersion::V3 => 3,
        }
    }
}

impl std::fmt::Display for VrrpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VRRP v{}", self.as_u8())
    }
}

impl TryFrom<u8> for VrrpVersion {
    type Error = error::PacketError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(VrrpVersion::V2),
            3 => Ok(VrrpVersion::V3),
            other => Err(error::PacketError::UnsupportedVersion(other)),
        }
    }
}

impl Serialize for VrrpVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.as_u8())
    }
}

impl<'de> Deserialize<'de> for VrrpVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        VrrpVersion::try_from(value).map_err(|_| {
            serde::de::Error::custom(format!(
                "invalid VRRP version {value}; must be 2 or 3"
            ))
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum VrrpAddresses {
    V4(Vec<Ipv4Addr>),
    V6(Vec<Ipv6Addr>),
}

// ==== impl VrrpAddresses ====

impl VrrpAddresses {
    pub fn len(&self) -> usize {
        match self {
            VrrpAddresses::V4(addrs) => addrs.len(),
            VrrpAddresses::V6(addrs) => addrs.len(),
        }
    }
}

pub(crate) type NetResult<T> = Result<T, NetworkError>;
pub(crate) type ConfigResult<T> = Result<T, error::ConfigError>;

#[derive(Clone)]
pub(crate) struct TaskItems {
    vrouter: Arc<Mutex<VirtualRouter>>,
    interface: NetworkInterface,
    interface_v6: Option<NetworkInterface>,
    parent_interface: NetworkInterface,
}

#[derive(Debug)]
pub(crate) enum AddressAction {
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
    let parent_interface = general::get_interface(&vrouter.network_interface)?;
    vrouter.primary_ip = general::primary_ipv4(&parent_interface)?;

    vrouter.mac_vlan_interface_v4 = general::create_mac_vlan(
        &parent_interface.name,
        vrouter.vrid,
        AddressFamily::V4,
    )
    .await?;
    let interface = general::get_interface(&vrouter.mac_vlan_interface_v4)?;

    let interface_v6 = if vrouter.version == VrrpVersion::V3 {
        let v6_name = general::create_mac_vlan(
            &parent_interface.name,
            vrouter.vrid,
            AddressFamily::V6,
        )
        .await?;
        vrouter.mac_vlan_interface_v6 = Some(v6_name.clone());
        vrouter.primary_ip_v6 = general::primary_ipv6(&parent_interface);
        Some(general::get_interface(&v6_name)?)
    } else {
        None
    };

    let items = TaskItems {
        vrouter: Arc::new(Mutex::new(vrouter)),
        interface,
        interface_v6,
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

    // v3 additionally listens for VRRP-over-IPv6 and NDP traffic on its
    // own mac-vlan.
    if items.interface_v6.is_some() {
        let vrrp_v6_items = items.clone();
        tasks_set
            .spawn(async { core_tasks::vrrp_process_v6(vrrp_v6_items).await });

        let ndp_items = items.clone();
        tasks_set.spawn(async { core_tasks::ndp_process(ndp_items).await });
    }

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
