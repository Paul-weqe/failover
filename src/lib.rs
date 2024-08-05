use error::{NetError, OptError};
use general::get_interface;
use observer::EventObserver;
use pkt::generators::{self, MutablePktGenerator};
use router::VirtualRouter;
use state_machine::Event;
use std::sync::{Arc, Mutex};
use tokio::task::JoinSet;

mod checksum;
pub mod config;
mod core_tasks;
pub mod general;
mod network;
mod observer;
mod packet;
mod pkt;
pub mod router;
mod state_machine;

pub(crate) type NetResult<T> = Result<T, NetError>;
pub(crate) type OptResult<T> = Result<T, OptError>;

#[derive(Clone)]
pub(crate) struct TaskItems {
    vrouter: Arc<Mutex<VirtualRouter>>,
    generator: MutablePktGenerator,
}

pub mod error {
    use std::{error::Error, fmt::Display};

    // Network errors
    #[derive(Debug)]
    pub struct NetError(pub String);
    impl Error for NetError {}
    impl Display for NetError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    // OptError
    // used for getting errors when parsing CLI arguments
    #[derive(Debug)]
    pub struct OptError(pub String);
    impl Error for OptError {}
    impl Display for OptError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }
}

/// initiates the VRRP functions across the board.
/// from interfaces, channels, packet handling etc...
pub async fn run(vrouter: VirtualRouter) -> NetResult<()> {
    let interface = get_interface(&vrouter.network_interface)?;

    let items = TaskItems {
        vrouter: Arc::new(Mutex::new(vrouter)),
        generator: generators::MutablePktGenerator::new(interface.clone()),
    };

    match EventObserver::notify(items.vrouter.clone(), Event::Startup) {
        Ok(_) => {}
        Err(err) => {
            //log::error!("{err}");
            panic!("Problem running initial notify statement");
        }
    };
    let mut tasks_set = JoinSet::new();

    // sync process listens for any incoming network requests
    let network_items = items.clone();
    tasks_set.spawn(async { core_tasks::network_process(network_items).await });

    let timer_items = items.clone();
    tasks_set.spawn(async { core_tasks::timer_process(timer_items).await });

    while tasks_set.join_next().await.is_some() {
        // join tasks
    }

    Ok(())
}
