use std::{sync::{Arc, Mutex}, thread};

use error::NetError;
use general::get_interface;
use pkt::generators::{self, MutablePktGenerator};
use router::VirtualRouter;


pub mod general;

mod config;
mod core;
mod router;
mod state_machine;
mod pkt;
mod checksum;

#[derive(Clone)]
pub(crate) struct TaskItems {
    vrouter: Arc<Mutex<VirtualRouter>>,
    generator: MutablePktGenerator
}

pub mod error{
    use std::fmt::Display;

    #[derive(Debug)]
    pub struct NetError(pub String);
    
    impl Display for NetError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }


    /// used for getting errors when parsing CLI arguments
    #[derive(Debug)]
    pub struct OptError(pub String);

    impl Display for OptError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }
}


/// initiates the network functions across the board. 
/// from interfaces, channels, packet handling etc...
pub fn run(vrouter: VirtualRouter) -> Result<(), NetError>{

    let interface = get_interface(&vrouter.network_interface);

    let items = TaskItems {
        vrouter: Arc::new(Mutex::new(vrouter)),
        generator: generators::MutablePktGenerator::new(interface.clone())
    };

    // sync process listens for any incoming network requests
    let network_items = items.clone();
    let network_process = thread::spawn(move || { core::network_process(network_items) });

    // wait for when either MasterDownTimer or AdvertTimer is reached to 
    // carry out necessary actions. 
    let timers_items = items.clone();
    let timers_process = thread::spawn( move || { core::timer_process(timers_items) });

    // listen for any events happening to the vrouter
    let event_items = items.clone();
    let event_process = thread::spawn( move || { core::event_process(event_items); });
    
    network_process.join().unwrap();
    timers_process.join().unwrap();
    event_process.join().unwrap();
    
    Ok(())
}