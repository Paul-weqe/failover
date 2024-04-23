use std::{io, sync::{Arc, Mutex}, thread};

use error::NetError;
use general::get_interface;
use observer::EventObserver;
use pkt::generators::{self, MutablePktGenerator};
use router::VirtualRouter;
use state_machine::Event;


pub mod general;
pub mod config;
mod observer;
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


/// initiates the VRRP functions across the board. 
/// from interfaces, channels, packet handling etc...
pub fn run(vrouter: VirtualRouter) -> Result<(), NetError>{

    let interface = get_interface(&vrouter.network_interface);

    let items = TaskItems {
        vrouter: Arc::new(Mutex::new(vrouter)),
        generator: generators::MutablePktGenerator::new(interface.clone())
    };

    EventObserver::notify(items.vrouter.clone(), Event::Startup);
    // sync process listens for any incoming network requests
    let network_items = items.clone();
    let network_process = thread::spawn(move || { core::network_process(network_items) });

    // wait for when either MasterDownTimer or AdvertTimer is reached to 
    // carry out necessary actions. 
    let timers_items = items.clone();
    let timers_process = thread::spawn( move || { 
        core::timer_process(timers_items).unwrap() 
    });
    
    match network_process.join() {
        Ok(_) => {},
        Err(_) => {
            log::error!("problem running network process");
            log::error!("{}", io::Error::last_os_error());
            return Result::Err(NetError("Unable to execute network thread".to_string()))
        }
    };
    match timers_process.join() {
        Ok(_) => {},
        Err(_) => {
            log::error!("problem unning the timer provess");
            log::error!("{}", io::Error::last_os_error());
            return Result::Err(NetError("Unable to execute event thread".to_string()));
        }
    }
    
    Ok(())
}