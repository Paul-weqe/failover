use std::sync::{Arc, Mutex, MutexGuard};

use crate::error::NetError;
use crate::general::{get_interface, virtual_address_action};
use crate::router::VirtualRouter;
use crate::state_machine::{Event, State};
use crate::{AddressAction, NetResult};

/// Listens for when any Event occurs in the Virtual Router.
/// Events that can occur are: Startup,  Shutdown, MasterDown, Null
/// Actions happening on when each of these Events is fired are
/// Specified in RFC 3768 section 6.3, 6.4 and 6.5
#[derive(Debug, Clone)]
pub(crate) struct EventObserver;

impl EventObserver {
    pub(crate) fn notify(
        vrouter: Arc<Mutex<VirtualRouter>>,
        event: Event,
    ) -> NetResult<()> {
        let vrouter = match vrouter.lock() {
            Ok(vrouter) => vrouter,
            Err(_) => {
                return Err(NetError(
                    "Unable to fetch vrouter mutex".to_string(),
                ));
            }
        };
        EventObserver::notify_mut(vrouter, event)?;
        Ok(())
    }

    pub(crate) fn notify_mut(
        mut vrouter: MutexGuard<'_, VirtualRouter>,
        event: Event,
    ) -> NetResult<()> {
        let interface = get_interface(&vrouter.network_interface)?;

        match event {
            Event::Startup if vrouter.fsm.state == State::Init => {
                if vrouter.priority == 255 {
                    vrouter.send_advertisement();
                    vrouter.send_gratuitous_arps(interface.mac.unwrap().octets());

                    // Bring virtual IP back up.
                    virtual_address_action(
                        AddressAction::Add,
                        &vrouter.str_ipv4_addresses(),
                        &vrouter.network_interface,
                    );
                    let advert_time = vrouter.advert_interval as f32;
                    vrouter.fsm.set_advert_timer(advert_time);
                    vrouter.fsm.state = State::Master;
                    log::info!(
                        "({}) transitioned to MASTER (init)",
                        vrouter.name
                    );
                } else {
                    // Delete virtual IP.
                    virtual_address_action(
                        AddressAction::Delete,
                        &vrouter.str_ipv4_addresses(),
                        &vrouter.network_interface,
                    );
                    let m_down_interval = vrouter.master_down_interval;
                    vrouter.fsm.set_master_down_timer(m_down_interval);
                    vrouter.fsm.state = State::Backup;
                    log::info!(
                        "({}) transitioned to BACKUP (init)",
                        vrouter.name
                    );
                }
            }
            Event::Shutdown => {
                match vrouter.fsm.state {
                    State::Backup => {
                        vrouter.fsm.disable_timer();
                        vrouter.fsm.state = State::Init;
                    }
                    State::Master => {
                        vrouter.fsm.disable_timer();
                        vrouter.send_advertisement();
                        vrouter.fsm.state = State::Init;
                    }
                    State::Init => {}
                }
            }
            Event::MasterDown if vrouter.fsm.state == State::Backup => {
                // Send ADVERTIEMENT then send gratuitous ARP.
                vrouter.send_advertisement();
                vrouter.send_gratuitous_arps(interface.mac.unwrap().octets());

                // Add virtual IP address.
                virtual_address_action(
                    AddressAction::Add,
                    &vrouter.str_ipv4_addresses(),
                    &vrouter.network_interface,
                );
                let advert_interval = vrouter.advert_interval as f32;
                vrouter.fsm.set_advert_timer(advert_interval);
                vrouter.fsm.state = State::Master;
                log::info!("({}) Transitioned to MASTER", vrouter.name);
            }
            _ => {}
        }
        Ok(())
    }
}
