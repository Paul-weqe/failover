use std::sync::{Arc, Mutex, MutexGuard};

use crate::error::NetworkError;
use crate::general::{delete_mac_vlan, get_interface, virtual_address_action};
use crate::router::VirtualRouter;
use crate::state_machine::{Event, State};
use crate::{AddressAction, NetResult};

/// The v6 mac-vlan's own MAC address (`00-00-5E-00-02-{VRID}`), distinct
/// from the v4 mac-vlan's -- `None` for a v2 instance, or if the interface
/// can't be looked up (e.g. torn down concurrently).
fn v6_interface_mac(vrouter: &VirtualRouter) -> Option<[u8; 6]> {
    let name = vrouter.mac_vlan_interface_v6.as_ref()?;
    get_interface(name).ok()?.mac.map(|mac| mac.octets())
}

fn add_virtual_addresses(vrouter: &VirtualRouter) {
    virtual_address_action(
        AddressAction::Add,
        &vrouter.str_ipv4_addresses(),
        &vrouter.mac_vlan_interface_v4,
    );
    if let Some(v6_iface) = &vrouter.mac_vlan_interface_v6 {
        virtual_address_action(
            AddressAction::Add,
            &vrouter.str_ipv6_addresses(),
            v6_iface,
        );
    }
}

fn delete_virtual_addresses(vrouter: &VirtualRouter) {
    virtual_address_action(
        AddressAction::Delete,
        &vrouter.str_ipv4_addresses(),
        &vrouter.mac_vlan_interface_v4,
    );
    if let Some(v6_iface) = &vrouter.mac_vlan_interface_v6 {
        virtual_address_action(
            AddressAction::Delete,
            &vrouter.str_ipv6_addresses(),
            v6_iface,
        );
    }
}

fn announce_ownership(vrouter: &VirtualRouter, v4_mac: [u8; 6]) {
    vrouter.send_gratuitous_arps(v4_mac);
    if let Some(v6_mac) = v6_interface_mac(vrouter) {
        vrouter.send_neighbor_advertisements(v6_mac);
    }
}

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
            Err(_) => return Err(NetworkError::LockPoisoned),
        };
        EventObserver::notify_mut(vrouter, event)?;
        Ok(())
    }

    pub(crate) fn notify_mut(
        mut vrouter: MutexGuard<'_, VirtualRouter>,
        event: Event,
    ) -> NetResult<()> {
        let interface = get_interface(&vrouter.mac_vlan_interface_v4)?;

        match event {
            Event::Startup if vrouter.fsm.state == State::Init => {
                if vrouter.priority == 255 {
                    vrouter.send_advertisement();
                    announce_ownership(&vrouter, interface.mac.unwrap().octets());

                    // Bring virtual IP(s) back up.
                    add_virtual_addresses(&vrouter);
                    let advert_time = vrouter.advert_interval as f32;
                    vrouter.fsm.set_advert_timer(advert_time);
                    vrouter.fsm.state = State::Master;
                    log::info!(
                        "({}) transitioned to MASTER (init)",
                        vrouter.name
                    );
                } else {
                    // Delete virtual IP(s).
                    delete_virtual_addresses(&vrouter);
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
                        delete_virtual_addresses(&vrouter);
                        vrouter.fsm.state = State::Init;
                    }
                    State::Init => {}
                }
                // Only actually removes an interface once no addresses --
                // ours or a sibling instance's -- remain on it; see
                // `general::delete_mac_vlan`.
                delete_mac_vlan(&vrouter.mac_vlan_interface_v4);
                if let Some(v6_iface) = &vrouter.mac_vlan_interface_v6 {
                    delete_mac_vlan(v6_iface);
                }
                log::info!(
                    "({}) shut down, mac-vlan {} torn down",
                    vrouter.name,
                    vrouter.mac_vlan_interface_v4
                );
            }
            Event::MasterDown if vrouter.fsm.state == State::Backup => {
                // Send ADVERTISEMENT then announce ownership.
                vrouter.send_advertisement();
                announce_ownership(&vrouter, interface.mac.unwrap().octets());

                // Add virtual IP address(es).
                add_virtual_addresses(&vrouter);
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
