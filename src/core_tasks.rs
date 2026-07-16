use std::sync::Arc;
use std::time::{Duration, Instant};

use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use tokio::time;

use crate::NetResult;
use crate::network::{ArpListener, VrrpListener};
use crate::observer::EventObserver;
use crate::pkt::handlers::{handle_incoming_arp_pkt, handle_incoming_vrrp_pkt};
use crate::state_machine::Event;

/// Listens for VRRP advertisements on a raw IP socket bound to the VRRP
/// multicast group and hands each one off to the VRRP packet handler.
pub(crate) async fn vrrp_process(items: crate::TaskItems) -> NetResult<()> {
    let listener = VrrpListener::bind(&items.interface.name).map_err(|err| {
        crate::error::NetError(format!(
            "Unable to bind VRRP listening socket: {err}"
        ))
    })?;
    let vrouter = items.vrouter;

    loop {
        let buf = match listener.recv().await {
            Ok(buf) => buf,
            Err(err) => {
                log::warn!("Error receiving VRRP packet: {err}");
                continue;
            }
        };

        let ip_packet = match Ipv4Packet::new(&buf) {
            Some(pkt) => pkt,
            None => {
                log::warn!("Unable to read incoming IP packet");
                continue;
            }
        };

        if let Err(err) =
            handle_incoming_vrrp_pkt(&ip_packet, Arc::clone(&vrouter))
        {
            log::warn!("problem handling incoming VRRP packet");
            log::warn!("{err}");
        }
    }
}

/// Listens for ARP frames on a raw AF_PACKET socket bound to this
/// interface and hands each one off to the ARP packet handler.
pub(crate) async fn arp_process(items: crate::TaskItems) -> NetResult<()> {
    let listener = ArpListener::bind(&items.interface.name).map_err(|err| {
        crate::error::NetError(format!(
            "Unable to bind ARP listening socket: {err}"
        ))
    })?;
    let vrouter = items.vrouter;

    loop {
        let buf = match listener.recv().await {
            Ok(buf) => buf,
            Err(err) => {
                log::warn!("Error receiving ARP packet: {err}");
                continue;
            }
        };

        let eth_packet = match EthernetPacket::new(&buf) {
            Some(pkt) => pkt,
            None => continue,
        };

        if let Err(err) =
            handle_incoming_arp_pkt(&eth_packet, Arc::clone(&vrouter))
        {
            log::error!("problem handling incoming ARP packet");
            log::error!("{err}");
        }
    }
}

/// Used to track the various timers: (MasterDownTimer and Advertimer)
/// Has been explained in RFC 3768 section 6.2
pub(crate) async fn timer_process(items: crate::TaskItems) -> NetResult<()> {
    let mut interval = time::interval(Duration::from_millis(1000));
    let vrouter = items.vrouter;

    loop {
        interval.tick().await;
        let mut vrouter = match vrouter.lock() {
            Ok(vrouter) => vrouter,
            Err(_) => {
                log::error!("Unable to get mutex for vrouter");
                continue;
            }
        };
        let timer = vrouter.fsm.timer;

        match timer.t_type {
            crate::state_machine::TimerType::MasterDown => {
                match vrouter.fsm.timer.waiting_for {
                    // waiting is the time being waited for
                    // to notify for the master down
                    Some(waiting) => {
                        if Instant::now() > waiting {
                            match EventObserver::notify_mut(
                                vrouter,
                                Event::MasterDown,
                            ) {
                                Ok(info) => info,
                                Err(err) => return Err(err),
                            }
                        }
                    }
                    None => {
                        log::warn!("No timer being waited for.");
                        continue;
                    }
                };
            }

            crate::state_machine::TimerType::Adver => {
                match vrouter.fsm.timer.waiting_for {
                    Some(waiting) => {
                        if Instant::now() > waiting {
                            vrouter.send_advertisement();
                            let advert_time = vrouter.advert_interval as f32;
                            vrouter.fsm.set_advert_timer(advert_time);
                        }
                    }
                    None => {
                        log::warn!("No timer being waited for.");
                        continue;
                    }
                };
            }

            crate::state_machine::TimerType::Null => {}
        }
    }
}
