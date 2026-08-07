use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use tokio::time;

use crate::NetResult;
use crate::error::NetworkError;
use crate::network::{ArpListener, NdpListener, VrrpListener};
use crate::observer::EventObserver;
use crate::pkt::handlers::{
    handle_incoming_arp_pkt, handle_incoming_ndp_pkt,
    handle_incoming_vrrp_v4_pkt, handle_incoming_vrrp_v6_pkt,
};
use crate::state_machine::Event;

/// Listens for VRRP advertisements on a raw IP socket bound to the VRRP
/// multicast group and hands each one off to the VRRP packet handler.
pub(crate) async fn vrrp_process(items: crate::TaskItems) -> NetResult<()> {
    let unspec_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let listener =
        VrrpListener::bind(&items.parent_interface.name, unspec_addr).map_err(
            |source| NetworkError::SocketBind {
                kind: "socket4",
                iface: items.parent_interface.name.clone(),
                source,
            },
        )?;

    let vrouter = items.vrouter;

    loop {
        let (buf, src) = match listener.recv(unspec_addr).await {
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
            handle_incoming_vrrp_v4_pkt(&ip_packet, Arc::clone(&vrouter))
        {
            log::warn!("problem handling incoming VRRP packet");
            log::warn!("{err}");
        }
    }
}

/// IPv6 counterpart of `vrrp_process`. Only ever spawned for a v3 instance
/// (see `TaskItems::interface_v6`); returns immediately if there's no v6
/// mac-vlan to listen on.
pub(crate) async fn vrrp_process_v6(items: crate::TaskItems) -> NetResult<()> {
    let Some(interface_v6) = items.interface_v6.clone() else {
        return Ok(());
    };

    let unspec_addr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
    let listener =
        VrrpListener::bind(&items.parent_interface.name, unspec_addr).map_err(
            |source| NetworkError::SocketBind {
                kind: "socket6",
                iface: items.parent_interface.name.clone(),
                source,
            },
        )?;

    let vrouter = items.vrouter;
    let _ = interface_v6;

    loop {
        let (buf, src) = match listener.recv(unspec_addr).await {
            Ok(pair) => pair,
            Err(err) => {
                log::warn!("Error receiving VRRPv6 packet: {err}");
                continue;
            }
        };

        if let IpAddr::V6(src) = src
            && let Err(err) =
                handle_incoming_vrrp_v6_pkt(&buf, src, Arc::clone(&vrouter))
        {
            log::warn!("problem handling incoming VRRPv6 packet");
            log::warn!("{err}");
        }
    }
}

/// Listens for ARP frames on a raw AF_PACKET socket bound to this
/// interface and hands each one off to the ARP packet handler.
pub(crate) async fn arp_process(items: crate::TaskItems) -> NetResult<()> {
    let listener =
        ArpListener::bind(&items.interface.name).map_err(|source| {
            NetworkError::SocketBind {
                kind: "ARP",
                iface: items.interface.name.clone(),
                source,
            }
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

/// IPv6's equivalent of `arp_process`: listens for Neighbor
/// Solicitation/Advertisement traffic on the v6 mac-vlan. Only ever
/// spawned for a v3 instance.
pub(crate) async fn ndp_process(items: crate::TaskItems) -> NetResult<()> {
    let Some(interface_v6) = items.interface_v6.clone() else {
        return Ok(());
    };

    let listener = NdpListener::bind(&interface_v6.name).map_err(|source| {
        NetworkError::SocketBind {
            kind: "NDP",
            iface: interface_v6.name.clone(),
            source,
        }
    })?;
    let vrouter = items.vrouter;

    loop {
        let (payload, src) = match listener.recv().await {
            Ok(pair) => pair,
            Err(err) => {
                log::warn!("Error receiving NDP packet: {err}");
                continue;
            }
        };

        if let Err(err) =
            handle_incoming_ndp_pkt(&payload, src, Arc::clone(&vrouter))
        {
            log::error!("problem handling incoming NDP packet");
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
