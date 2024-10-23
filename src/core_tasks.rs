/// This is the main file for the processes being run.
/// There are three functions holding these processes
/// functions that are to be run:
///     - Network Process (pub(crate) fn network_process)
///     - Timer Process (pub(crate) fn timer_process)
///
/// Each of the above will be run on a thread of their own.
/// Avoided using async since they were only three separate threads needed.
///
///
use crate::packet::VrrpPacket;
use crate::{checksum, network};
use crate::{
    general::create_datalink_channel,
    observer::EventObserver,
    pkt::handlers::{handle_incoming_arp_pkt, handle_incoming_vrrp_pkt},
    state_machine::{Event, States},
    NetResult,
};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    Packet,
};
use std::net::Ipv4Addr;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::time;

/// Waits for network connections and does the necessary actions.
/// Acts on the queries mostly described from the state machine
/// in chapter 6.3 onwards ofRFC 3768
pub(crate) async fn network_process(items: crate::TaskItems) -> NetResult<()> {
    // NetworkInterface
    let interface = items.generator.interface;

    let (_sender, mut receiver) = create_datalink_channel(&interface)?;
    let vrouter = items.vrouter;

    loop {
        let buff = match receiver.next() {
            Ok(buf) => buf,
            Err(_) => {
                log::warn!("Error Receiving Packet");
                continue;
            }
        };

        let incoming_eth_pkt = match EthernetPacket::new(buff) {
            Some(incoming_eth_pkt) => incoming_eth_pkt,
            None => continue,
        };

        match incoming_eth_pkt.get_ethertype() {
            EtherTypes::Ipv4 => {
                let incoming_ip_pkt = match Ipv4Packet::new(incoming_eth_pkt.payload()) {
                    Some(pkt) => pkt,
                    // when there is no IPv4 packet received or the IP packet is unable to be read
                    None => {
                        log::warn!("Unable to read IP packet");
                        continue;
                    }
                };

                if incoming_ip_pkt.get_next_level_protocol() == IpNextHeaderProtocols::Vrrp {
                    match handle_incoming_vrrp_pkt(&incoming_eth_pkt, Arc::clone(&vrouter)) {
                        Ok(_) => {}
                        Err(_) => continue,
                    }
                }
            }

            EtherTypes::Arp => {
                match handle_incoming_arp_pkt(&incoming_eth_pkt, Arc::clone(&vrouter)) {
                    Ok(_) => {}
                    Err(err) => {
                        log::error!("problem handing incoming ARP packet");
                        log::error!("{err}");
                    }
                }
            }

            _ => {
                // see if we can get the vrouter
                let lock = &vrouter.lock();
                let net_vr = match lock {
                    Ok(net_vr) => net_vr,
                    Err(err) => {
                        log::warn!("Cannot Get router mutex");
                        log::warn!("{err}");
                        continue;
                    }
                };

                // if we are master, we forward the packet.
                // otherwise we leave the packet be
                if net_vr.fsm.state == States::Master {}
            }
        }
    }
}

/// Used to track the various timers: (MasterDownTimer and Advertimer)
/// Has been explained in RFC 3768 section 6.2
pub(crate) async fn timer_process(items: crate::TaskItems) -> NetResult<()> {
    let mut interval = time::interval(Duration::from_millis(100));
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
                            match EventObserver::notify_mut(vrouter, Event::MasterDown) {
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
                            // send vrrp advertisement
                            let mut addresses: Vec<Ipv4Addr> = vec![];
                            vrouter.ip_addresses.iter().for_each(|ip| {
                                addresses.push(ip.addr());
                            });
                            let mut pkt = VrrpPacket {
                                version: 2,
                                hdr_type: 1,
                                vrid: vrouter.vrid,
                                priority: vrouter.priority,
                                count_ip: vrouter.ip_addresses.len() as u8,
                                auth_type: 0,
                                adver_int: vrouter.advert_interval,
                                checksum: 0,
                                ip_addresses: addresses,
                                auth_data: 0,
                                auth_data2: 0,
                            };
                            pkt.checksum = checksum::one_complement_sum(&pkt.encode(), Some(6));
                            let _ = network::send_vrrp_packet(&vrouter.network_interface, pkt);
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
