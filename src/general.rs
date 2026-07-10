use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use futures_util::stream::TryStreamExt;
use ipnet::Ipv4Net;
use pnet::datalink::{
    self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface,
};
use rand::Rng;
use rand::distributions::Alphanumeric;
use rtnetlink::{AddressMessageBuilder, new_connection};

use crate::config::VrrpConfig;
use crate::error::NetError;
use crate::router::VirtualRouter;
use crate::{AddressAction, NetResult};

pub(crate) fn get_interface(name: &str) -> NetResult<NetworkInterface> {
    let interface_names_match = |iface: &NetworkInterface| iface.name == name;
    let interfaces = datalink::linux::interfaces();

    // check if interface name exists, if not create it
    match interfaces.into_iter().find(interface_names_match) {
        Some(interface) => Ok(interface),
        None => Err(NetError(format!(
            "unable to find interface with name {name}"
        ))),
    }
}

pub(crate) fn create_datalink_channel(
    interface: &NetworkInterface,
) -> NetResult<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)> {
    match pnet::datalink::channel(interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => Ok((tx, rx)),
        Ok(_) => {
            let err = "Unknown channel type";
            log::error!("{err}");
            Err(NetError(err.to_string()))
        }
        Err(err) => {
            log::error!("Problem creating datalink channel");
            log::error!("{err}");
            Err(NetError("Problem creating datalink channel".to_string()))
        }
    }
}

// Takes the configs that have been received and converts them into a virtual
//  router instance.
pub fn config_to_vr(conf: VrrpConfig) -> VirtualRouter {
    let mut ips: Vec<Ipv4Net> = vec![];
    if conf.ip_addresses().len() > 20 {
        log::warn!(
            "({})  More than 20 IP addresses(max for VRRP) have been configured. Only first 20 addresses will be used..",
            conf.name()
        );
    }

    let addresses = if conf.ip_addresses().len() <= 20 {
        conf.ip_addresses()
    } else {
        conf.ip_addresses()[0..20].to_vec()
    };
    for ip_config in addresses.iter() {
        // TODO: have error logging if this is Err.
        if let Ok(ip_addr) = Ipv4Net::from_str(ip_config) {
            ips.push(ip_addr);
        }
    }

    let vr = VirtualRouter::new(
        conf.name(),
        conf.vrid(),
        ips,
        conf.priority(),
        conf.advert_interval(),
        conf.preempt_mode(),
        conf.interface_name(),
    );
    log::info!("({}) Entered {:?} state.", vr.name, vr.fsm.state);
    vr
}

/// Adds/removes the given virtual IP addresses on `interface_name` via
/// Netlink (equivalent to `ip address add/delete <addr> dev <iface>`).
///
/// Bridges into async rtnetlink code from what is otherwise a synchronous
/// call chain, so this must be invoked from within a multi-threaded tokio
/// runtime.
pub fn virtual_address_action(
    action: AddressAction,
    addresses: &[String],
    interface_name: &str,
) {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(apply_address_action(
            action,
            addresses,
            interface_name,
        ));
    });
}

async fn apply_address_action(
    action: AddressAction,
    addresses: &[String],
    interface_name: &str,
) {
    let (connection, handle, _) = match new_connection() {
        Ok(conn) => conn,
        Err(err) => {
            log::error!("Unable to open netlink connection: {err}");
            return;
        }
    };
    tokio::spawn(connection);

    let mut links = handle
        .link()
        .get()
        .match_name(interface_name.to_string())
        .execute();
    let index = match links.try_next().await {
        Ok(Some(link)) => link.header.index,
        Ok(None) => {
            log::error!(
                "Unable to find interface {interface_name} for virtual address action"
            );
            return;
        }
        Err(err) => {
            log::error!("Problem fetching interface {interface_name}: {err}");
            return;
        }
    };

    for addr in addresses {
        let net = match Ipv4Net::from_str(addr) {
            Ok(net) => net,
            Err(err) => {
                log::error!("Invalid virtual address {addr}: {err}");
                continue;
            }
        };

        let result = match action {
            AddressAction::Add => {
                handle
                    .address()
                    .add(index, IpAddr::V4(net.addr()), net.prefix_len())
                    .replace()
                    .execute()
                    .await
            }
            AddressAction::Delete => {
                let message = AddressMessageBuilder::<Ipv4Addr>::new()
                    .index(index)
                    .address(net.addr(), net.prefix_len())
                    .build();
                handle.address().del(message).execute().await
            }
        };

        if let Err(err) = result {
            log::warn!(
                "Problem performing netlink '{action}' for {addr} on {interface_name}: {err}"
            );
        }
    }
}

pub(crate) fn random_vr_name() -> String {
    let val: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();

    log::info!("Name for Virtual Router not given. generated name VR_{val}");
    format!("VR_{val}")
}
