
use std::{error::Error, fs::File, io::BufReader, path::Path};
use crate::{config::{CliConfig, FileConfig, VrrpConfig}, error::OptError};
use getopts::Options;
use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};

pub fn read_config_from_json_file<P: AsRef<Path>>(path: P) -> Result<FileConfig, Box<dyn Error>> {
    log::info!("Reading from config file {:?}", path.as_ref().as_os_str());
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let u = serde_json::from_reader(reader)?;
    Ok(u)
}


pub fn get_interface(name: &str) -> NetworkInterface {
    let interface_names_match = |iface: &NetworkInterface| iface.name == name;
    let interfaces = datalink::linux::interfaces();
    interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap()
}

pub fn create_datalink_channel(interface: &NetworkInterface)  -> (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>){
    match pnet::datalink::channel(interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => return (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(err) => {
            log::error!("Unable to create datalink channel");
            panic!("ERROR: {err}")
        }
    }
}


pub fn parse_cli_opts(args: &[String]) -> Result<VrrpConfig, OptError>{

    // let mut program = args[0].clone();
    let mut opts = Options::new();
    
    opts.optflag("h", "help", "display help information");
    
    // name
    opts.reqopt(
        "n", 
        "name", 
        "name of the virtual router instance.",
    "When logging, this will help in identifying which instance is being referred to");
    
    // vrid 
    opts.reqopt(
        "v", 
        "vrid", 
        "The Virtual Router ID of the instance.", 
        "Should be in the range of 1-255. Each Instance in the VRRP group must have a unique VRID"
    );

    // ip addresses 
    opts.optmulti(
    "I", 
    "ip-address", 
    "An Ip address that is associated with the virtual router instance", 
    "Virtual Ip Address that is to be seen by end users as an actual IP address");

    // interface name
    opts.reqopt(
        "i", 
        "iface", 
        "The interfaece that the virtual IP(s) will be attached to", 
        "The ethernet interface that will be receiving the packets. preferably wifi / ethernet / optical interface");
    
    // priority
    opts.optopt(
        "p", 
        "priority", 
        "priority of the virutal router in the VRRP network group", 
        "Give higher priority to instances that you want to be first selected as MASTER.");
    
    opts.optopt(
        "a", 
        "adv-interval", 
        "When in master, the interval when ADVERTISEMENTS should be carried across", 
    "default 1. ");

    opts.optopt(
        "P", 
        "preempt-mode", 
        "Controls whether a higher priority Backup router preempts a lower priority Master.", 
    "");

    opts.optopt(
        "j", 
        "json-file", 
        "the json file with the necessary configurations", 
    "vrrp-config.json");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(err) => return Result::Err(OptError(err.to_string().into()))
    };

    if matches.opt_str("json-file") != None {
        let filename = matches.opt_str("json-file").unwrap();
        match read_config_from_json_file(&filename) {
            Ok(config) => return Ok(VrrpConfig::File(config)),
            Err(_) => return Result::Err(OptError(format!("Problem Parsing file {}", &filename)))
        };
    } else {

        let mut config = CliConfig::default();
        config.name = match matches.opt_str("name") {
            Some(x) => x,
            None => return Result::Err(OptError("instance name '--name' is a mandatory field".into()))
        };
    
        config.vrid = match matches.opt_str("vrid") {
            Some(x) => x.parse::<u8>().unwrap(),
            None => return Result::Err(OptError("VRID '--vrid' is a mandatory field".into()))
        };
    
        config.interface_name = match matches.opt_str("iface") {
            Some(x) => x,
            None => return Result::Err(OptError("interface name '--iface' is a mandatory field".into()))
        };
    
        for addr in matches.opt_strs("ip-address") {
            config.ip_addresses.push(addr);
        }
    
        config.priority = match matches.opt_str("priority") {
            Some(x) => x.parse::<u8>().unwrap(),
            None => config.priority
        };
    
        config.advert_interval = match matches.opt_str("adv-interval") {
            Some(x) => x.parse::<u8>().unwrap(),
            None => config.advert_interval
        };
        config.preempt_mode = match matches.opt_str("preempt-mode") {
            Some (x) => x.parse::<bool>().unwrap(),
            None => config.preempt_mode
        };
    
        Ok(VrrpConfig::Cli(config))
    }
    
    
}

