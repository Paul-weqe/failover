
use std::{error::Error, fs::File, io::BufReader, path::Path, process::Command};
use crate::{config::{CliConfig, FileConfig, VrrpConfig}, error::OptError};
use getopts::Options;
use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};


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
    let mut opts = Options::new();

    opts.optflag("h", "help", "display help information");
    
    opts.optopt(
        "A", 
        "action", 
        "action that will be done to the interfaces ['create' or 'delete']", 
        "(--action startup / --action teardown / --action run)");

    // name
    opts.optopt(
        "n", 
        "name", 
        "name of the virtual router instance.",
    "(--name VR_1)");
    
    // vrid 
    opts.optopt(
        "v", 
        "vrid", 
        "The Virtual Router ID of the instance. In the range of 1-255", 
        "(--vrid 51)");

    // ip addresses 
    opts.optmulti(
    "I", 
    "ip-address", 
    "An Ip address that is associated with the virtual router instance", 
    "(--ip-address 192.168.100.5/24)");

    // interface name
    opts.optopt(
        "i", 
        "iface", 
        "The interfaece that the virtual IP(s) will be attached to.", 
        "(--iface eth0)");
    
    // priority
    opts.optopt(
        "p", 
        "priority", 
        "priority of the virutal router in the VRRP network group. In the range 1-44", 
        "(--priority 100)");
    
    opts.optopt(
        "a", 
        "adv-interval", 
        "When in master, the interval when ADVERTISEMENTS should be carried across", 
    "(--adv-interval 2)");

    opts.optopt(
        "P", 
        "preempt-mode", 
        "Controls whether a higher priority Backup router preempts a lower priority Master.", 
    "(--preempt-mode false)");

    opts.optopt(
        "j", 
        "json-file", 
        "the json file with the necessary configurations", 
    "(--json-file vrrp-config.json)");


    // if it is the help request
    if args[1..].is_empty() || args[1..].contains(&"--help".to_string()) {
        println!("HELP");
        println!("{}", opts.usage("Failover Usage: \n"));
        std::process::exit(1);
    }

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(err) => return Result::Err(OptError(err.to_string().into()))
    };

    if matches.opt_str("json-file") != None {
        let filename = matches.opt_str("json-file").unwrap();
        let file_config = match read_config_from_json_file(&filename) {
            Ok(config) => VrrpConfig::File(config),
            Err(err) => {
                log::error!("{err}");
                return  Result::Err(OptError(format!("Problem Parsing file {}", &filename)))
            }
        };

        match matches.opt_str("action") {
            Some (x) => {
                if vec!["startup", "teardown"].contains(&x.to_lowercase().as_str()){
                    let action = if x.to_lowercase().as_str() == "startup" { "add" } else { "delete" };
                    virtual_address_action(action, &file_config.ip_addresses(), &file_config.interface_name());
                    std::process::exit(1);
                } else if x.to_lowercase().as_str() == "run" {
                    return Ok(file_config)
                } else {
                    return Result::Err(OptError("--action has to be ether 'startup', 'teardown' or 'run'".into()));
                }
            }
            
            None => {
                return Ok(file_config)
            }
        }
    } else {

        let mut cli_config = CliConfig::default();
        cli_config.name = match matches.opt_str("name") {
            Some(x) => x,
            None => return Result::Err(OptError("instance name '--name' is a mandatory field".into()))
        };
    
        cli_config.vrid = match matches.opt_str("vrid") {
            Some(x) => x.parse::<u8>().unwrap(),
            None => return Result::Err(OptError("VRID '--vrid' is a mandatory field".into()))
        };
    
        cli_config.interface_name = match matches.opt_str("iface") {
            Some(x) => x,
            None => return Result::Err(OptError("interface name '--iface' is a mandatory field".into()))
        };
    
        for addr in matches.opt_strs("ip-address") {
            cli_config.ip_addresses.push(addr);
        }
    
        cli_config.priority = match matches.opt_str("priority") {
            Some(x) => x.parse::<u8>().unwrap(),
            None => cli_config.priority
        };
    
        cli_config.advert_interval = match matches.opt_str("adv-interval") {
            Some(x) => x.parse::<u8>().unwrap(),
            None => cli_config.advert_interval
        };
        cli_config.preempt_mode = match matches.opt_str("preempt-mode") {
            Some (x) => x.parse::<bool>().unwrap(),
            None => cli_config.preempt_mode
        };

        match matches.opt_str("action") {
            Some (x) => {
                if !(vec!["delete", "add"].contains(&x.to_lowercase().as_str())){
                    return Result::Err(OptError("".into()));
                } 
                virtual_address_action(x.to_lowercase().as_str(), &cli_config.ip_addresses, &cli_config.interface_name); 
            }
            
            None => {}
        }
        Ok(VrrpConfig::Cli(cli_config))
    }

}

fn virtual_address_action(action: &str, addresses: &[String], interface_name: &str)
{
    for addr in addresses {
        let cmd_args = vec!["ip", "address", action, &addr, "dev", interface_name];
        let _ = Command::new("sudo")
            .args(cmd_args)
            .output();
    }
}



pub fn read_config_from_json_file<P: AsRef<Path>>(path: P) -> Result<FileConfig, Box<dyn Error>> 
{
    log::info!("Reading from config file {:?}", path.as_ref().as_os_str());
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let u = serde_json::from_reader(reader)?;
    Ok(u)
}
