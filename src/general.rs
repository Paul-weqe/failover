
use std::{error::Error, fs::{self, File}, io::{BufReader, Write}, path::Path, process::Command, str::FromStr};
use crate::{config::{CliConfig, FileConfig, VrrpConfig}, error::OptError, router::VirtualRouter, state_machine::VirtualRouterMachine};
use getopts::Options;
use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};
use ipnet::Ipv4Net;

pub(crate) fn get_interface(name: &str) -> NetworkInterface {
    let interface_names_match = |iface: &NetworkInterface| iface.name == name;
    let interfaces = datalink::linux::interfaces();
    interfaces.into_iter().find(interface_names_match).unwrap()
}

pub(crate) fn create_datalink_channel(interface: &NetworkInterface)  -> (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>){
    match pnet::datalink::channel(interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(err) => {
            log::error!("Unable to create datalink channel");
            panic!("{err}")
        }
    }
}

// takes the configs that have been received and converts them 
// into a virtual router instance. 
pub fn config_to_vr(conf: VrrpConfig) -> VirtualRouter {

    // SKEW TIME = (256 * priority) / 256
    let skew_time: f32 = (256_f32 - conf.priority() as f32) / 256_f32;
    
    // MASTER DOWN INTERVAL = (3 * ADVERTISEMENT INTERVAL ) + SKEW TIME 
    let master_down_interval: f32 = (3_f32 * conf.advert_interval() as f32) + skew_time;
    
    let mut ips: Vec<Ipv4Net> = vec![];
    for ip_config in &conf.ip_addresses() {
        match Ipv4Net::from_str(ip_config) {
            Ok(ip_addr) => ips.push(ip_addr),
            Err(err) => {
                log::error!("Address '{:?}' not in the correct format", &ip_config);
                panic!("Error: {err}");
            }
        }
    }
    
    log::info!("({}) Setting up.", conf.name());
    let vr = VirtualRouter {
        name: conf.name().clone(),
        vrid: conf.vrid(),
        ip_addresses: ips,
        priority: conf.priority(),
        skew_time,
        advert_interval: conf.advert_interval(),
        master_down_interval,
        preempt_mode: conf.preempt_mode(),
        network_interface: conf.interface_name().clone(),
        fsm: VirtualRouterMachine::default()
    };
    log::info!("({}) Entered {:?} state.", vr.name, vr.fsm.state);
    vr

}


pub fn parse_cli_opts(args: &[String]) -> Result<VrrpConfig, OptError>{
    let mut opts = Options::new();

    opts.optflag("H", "help", "display help information");
    opts.optflag("C", "cli", "use the cli config option");
    
    opts.optopt(
        "A", 
        "action", 
        "action that will be done to the addresses on the interface configured. Default is 'run'", 
        "(--action teardown / --action run)");

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
        "f", 
        "file", 
        "the json file with the necessary configurations. By default will be looked for at: '{CURRENT_PATH}/vrrp-config.json'", 
    "(--file FILENAME)");


    // if it is the help request
    if args[1..].contains(&"--help".to_string()) {
        let help_format = "
        Failover Usage:
            # running failover, we take configs either from a json file or from the cli   
            CONFIG
            ======

            FILE CONFIG MODE
            ----------------
            ./failover --file custom-vrrp-config.json

            CLI CONFIG MODE 
            ---------------
            ./failover --cli --iface wlo1 --priority 101 --adv-interval 1 --preempt-mode false

            DEFAULT
            -------
            ./failover 
            # if neither 'file' not 'cli' is specified, failover chooses 'file' by default. 
            # The file that is used for configs is '{CURRENT_PATH}/vrrp-config.json' in the same 
            # directory where failover is being run from (TODO: to change this to relevant config file in /etc directory).

            ACTIONS
            =======
            # Two actions can be run: 'teardown' or 'run'. 
            # 'run' is default if no actions are specified. 
            ./failover --teardown
            
            # can also be called without --run
            ./failover --run 
            ./failover --teardown

        ".to_string();
        
        println!("{}", opts.usage(&help_format));
        std::process::exit(0);
    }

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(err) => return Result::Err(OptError(err.to_string()))
    };

    if matches.opt_str("cli").is_some() {
        
        let cli_config = CliConfig {
            name: match matches.opt_str("name") {
                Some(x) => x,
                None => return Result::Err(OptError("instance name '--name' is a mandatory field".into()))
            },
            vrid: match matches.opt_str("vrid") {
                Some(x) => x.parse::<u8>().unwrap(),
                None => return Result::Err(OptError("VRID '--vrid' is a mandatory field".into()))
            },
            interface_name: match matches.opt_str("iface") {
                Some(x) => x,
                None => return Result::Err(OptError("interface name '--iface' is a mandatory field".into()))
            },
            ip_addresses: matches.opt_strs("ip-address"),
            priority: match matches.opt_str("priority") {
                Some(x) => x.parse::<u8>().unwrap(),
                None => CliConfig::default().priority
            },
            advert_interval: match matches.opt_str("adv-interval") {
                Some(x) => x.parse::<u8>().unwrap(),
                None => CliConfig::default().advert_interval
            },
            preempt_mode: match matches.opt_str("preempt-mode") {
                Some (x) => x.parse::<bool>().unwrap(),
                None => CliConfig::default().preempt_mode
            }
        };

        match matches.opt_str("action") {
            Some(x) => {

                if ["teardown"].contains(&x.to_lowercase().as_str()){
                    virtual_address_action("delete", &cli_config.ip_addresses, &cli_config.interface_name);
                    std::process::exit(0);
                } else {
                    return Result::Err(OptError("--action has to be ether 'run' or 'teardown' . If none is specified, run will be default.".into()));
                }
            }
            None => {
                // should have 'run' as action by default if nothing is specified.  
            }
        }


        Ok(VrrpConfig::Cli(cli_config))
    } else {

        let filename = if matches.opt_str("file").is_some() { 
            matches.opt_str("file").unwrap() 
        } else {
            // let curr_path = current_dir().unwrap();

            let file_path = "/etc/failover/vrrp-config.json";
            let _ = fs::create_dir_all("/etc/failover/");
            if !Path::new(file_path).exists() {
                let mut file = File::create(file_path).unwrap();
                let _ = file.write_all(b"
                {
                    \"name\": \"VR_1\",
                    \"vrid\": 51,
                    \"interface_name\": \"wlo1\",
                    \"ip_addresses\": [
                        \"192.168.100.100/24\"
                    ],
                    \"priority\": 101,
                    \"advert_interval\": 1,
                    \"preempt_mode\": true
                }
                ");
            }
            file_path.to_string()
        };
        let file_config = match read_config_from_json_file(&filename) {
            Ok(config) => VrrpConfig::File(config),
            Err(err) => {
                log::error!("{err}");
                return  Result::Err(OptError(format!("Problem Parsing file {}", &filename)))
            }
        };

        match matches.opt_str("action") {
            Some (x) => {
                if ["setup", "teardown"].contains(&x.to_lowercase().as_str()){
                    let action = if x.to_lowercase().as_str() == "setup" { "add" } else { "delete" };
                    virtual_address_action(action, &file_config.ip_addresses(), &file_config.interface_name());
                    std::process::exit(0);
                } else if !["run"].contains(&x.to_lowercase().as_str()) {
                    return Result::Err(OptError("--action has to be ether 'setup', 'teardown' or 'run' ".into()));
                } else {
                    Ok(file_config)
                }
            }
            
            None => {
                Ok(file_config)
            }
        }
    } 
}

pub(crate) fn virtual_address_action(action: &str, addresses: &[String], interface_name: &str)
{
    for addr in addresses {
        let cmd_args = vec!["address", action, &addr, "dev", interface_name];
        let _ = Command::new("ip")
            .args(cmd_args)
            .output();
    }
}



fn read_config_from_json_file<P: AsRef<Path>>(path: P) -> Result<FileConfig, Box<dyn Error>> 
{
    log::info!("Reading from config file {:?}", path.as_ref().as_os_str());
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let u = serde_json::from_reader(reader)?;
    Ok(u)
}
