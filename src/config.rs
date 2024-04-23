use std::{env, fs::{self, File}, io::{BufReader, Write}, path::Path};
use getopts::Options;
use serde::{Deserialize, Serialize};
use crate::{error::OptError, general::random_string};


fn default_priority() -> u8 { 100 }
fn default_advert_int() -> u8 { 1 }
fn default_preempt_mode() -> bool { true }
fn default_action() -> Action { Action::Run }

// for reading JSON config file
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileConfig {
    pub name: Option<String>,
    pub vrid: u8,
    pub ip_addresses: Vec<String>,
    pub interface_name: Option<String>,

    #[serde(default = "default_priority")]
    pub priority: u8,
    #[serde(default = "default_advert_int")]
    pub advert_interval: u8,
    #[serde(default = "default_preempt_mode")]
    pub preempt_mode: bool,
    #[serde(default = "default_action")]
    pub action: Action
}



#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    Run, 
    Teardown
}

#[derive(Debug, Clone)]
pub struct CliConfig {
    pub name: Option<String>,
    pub vrid: u8,
    pub ip_addresses: Vec<String>,
    pub interface_name: Option<String>,

    pub priority: u8,
    pub advert_interval: u8,
    pub preempt_mode: bool,
    pub action: Action
}


#[derive(Debug, Clone)]
pub enum VrrpConfig {
    File(FileConfig),
    Cli(CliConfig)
}

impl VrrpConfig {

    // for name, if not specified, we will generate a random name (VR-{random-string})
    pub fn name(&self) -> String {
        let name = match self { 
            VrrpConfig::File(config) => config.name.clone(),
            VrrpConfig::Cli(config) => config.name.clone()
        };
        match name {
            Some(n) => n,
            None => format!("VR-{}", random_string(10))
        }   
    }
    
    pub fn vrid(&self) -> u8 {
        match self {
            VrrpConfig::File(config) => config.vrid,
            VrrpConfig::Cli(config) => config.vrid
        }
    }

    pub fn ip_addresses(&self) -> Vec<String> {
        match self {
            VrrpConfig::File(config) => config.ip_addresses.clone(),
            VrrpConfig::Cli(config) => config.ip_addresses.clone()
        }
    }

    // if interface name has not been specified, we will create one with format: ( fover-{random-string} )
    pub fn interface_name(&self) -> String {
        let iname = match self {
            VrrpConfig::File(config) => config.interface_name.clone(),
            VrrpConfig::Cli(config) => config.interface_name.clone()
        };
        iname.unwrap()
    }

    pub fn priority(&self) -> u8 {
        match self {
            VrrpConfig::File(config) => config.priority,
            VrrpConfig::Cli(config) => config.priority
        }
    }

    pub fn advert_interval(&self) -> u8 {
        match self {
            VrrpConfig::File(config) => config.advert_interval,
            VrrpConfig::Cli(config) => config.advert_interval
        }
    }

    pub fn preempt_mode(&self) -> bool {
        match self {
            VrrpConfig::File(config) => config.preempt_mode,
            VrrpConfig::Cli(config) => config.preempt_mode
        }
    }
}




const DEFAULT_JSON_CONFIG: &[u8; 201] = b"
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
";


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
            name: matches.opt_str("name"),
            vrid: match matches.opt_str("vrid") {
                Some(x) => x.parse::<u8>().unwrap(),
                None => return Result::Err(OptError("VRID '--vrid' is a mandatory field".into()))
            },
            interface_name: matches.opt_str("iface"),
            ip_addresses: matches.opt_strs("ip-address"),
            priority: match matches.opt_str("priority") {
                Some(x) => x.parse::<u8>().unwrap(),
                None => default_priority()
            },
            advert_interval: match matches.opt_str("adv-interval") {
                Some(x) => x.parse::<u8>().unwrap(),
                None => default_advert_int()
            },
            preempt_mode: match matches.opt_str("preempt-mode") {
                Some (x) => x.parse::<bool>().unwrap(),
                None => default_preempt_mode()
            },
            action: match matches.opt_str("action") {
                Some(x) => {
                    if x.to_lowercase().as_str() == "teardown" {
                        Action::Teardown
                    } else if x.to_lowercase().as_str() == "run" {
                        Action::Run
                    } else {
                        log::warn!("{x} is not a valid action, therefore resulted to default 'run' action");
                        Action::Run
                    }
                },
                None => Action::Run
            }
        };

        // match matches.opt_str("action") {
        //     Some(x) => {
        //         if ["teardown"].contains(&x.to_lowercase().as_str()){
        //             virtual_address_action("delete", &cli_config.ip_addresses, &cli_config.interface_name);
        //             std::process::exit(0);
        //         } else {
        //             return Result::Err(OptError("--action has to be ether 'run' or 'teardown' . If none is specified, run will be default.".into()));
        //         }
        //     }
        //     None => {
        //         // should have 'run' as action by default if nothing is specified.  
        //     }
        // }


        Ok(VrrpConfig::Cli(cli_config))
    } else {

        let filename = if matches.opt_str("file").is_some() { 
            matches.opt_str("file").unwrap() 
        } else {

            // if app is running via snap, the SNAP_COMMON environment 
            // variable will be used as the config directory
            let directory = match env::var("SNAP_COMMON") {
                Ok(path) => path + "/",
                Err(_) => {
                    let _ = fs::create_dir_all("/etc/failover/");
                    "/etc/failover/".to_string()
                }
            };

            let file_path = &format!("{}vrrp-config.json", directory);

            if !Path::new(file_path).exists() {
                let mut file = File::create(file_path).unwrap();
                let _ = file.write_all(DEFAULT_JSON_CONFIG);
            }
            file_path.to_string()
        };
        let file_config = match read_config_from_json_file(&filename) {
            Ok(mut config) => {
                config.action = match matches.opt_str("action") {

                    Some (x) => {
                        let act = x.to_lowercase(); 
                        if act == "teardown" {
                            Action::Teardown
                        } else if act == "run" {
                            Action::Run
                        } else {
                            log::warn!("{x} is not a valid action, therefore resulted to default 'run' action");
                            Action::Run
                        }
                    }
                    
                    None => {
                        Action::Run
                    }
                };
                VrrpConfig::File(config)
            },
            Err(err) => {
                log::error!("{err}");
                return  Result::Err(OptError(format!("Problem Parsing file {}", &filename)))
            }
        };
        Ok(file_config)

    } 
}


fn read_config_from_json_file<P: AsRef<Path>>(path: P) -> Result<FileConfig, Box<dyn std::error::Error>> 
{
    log::info!("Reading from config file {:?}", path.as_ref().as_os_str());
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let u = serde_json::from_reader(reader)?;
    Ok(u)
}
