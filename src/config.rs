use crate::{error::OptError, general::random_vr_name, OptResult};
use clap::Parser;
use ipnet::Ipv4Net;
use log::LevelFilter;
use log4rs::{
    append::{console::ConsoleAppender, file::FileAppender},
    config::{Appender, Root},
    Config,
};
use serde::{Deserialize, Serialize};
use std::{
    env,
    ffi::OsStr,
    fs::{create_dir_all, File},
    io::{BufReader, Write},
    path::Path,
};

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

fn default_priority() -> u8 {
    100
}
fn default_advert_int() -> u8 {
    1
}
fn default_preempt_mode() -> bool {
    true
}
fn default_action() -> Action {
    Action::Run
}

// for reading JSON config file
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileConfig {
    pub vrid: u8,
    pub ip_addresses: Vec<String>,
    pub interface_name: String,

    #[serde(default = "random_vr_name")]
    pub name: String,
    #[serde(default = "default_priority")]
    pub priority: u8,
    #[serde(default = "default_advert_int")]
    pub advert_interval: u8,
    #[serde(default = "default_preempt_mode")]
    pub preempt_mode: bool,
    #[serde(default = "default_action")]
    pub action: Action,
}

#[derive(Debug, Clone)]
pub struct CliConfig {
    pub name: Option<String>,
    pub vrid: u8,
    pub ip_addresses: Vec<String>,
    pub interface_name: String,

    pub priority: u8,
    pub advert_interval: u8,
    pub preempt_mode: bool,
    pub action: Action,
}

#[derive(Debug, Clone)]
pub struct BaseConfig {
    pub name: Option<String>,
    pub vrid: u8,
    pub ip_addresses: Vec<Ipv4Net>,
    pub interface_name: String,
    pub priority: u8,
    pub advert_interval: u8,
    pub preempt_mode: bool,
    pub action: Action,
}

// pub struct

#[derive(Debug, Clone)]
pub enum VrrpConfig {
    File(FileConfig),
    Cli(CliConfig),
}

impl VrrpConfig {
    // for name, if not specified, we will generate a random name (VR-{random-string})
    pub fn name(&self) -> String {
        let name = match self {
            VrrpConfig::File(config) => Some(config.name.clone()),
            VrrpConfig::Cli(config) => config.name.clone(),
            // VrrpConfig::Base(config) => config.name.unwrap()
        };
        match name {
            Some(n) => n,
            None => random_vr_name(),
        }
    }

    pub fn vrid(&self) -> u8 {
        match self {
            VrrpConfig::File(config) => config.vrid,
            VrrpConfig::Cli(config) => config.vrid,
        }
    }

    pub fn ip_addresses(&self) -> Vec<String> {
        match self {
            VrrpConfig::File(config) => config.ip_addresses.clone(),
            VrrpConfig::Cli(config) => config.ip_addresses.clone(),
        }
    }

    // if interface name has not been specified, we will create one with format: ( fover-{random-string} )
    pub fn interface_name(&self) -> String {
        match self {
            VrrpConfig::File(config) => config.interface_name.clone(),
            VrrpConfig::Cli(config) => config.interface_name.clone(),
        }
    }

    pub fn priority(&self) -> u8 {
        match self {
            VrrpConfig::File(config) => config.priority,
            VrrpConfig::Cli(config) => config.priority,
        }
    }

    pub fn advert_interval(&self) -> u8 {
        match self {
            VrrpConfig::File(config) => config.advert_interval,
            VrrpConfig::Cli(config) => config.advert_interval,
        }
    }

    pub fn preempt_mode(&self) -> bool {
        match self {
            VrrpConfig::File(config) => config.preempt_mode,
            VrrpConfig::Cli(config) => config.preempt_mode,
        }
    }

    pub fn action(&self) -> Action {
        match self {
            VrrpConfig::File(config) => config.action.clone(),
            VrrpConfig::Cli(config) => config.action.clone(),
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "Version")]
#[command(about = "Runs the VRRP protocol", long_about = None)]
pub struct CliArgs2 {
    #[command(
        subcommand,
        help = "`run` for starting the VRRP instances and `teardown` for stopping them"
    )]
    cfg: Cfg,
}

#[derive(Parser, Debug)]
enum Cfg {
    Run {
        #[command(subcommand)]
        mode: Mode,
    },
    Teardown {
        #[command(subcommand)]
        mode: Mode,
    },
}

#[derive(Parser, Debug)]
enum Mode {
    FileMode {
        #[arg(long, help = "path to the we will get our configs from")]
        filename: Option<String>,

        #[arg(
            long,
            default_value = None,
            help = "Path log file you want to use"
        )]
        log_file_path: Option<String>,
    },
    CliMode {
        #[arg(long, help = "The name of the Virtual Router Instance. e.g `VR_1`")]
        name: Option<String>,

        #[arg(long, help = "Virtual Router ID of the Virtual router instance. ")]
        vrid: u8,

        #[arg(long, num_args=1.., help="The IP Address(es) of that will the Virtual router will be assigned. Can be more than one. ")]
        ip_address: Vec<String>,

        #[arg(
            long,
            help = "name of the network interface where the Virtual Router instance will be attached. "
        )]
        interface_name: String,

        #[arg(
            long,
            default_value = "100",
            help = "The priority of this instance of the Virtual Router, maximum of 255. The higher priority is chosen to be MASTER."
        )]
        priority: u8,

        #[arg(
            long,
            default_value = "1",
            help = "Interval(in seconds) between which the priodic advert updates are sent (when MASTER). Also used to calculate MasterDown interval when in BACKUP state."
        )]
        advert_interval: u8,

        #[arg(
            long,
            action,
            help = "(highly advised to be true). When true, the higher priority will always preempt the lower priority."
        )]
        preempt_mode: bool,

        #[arg(
            long,
            default_value = None,
            help = "Path log file you want to use"
        )]
        log_file_path: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Action {
    Run,
    Teardown,
}

pub fn parse_cli_opts(args: CliArgs2) -> OptResult<Vec<VrrpConfig>> {
    match args.cfg {
        Cfg::Run { mode } => load_mode(mode, Action::Run),
        Cfg::Teardown { mode } => load_mode(mode, Action::Teardown),
    }
}

fn load_mode(mode: Mode, action: Action) -> OptResult<Vec<VrrpConfig>> {
    match mode {
        Mode::FileMode {
            filename,
            log_file_path,
        } => {
            configure_logging(log_file_path);
            // generate file path if none is given
            let fpath = match filename {
                None => {
                    // get default file path and create new directory if it does not exist
                    match env::var("SNAP_COMMON") {
                        Ok(path) => path + "/vrrp-config.json",
                        Err(_) => "/etc/failover/vrrp-config.json".to_string(),
                    }
                }
                Some(f) => f,
            };

            log::info!("using config file {:#?}", fpath);
            // create the config file (if it does not exist)
            if !Path::new(&fpath).exists() {
                let mut file = match File::create(&fpath) {
                    Ok(f) => f,
                    Err(_) => {
                        let dir_path = match std::path::Path::new(&fpath).parent() {
                            Some(dir) => dir,
                            None => {
                                return Err(OptError(String::from("unable to find config path")))
                            }
                        };
                        let _ = create_dir_all(dir_path);
                        File::create(&fpath).unwrap()
                    }
                };
                let _ = file.write_all(DEFAULT_JSON_CONFIG);
            }

            let mut configs: Vec<VrrpConfig> = vec![];
            match read_json_config(&fpath) {
                Ok(vec_config) => {
                    for mut config_item in vec_config {
                        config_item.action = action.clone();
                        configs.push(VrrpConfig::File(config_item));
                    }
                }
                Err(_) => return Result::Err(OptError(format!("Problem parsing file {}", &fpath))),
            }
            Ok(configs)
        }
        Mode::CliMode {
            mut name,
            vrid,
            ip_address,
            interface_name,
            priority,
            advert_interval,
            preempt_mode,
            log_file_path,
        } => {
            configure_logging(log_file_path);
            if name.is_none() {
                name = Some(random_vr_name());
            }

            let config = CliConfig {
                name,
                vrid,
                ip_addresses: ip_address,
                interface_name,
                priority,
                advert_interval,
                preempt_mode,
                action,
            };
            Ok(vec![VrrpConfig::Cli(config)])
        }
    }
}

fn configure_logging(log_file_path: Option<String>) {
    let log_console_stderr = ConsoleAppender::builder().build();
    let mut log_builder = Config::builder()
        .appender(Appender::builder().build("stderr", Box::new(log_console_stderr)));
    let mut root_builder = Root::builder();

    // set file path logging
    if let Some(file_path) = log_file_path {
        // Logging to log file.
        let log_file = FileAppender::builder()
            // Pattern: https://docs.rs/log4rs/*/log4rs/encode/pattern/index.html
            //.encoder(Box::new(PatternEncoder::new("{l} - {m}\n")))
            .build(file_path)
            .unwrap();
        log_builder =
            log_builder.appender(Appender::builder().build("logfile", Box::new(log_file)));
        root_builder = root_builder.appender("logfile");
    }
    root_builder = root_builder.appender("stderr"); // .appender("stdout");
                                                    //.build(LevelFilter::Trace);

    let log_config = log_builder
        .build(root_builder.build(LevelFilter::Trace))
        .unwrap();
    let _handler = log4rs::init_config(log_config);
}

fn read_json_config<P: AsRef<Path>>(path: P) -> OptResult<Vec<FileConfig>> {
    let path_str = path.as_ref().as_os_str();

    //log::info!("Reading from config file {:?}", path_str);
    let file = match File::open(path_str) {
        Ok(f) => f,
        Err(_) => {
            //log::error!("Unable to open file {:?}", path.as_ref().as_os_str());
            return Err(OptError(format!(
                "unable to open file `{:?}`",
                path.as_ref().as_os_str()
            )));
        }
    };

    let reader = BufReader::new(file);
    let mut result: Vec<FileConfig> = Vec::new();

    let list_file_configs: Vec<FileConfig> = match serde_json::from_reader(reader) {
        Ok(config) => config,
        Err(_) => match single_file_config(path_str) {
            Ok(conf) => conf,
            Err(err) => return Err(err),
        },
    };

    for file_config in list_file_configs {
        // check if the name of Virtual Router being entered is unique
        if let Some(_con) = result
            .iter()
            .find(|r: &&FileConfig| r.name == file_config.name)
        {
            //log::warn!("Configs for Virtual Router with name {:?} already exist. Will be ignored", con.name);
            continue;
        };

        // check if VRID of the Virtual Router being entered is unique
        if let Some(_con) = result
            .iter()
            .find(|r: &&FileConfig| r.vrid == file_config.vrid)
        {
            //log::warn!("Configs for Virtual Router with VRID {:?} already exist. Will be ignored", con.vrid);
            continue;
        };

        result.push(file_config);
    }

    Ok(result)
}

fn single_file_config(path: &OsStr) -> OptResult<Vec<FileConfig>> {
    // this single file config method is called only after
    // the normal config fails, which it does after reading the file.
    // thus unwrap()'ing here is safe.
    let file = File::open(path).unwrap();

    let reader = BufReader::new(file);
    let _: FileConfig = match serde_json::from_reader(reader) {
        Ok(config) => return Ok(vec![config]),
        Err(_) => {
            //log::error!("Wrong configurations for file {:?}", path);
            return Err(OptError(format!(
                "Wrong config formatting in file {:?}",
                path
            )));
        }
    };
}
