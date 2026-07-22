use std::env;
use std::ffi::OsStr;
use std::fs::{File, create_dir_all};
use std::io::{BufReader, Write};
use std::path::Path;

use clap::Parser;
use log::LevelFilter;
use log4rs::Config;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Root};
use serde::{Deserialize, Serialize};

use crate::ConfigResult;
use crate::error::{ConfigError, FailoverError};
use crate::general::random_vr_name;

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
}

#[derive(Debug, Clone)]
pub enum VrrpConfig {
    File(FileConfig),
    Cli(CliConfig),
}

impl VrrpConfig {
    // For name, if not specified, we will generate a random name
    //  (VR-{random-string}).
    pub fn name(&self) -> String {
        let name = match self {
            VrrpConfig::File(config) => Some(config.name.clone()),
            VrrpConfig::Cli(config) => config.name.clone(),
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

    // If interface name has not been specified, we will create one with
    //  format: ( fover-{random-string} ).
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
}

#[derive(Parser, Debug)]
#[command(name = "Version")]
#[command(about = "Runs the VRRP protocol", long_about = None)]
pub struct CliArgs {
    #[command(subcommand)]
    mode: Mode,
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
        #[arg(
            long,
            help = "The name of the Virtual Router Instance. e.g `VR_1`"
        )]
        name: Option<String>,

        #[arg(
            long,
            help = "Virtual Router ID of the Virtual router instance. "
        )]
        vrid: u8,

        #[arg(long, num_args=1.., help="The IP Address(es) of that will the Virtual router will be assigned.")]
        ip_address: Vec<String>,

        #[arg(
            long,
            help = "name of the network interface where the Virtual Router instance will be attached."
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

pub fn parse_cli_opts(
    args: CliArgs,
) -> Result<Vec<VrrpConfig>, FailoverError> {
    Ok(load_mode(args.mode)?)
}

fn load_mode(mode: Mode) -> ConfigResult<Vec<VrrpConfig>> {
    match mode {
        Mode::FileMode {
            filename,
            log_file_path,
        } => {
            configure_logging(log_file_path)?;
            // Generate file path if none is given.
            let fpath = match filename {
                None => {
                    // Get default file path and create new directory if it
                    //  does not exist.
                    match env::var("SNAP_COMMON") {
                        Ok(path) => path + "/vrrp-config.json",
                        Err(_) => "/etc/failover/vrrp-config.json".to_string(),
                    }
                }
                Some(f) => f,
            };

            log::info!("using config file {:#?}", fpath);
            // Create the config file (if it does not exist).
            if !Path::new(&fpath).exists() {
                let mut file = match File::create(&fpath) {
                    Ok(f) => f,
                    Err(_) => {
                        let dir_path = std::path::Path::new(&fpath)
                            .parent()
                            .ok_or_else(|| {
                                ConfigError::NoParentDirectory(fpath.clone())
                            })?;
                        let _ = create_dir_all(dir_path);
                        File::create(&fpath).map_err(|source| {
                            ConfigError::FileCreate {
                                path: fpath.clone(),
                                source,
                            }
                        })?
                    }
                };
                let _ = file.write_all(DEFAULT_JSON_CONFIG);
            }

            let mut configs: Vec<VrrpConfig> = vec![];
            for config_item in read_json_config(&fpath)? {
                configs.push(VrrpConfig::File(config_item));
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
            configure_logging(log_file_path)?;
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
            };
            Ok(vec![VrrpConfig::Cli(config)])
        }
    }
}

fn configure_logging(log_file_path: Option<String>) -> ConfigResult<()> {
    let log_console_stderr = ConsoleAppender::builder().build();
    let mut log_builder = Config::builder().appender(
        Appender::builder().build("stderr", Box::new(log_console_stderr)),
    );
    let mut root_builder = Root::builder();

    // set file path logging
    if let Some(file_path) = log_file_path {
        // Logging to log file.
        let log_file = FileAppender::builder().build(&file_path).map_err(
            |source| ConfigError::LogFileOpen {
                path: file_path.clone(),
                source,
            },
        )?;
        log_builder = log_builder
            .appender(Appender::builder().build("logfile", Box::new(log_file)));
        root_builder = root_builder.appender("logfile");
    }
    root_builder = root_builder.appender("stderr");

    let log_config = log_builder
        .build(root_builder.build(LevelFilter::Debug))
        .map_err(ConfigError::LoggingSetup)?;
    let _handler = log4rs::init_config(log_config);
    Ok(())
}

fn read_json_config<P: AsRef<Path>>(path: P) -> ConfigResult<Vec<FileConfig>> {
    let path_str = path.as_ref().as_os_str();
    let path_display = path.as_ref().display().to_string();

    let file =
        File::open(path_str).map_err(|source| ConfigError::FileOpen {
            path: path_display.clone(),
            source,
        })?;

    let reader = BufReader::new(file);
    let mut result: Vec<FileConfig> = Vec::new();

    let list_file_configs: Vec<FileConfig> =
        match serde_json::from_reader(reader) {
            Ok(config) => config,
            Err(_) => single_file_config(path_str, &path_display)?,
        };

    for file_config in list_file_configs {
        // check if the name of Virtual Router being entered is unique
        if let Some(_con) = result
            .iter()
            .find(|r: &&FileConfig| r.name == file_config.name)
        {
            continue;
        };

        // check if VRID of the Virtual Router being entered is unique
        if let Some(_con) = result
            .iter()
            .find(|r: &&FileConfig| r.vrid == file_config.vrid)
        {
            continue;
        };

        result.push(file_config);
    }

    Ok(result)
}

fn single_file_config(
    path: &OsStr,
    path_display: &str,
) -> ConfigResult<Vec<FileConfig>> {
    // Called only after the file failed to parse as a config array; re-reads
    // it as a single config object instead.
    let file =
        File::open(path).map_err(|source| ConfigError::FileOpen {
            path: path_display.to_string(),
            source,
        })?;

    let reader = BufReader::new(file);
    match serde_json::from_reader(reader) {
        Ok(config) => Ok(vec![config]),
        Err(source) => Err(ConfigError::Parse {
            path: path_display.to_string(),
            source,
        }),
    }
}
