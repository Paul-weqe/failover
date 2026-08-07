use std::env;
use std::ffi::OsStr;
use std::fs::{File, create_dir_all};
use std::io::{BufReader, Write};
use std::path::Path;
use std::str::FromStr;

use clap::Parser;
use ipnet::IpNet;
use log::LevelFilter;
use log4rs::Config as Log4rsConfig;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Root};
use serde::{Deserialize, Serialize};

use crate::error::{ConfigError, FailoverError};
use crate::general::random_vr_name;
use crate::{ConfigResult, VrrpVersion};

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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    #[serde(default = "random_vr_name")]
    pub(crate) name: String,
    pub(crate) vrid: u8,
    pub(crate) ip_addresses: Vec<String>,
    pub(crate) interface_name: String,

    #[serde(default = "default_priority")]
    pub(crate) priority: u8,
    #[serde(default = "default_advert_int")]
    pub(crate) advert_interval: u8,
    #[serde(default = "default_preempt_mode")]
    pub(crate) preempt_mode: bool,
    #[serde(default)]
    pub(crate) version: VrrpVersion,
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
            long = "vrrp-version",
            default_value = "3",
            help = "VRRP protocol version to run for this instance: 2 or 3. Defaults to 3."
        )]
        vrrp_version: u8,

        #[arg(
            long,
            default_value = None,
            help = "Path log file you want to use"
        )]
        log_file_path: Option<String>,
    },
}

pub fn parse_cli_opts(args: CliArgs) -> Result<Vec<Config>, FailoverError> {
    Ok(load_mode(args.mode)?)
}

fn load_mode(mode: Mode) -> ConfigResult<Vec<Config>> {
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

            let mut configs: Vec<Config> = vec![];
            for config_item in read_json_config(&fpath)? {
                configs.push(config_item);
            }
            validate_configs(&configs)?;
            Ok(configs)
        }
        Mode::CliMode {
            name,
            vrid,
            ip_address,
            interface_name,
            priority,
            advert_interval,
            preempt_mode,
            vrrp_version,
            log_file_path,
        } => {
            configure_logging(log_file_path)?;
            let name = name.unwrap_or(random_vr_name());
            let version = VrrpVersion::try_from(vrrp_version)
                .map_err(|_| ConfigError::InvalidVersion(vrrp_version))?;

            let config = Config {
                name,
                vrid,
                ip_addresses: ip_address,
                interface_name,
                priority,
                advert_interval,
                preempt_mode,
                version,
            };
            let configs = vec![config];
            validate_configs(&configs)?;
            Ok(configs)
        }
    }
}

/// Cross-instance and per-instance checks that deserialization alone can't
/// express: name/vrid uniqueness per version, no IPv6 on v2, and
/// advert_interval capped at 40s for v3 (12-bit centisecond wire field).
fn validate_configs(configs: &[Config]) -> ConfigResult<()> {
    for (i, cfg) in configs.iter().enumerate() {
        let version = cfg.version;

        if version == VrrpVersion::V3 {
            let interval = cfg.advert_interval;
            if interval > 40 {
                return Err(ConfigError::AdvertIntervalTooLarge {
                    name: cfg.name.clone(),
                    interval,
                });
            }
        }

        match version {
            VrrpVersion::V2 => {
                for addr in &cfg.ip_addresses {
                    if matches!(IpNet::from_str(&addr), Ok(IpNet::V6(_))) {
                        return Err(ConfigError::Ipv6NotSupportedInV2 {
                            name: cfg.name.clone(),
                            address: addr.to_string(),
                        });
                    }
                    // Check for if the IPV4 entered is valid.
                    if !matches!(IpNet::from_str(&addr), Ok(IpNet::V4(_))) {
                        return Err(ConfigError::IPFormatting(
                            addr.to_string(),
                        ));
                    }
                }
            }
            VrrpVersion::V3 => {
                for addr in &cfg.ip_addresses {
                    if !matches!(IpNet::from_str(addr), Ok(IpNet::V4(_)))
                        && !matches!(IpNet::from_str(addr), Ok(IpNet::V6(_)))
                    {
                        return Err(ConfigError::IPFormatting(
                            addr.to_string(),
                        ));
                    }
                }
            }
        }

        for other in configs.iter().skip(i + 1) {
            if other.version != version {
                continue;
            }
            if other.name == cfg.name {
                return Err(ConfigError::DuplicateName {
                    name: cfg.name.clone(),
                    version: version.as_u8(),
                });
            }
            if other.vrid == cfg.vrid {
                return Err(ConfigError::DuplicateVrid {
                    vrid: cfg.vrid,
                    version: version.as_u8(),
                });
            }
        }
    }
    Ok(())
}

fn configure_logging(log_file_path: Option<String>) -> ConfigResult<()> {
    let log_console_stderr = ConsoleAppender::builder().build();
    let mut log_builder = Log4rsConfig::builder().appender(
        Appender::builder().build("stderr", Box::new(log_console_stderr)),
    );
    let mut root_builder = Root::builder();

    // set file path logging
    if let Some(file_path) = log_file_path {
        // Logging to log file.
        let log_file =
            FileAppender::builder()
                .build(&file_path)
                .map_err(|source| ConfigError::LogFileOpen {
                    path: file_path.clone(),
                    source,
                })?;
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

fn read_json_config<P: AsRef<Path>>(path: P) -> ConfigResult<Vec<Config>> {
    let path_str = path.as_ref().as_os_str();
    let path_display = path.as_ref().display().to_string();

    let file =
        File::open(path_str).map_err(|source| ConfigError::FileOpen {
            path: path_display.clone(),
            source,
        })?;

    let reader = BufReader::new(file);

    let list_file_configs: Vec<Config> = match serde_json::from_reader(reader) {
        Ok(config) => config,
        Err(_) => single_file_config(path_str, &path_display)?,
    };

    Ok(list_file_configs)
}

fn single_file_config(
    path: &OsStr,
    path_display: &str,
) -> ConfigResult<Vec<Config>> {
    // Called only after the file failed to parse as a config array; re-reads
    // it as a single config object instead.
    let file = File::open(path).map_err(|source| ConfigError::FileOpen {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(name: &str, vrid: u8, version: VrrpVersion) -> Config {
        Config {
            vrid,
            ip_addresses: vec!["192.168.100.10/24".to_string()],
            interface_name: "eth0".to_string(),
            name: name.to_string(),
            priority: 100,
            advert_interval: 1,
            preempt_mode: true,
            version,
        }
    }

    #[test]
    fn version_defaults_to_v3_when_omitted() {
        let json = r#"{
            "vrid": 51,
            "ip_addresses": ["192.168.100.10/24"],
            "interface_name": "eth0"
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.version, VrrpVersion::V3);
    }

    #[test]
    fn version_rejects_values_other_than_2_or_3() {
        let json = r#"{
            "vrid": 51,
            "ip_addresses": ["192.168.100.10/24"],
            "interface_name": "eth0",
            "version": 4
        }"#;
        assert!(serde_json::from_str::<Config>(json).is_err());
    }

    #[test]
    fn same_name_and_vrid_allowed_across_different_versions() {
        let configs = vec![
            sample("VR_1", 51, VrrpVersion::V2),
            sample("VR_1", 51, VrrpVersion::V3),
        ];
        assert!(validate_configs(&configs).is_ok());
    }

    #[test]
    fn duplicate_name_same_version_is_a_hard_error() {
        let configs = vec![
            sample("VR_1", 51, VrrpVersion::V3),
            sample("VR_1", 52, VrrpVersion::V3),
        ];
        assert!(matches!(
            validate_configs(&configs),
            Err(ConfigError::DuplicateName { .. })
        ));
    }

    #[test]
    fn duplicate_vrid_same_version_is_a_hard_error() {
        let configs = vec![
            sample("VR_1", 51, VrrpVersion::V3),
            sample("VR_2", 51, VrrpVersion::V3),
        ];
        assert!(matches!(
            validate_configs(&configs),
            Err(ConfigError::DuplicateVrid { .. })
        ));
    }

    #[test]
    fn ipv6_address_on_v2_instance_is_rejected() {
        let mut cfg = sample("VR_1", 51, VrrpVersion::V2);
        cfg.ip_addresses.push("fd00::1/64".to_string());
        assert!(matches!(
            validate_configs(&[cfg]),
            Err(ConfigError::Ipv6NotSupportedInV2 { .. })
        ));
    }

    #[test]
    fn ipv6_address_on_v3_instance_is_allowed() {
        let mut cfg = sample("VR_1", 51, VrrpVersion::V3);

        cfg.ip_addresses.push("fd00::1/64".to_string());
        assert!(validate_configs(&[cfg]).is_ok());
    }

    #[test]
    fn advert_interval_over_40s_rejected_for_v3() {
        let mut cfg = sample("VR_1", 51, VrrpVersion::V3);
        cfg.advert_interval = 41;

        assert!(matches!(
            validate_configs(&[cfg]),
            Err(ConfigError::AdvertIntervalTooLarge { .. })
        ));
    }

    #[test]
    fn advert_interval_over_40s_allowed_for_v2() {
        let mut cfg = sample("VR_1", 51, VrrpVersion::V2);
        cfg.advert_interval = 200;

        assert!(validate_configs(&[cfg]).is_ok());
    }
}
