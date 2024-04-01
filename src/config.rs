use serde::{Deserialize, Serialize};

// for reading JSON config file
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileConfig {
    pub name: String,
    pub vrid: u8,
    pub ip_addresses: Vec<String>,
    pub interface_name: String,

    #[serde(default = "default_priority")]
    pub priority: u8,
    #[serde(default = "default_advert_int")]
    pub advert_interval: u8,
    #[serde(default = "default_preempt_mode")]
    pub preempt_mode: bool
}

#[derive(Debug, Clone)]
pub struct CliConfig {
    pub name: String,
    pub vrid: u8,
    pub ip_addresses: Vec<String>,
    pub interface_name: String,

    pub priority: u8,
    pub advert_interval: u8,
    pub preempt_mode: bool
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            name: String::default(),
            vrid: u8::default(),
            ip_addresses: vec![],
            interface_name: String::default(),
            priority: default_priority(),
            advert_interval: default_advert_int(),
            preempt_mode: default_preempt_mode()
        }
    }
}

fn default_priority() -> u8 { 100 }
fn default_advert_int() -> u8 { 1 }
fn default_preempt_mode() -> bool { true }


#[derive(Debug, Clone)]
pub enum VrrpConfig {
    File(FileConfig),
    Cli(CliConfig)
}

// impl BaseConfig for 
impl VrrpConfig {
    pub fn name(&self) -> String {
        match self { 
            VrrpConfig::File(config) => config.name.clone(),
            VrrpConfig::Cli(config) => config.name.clone()
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

    pub fn interface_name(&self) -> String {
        match self {
            VrrpConfig::File(config) => config.interface_name.clone(),
            VrrpConfig::Cli(config) => config.interface_name.clone()
        }
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
