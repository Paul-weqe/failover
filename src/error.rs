//! Error types for the crate, grouped by where a failure originates rather
//! than lumped into one catch-all string. Four kinds:
//!
//! - [`ConfigError`]: CLI/JSON config loading, before any `VirtualRouter`
//!   exists.
//! - [`NetworkError`]: the OS/netlink/socket boundary -- interfaces,
//!   mac-vlans, listeners.
//! - [`PacketError`]: RFC 3768(/5798) packet decode and validation
//!   outcomes. These are normal, expected results of listening on a shared
//!   multicast group (a stray packet for another VRID, a bad checksum from
//!   a misbehaving neighbour) rather than faults in this program, so
//!   they're consumed and logged where they occur instead of propagated as
//!   a task-ending `Err`. They still implement `Error`/`Display` for
//!   uniformity with the other error kinds.
//! - [`FailoverError`]: aggregates the above for public API boundaries
//!   (`run`, `parse_cli_opts`) so a library caller only deals with one
//!   error type.
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("unable to open config file {path}: {source}")]
    FileOpen {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("unable to create config file {path}: {source}")]
    FileCreate {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("unable to determine parent directory of config path {0}")]
    NoParentDirectory(String),

    #[error("problem parsing config file {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("unable to open log file {path}: {source}")]
    LogFileOpen {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("unable to initialize logging: {0}")]
    LoggingSetup(#[source] log4rs::config::runtime::ConfigErrors),
}

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("unable to find interface with name {0}")]
    InterfaceNotFound(String),

    #[error("interface {0} has no IPv4 address configured")]
    NoIpv4Address(String),

    #[error("unable to open netlink connection: {0}")]
    NetlinkConnect(#[source] std::io::Error),

    #[error("problem fetching interface {name}: {source}")]
    InterfaceLookup {
        name: String,
        #[source]
        source: rtnetlink::Error,
    },

    #[error(
        "interface {0} already exists and is not a mac-vlan; refusing to remove it"
    )]
    NotAMacVlan(String),

    #[error("unable to remove stale mac-vlan {name}: {source}")]
    StaleMacVlanRemoval {
        name: String,
        #[source]
        source: rtnetlink::Error,
    },

    #[error("unable to create mac-vlan interface {name}: {source}")]
    MacVlanCreate {
        name: String,
        #[source]
        source: rtnetlink::Error,
    },

    #[error("unable to bind {kind} listening socket on {iface}: {source}")]
    SocketBind {
        kind: &'static str,
        iface: String,
        #[source]
        source: std::io::Error,
    },

    #[error("unable to install SIGTERM handler: {0}")]
    SignalHandler(#[source] std::io::Error),

    #[error("unable to lock virtual router state")]
    LockPoisoned,
}

#[derive(Debug, Error)]
pub enum PacketError {
    #[error("unsupported VRRP version {0}")]
    UnsupportedVersion(u8),

    #[error("packet is malformed or truncated")]
    Malformed,

    #[error("IP TTL {0} != 255")]
    BadTtl(u8),

    #[error("invalid VRRP checksum")]
    BadChecksum,

    #[error("VRID {received} does not match configured VRID {expected}")]
    VridMismatch { expected: u8, received: u8 },

    #[error(
        "advertisement interval {received} does not match configured interval {expected}"
    )]
    AdvertIntervalMismatch { expected: u8, received: u8 },

    #[error(
        "IP address count {received} does not match configured count {expected}"
    )]
    IpCountMismatch { expected: u8, received: u8 },

    #[error("IP address list does not match configured addresses")]
    IpListMismatch,
}

#[derive(Debug, Error)]
pub enum FailoverError {
    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error(transparent)]
    Network(#[from] NetworkError),
}
