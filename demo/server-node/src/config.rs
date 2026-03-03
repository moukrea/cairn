//! Server node configuration from environment variables and CLI flags.
//!
//! All settings can be specified via environment variables (preferred for Docker)
//! or CLI flags. Environment variables take the form `CAIRN_<SETTING>`.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

/// Server node CLI arguments.
#[derive(Parser, Debug)]
#[command(name = "cairn-server", about = "cairn personal server node")]
pub struct ServerArgs {
    /// Subcommand: pair (generate pairing credentials)
    #[command(subcommand)]
    pub command: Option<ServerCommand>,

    /// Enable verbose/structured logging
    #[arg(long)]
    pub verbose: bool,
}

/// Server subcommands.
#[derive(clap::Subcommand, Debug)]
pub enum ServerCommand {
    /// Generate pairing credentials
    Pair {
        /// Generate a PIN code for pairing
        #[arg(long)]
        pin: bool,

        /// Generate a pairing link
        #[arg(long)]
        link: bool,

        /// Generate a QR code (ASCII art)
        #[arg(long)]
        qr: bool,
    },
}

/// Server configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Data directory for persistent storage
    pub data_dir: PathBuf,

    /// Whether the management API is enabled
    pub mgmt_enabled: bool,

    /// Management API bearer token
    pub mgmt_token: String,

    /// Management API bind address
    pub mgmt_bind: IpAddr,

    /// Management API port
    pub mgmt_port: u16,

    /// Pre-shared key for automatic pairing
    pub psk: Option<String>,

    /// Store-and-forward enabled
    pub forward_enabled: bool,

    /// Maximum forwarded messages per peer
    pub forward_max_per_peer: u32,

    /// Maximum message age
    pub forward_max_age: Duration,

    /// Maximum total storage in bytes
    pub forward_max_total: u64,

    /// Signaling server URLs
    pub signal_servers: Vec<String>,

    /// TURN relay server URLs
    pub turn_servers: Vec<String>,

    /// Relay capacity (max concurrent relay sessions)
    pub relay_capacity: u32,
}

impl ServerConfig {
    /// Load configuration from environment variables with defaults.
    pub fn from_env() -> Self {
        Self {
            data_dir: env_path("CAIRN_DATA_DIR", "/data"),
            mgmt_enabled: env_bool("CAIRN_MGMT_ENABLED", true),
            mgmt_token: env_string("CAIRN_MGMT_TOKEN", ""),
            mgmt_bind: env_ip("CAIRN_MGMT_BIND", IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            mgmt_port: env_u16("CAIRN_MGMT_PORT", 9090),
            psk: env_opt("CAIRN_PSK"),
            forward_enabled: env_bool("CAIRN_FORWARD_ENABLED", true),
            forward_max_per_peer: env_u32("CAIRN_FORWARD_MAX_PER_PEER", 10_000),
            forward_max_age: parse_duration_env("CAIRN_FORWARD_MAX_AGE", Duration::from_secs(7 * 86400)),
            forward_max_total: env_u64("CAIRN_FORWARD_MAX_TOTAL", 1_073_741_824), // 1GB
            signal_servers: env_csv("CAIRN_SIGNAL_SERVERS"),
            turn_servers: env_csv("CAIRN_TURN_SERVERS"),
            relay_capacity: env_u32("CAIRN_RELAY_CAPACITY", 100),
        }
    }

    /// Validate configuration, returning warnings.
    pub fn validate(&self) -> Vec<String> {
        let mut warnings = Vec::new();

        if self.mgmt_enabled && self.mgmt_token.is_empty() {
            warnings.push("CAIRN_MGMT_TOKEN is empty; management API will reject all requests".into());
        }

        if self.mgmt_enabled && !self.mgmt_bind.is_loopback() {
            warnings.push(format!(
                "Management API bound to non-loopback address {} without TLS. This is insecure.",
                self.mgmt_bind
            ));
        }

        if !self.data_dir.exists() {
            warnings.push(format!("Data directory {} does not exist; will be created", self.data_dir.display()));
        }

        warnings
    }
}

// ---------------------------------------------------------------------------
// Environment variable helpers
// ---------------------------------------------------------------------------

fn env_string(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(val) => matches!(val.to_lowercase().as_str(), "true" | "1" | "yes"),
        Err(_) => default,
    }
}

fn env_u16(key: &str, default: u16) -> u16 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_ip(key: &str, default: IpAddr) -> IpAddr {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_path(key: &str, default: &str) -> PathBuf {
    PathBuf::from(env_string(key, default))
}

fn env_csv(key: &str) -> Vec<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default()
}

/// Parse a duration from an environment variable. Supports suffixes: s, m, h, d.
fn parse_duration_env(key: &str, default: Duration) -> Duration {
    let val = match std::env::var(key) {
        Ok(v) => v,
        Err(_) => return default,
    };

    let val = val.trim();
    if val.is_empty() {
        return default;
    }

    let (num_str, multiplier) = if let Some(n) = val.strip_suffix('d') {
        (n, 86400u64)
    } else if let Some(n) = val.strip_suffix('h') {
        (n, 3600)
    } else if let Some(n) = val.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = val.strip_suffix('s') {
        (n, 1)
    } else {
        // Assume seconds
        (val, 1)
    };

    num_str
        .parse::<u64>()
        .map(|n| Duration::from_secs(n * multiplier))
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_seconds() {
        assert_eq!(parse_duration_env("__TEST_NONEXISTENT", Duration::from_secs(60)), Duration::from_secs(60));
    }

    #[test]
    fn config_defaults() {
        let cfg = ServerConfig::from_env();
        assert!(cfg.forward_enabled);
        assert_eq!(cfg.forward_max_per_peer, 10_000);
        assert_eq!(cfg.relay_capacity, 100);
    }

    #[test]
    fn config_validate_empty_token() {
        let mut cfg = ServerConfig::from_env();
        cfg.mgmt_enabled = true;
        cfg.mgmt_token = String::new();
        let warnings = cfg.validate();
        assert!(warnings.iter().any(|w| w.contains("CAIRN_MGMT_TOKEN")));
    }

    #[test]
    fn config_validate_non_loopback() {
        let mut cfg = ServerConfig::from_env();
        cfg.mgmt_enabled = true;
        cfg.mgmt_token = "test".into();
        cfg.mgmt_bind = IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
        let warnings = cfg.validate();
        assert!(warnings.iter().any(|w| w.contains("non-loopback")));
    }
}
