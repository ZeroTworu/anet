use anet_common::config::StealthConfig;
use anet_common::quic_settings::QuicConfig;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct MainConfig {
    pub address: String,
    pub tun_name: String,

    #[serde(default)]
    pub manual_routing: bool,

    #[serde(default)]
    pub route_for: Vec<String>,

    #[serde(default)]
    pub exclude_route_for: Vec<String>,

    #[serde(default)]
    pub dns_server_list: Vec<String>,
}

impl Default for MainConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:443".to_string(),
            tun_name: "anet-client".to_string(),
            route_for: vec![],
            exclude_route_for: vec![],
            dns_server_list: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            manual_routing: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientKeys {
    pub private_key: String,
    pub server_pub_key: String,
}

impl Default for ClientKeys {
    fn default() -> Self {
        Self {
            private_key: "".to_string(),
            server_pub_key: "".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct StatsConfig {
    pub enabled: bool,
    pub interval_minutes: u64,
}

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_minutes: 1,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Copy)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    Quic,
    Ssh,
    Auto, // Задел на будущее
}

impl Default for TransportMode {
    fn default() -> Self {
        TransportMode::Quic
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TransportConfig {
    #[serde(default)]
    pub mode: TransportMode,
    pub ssh_user: Option<String>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            mode: TransportMode::Quic,
            ssh_user: Some("hanyuu".to_string()),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CoreConfig {
    #[serde(default)]
    pub main: MainConfig,

    #[serde(default)]
    pub keys: ClientKeys,

    #[serde(default)]
    pub quic_transport: QuicConfig,

    #[serde(default)]
    pub stats: StatsConfig,

    #[serde(default)]
    pub stealth: StealthConfig,

    #[serde(default)]
    pub transport: TransportConfig,
}
