use anet_common::config::StealthConfig;
use anet_common::quic_settings::QuicConfig;
use clap::Parser;
use log::warn;
use serde::Deserialize;
use std::process::exit;
use tokio::fs::read_to_string;

#[derive(Debug, Clone, Deserialize)]
pub struct CryptoConfig {
    pub quic_cert: String,
    pub quic_key: String,
    pub server_signing_key: String,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            quic_cert: "QUIC_CERT_PLACEHOLDER".to_string(),
            quic_key: "QUIC_KEY_PLACEHOLDER".to_string(),
            server_signing_key: "SERVER_SIGNING_KEY_PLACEHOLDER".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticationConfig {
    pub allowed_clients: Vec<String>,
    #[serde(default)]
    pub auth_servers: Vec<String>,
    #[serde(default)]
    pub auth_server_token: String,
}

impl Default for AuthenticationConfig {
    fn default() -> Self {
        Self {
            allowed_clients: vec![],
            auth_servers: vec![],
            auth_server_token: "default_secret".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ControlPlaneConfig {
    pub node_id: String,
    pub url: String,
    pub token: String,
    pub heartbeat_interval_seconds: u64,
}

impl Default for ControlPlaneConfig {
    fn default() -> Self {
        Self {
            node_id: String::new(),
            url: String::new(),
            token: String::new(),
            heartbeat_interval_seconds: 15,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    pub mask: String,
    pub net: String,
    pub gateway: String,
    pub self_ip: String,
    pub if_name: String,
    pub mtu: u16,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            mask: "255.255.255.0".to_string(),
            net: "10.0.0.0".to_string(),
            gateway: "10.0.0.1".to_string(),
            self_ip: "10.0.0.2".to_string(),
            if_name: "anet-server".to_string(),
            mtu: 1400,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerCoreConfig {
    pub quic_bind_to: String,
    pub ssh_bind_to: String,
    pub vnc_bind_to: String,
    pub websocket_bind_to: String,
    pub websocket_path: String,
    pub ahttp_bind_to: String,
    pub ahttp_path: String,
    pub ssh_host_key: String,
}

impl Default for ServerCoreConfig {
    fn default() -> Self {
        Self {
            quic_bind_to: "0.0.0.0:8443".to_string(),
            ssh_bind_to: "0.0.0.0:822".to_string(),
            vnc_bind_to: "0.0.0.0:5900".to_string(),
            websocket_bind_to: "0.0.0.0:8080".to_string(),
            websocket_path: "/socket".to_string(),
            ahttp_bind_to: "127.0.0.1:8081".to_string(),
            ahttp_path: "/api/v2/telemetry".to_string(),
            ssh_host_key: "/etc/ssh/ssh_host_rsa_key".to_string(),
        }
    }
}

// Новая структура для настройки HTTP-транспорта на стороне сервера
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AhttpServerConfig {
    pub handshake_path: String,
    pub auth_path: String,
    pub traffic_path: String,
    pub response_headers: String,
    pub max_header_bytes: usize,
    pub reassembly_queue_max_size: usize,
}

impl Default for AhttpServerConfig {
    fn default() -> Self {
        Self {
            handshake_path: "/handshake".to_string(),
            auth_path: "/auth".to_string(),
            traffic_path: "/traffic".to_string(),
            max_header_bytes: 16384,
            response_headers: "HTTP/1.1 200 OK\r\n\
                               Content-Type: video/mp4\r\n\
                               Cache-Control: no-cache, no-transform, private, must-revalidate\r\n\
                               Pragma: no-cache\r\n\
                               X-Accel-Buffering: no\r\n\
                               Content-Length: {}\r\n\
                               Connection: keep-alive\r\n\r\n".to_string(),
            reassembly_queue_max_size: 1024,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub server: ServerCoreConfig,
    #[serde(default)]
    pub quic_transport: QuicConfig,
    #[serde(default)]
    pub crypto: CryptoConfig,
    #[serde(default)]
    pub authentication: AuthenticationConfig,
    #[serde(default)]
    pub control_plane: ControlPlaneConfig,
    #[serde(default)]
    pub stealth: StealthConfig,
    #[serde(default)]
    pub ahttp: AhttpServerConfig,
}

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long, default_value = "./server.toml")]
    pub cfg: String,
}

pub async fn load() -> anyhow::Result<Config> {
    let opt = Opt::parse();
    let toml_str = read_to_string(&opt.cfg).await;
    match toml_str {
        Ok(toml_str) => {
            let cfg: Config = toml::from_str(&toml_str)?;
            Ok(cfg)
        }
        Err(_) => {
            warn!("\nCannot find server config file in {}, use '-c' or '--cfg'\n", opt.cfg);
            exit(-1)
        }
    }
}
