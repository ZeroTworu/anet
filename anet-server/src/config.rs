use anet_common::quic_settings::QuicConfig;
use clap::Parser;
use log::warn;
use serde::Deserialize;
use std::process::exit;
use tokio::fs::read_to_string;

#[derive(Debug, Clone, Deserialize)]
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
pub struct ServerCoreConfig {
    pub auth_phrase: String,
    pub cert: String,
    pub key: String,
    pub bind_to: String,
    pub external_if: String,
    pub udp_port: u32,
}

impl Default for ServerCoreConfig {
    fn default() -> Self {
        Self {
            auth_phrase: "default_secret".to_string(),
            cert: "CERT_PLACEHOLDER".to_string(),
            key: "KEY_PLACEHOLDER".to_string(),
            bind_to: "0.0.0.0:8443".to_string(),
            external_if: "eth0".to_string(),
            udp_port: 8444,
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
    pub quic_transport: QuicConfig, // НОВАЯ СЕКЦИЯ
}

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long, default_value = "./server.toml")]
    cfg: String,
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
            warn!(
                "\n\
                Cannot find server config file in {}, use '-c' or '-cfg' \n\
                './anet-server -c /home/anet/anet/config.toml' for example,
                ",
                opt.cfg,
            );
            exit(-1)
        }
    }
}
