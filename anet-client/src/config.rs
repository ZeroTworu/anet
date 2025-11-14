use anet_common::quic_settings::QuicConfig;
use clap::Parser;
use log::warn;
use serde::Deserialize;
use std::process::exit;
use tokio::fs::read_to_string;

#[derive(Debug, Clone, Deserialize)]
pub struct MainConfig {
    pub address: String,
    pub tun_name: String,
}

impl Default for MainConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:443".to_string(),
            tun_name: "anet-client".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientKeys {
    pub private_key: String, // Base64-encoded Ed25519 private key
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
#[serde(default)]
pub struct StatsConfig {
    /// Включить или выключить периодический вывод статистики соединения.
    pub enabled: bool,
    /// Интервал вывода статистики в минутах.
    pub interval_minutes: u64,
}

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            enabled: false,      // По умолчанию выключено, чтобы не засорять логи
            interval_minutes: 1, // По умолчанию - раз в минуту
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub main: MainConfig,

    #[serde(default)]
    pub keys: ClientKeys,

    #[serde(default)]
    pub quic_transport: QuicConfig,

    #[serde(default)]
    pub stats: StatsConfig,
}

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long, default_value = "./client.toml")]
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
                Cannot find client config file in {}, use '-c' or '-cfg' \n\
                './anet-client -c /home/anet/anet/config.toml' for example,
                ",
                opt.cfg,
            );
            exit(-1)
        }
    }
}
