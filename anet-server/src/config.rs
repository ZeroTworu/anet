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
    pub server_signing_key: String, // Приватный ключ сервера для подписи
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

// Новая структура для настроек статистики
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
pub struct AuthenticationConfig {
    pub allowed_clients: Vec<String>, // Список разрешенных fingerprint'ов клиентов
}

impl Default for AuthenticationConfig {
    fn default() -> Self {
        Self {
            allowed_clients: vec![],
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
    pub auth_phrase: String,
    pub bind_to: String,
    pub external_if: String,
}

impl Default for ServerCoreConfig {
    fn default() -> Self {
        Self {
            auth_phrase: "default_secret".to_string(),
            bind_to: "0.0.0.0:8443".to_string(),
            external_if: "eth0".to_string(),
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
