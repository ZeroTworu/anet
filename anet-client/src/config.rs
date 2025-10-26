use clap::Parser;
use tokio::fs::read_to_string;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct WindowsTcpConfig {
    pub congestion_algorithm: String,
    pub enable_tcp_tuning: bool,
}

impl Default for WindowsTcpConfig {
    fn default() -> Self {
        Self {
            congestion_algorithm: "ctcp".to_string(),
            enable_tcp_tuning: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UnixTcpConfig {
    pub preferred_algorithm: String,
    pub fallback_algorithm: String,
    pub enable_tcp_tuning: bool,
}

impl Default for UnixTcpConfig {
    fn default() -> Self {
        Self {
            preferred_algorithm: "bbr".to_string(),
            fallback_algorithm: "cubic".to_string(),
            enable_tcp_tuning: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub address: String,
    pub auth_phrase: String,
    pub server_cert: String,
    #[serde(default)]
    pub windows_tcp: WindowsTcpConfig,
    #[serde(default)]
    pub unix_tcp: UnixTcpConfig,
}


#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long, default_value = "./client.toml")]
    cfg: String,
}

pub async fn load() -> anyhow::Result<Config> {
    let opt = Opt::parse();
    let toml_str = read_to_string(&opt.cfg).await?;
    let cfg: Config = toml::from_str(&toml_str)?;
    Ok(cfg)
}
