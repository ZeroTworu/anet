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
    pub auth_phrase: String,
    pub server_cert: String,
}

impl Default for MainConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:443".to_string(),
            tun_name: "anet-client".to_string(),
            auth_phrase: "test".to_string(),
            server_cert: "test".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub main: MainConfig,

    #[serde(default)]
    pub quic_transport: QuicConfig,
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
