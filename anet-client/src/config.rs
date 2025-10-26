use clap::Parser;
use serde::Deserialize;
use tokio::fs::read_to_string;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub address: String,
    pub auth_phrase: String,
    pub server_cert: String,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
}

fn default_batch_size() -> usize {
    8
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
