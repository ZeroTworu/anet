use clap::Parser;
use tokio::fs::read_to_string;
use yaml_rust2::{YamlLoader};

#[derive(Debug, Clone)]
pub struct Config {
    pub address: String,
    pub auth_phrase: String,
    pub cert_path: String,
}

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long, default_value = "./client.yaml")]
    cfg: String,
}

pub async fn load() -> anyhow::Result<Config> {
    let opt = Opt::parse();
    let yaml = read_to_string(&opt.cfg).await?;
    let settings = YamlLoader::load_from_str(&yaml)?;
    let client = &settings[0]["client"];
    let cfg = Config {
        address: client["address"].as_str().unwrap().to_string(),
        auth_phrase: client["auth_phrase"].as_str().unwrap().to_string(),
        cert_path: client["cert_path"].as_str().unwrap().to_string(),
    };
    Ok(cfg)
}