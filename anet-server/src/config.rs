use clap::Parser;
use tokio::fs::read_to_string;
use yaml_rust2::YamlLoader;

#[derive(Debug, Clone)]
pub struct Config {
    pub mask: String,
    pub net: String,
    pub gateway: String,
    pub self_ip: String,
    pub auth_phrase: String,
    pub cert_path: String,
    pub key_path: String,
    pub bind_to: String,
    pub external_if: String,
}

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long, default_value = "./server.yaml")]
    cfg: String,
}

pub async fn load() -> anyhow::Result<Config> {
    let opt = Opt::parse();
    let yaml = read_to_string(&opt.cfg).await?;
    let settings = YamlLoader::load_from_str(&yaml)?;
    let server = &settings[0]["server"];
    let network = &settings[0]["network"];
    let cfg = Config{
        mask: network["mask"].as_str().unwrap().to_string(),
        net: network["net"].as_str().unwrap().to_string(),
        gateway: network["gateway"].as_str().unwrap().to_string(),
        self_ip: network["self_ip"].as_str().unwrap().to_string(),
        auth_phrase: server["auth_phrase"].as_str().unwrap().to_string(),
        cert_path: server["cert_path"].as_str().unwrap().to_string(),
        key_path: server["key_path"].as_str().unwrap().to_string(),
        bind_to: server["bind_to"].as_str().unwrap().to_string(),
        external_if: server["external_if"].as_str().unwrap().to_string(),
    };
    Ok(cfg)
}