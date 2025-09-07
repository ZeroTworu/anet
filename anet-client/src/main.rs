use anet_client::client::ANetClient;
use anyhow::Result;
use anet_client::config::load;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cfg = load().await?;
    let client = ANetClient::new(&cfg.cert_path)?;
    client.connect(&cfg.address, &cfg.auth_phrase).await?;

    Ok(())
}
