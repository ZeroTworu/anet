use anet_client::client::ANetClient;
use anet_client::config::load;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cfg = load().await?;
    let client = ANetClient::new(&cfg.cert_path)?;
    client.connect(&cfg.address, &cfg.auth_phrase).await?;

    Ok(())
}
