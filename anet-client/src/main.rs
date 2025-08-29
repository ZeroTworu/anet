use anet_client::client;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let _ = client::run_client("localhost:8443", "cert.pem").await;

    Ok(())
}
