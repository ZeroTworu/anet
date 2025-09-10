use anet_client::client::ANetClient;
use anet_client::config::load;
use anyhow::Result;
use log::info;

#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
#[cfg(windows)]
use tokio::signal::windows::ctrl_c;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cfg = load().await?;
    let client = ANetClient::new(&cfg)?;
    client.connect().await?;

    #[cfg(unix)]
    let mut sig = signal(SignalKind::terminate())?;
    #[cfg(windows)]
    let mut sig = ctrl_c()?;
    info!("Press Ctrl-C to exit.");

    sig.recv().await;
    info!("Shutting down...");
    Ok(())
}
