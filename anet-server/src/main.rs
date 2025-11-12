use anet_server::config::load;
use anet_server::server;
use anyhow::Result;
use server::ANetServer;

// #[tokio::main(flavor = "current_thread")]
#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    if let Err(e) = rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|e| anyhow::anyhow!("Failed to install crypto provider: {:?}", e))
    {
        log::warn!("{}", e);
        // Можно запустить процесс дальше, но проблема в том, что build() падает
        // Return Err(e) if crucial. Here, we must prevent panic.
    }
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cfg = load().await?;

    let mut server = ANetServer::new(&cfg)?;
    server.run().await?;

    Ok(())
}
