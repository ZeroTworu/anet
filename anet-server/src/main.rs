use anet_server::config::load;
use anet_server::server;
use anyhow::Result;
use server::ANetServer;

fn main() -> Result<()> {
    let worker_threads = std::thread::available_parallelism()
        .map(|n| n.get().clamp(2, 4))
        .unwrap_or(2);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        if let Err(e) = rustls::crypto::ring::default_provider()
            .install_default()
            .map_err(|e| anyhow::anyhow!("Failed to install crypto provider: {:?}", e))
        {
            log::warn!("{}", e);
        }
        env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or("info,rtc::peer_connection::handler=error"),
        )
        .init();
        let cfg = load().await?;

        let mut server = ANetServer::new(&cfg)?;
        server.run().await?;

        Ok(())
    })
}
