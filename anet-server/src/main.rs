use anet_server::config::load;
use anet_server::server::ANetServer;
use anyhow::{anyhow, Result};
use env_logger::{Builder as EnvLoggerBuilder, Env};
use log::warn;
use rustls::crypto::ring::default_provider;
use std::thread::available_parallelism;
use tokio::runtime::Builder as RuntimeBuilder;

fn main() -> Result<()> {
    let worker_threads = available_parallelism()
        .map(|n| n.get().clamp(2, 4))
        .unwrap_or(2);
    let runtime = RuntimeBuilder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        if let Err(e) = default_provider()
            .install_default()
            .map_err(|e| anyhow!("Failed to install crypto provider: {:?}", e))
        {
            warn!("{}", e);
        }
        EnvLoggerBuilder::from_env(
            Env::default().default_filter_or("info,rtc::peer_connection::handler=error"),
        )
        .init();
        let cfg = load().await?;

        let mut server = ANetServer::new(&cfg)?;
        server.run().await?;

        Ok(())
    })
}
