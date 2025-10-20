use anet_server::config::load;
use anet_server::server;
use anyhow::Result;
use server::ANetServer;
use tokio_uring;

fn main() -> Result<()> {
    tokio_uring::start(async move {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
        let cfg = load().await?;

        let server = ANetServer::new(&cfg)?;
        server.run().await?;

        Ok(()) 
    })
}