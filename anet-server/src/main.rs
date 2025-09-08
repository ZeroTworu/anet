use anet_server::config::load;
use anet_server::server;
use anyhow::Result;
use server::ANetServer;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cfg = load().await?;

    let server = ANetServer::new(&cfg)?;
    server.run().await?;

    Ok(())
}
