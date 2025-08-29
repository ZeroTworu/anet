use anet_server::atun_server::TunManager;
use anet_server::server;
use anyhow::Result;
use log::{error, info};
use std::error::Error;
use tokio_util::sync::CancellationToken;
type BoxError = Box<dyn Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cert_path = "cert.pem";
    let key_path = "key.pem";
    let bind_addr = "0.0.0.0:8443";

    let tun_manager = TunManager::new();
    info!("Server TUN configuration: {}", tun_manager.get_info());

    let token = CancellationToken::new();
    let token_clone = token.clone();

    tokio::spawn(async move {
        if let Err(e) = tun_manager.start_processing(token_clone).await {
            error!("TUN processing error: {}", e);
        }
    });

    server::run_server(cert_path, key_path, bind_addr).await?;

    Ok(())
}
