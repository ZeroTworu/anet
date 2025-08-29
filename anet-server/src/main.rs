use anyhow::Result;
use std::error::Error;
use anet_server::server;

type BoxError = Box<dyn Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    // Параметры для запуска сервера
    let cert_path = "cert.pem";
    let key_path = "key.pem";
    let bind_addr = "0.0.0.0:8443";

    server::run_server(cert_path, key_path, bind_addr).await?;

    Ok(())
}