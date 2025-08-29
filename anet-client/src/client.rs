use std::{sync::Arc, time::Duration};

use crate::atun_client::TunManager;
use anet_common::protocol::{AuthRequest, Message};
use anyhow::Result;
use log::{error, info};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::sleep;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
const AUTH_KEY: &str = "supersecretkey";
const MAX_RETRIES: u32 = 5;

pub async fn run_client(server_addr: &str, ca_cert_path: &str) -> Result<()> {
    let mut tun_manager = TunManager::new();
    info!("Client TUN manager created");

    let tls_config = load_tls_config(ca_cert_path)?;
    let connector = TlsConnector::from(Arc::new(tls_config));

    let stream = connect_with_retry(server_addr, MAX_RETRIES).await?;
    info!("Connected to server: {}", server_addr);

    let server_name = ServerName::try_from("alco").expect("Invalid server name");

    let tls_stream = connector.connect(server_name, stream).await?;
    info!("TLS connection established");

    let (reader, mut writer) = tokio::io::split(tls_stream);
    let mut reader = BufReader::new(reader);

    let auth_request = Message::AuthRequest(AuthRequest {
        key: AUTH_KEY.to_string(),
    });
    let request_data = serde_json::to_string(&auth_request)? + "\n";
    writer.write_all(request_data.as_bytes()).await?;
    info!("Authentication request sent");

    let mut line = String::new();
    reader.read_line(&mut line).await?;

    match serde_json::from_str::<Message>(&line) {
        Ok(Message::AuthResponse(assigned_ip)) => {
            info!("Success! Assigned IP: {}", assigned_ip.ip);

            tun_manager.set_ip_address(&assigned_ip.ip)?;
            info!("TUN configuration updated with new IP: {}", assigned_ip.ip);

            info!("Current TUN configuration: {}", tun_manager.get_info());

            let token = CancellationToken::new();
            tun_manager.start_processing(token).await?;
        }
        Ok(_) => {
            error!("Unexpected response type");
        }
        Err(e) => {
            error!("Failed to parse response: {}", e);
        }
    }

    Ok(())
}

fn load_tls_config(ca_cert_path: &str) -> Result<ClientConfig> {
    let mut root_store = RootCertStore::empty();

    let cert_file = std::fs::File::open(ca_cert_path)?;
    let mut cert_reader = std::io::BufReader::new(cert_file);

    let certs =
        rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<CertificateDer>, _>>()?;

    for cert in certs {
        let _ = root_store.add(cert);
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(config)
}

async fn connect_with_retry(server_addr: &str, max_retries: u32) -> Result<TcpStream> {
    let mut retries = 0;

    loop {
        match TcpStream::connect(server_addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                retries += 1;
                if retries >= max_retries {
                    return Err(e.into());
                }

                error!(
                    "Connection failed (attempt {}): {}. Retrying...",
                    retries, e
                );
                sleep(Duration::from_secs(2)).await;
            }
        }
    }
}
