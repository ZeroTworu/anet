use std::{sync::Arc, time::Duration};

use crate::atun_client::TunManager;
use crate::exchange::Exchange;
use anet_common::protocol::{AuthRequest, ClientTrafficReceive, Message};
use anyhow::Result;
use log::{debug, error, info};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::sleep;
use tokio_rustls::TlsConnector;

const MAX_RETRIES: u32 = 5;

pub struct ANetClient {
    tun_manager: TunManager,
    tls_connector: TlsConnector,
}

impl ANetClient {
    pub fn new(ca_crt_path: &str) -> anyhow::Result<Self> {
        let mut root_store = RootCertStore::empty();

        let cert_file = std::fs::File::open(ca_crt_path)?;
        let mut cert_reader = std::io::BufReader::new(cert_file);

        let certs =
            rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<CertificateDer>, _>>()?;

        for cert in certs {
            let _ = root_store.add(cert);
        }

        let tls_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        info!("ANet Client manager created");
        let connector = TlsConnector::from(Arc::new(tls_config));
        Ok(Self {
            tun_manager: TunManager::new(),
            tls_connector: connector,
        })
    }
    pub async fn connect(&self, server_addr: &str, auth_phrase: &str) -> Result<()> {
        info!("Connecting to {} ...", server_addr);
        let exchange = Exchange::new();
        let tx_to_tun = exchange.frame_channels.tx_to_tun.clone();
        let tx_to_tls = exchange.tls_channels.tx_to_tls.clone();

        let rx_from_tun = exchange.frame_channels.rx_from_tun;
        let mut rx_from_tls = exchange.tls_channels.rx_from_tls;

        let stream = connect_with_retry(server_addr, MAX_RETRIES).await?;

        info!("Connected to server: {}", server_addr);

        let server_name = ServerName::try_from("alco").expect("Invalid server name");

        let tls_stream = self.tls_connector.connect(server_name, stream).await?;
        info!("TLS connection established");

        let (reader, mut writer) = tokio::io::split(tls_stream);
        let mut reader = BufReader::new(reader);

        let auth_request = Message::AuthRequest(AuthRequest {
            key: auth_phrase.to_string(),
        });
        let request_data = serde_json::to_string(&auth_request)? + "\n";
        writer.write_all(request_data.as_bytes()).await?;
        info!("Authentication request sent");
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let mut tun_manager = self.tun_manager.clone();

        match serde_json::from_str::<Message>(&line) {
            Ok(Message::AuthResponse(assigned_ip)) => {
                info!("Success! Assigned IP: {}", assigned_ip.ip);
                tun_manager.set_ip_network_params(&assigned_ip)?;
                info!("Current TUN configuration: {}", tun_manager.get_info());
                tokio::spawn(async move {
                    if let Err(e) = &tun_manager.start_processing(tx_to_tls, rx_from_tun).await {
                        error!("TUN processing error: {}", e);
                    }
                });

                tokio::spawn(async move {
                    let mut line = String::new();
                    loop {
                        line.clear();
                        if let Err(e) = reader.read_line(&mut line).await {
                            error!("Failed to read from TLS: {}", e);
                            break;
                        }

                        if !line.is_empty() {
                            match serde_json::from_str::<Message>(&line) {
                                Ok(Message::ClientTrafficSend(traffic)) => {
                                    debug!("Received ClientTrafficSend from server");
                                    if let Err(e) = tx_to_tun.send(traffic.encrypted_packet).await {
                                        error!("Failed to send to TUN: {}", e);
                                        break;
                                    }
                                }
                                Ok(other) => {
                                    info!("Received other message type: {:?}", other);
                                }
                                Err(e) => {
                                    error!("Failed to parse message: {}, err: {}", line, e);
                                }
                            }
                        }
                    }
                });

                loop {
                    if let Some(tls_data) = rx_from_tls.recv().await {
                        let message = Message::ClientTrafficReceive(ClientTrafficReceive {
                            encrypted_packet: tls_data,
                        });
                        let json = serde_json::to_string(&message)? + "\n";
                        writer.write_all(json.as_bytes()).await?;
                        debug!("Sent ClientTrafficReceive to server");
                    }
                }
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
