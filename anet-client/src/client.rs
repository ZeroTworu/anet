use std::{sync::Arc, time::Duration};

use crate::atun_client::TunManager;
use anet_common::protocol::{
    AuthRequest, ClientTrafficReceive, Message as AnetMessage, message::Content,
};
use anyhow::Result;
use bytes::Bytes;
use log::{debug, error, info};
use prost::Message;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
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

        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        tls_config.enable_early_data = true;
        tls_config.enable_sni = true;

        info!("ANet Client manager created");
        let connector = TlsConnector::from(Arc::new(tls_config));
        Ok(Self {
            tun_manager: TunManager::new(),
            tls_connector: connector,
        })
    }
    pub async fn connect(&self, server_addr: &str, auth_phrase: &str) -> Result<()> {
        info!("Connecting to {} ...", server_addr);
        let (tx_to_tun, rx_from_tun) = mpsc::channel(1024);

        let (tx_to_tls, mut rx_from_tls) = mpsc::channel(1024);

        let stream = connect_with_retry(server_addr, MAX_RETRIES).await?;

        info!("Connected to server: {}", server_addr);

        let server_name = ServerName::try_from("alco").expect("Invalid server name");

        let tls_stream = self.tls_connector.connect(server_name, stream).await?;
        info!("TLS connection established");

        let (reader, mut writer) = tokio::io::split(tls_stream);
        let mut reader = BufReader::new(reader);

        let auth_request = AnetMessage {
            content: Some(Content::AuthRequest(AuthRequest {
                key: auth_phrase.to_string(),
            })),
        };
        let mut request_data = Vec::new();
        auth_request.encode(&mut request_data)?;

        writer
            .write_all(&(request_data.len() as u32).to_be_bytes())
            .await?;
        writer.write_all(&request_data).await?;

        info!("Authentication request sent");

        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let msg_len = u32::from_be_bytes(len_buf) as usize;

        let mut response_buf = vec![0u8; msg_len];
        reader.read_exact(&mut response_buf).await?;

        let response: AnetMessage = Message::decode(Bytes::from(response_buf))?;
        let mut tun_manager = self.tun_manager.clone();

        match response.content {
            Some(Content::AuthResponse(assigned_ip)) => {
                info!("Success! Assigned IP: {}", assigned_ip.ip);
                tun_manager.set_ip_network_params(&assigned_ip.into())?;
                info!("Current TUN configuration: {}", tun_manager.get_info());

                tokio::spawn(async move {
                    if let Err(e) = &tun_manager.start_processing(tx_to_tls, rx_from_tun).await {
                        error!("TUN processing error: {}", e);
                    }
                });

                tokio::spawn(async move {
                    let mut len_buf = [0u8; 4];
                    loop {
                        // Читаем длину сообщения
                        if let Err(e) = reader.read_exact(&mut len_buf).await {
                            error!("Failed to read message length from TLS: {}", e);
                            break;
                        }

                        let msg_len = u32::from_be_bytes(len_buf) as usize;
                        let mut msg_buf = vec![0u8; msg_len];

                        if let Err(e) = reader.read_exact(&mut msg_buf).await {
                            error!("Failed to read message from TLS: {}", e);
                            break;
                        }

                        match Message::decode(Bytes::from(msg_buf)) {
                            Ok(AnetMessage {
                                content: Some(Content::ClientTrafficSend(traffic)),
                            }) => {
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
                                error!("Failed to parse message: {}", e);
                            }
                        }
                    }
                });

                loop {
                    if let Some(tls_data) = rx_from_tls.recv().await {
                        let message = AnetMessage {
                            content: Some(Content::ClientTrafficReceive(ClientTrafficReceive {
                                encrypted_packet: tls_data,
                            })),
                        };

                        let mut data = Vec::new();
                        message.encode(&mut data)?;

                        // Отправляем длину и данные
                        writer.write_all(&(data.len() as u32).to_be_bytes()).await?;
                        writer.write_all(&data).await?;

                        debug!("Sent ClientTrafficReceive to server");
                    }
                }
            }
            Some(_) => {
                error!("Unexpected response type");
            }
            None => {
                error!("Empty response received");
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
