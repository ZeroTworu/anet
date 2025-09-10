// anet-client/src/client.rs
use crate::atun_client::TunManager;
use crate::config::Config;
use anet_common::consts::MAX_PACKET_SIZE;
use anet_common::protocol::{
    AuthRequest, ClientTrafficReceive, Message as AnetMessage, message::Content,
};
use anet_common::tcp::optimize_tcp_connection;
use anyhow::Result;
use bytes::{Buf, Bytes, BytesMut};
use log::{debug, error, info, warn};
use prost::Message;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::io::IoSlice;
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_rustls::TlsConnector;

// Наверно то же в константы надо?
const MAX_RETRIES: u32 = 5;
const INITIAL_DELAY: u64 = 2;
const MAX_DELAY: u64 = 60;

pub struct ANetClient {
    tun_manager: TunManager,
    tls_connector: TlsConnector,
    server_addr: String,
    auth_phrase: String,
}

impl ANetClient {
    pub fn new(cfg: &Config) -> anyhow::Result<Self> {
        let mut root_store = RootCertStore::empty();

        let cert_file = std::fs::File::open(&cfg.cert_path)?;
        let mut cert_reader = std::io::BufReader::new(cert_file);

        let certs =
            rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<CertificateDer>, _>>()?;

        for cert in certs {
            let _ = root_store.add(cert);
        }

        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        tls_config.alpn_protocols = vec![b"h2".to_vec()];
        tls_config.enable_early_data = true;
        tls_config.enable_sni = true;

        info!("ANet Client manager created");
        let connector = TlsConnector::from(Arc::new(tls_config));
        Ok(Self {
            tun_manager: TunManager::new(),
            tls_connector: connector,
            server_addr: cfg.address.to_string(),
            auth_phrase: cfg.auth_phrase.to_string(),
          })
    }

    pub async fn connect(&self) -> Result<()> {
        let mut retry_count = 0;
        let mut delay = INITIAL_DELAY;

        loop {
            match self.try_connect().await {
                Ok(()) => {
                    info!("Connection established successfully");
                    retry_count = 0;
                    delay = INITIAL_DELAY;
                }
                Err(e) => {
                    retry_count += 1;
                    if retry_count >= MAX_RETRIES {
                        error!("Max retries exceeded, stopping connection attempts");
                        return Err(e);
                    }

                    error!(
                        "Connection failed (attempt {}): {}. Retrying in {} seconds...",
                        retry_count, e, delay
                    );

                    let next_delay = std::cmp::min(delay * 2, MAX_DELAY);
                    info!("Next retry will be in {} seconds", next_delay);

                    sleep(Duration::from_secs(delay)).await;
                    delay = next_delay;
                }
            }
        }
    }

    async fn try_connect(&self) -> Result<()> {
        let (tx_to_tun, rx_from_tun) = mpsc::channel(8192);
        let (tx_to_tls, mut rx_from_tls) = mpsc::channel(8192);

        let stream = connect_with_backoff(&self.server_addr).await?;
        let _ = optimize_tcp_connection(&stream);

        info!("Connected to server: {}", self.server_addr);

        let server_name = ServerName::try_from("alco").expect("Invalid server name");
        let tls_stream = self.tls_connector.connect(server_name, stream).await?;
        info!("TLS connection established");

        let (mut reader, mut writer) = tokio::io::split(tls_stream);

        let auth_request = AnetMessage {
            content: Some(Content::AuthRequest(AuthRequest {
                key: self.auth_phrase.clone(),
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
            }
            Some(_) => {
                error!("Unexpected response type");
                return Err(anyhow::anyhow!("Unexpected response type"));
            }
            None => {
                error!("Empty response received");
                return Err(anyhow::anyhow!("Empty response received"));
            }
        };

        if !tun_manager.is_set {
            warn!("TUN manager is disabled, shutting down");
            return Ok(());
        }

        let tun_task = tokio::spawn({
            let mut tun_manager = tun_manager.clone();
            async move {
                if let Err(e) = tun_manager.start_processing(tx_to_tls, rx_from_tun).await {
                    error!("TUN processing error: {}", e);
                }
            }
        });

        let reader_task = tokio::spawn({
            let server_addr = self.server_addr.clone();
            let auth_phrase = self.auth_phrase.clone();
            let tls_connector = self.tls_connector.clone();
            async move {
                info!("TLS -> TUN task started.");
                let mut len_buf = [0u8; 4];
                let mut read_buffer = BytesMut::with_capacity(MAX_PACKET_SIZE);

                loop {
                    let n = reader.read_buf(&mut read_buffer).await;
                    match n {
                        Ok(n) => {
                            if n == 0 {
                                break; // closed
                            }

                            while read_buffer.len() >= 4 {
                                len_buf.copy_from_slice(&read_buffer[0..4]);
                                let msg_len = u32::from_be_bytes(len_buf) as usize;

                                if read_buffer.len() < 4 + msg_len {
                                    break;
                                }

                                read_buffer.advance(4);

                                let message_data = read_buffer.split_to(msg_len);

                                match Message::decode(Bytes::from(message_data)) {
                                    Ok(AnetMessage {
                                        content: Some(Content::ClientTrafficSend(traffic)),
                                    }) => {
                                        debug!(
                                            "TLS -> TUN, size: {}",
                                            traffic.encrypted_packet.len()
                                        );
                                        if let Err(e) =
                                            tx_to_tun.send(traffic.encrypted_packet).await
                                        {
                                            error!("Failed to send to TUN: {}", e);
                                            break;
                                        }
                                    }
                                    Ok(other) => {
                                        info!(
                                            "TLS -> TUN, Received other message type: {:?}",
                                            other
                                        );
                                    }
                                    Err(e) => {
                                        error!("TLS -> TUN, Failed to parse message: {}", e);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("TLS -> TUN, error: {}", e);
                              if let Err(e) =
                                reconnect(&server_addr, &auth_phrase, &tls_connector).await
                            {
                                error!("Reconnection failed: {}", e);
                            }
                            break;
                        }
                    }
                }
            }
        });

        let writer_task = tokio::spawn({
            let server_addr = self.server_addr.clone();
            let auth_phrase = self.auth_phrase.clone();
            let tls_connector = self.tls_connector.clone();
            async move {
                let mut flush_interval = tokio::time::interval(Duration::from_millis(10));
                info!("TUN -> TLS task started.");

                loop {
                    tokio::select! {
                        biased;
                        tls_data = rx_from_tls.recv() => {
                            if let Some(tls_data) = tls_data {
                                let message = AnetMessage {
                                    content: Some(Content::ClientTrafficReceive(ClientTrafficReceive {
                                        encrypted_packet: tls_data,
                                    })),
                                };

                                let mut data = Vec::new();
                                if let Err(e) = message.encode(&mut data) {
                                    error!("TUN -> TLS, Failed to encode message: {}", e);
                                    continue;
                                }

                                let header = (data.len() as u32).to_be_bytes();
                                let slices = [IoSlice::new(&header), IoSlice::new(&data)];
                                debug!("TUN -> TLS, size: {}", slices.len());
                                if let Err(e) = writer.write_vectored(&slices).await {
                                    error!("TUN -> TLS, error sending data to server {}", e);
                                    // Запускаем переподключение
                                    if let Err(e) = reconnect(&server_addr, &auth_phrase, &tls_connector).await {
                                        error!("Reconnection failed: {}", e);
                                    }
                                    break;
                                }
                            }
                        }
                        _ = flush_interval.tick() => {
                            if let Err(e) = writer.flush().await {
                                error!("Failed to flush writer: {}", e);
                                break;
                            }
                        }
                    }
                }
            }
        });

        tokio::select! {
            _ = tun_task => {}
            _ = reader_task => {}
            _ = writer_task => {}
        }

        Ok(())
    }
}

async fn connect_with_backoff(server_addr: &str) -> Result<TcpStream> {
    let mut retries = 0;
    let mut delay = INITIAL_DELAY;

    loop {
        match TcpStream::connect(server_addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                retries += 1;
                if retries >= MAX_RETRIES {
                    return Err(e.into());
                }

                let next_delay = std::cmp::min(delay * 2, MAX_DELAY);
                error!(
                    "Connection failed (attempt {}): {}. Retrying in {} seconds (next retry in {} seconds)...",
                    retries, e, delay, next_delay
                );
                sleep(Duration::from_secs(delay)).await;
                delay = next_delay;
            }
        }
    }
}

async fn reconnect(
    server_addr: &str,
    auth_phrase: &str,
    tls_connector: &TlsConnector,
) -> Result<()> {
    let mut retries = 0;
    let mut delay = INITIAL_DELAY;

    loop {
        info!("Attempting to reconnect to {}...", server_addr);

        match TcpStream::connect(server_addr).await {
            Ok(stream) => {
                let _ = optimize_tcp_connection(&stream);
                let server_name = ServerName::try_from("alco").expect("Invalid server name");
                let tls_stream = tls_connector.connect(server_name, stream).await?;

                let (_, mut writer) = tokio::io::split(tls_stream);

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

                info!("Reauthentication request sent");
                return Ok(());
            }
            Err(e) => {
                retries += 1;
                if retries >= MAX_RETRIES {
                    return Err(e.into());
                }

                let next_delay = std::cmp::min(delay * 2, MAX_DELAY);
                error!(
                    "Reconnection failed (attempt {}): {}. Retrying in {} seconds (next retry in {} seconds)...",
                    retries, e, delay, next_delay
                );
                sleep(Duration::from_secs(delay)).await;
                delay = next_delay;
            }
        }
    }
}
