use crate::config::{Config, load};
use crate::client_udp_socket::AnetUdpSocket;
use anet_common::atun::TunManager;
use anet_common::encryption::Cipher;
use anet_common::protocol::{AuthRequest, AuthResponse, Message as AnetMessage, message::Content};
use anet_common::quic_settings::build_transport_config;
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose;
use bytes::Bytes;
use log::{error, info, warn};
use prost::Message;
use quinn::{
    ClientConfig as QuinnClientConfig, Endpoint, EndpointConfig, TokioRuntime,
    crypto::rustls::QuicClientConfig,
};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::net::SocketAddr;
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::sleep;
use tokio_rustls::TlsConnector;

const MAX_RETRIES: u32 = 5;
const INITIAL_DELAY: u64 = 2;
const MAX_DELAY: u64 = 60;

pub struct ANetClient {
    tls_connector: TlsConnector,
    server_addr: String,
    auth_phrase: String,
    server_cert: String,
}

impl ANetClient {
    pub fn new(cfg: &Config) -> anyhow::Result<Self> {
        let mut root_store = RootCertStore::empty();
        let cert_bytes = cfg.main.server_cert.as_bytes();
        let mut cert_reader = std::io::BufReader::new(cert_bytes);
        let certs =
            rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<CertificateDer>, _>>()?;
        for cert in certs {
            let _ = root_store.add(cert);
        }
        let tls_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(tls_config));
        info!("ANET Client created");
        Ok(Self {
            tls_connector: connector,
            server_addr: cfg.main.address.to_string(),
            auth_phrase: cfg.main.auth_phrase.to_string(),
            server_cert: cfg.main.server_cert.clone(),
        })
    }

    pub async fn authenticate(&self) -> Result<AuthResponse> {
        info!("Try authenticating on {}...", self.server_addr);
        let stream = connect_with_backoff(&self.server_addr).await?;

        let server_name = ServerName::try_from("alco").expect("Invalid server name");
        let tls_stream = self.tls_connector.connect(server_name, stream).await?;

        let (mut reader, mut writer) = tokio::io::split(tls_stream);

        // Отправляем аутентификацию
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

        // Получаем ответ с ключом и портом
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let msg_len = u32::from_be_bytes(len_buf) as usize;

        let mut response_buf = vec![0u8; msg_len];
        reader.read_exact(&mut response_buf).await?;

        let response: AnetMessage = Message::decode(Bytes::from(response_buf))?;

        match response.content {
            Some(Content::AuthResponse(auth_response)) => {
                if auth_response.crypto_key.len() != 32 {
                    return Err(anyhow::anyhow!("Invalid crypto key length"));
                }

                Ok(auth_response)
            }
            _ => Err(anyhow::anyhow!("Unexpected response type")),
        }
    }

    pub async fn run_quic_vpn(
        &self,
        auth_response: &AuthResponse,
        tun_manager: &TunManager,
    ) -> Result<Endpoint> {
        let config_result = load().await?;

        let transport_config =
            build_transport_config(&config_result.quic_transport, auth_response.mtu as u16)?;
        let transport_config_arc = Arc::new(transport_config);

        let udp_addr_str = format!(
            "{}:{}",
            self.server_addr.split(':').next().unwrap(),
            auth_response.udp_port
        );
        let remote_addr: SocketAddr = udp_addr_str.parse()?;
        let real_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let cipher = Arc::new(Cipher::new(&auth_response.crypto_key));

        // Конвертируем session_id из строки в [u8; 16]
        let session_id_bytes = decode_session_id(&auth_response.session_id)?;
        info!("Client session_id: {}", &auth_response.session_id);

        let anet_socket = Arc::new(AnetUdpSocket::new(real_socket, cipher, session_id_bytes));

        // Отправляем initial handshake перед установкой QUIC соединения
        info!("Sending initial handshake to server...");
        anet_socket.send_initial_handshake(remote_addr).await?;
        info!("Initial handshake sent to server");

        let mut endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            anet_socket,
            Arc::new(TokioRuntime),
        )?;

        let mut client_config = self.build_quinn_client_config()?;
        client_config.transport_config(transport_config_arc);

        endpoint.set_default_client_config(client_config);

        info!(
            "Connecting to QUIC endpoint [{}] via ANET transport...",
            remote_addr
        );

        // Добавляем задержку для обработки handshake сервером
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        let connection = endpoint.connect(remote_addr, "alco")?.await?;
        info!(
            "QUIC connection established with {}, SEID: {}",
            connection.remote_address(),
            auth_response.session_id,
        );

        let (send_stream, recv_stream) = connection.open_bi().await?;
        info!("Opened bidirectional QUIC stream for VPN traffic.");

        // Получаем каналы для TUN
        let (tx_to_tun, mut rx_from_tun) = tun_manager.run().await?;

        // Задача: чтение из TUN и отправка в QUIC
        let mut quic_sender = send_stream;

        tokio::spawn(async move {
            let mut sequence: u64 = 1; // Начинаем с 1, так как 0 используется для handshake

            while let Some(packet) = rx_from_tun.recv().await {
                // Проверяем, что это IP пакет (минимум 20 байт для IPv4)
                if packet.len() < 20 {
                    info!("Received non-IP packet from TUN: {} bytes", packet.len());
                    continue;
                }

                // Проверяем версию IP (4 или 6)
                let version = packet[0] >> 4;
                if version != 4 && version != 6 {
                    warn!("Unknown IP version: {} in packet from TUN", version);
                    continue;
                }

                // Оборачиваем IP-пакет в транспортный фрейм [u16 длина][IP пакет]
                let framed_packet = frame_packet(packet);

                // Отправляем через транспортный слой
                if let Err(e) = quic_sender.write_all(&framed_packet).await {
                    error!("QUIC stream write failed. TUN->QUIC task is closing: {}", e);
                    break;
                }

                // Flush чтобы убедиться что данные отправлены
                if let Err(e) = quic_sender.flush().await {
                    error!("QUIC stream flush failed: {}", e);
                    break;
                }

                sequence += 1;
            }

            // Закрываем стрим грациозно
            if let Err(e) = quic_sender.finish() {
                error!("Error finishing QUIC stream: {}", e);
            }
            info!("TUN->QUIC task finished");
        });

        // Задача: чтение из QUIC и отправка в TUN
        let mut quic_receiver = recv_stream;
        let tx_to_tun_clone = tx_to_tun.clone();
        tokio::spawn(async move {
            loop {
                match read_next_packet(&mut quic_receiver).await {
                    Ok(Some(packet)) => {
                        if let Err(e) = tx_to_tun_clone.send(packet).await {
                            error!("TUN channel write failed. QUIC->TUN task is closing: {}", e);
                            break;
                        }
                    }
                    Ok(None) => {
                        info!("QUIC receive stream closed gracefully.");
                        break;
                    }
                    Err(e) => {
                        error!("Error reading and deframing QUIC stream: {}", e);
                        break;
                    }
                }
            }
            info!("QUIC->TUN task finished");
        });

        // Сохраняем endpoint чтобы он не был уничтожен
        Ok(endpoint)
    }
    fn build_quinn_client_config(&self) -> Result<QuinnClientConfig> {
        let mut root_store = RootCertStore::empty();
        let certs_result =
            rustls_pemfile::certs(&mut self.server_cert.as_bytes()).collect::<Result<Vec<_>, _>>();

        let certs = match certs_result {
            Ok(certs) => certs,
            Err(e) => {
                error!("Error reading certificate: {}", e);
                return Err(anyhow::anyhow!(e));
            }
        };

        for cert in certs {
            match root_store.add(cert) {
                Ok(_) => (),
                Err(e) => {
                    error!("Error adding certificate: {}", e);
                    return Err(anyhow::anyhow!(e));
                }
            }
        }

        let client_crypto = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let quic_config_result = QuicClientConfig::try_from(client_crypto);

        let quic_config = match quic_config_result {
            Ok(quic_config) => quic_config,
            Err(e) => {
                error!("Error creating QUIC client: {}", e);
                return Err(anyhow::anyhow!(e));
            }
        };

        let cfg = QuinnClientConfig::new(Arc::new(quic_config));
        Ok(cfg)
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
                    "Connection to {} failed (attempt {}): {}. Retrying in {} seconds (next retry in {} seconds)...",
                    server_addr, retries, e, delay, next_delay
                );
                sleep(Duration::from_secs(delay)).await;
                delay = next_delay;
            }
        }
    }
}

fn decode_session_id(session_id: &str) -> Result<[u8; 16]> {
    let decoded = general_purpose::STANDARD
        .decode(session_id)
        .context("Failed to decode session_id from base64")?;

    if decoded.len() != 16 {
        return Err(anyhow::anyhow!("Invalid session_id length"));
    }

    let mut session_id_bytes = [0u8; 16];
    session_id_bytes.copy_from_slice(&decoded);
    Ok(session_id_bytes)
}
