use crate::config::{Config, load};
use anet_common::anet_udp_socket::AnetUdpSocket;
use anet_common::atun::TunManager;
use anet_common::encryption::Cipher;
use anet_common::protocol::{AuthRequest, AuthResponse, Message as AnetMessage, message::Content};
use anet_common::quic_settings::build_transport_config;
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anet_common::tun_params::TunParams;
use anyhow::Result;
use bytes::Bytes;
use log::{error, info};
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

    pub async fn connect(&self) -> Result<(AuthResponse, Endpoint)> {
        let auth_params = self.authenticate().await?;
        info!("Authentication successful, starting QUIC VPN session...");

        // Мы не возвращаем Endpoint, а ждем завершения QUIC сессии
        let endpoint = self.run_quic_vpn(&auth_params).await?;

        Ok((auth_params, endpoint))
    }

    async fn authenticate(&self) -> Result<AuthResponse> {
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

    async fn run_quic_vpn(&self, auth_response: &AuthResponse) -> Result<Endpoint> {
        let config_result = load().await?;
        let params = TunParams::from_auth_response(auth_response, "anet-client");

        let tun_manager = TunManager::new(params);

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

        let anet_socket = Arc::new(AnetUdpSocket::new(real_socket, cipher));

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
        let connection = endpoint.connect(remote_addr, "alco")?.await?;
        info!(
            "QUIC connection established with {}, SEID: {}",
            connection.remote_address(),
            auth_response.session_id,
        );

        let (mut quic_tx, mut quic_rx) = connection.open_bi().await?;
        info!("Opened bidirectional QUIC stream for VPN traffic.");
        let (tx_to_tun, mut rx_from_tun) = tun_manager.run().await?;

        tokio::spawn(async move {
            while let Some(packet) = rx_from_tun.recv().await {
                // 1. Оборачиваем IP-пакет в транспортный фрейм [u16 длина][IP пакет]
                let framed_packet = frame_packet(packet);

                if quic_tx.write_all(&framed_packet).await.is_err() {
                    error!("QUIC stream write failed. TUN->QUIC task is closing.");
                    break;
                }
            }
            quic_tx.finish().unwrap();
        });

        tokio::spawn(async move {
            loop {
                // Используем универсальный сборщик пакетов на основе u16 префикса
                match read_next_packet(&mut quic_rx).await {
                    Ok(Some(packet)) => {
                        if tx_to_tun.send(packet).await.is_err() {
                            error!("TUN channel write failed. QUIC->TUN task is closing.");
                            break;
                        }
                    }
                    Ok(None) => {
                        info!("QUIC receive stream closed.");
                        break;
                    }
                    Err(e) => {
                        error!("Error reading and deframing QUIC stream: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(endpoint)
    }

    fn build_quinn_client_config(&self) -> Result<QuinnClientConfig> {
        let mut root_store = RootCertStore::empty();
        let certs = rustls_pemfile::certs(&mut self.server_cert.as_bytes())
            .collect::<Result<Vec<_>, _>>()?;
        for cert in certs {
            root_store.add(cert)?;
        }
        let client_crypto = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let quic_config = QuicClientConfig::try_from(client_crypto)?;

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
                    "Connection failed (attempt {}): {}. Retrying in {} seconds (next retry in {} seconds)...",
                    retries, e, delay, next_delay
                );
                sleep(Duration::from_secs(delay)).await;
                delay = next_delay;
            }
        }
    }
}
