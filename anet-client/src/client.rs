use crate::config::{Config, load};
use anet_common::anet_udp_socket::AnetUdpSocket;
use anet_common::atun::TunManager;
use anet_common::encryption::Cipher;
use anet_common::protocol::AuthResponse;
use anet_common::quic_settings::build_transport_config;
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anet_common::transport;
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose};
use bytes::Bytes;
use log::{error, info, warn};
use quinn::{
    ClientConfig as QuinnClientConfig, Endpoint, EndpointConfig, TokioRuntime,
    crypto::rustls::QuicClientConfig,
};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::net::SocketAddr;
use std::{sync::Arc, time::Duration};
use rand::RngCore;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::time::sleep;

use anet_common::consts::{AUTH_TIMEOUT_SECONDS, AUTH_MAX_RETRIES, SESSION_ID_LENGTH};

pub struct ANetClient {
    server_addr: String,
    auth_phrase: String,
    server_cert: String,
}

impl ANetClient {
    pub fn new(cfg: &Config) -> anyhow::Result<Self> {
        info!("ANET Client created");
        Ok(Self {
            server_addr: cfg.main.address.to_string(),
            auth_phrase: cfg.main.auth_phrase.to_string(),
            server_cert: cfg.main.server_cert.clone(),
        })
    }

    pub async fn authenticate(&self) -> Result<AuthResponse> {
        info!("Starting UDP authentication to {}...", self.server_addr);

        let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
        let server_addr: SocketAddr = self.server_addr.parse()?;

        let mut client_random = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut client_random);

        let temp_cipher = self.create_temp_cipher()?;
        let temp_session_id = [0u8; SESSION_ID_LENGTH];

        let auth_packet = transport::wrap_auth_request(
            &temp_cipher,
            temp_session_id,
            self.auth_phrase.clone(),
            client_random,
        )?;

        let mut retries = 0;
        let mut response_buf = [0u8; 1024];

        loop {
            udp_socket.send_to(&auth_packet, server_addr).await?;
            info!("Sent authentication request (attempt {})", retries + 1);

            let recv_result = tokio::time::timeout(
                Duration::from_secs(AUTH_TIMEOUT_SECONDS),
                udp_socket.recv_from(&mut response_buf)
            ).await;

            match recv_result {
                Ok(Ok((size, _))) => {
                    let response_data = &response_buf[..size];

                    match transport::unwrap_auth_response(&temp_cipher, temp_session_id, response_data) {
                        Ok((crypto_key, udp_port, gateway, netmask, client_ip, mtu)) => {
                            let session_id = generate_seid();
                            let session_id_bytes = general_purpose::STANDARD
                                .decode(&session_id)
                                .context("Failed to decode session_id")?;

                            let mut session_id_bytes_array = [0u8; SESSION_ID_LENGTH];
                            session_id_bytes_array.copy_from_slice(&session_id_bytes[..SESSION_ID_LENGTH]);

                            return Ok(AuthResponse {
                                ip: client_ip,
                                netmask,
                                gateway,
                                mtu,
                                crypto_key,
                                udp_port,
                                session_id,
                            });
                        }
                        Err(e) => {
                            error!("Failed to decrypt auth response: {}", e);
                        }
                    }
                }
                Ok(Err(e)) => {
                    error!("Error receiving auth response: {}", e);
                }
                Err(_) => {
                    info!("Authentication timeout");
                }
            }

            retries += 1;
            if retries >= AUTH_MAX_RETRIES {
                return Err(anyhow::anyhow!("Authentication failed after {} attempts", retries));
            }

            let delay = Duration::from_secs(2u64.pow(retries));
            tokio::time::sleep(delay).await;
        }
    }

    fn create_temp_cipher(&self) -> Result<Cipher> {
        let temp_key = [0u8; 32];
        Ok(Cipher::new(&temp_key))
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

        let session_id_bytes = decode_session_id(&auth_response.session_id)?;
        info!("Client session_id: {}", &auth_response.session_id);

        let anet_socket = Arc::new(AnetUdpSocket::new(real_socket, cipher, session_id_bytes));

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

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        let connection = endpoint.connect(remote_addr, "alco")?.await?;
        info!(
            "QUIC connection established with {}, SEID: {}",
            connection.remote_address(),
            auth_response.session_id,
        );

        let (send_stream, recv_stream) = connection.open_bi().await?;
        info!("Opened bidirectional QUIC stream for VPN traffic.");

        let (tx_to_tun, mut rx_from_tun) = tun_manager.run().await?;

        let mut quic_sender = send_stream;

        tokio::spawn(async move {
            let mut sequence: u64 = 1;

            while let Some(packet) = rx_from_tun.recv().await {
                if packet.len() < 20 {
                    info!("Received non-IP packet from TUN: {} bytes", packet.len());
                    continue;
                }

                let version = packet[0] >> 4;
                if version != 4 && version != 6 {
                    warn!("Unknown IP version: {} in packet from TUN", version);
                    continue;
                }

                let framed_packet = frame_packet(packet);

                if let Err(e) = quic_sender.write_all(&framed_packet).await {
                    error!("QUIC stream write failed. TUN->QUIC task is closing: {}", e);
                    break;
                }

                if let Err(e) = quic_sender.flush().await {
                    error!("QUIC stream flush failed: {}", e);
                    break;
                }

                sequence += 1;
            }

            if let Err(e) = quic_sender.finish() {
                error!("Error finishing QUIC stream: {}", e);
            }
            info!("TUN->QUIC task finished");
        });

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

fn decode_session_id(session_id: &str) -> Result<[u8; SESSION_ID_LENGTH]> {
    let decoded = general_purpose::STANDARD
        .decode(session_id)
        .context("Failed to decode session_id from base64")?;

    if decoded.len() != SESSION_ID_LENGTH {
        return Err(anyhow::anyhow!("Invalid session_id length"));
    }

    let mut session_id_bytes = [0u8; SESSION_ID_LENGTH];
    session_id_bytes.copy_from_slice(&decoded);
    Ok(session_id_bytes)
}

fn generate_seid() -> String {
    let mut rng = rand::thread_rng();
    let mut session_id = [0u8; SESSION_ID_LENGTH];
    rng.fill_bytes(&mut session_id);
    general_purpose::STANDARD.encode(session_id)
}