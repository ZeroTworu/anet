use crate::config::CoreConfig;
use crate::socket::AnetUdpSocket;
use anet_common::consts::MAX_PACKET_SIZE;
use anet_common::encryption::Cipher;
use anet_common::jitter::bridge_with_jitter;
use anet_common::protocol::AuthResponse;
use anet_common::quic_settings::build_transport_config;
use anet_common::stream_framing::read_next_packet;
use anyhow::Result;
use log::{error, info};
use quinn::{ClientConfig, Connection, Endpoint, EndpointConfig, TokioRuntime};
use rustls::RootCertStore;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub struct VpnHandler {
    config: CoreConfig,
}

impl VpnHandler {
    pub fn new(config: CoreConfig) -> Self {
        Self { config }
    }

    /// Запускает QUIC соединение и возвращает Endpoint + Каналы данных (внутри QUIC)
    pub async fn connect(
        &self,
        auth_response: &AuthResponse,
        shared_key: [u8; 32],
    ) -> Result<(
        Endpoint,
        Connection,
        mpsc::Sender<bytes::Bytes>,
        mpsc::Receiver<bytes::Bytes>,
    )> {
        // 1. Настройка транспорта
        let transport_config =
            build_transport_config(&self.config.quic_transport, auth_response.mtu as u16)?;

        // 2. Создание сокета (AnetUdpSocket)
        let server_addr: SocketAddr = self.config.server_addr.parse()?;
        let real_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let cipher = Arc::new(Cipher::new(&shared_key));
        let nonce_prefix: [u8; 4] = auth_response.nonce_prefix.as_slice().try_into()?;

        let anet_socket = Arc::new(AnetUdpSocket::new(
            real_socket,
            cipher,
            nonce_prefix,
            self.config.stealth.clone(),
        ));

        // 3. Создание Endpoint
        let mut endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            anet_socket,
            Arc::new(TokioRuntime),
        )?;

        // 4. Crypto Config
        let mut root_store = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut auth_response.quic_cert.as_slice()) {
            root_store.add(cert?)?;
        }
        let client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let mut client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
        ));
        client_config.transport_config(Arc::new(transport_config));
        endpoint.set_default_client_config(client_config);

        // 5. Connect
        info!("[Core] Connecting to {}...", server_addr);
        let connection = endpoint.connect(server_addr, "alco")?.await?;

        info!(
            "[Core] Connection established. SEID: {}",
            auth_response.session_id
        );

        // 6. Запуск стримов
        let (send_stream, mut recv_stream) = connection.open_bi().await?;

        // Каналы для связи с TUN (Logic <-> TUN)
        let (tx_to_quic, rx_to_quic) = mpsc::channel(MAX_PACKET_SIZE); // TUN -> QUIC
        let (tx_from_quic, rx_from_quic) = mpsc::channel(MAX_PACKET_SIZE); // QUIC -> TUN

        let stealth_config = self.config.stealth.clone();

        // Task: TUN -> QUIC
        tokio::spawn(async move {
            if let Err(e) = bridge_with_jitter(rx_to_quic, send_stream, stealth_config).await {
                error!("[Core] QUIC TX error: {}", e);
            }
        });

        // Task: QUIC -> TUN
        tokio::spawn(async move {
            loop {
                match read_next_packet(&mut recv_stream).await {
                    Ok(Some(packet)) => {
                        if tx_from_quic.send(packet).await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
            info!("[Core] QUIC RX finished.");
        });

        Ok((endpoint, connection.clone(), tx_to_quic, rx_from_quic))
    }
}
