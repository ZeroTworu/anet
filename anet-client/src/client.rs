use crate::atun_client::TunManager;
use crate::config::Config;
use anet_common::consts::{
    CHANNEL_BUFFER_SIZE, MAX_PACKET_SIZE, PACKET_TYPE_DATA, PACKET_TYPE_PING, PACKET_TYPE_PONG,
    PING_PONG_INTERVAL,
};
use anet_common::encryption::Cipher;
use anet_common::protocol::{
    AuthRequest, AuthResponse, Message as AnetMessage, UdpHandshake, message::Content,
};
use anyhow::Result;
use bytes::Bytes;
use log::{error, info, warn};
use prost::Message;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::RwLock;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_rustls::TlsConnector;

const MAX_RETRIES: u32 = 5;
const INITIAL_DELAY: u64 = 2;
const MAX_DELAY: u64 = 60;
const RECONNECT_DELAY: u64 = 3;

pub struct ANetClient {
    pub tun_manager: TunManager,
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

    pub async fn connect(&self) -> Result<AuthResponse> {
        let mut retry_count = 0;
        let mut delay = INITIAL_DELAY;

        loop {
            match self.authenticate_via_tls().await {
                Ok(params) => {
                    info!("Connection established successfully");

                    // Запускаем UDP соединение в отдельной задаче с мониторингом
                    let client_clone = self.clone();
                    let params_clone = params.clone();
                    tokio::spawn(async move {
                        client_clone
                            .run_udp_connection_with_reconnect(&params_clone)
                            .await;
                    });

                    break Ok(params);
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

    fn clone(&self) -> Self {
        Self {
            tun_manager: self.tun_manager.clone(),
            tls_connector: self.tls_connector.clone(),
            server_addr: self.server_addr.clone(),
            auth_phrase: self.auth_phrase.clone(),
        }
    }

    async fn run_udp_connection_with_reconnect(&self, initial_auth_response: &AuthResponse) {
        let mut reconnect_attempts = 0;
        let max_reconnect_attempts = 10;
        let mut current_auth_response = initial_auth_response.clone();

        loop {
            info!(
                "Starting UDP connection (attempt {})",
                reconnect_attempts + 1
            );

            match self
                .run_udp_connection(&current_auth_response, self.tun_manager.clone())
                .await
            {
                Ok(()) => {
                    info!("UDP connection finished normally");
                    break;
                }
                Err(e) => {
                    reconnect_attempts += 1;
                    error!(
                        "UDP connection failed (attempt {}): {}",
                        reconnect_attempts, e
                    );

                    if reconnect_attempts >= max_reconnect_attempts {
                        error!("Max UDP reconnection attempts reached, giving up");
                        break;
                    }

                    // Пытаемся переаутентифицироваться перед следующим подключением
                    info!("Attempting reauthentication...");
                    match self.authenticate_via_tls().await {
                        Ok(new_auth_response) => {
                            current_auth_response = new_auth_response;
                            info!("Reauthentication successful");
                        }
                        Err(e) => {
                            error!("Reauthentication failed: {}", e);
                            // Продолжаем со старыми учетными данными на следующий цикл
                        }
                    }

                    info!("Reconnecting in {} seconds...", RECONNECT_DELAY);
                    sleep(Duration::from_secs(RECONNECT_DELAY)).await;
                }
            }
        }
    }

    async fn authenticate_via_tls(&self) -> Result<AuthResponse> {
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

    async fn run_udp_connection(
        &self,
        auth_response: &AuthResponse,
        mut tun_manager: TunManager,
    ) -> Result<()> {
        let udp_addr = format!(
            "{}:{}",
            self.server_addr.split(':').next().unwrap(),
            auth_response.udp_port
        );
        info!("UDP will connect to {}", udp_addr);
        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        socket.connect(&udp_addr).await?;

        info!("Starting UDP connection");

        let _ = tun_manager.set_ip_network_params(auth_response);

        // Отправляем UDP handshake
        let handshake = AnetMessage {
            content: Some(Content::UdpHandshake(UdpHandshake {
                client_id: auth_response.client_id.clone(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
            })),
        };

        let mut handshake_data = Vec::new();
        handshake.encode(&mut handshake_data)?;
        socket.send(&handshake_data).await?;
        info!(
            "Sent UDP handshake with client_id: {}",
            auth_response.client_id
        );

        let socket = Arc::new(RwLock::new(socket));
        let connection_active = Arc::new(AtomicBool::new(true));
        let last_ping_time = Arc::new(RwLock::new(Instant::now()));

        // Настраиваем шифрование
        let cipher = Cipher::new(&auth_response.crypto_key);

        // Запускаем обработку пакетов
        let (tx_to_tun, rx_from_tun) = mpsc::channel(CHANNEL_BUFFER_SIZE);
        let (tx_to_udp, mut rx_from_udp) = mpsc::channel(CHANNEL_BUFFER_SIZE);

        // Создаём TUN
        tun_manager.start_processing(tx_to_udp, rx_from_tun).await?;

        // Задача для приёма пакетов через UDP
        let recv_task = {
            let socket = socket.clone();
            let cipher = cipher.clone();
            let tx_to_tun = tx_to_tun.clone();
            let connection_active = connection_active.clone();
            let last_ping_time = last_ping_time.clone();

            tokio::spawn(async move {
                let mut buffer = vec![0u8; MAX_PACKET_SIZE];
                loop {
                    if !connection_active.load(Ordering::Relaxed) {
                        break;
                    }

                    let read_result = {
                        let socket_guard = socket.read().await;
                        socket_guard.recv(&mut buffer).await
                    };

                    match read_result {
                        Ok(len) => {
                            if len < 1 {
                                continue;
                            }

                            let packet = Bytes::copy_from_slice(&buffer[..len]);
                            let packet_type = packet[0];

                            match packet_type {
                                PACKET_TYPE_PING => {
                                    // Обновляем время получения PING
                                    {
                                        let mut last_ping = last_ping_time.write().await;
                                        *last_ping = Instant::now();
                                    }
                                    info!("Received PING from server, sending PONG");

                                    // Отправляем PONG
                                    let pong_packet = vec![PACKET_TYPE_PONG];
                                    let send_result = {
                                        let socket_guard = socket.read().await;
                                        socket_guard.send(&pong_packet).await
                                    };

                                    if let Err(e) = send_result {
                                        error!("Failed to send PONG: {}", e);
                                        connection_active.store(false, Ordering::Relaxed);
                                        break;
                                    }
                                }
                                PACKET_TYPE_DATA => {
                                    if packet.len() < 1 + 8 + 1 {
                                        error!("Data packet too short");
                                        continue;
                                    }

                                    let sequence_bytes = packet.slice(1..9);
                                    let sequence = u64::from_be_bytes(
                                        sequence_bytes.as_ref().try_into().unwrap(),
                                    );

                                    let encrypted_data = packet.slice(9..);
                                    let nonce = Cipher::generate_nonce(sequence);

                                    match cipher.decrypt(&nonce, encrypted_data) {
                                        Ok(decrypted) => {
                                            if tx_to_tun.send(decrypted).await.is_err() {
                                                break;
                                            }
                                        }
                                        Err(e) => {
                                            error!("Decryption failed: {}", e);
                                        }
                                    }
                                }
                                _ => {
                                    warn!("Unknown packet type: {}", packet_type);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to receive UDP packet: {}", e);
                            connection_active.store(false, Ordering::Relaxed);
                            break;
                        }
                    }
                }
            })
        };

        // Задача для отправки пакетов через UDP
        let send_task = {
            let socket = socket.clone();
            let cipher = cipher.clone();
            let connection_active = connection_active.clone();

            tokio::spawn(async move {
                let mut sequence: u64 = 0;

                while let Some(packet) = rx_from_udp.recv().await {
                    if !connection_active.load(Ordering::Relaxed) {
                        break;
                    }

                    sequence += 1;
                    let nonce = Cipher::generate_nonce(sequence);

                    let encrypted_data = match cipher.encrypt(&nonce, packet) {
                        Ok(data) => data,
                        Err(e) => {
                            error!("Encryption failed: {}", e);
                            continue;
                        }
                    };

                    let mut data = Vec::with_capacity(1 + 8 + encrypted_data.len());
                    data.push(PACKET_TYPE_DATA);
                    data.extend_from_slice(&sequence.to_be_bytes());
                    data.extend_from_slice(&encrypted_data);

                    let send_result = {
                        let socket_guard = socket.read().await;
                        socket_guard.send(&data).await
                    };

                    if send_result.is_err() {
                        connection_active.store(false, Ordering::Relaxed);
                        break;
                    }
                }
            })
        };

        // Задача для мониторинга PING от сервера
        let monitor_task = {
            let connection_active = connection_active.clone();
            let last_ping_time = last_ping_time.clone();

            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(1));

                loop {
                    interval.tick().await;

                    if !connection_active.load(Ordering::Relaxed) {
                        break;
                    }

                    let time_since_last_ping = {
                        let last_ping = last_ping_time.read().await;
                        last_ping.elapsed()
                    };

                    if time_since_last_ping > Duration::from_secs(PING_PONG_INTERVAL) {
                        error!(
                            "No PING received from server for {} seconds, reconnecting...",
                            PING_PONG_INTERVAL
                        );
                        connection_active.store(false, Ordering::Relaxed);
                        break;
                    }
                }
                info!("PING monitor task finished");
            })
        };

        // Ожидаем завершения одной из задач
        tokio::select! {
            _ = recv_task => info!("Receive task finished"),
            _ = send_task => info!("Send task finished"),
            _ = monitor_task => info!("Monitor task finished"),
        }

        connection_active.store(false, Ordering::Relaxed);

        // Останавливаем TUN manager
        tun_manager.shutdown();

        Err(anyhow::anyhow!("UDP connection terminated"))
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
                    "Connection failed (attempt {}): {}. Retrying in {} seconds...",
                    retries, e, delay
                );
                sleep(Duration::from_secs(delay)).await;
                delay = next_delay;
            }
        }
    }
}
