use crate::atun_client::TunManager;
use crate::config::Config;
use anet_common::consts::{PACKET_TYPE_DATA, CHANNEL_BUFFER_SIZE, MAX_PACKET_SIZE};
use anet_common::protocol::{
    AuthRequest, AuthResponse, Message as AnetMessage, UdpHandshake, message::Content,
};
use anyhow::Result;
use bytes::Bytes;
use anet_common::encryption::Cipher;
use log::{error, info, warn};
use prost::Message;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_rustls::TlsConnector;

const MAX_RETRIES: u32 = 5;
const INITIAL_DELAY: u64 = 2;
const MAX_DELAY: u64 = 60;

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
                    self.run_udp_connection(&params, self.tun_manager.clone())
                        .await?;
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
        let socket = Arc::new(socket);
        // Настраиваем шифрование
        let cipher = Cipher::new(&auth_response.crypto_key);

        // Запускаем обработку пакетов
        let (tx_to_tun, rx_from_tun) = mpsc::channel(CHANNEL_BUFFER_SIZE);
        let (tx_to_udp, mut rx_from_udp) = mpsc::channel(CHANNEL_BUFFER_SIZE);

        let tun_task = tokio::spawn({
            let mut tun_manager = tun_manager.clone();
            async move {
                if let Err(e) = tun_manager.start_processing(tx_to_udp, rx_from_tun).await {
                    error!("TUN processing error: {}", e);
                }
            }
        });

        // Задача для приёма пакетов через UDP
        let recv_task = tokio::spawn({
            let socket = socket.clone();
            let cipher = cipher.clone();
            let tx_to_tun = tx_to_tun.clone();
            async move {
                let mut buffer = vec![0u8; MAX_PACKET_SIZE];
                loop {
                    match socket.recv(&mut buffer).await {
                        Ok(len) => {
                            if len < 1 {
                                error!("Packet too short");
                                continue;
                            }
                            // Создаем Bytes из полученных данных
                            let packet = Bytes::copy_from_slice(&buffer[..len]);
                            let packet_type = packet[0];

                            match packet_type {
                                PACKET_TYPE_DATA => {
                                    // Проверяем минимальный размер пакета: тип + sequence + минимальные данные
                                    if packet.len() < 1 + 8 + 1 {
                                        error!("Data packet too short");
                                        continue;
                                    }

                                    // Извлекаем sequence number (байты 1-8)
                                    let sequence_bytes = packet.slice(1..9);
                                    let sequence = u64::from_be_bytes(sequence_bytes.as_ref().try_into().unwrap());

                                    // Извлекаем зашифрованные данные (байты 9 и дальше)
                                    let encrypted_data = packet.slice(9..);

                                    // Расшифровываем пакет
                                    let nonce = Cipher::generate_nonce(sequence);

                                    match cipher.decrypt(&nonce, encrypted_data) {
                                        Ok(decrypted) => {
                                            // Отправляем в TUN
                                            if let Err(e) = tx_to_tun.send(decrypted).await {
                                                error!("Failed to send to TUN: {}", e);
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
                        }
                    }
                }
            }
        });

        // Задача для отправки пакетов через UDP
        let send_task = tokio::spawn({
            let socket = socket.clone();
            let cipher = cipher.clone();
            async move {
                let mut sequence: u64 = 0;

                while let Some(packet) = rx_from_udp.recv().await {
                    sequence += 1;

                    // Шифруем пакет
                    let nonce = Cipher::generate_nonce(sequence);

                    let encrypted_data = match cipher.encrypt(&nonce, packet) {
                        Ok(data) => data,
                        Err(e) => {
                            error!("Encryption failed: {}", e);
                            continue;
                        }
                    };

                    // Формируем бинарный пакет: [тип: 1 байт][sequence: 8 байт][зашифрованные данные]
                    let mut data = Vec::with_capacity(1 + 8 + encrypted_data.len());
                    data.push(PACKET_TYPE_DATA);
                    data.extend_from_slice(&sequence.to_be_bytes());
                    data.extend_from_slice(&encrypted_data);

                    // Отправляем
                    if let Err(e) = socket.send(&data).await {
                        error!("Failed to send UDP packet: {}", e);
                    }
                }
            }
        });

        // Ожидаем завершения задач
        tokio::select! {
            _ = tun_task => {},
            _ = send_task => {},
            _ = recv_task => {},
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
