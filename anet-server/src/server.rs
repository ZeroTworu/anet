use std::collections::HashMap;
use std::{fs::File, io::BufReader, sync::Arc};

use crate::atun_server::TunManager;
use crate::config::Config;
use crate::ip_pool::IpPool;
use crate::utils::{generate_crypto_key, generate_uid};
use anet_common::AuthResponse;
use anet_common::consts::{PACKET_TYPE_DATA, PACKET_TYPE_HANDSHAKE};
use anet_common::protocol::{Message as AnetMessage, message::Content};
use anet_common::tun_params::TunParams;
use anyhow::Context;
use bytes::Bytes;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
use log::{debug, error, info, warn};
use prost::Message;
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio::time::{Duration, interval};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

#[derive(Clone)]
struct UdpClient {
    cipher: ChaCha20Poly1305,
    last_seen: std::time::Instant,
    client_id: String,
    assigned_ip: String,
}

pub struct ANetServer {
    tls_acceptor: TlsAcceptor,
    ip_pool: IpPool,
    cfg: Config,
    udp_clients: Arc<Mutex<HashMap<SocketAddr, UdpClient>>>,
    uid_to_key: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    tun_manager: TunManager,
    ip_to_addr: Arc<Mutex<HashMap<String, SocketAddr>>>,
    client_id_to_ip: Arc<Mutex<HashMap<String, String>>>,
}

impl ANetServer {
    pub fn new(cfg: &Config) -> anyhow::Result<Self> {
        let tls_cfg = load_tls_config(cfg.cert_path.as_str(), cfg.key_path.as_str())?;
        let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));
        let params = TunParams {
            netmask: cfg.mask.parse().unwrap(),
            gateway: cfg.gateway.parse().unwrap(),
            address: cfg.self_ip.parse().unwrap(),
            name: cfg.if_name.parse().unwrap(),
            mtu: cfg.mtu,
        };
        let tun_manager = TunManager::new(params, cfg.net.parse().unwrap());
        let ip_pool = IpPool::new(
            cfg.net.parse().unwrap(),
            cfg.mask.parse().unwrap(),
            cfg.gateway.parse().unwrap(),
            cfg.self_ip.parse().unwrap(),
            cfg.mtu,
        );
        info!("Server TUN configuration: {}", tun_manager.get_info());

        Ok(Self {
            tls_acceptor: acceptor,
            ip_pool,
            cfg: cfg.clone(),
            udp_clients: Arc::new(Mutex::new(HashMap::new())),
            uid_to_key: Arc::new(Mutex::new(HashMap::new())),
            tun_manager,
            ip_to_addr: Arc::new(Mutex::new(HashMap::new())),
            client_id_to_ip: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let tcp_listener = TcpListener::bind(self.cfg.bind_to.as_str()).await?;

        let udp_socket: UdpSocket =
            UdpSocket::bind(format!("0.0.0.0:{}", self.cfg.udp_port)).await?;

        info!("Bind on {} for TCP, and ", self.cfg.bind_to.as_str());
        let udp_socket = Arc::new(udp_socket);

        let (tx_to_tun, mut rx_from_tun) = self.tun_manager.run().await?;
        self.tun_manager
            .setup_tun_routing(self.cfg.external_if.as_str())
            .await?;

        //  TUN -> UDP
        let udp_socket_for_tun = udp_socket.clone();
        let udp_clients_for_tun = self.udp_clients.clone();
        let ip_to_addr_for_tun = self.ip_to_addr.clone();
        let sequence_numbers = Arc::new(Mutex::new(HashMap::<SocketAddr, u64>::new()));

        tokio::spawn(async move {
            while let Some(packet) = rx_from_tun.recv().await {
                if packet.len() < 20 {
                    error!("Packet too short to parse IP header");
                    continue;
                }

                let dst_ip = format!(
                    "{}.{}.{}.{}",
                    packet[16], packet[17], packet[18], packet[19]
                );

                let addr = {
                    let ip_to_addr = ip_to_addr_for_tun.lock().await;
                    ip_to_addr.get(&dst_ip).cloned()
                };

                if let Some(addr) = addr {
                    let client = {
                        let udp_clients = udp_clients_for_tun.lock().await;
                        udp_clients.get(&addr).cloned()
                    };

                    if let Some(client) = client {
                        // Получаем и увеличиваем sequence number для этого клиента
                        let sequence = {
                            let mut seq_nums = sequence_numbers.lock().await;
                            let seq = seq_nums.entry(addr).or_insert(0);
                            *seq += 1;
                            *seq
                        };

                        // Шифруем пакет для этого клиента
                        let mut nonce_bytes = [0u8; 12];
                        nonce_bytes[4..].copy_from_slice(&sequence.to_be_bytes());
                        let nonce = GenericArray::from_slice(&nonce_bytes);

                        let mut encrypted_data = packet.clone();
                        if let Err(e) =
                            client
                                .cipher
                                .encrypt_in_place(nonce, b"", &mut encrypted_data)
                        {
                            error!("Encryption failed: {}", e);
                            continue;
                        }

                        // [тип: 1 байт][sequence: 8 байт][зашифрованные данные]
                        let mut data = Vec::with_capacity(1 + 8 + encrypted_data.len());
                        data.push(PACKET_TYPE_DATA);
                        data.extend_from_slice(&sequence.to_be_bytes());
                        data.extend_from_slice(&encrypted_data);

                        // send
                        if let Err(e) = udp_socket_for_tun.send_to(&data, addr).await {
                            error!("Failed to send UDP packet: {}", e);

                            // Если отправка не удалась
                            // Удаляем его sequence number
                            let mut seq_nums = sequence_numbers.lock().await;
                            seq_nums.remove(&addr);
                        }
                    } else {
                        warn!("Client not found for addr: {}", addr);
                    }
                } else {
                    debug!("No client found for IP: {}", dst_ip);
                }
            }
        });

        //  UDP -> TUN
        let udp_clients_for_task = self.udp_clients.clone();
        let udp_socket_for_task = udp_socket.clone();
        let uid_to_key = self.uid_to_key.clone();
        let tx_to_tun = tx_to_tun.clone();
        let ip_to_addr_for_udp = self.ip_to_addr.clone();
        let client_id_to_ip = self.client_id_to_ip.clone();

        tokio::spawn(async move {
            let mut buffer = [0u8; 65536];
            loop {
                match udp_socket_for_task.recv_from(&mut buffer).await {
                    Ok((len, addr)) => {
                        let data = buffer[..len].to_vec();
                        let mut clients = udp_clients_for_task.lock().await;

                        if let Some(client) = clients.get_mut(&addr) {
                            client.last_seen = std::time::Instant::now();

                            // Создаем копию клиента для обработки
                            let client_clone = client.clone();

                            // Освобождаем Mutex перед асинхронной обработкой
                            drop(clients);

                            // Обрабатываем пакет
                            if let Err(e) =
                                Self::handle_udp_data(data.clone(), client_clone, tx_to_tun.clone())
                                    .await
                            {
                                error!("Failed to handle UDP packet: {}", e);
                            }
                        } else {
                            // Освобождаем Mutex перед асинхронной обработкой
                            drop(clients);

                            // Новый клиент
                            if let Err(e) = Self::handle_udp_handshake(
                                udp_clients_for_task.clone(),
                                uid_to_key.clone(),
                                ip_to_addr_for_udp.clone(),
                                client_id_to_ip.clone(),
                                data,
                                addr,
                            )
                            .await
                            {
                                error!("Failed to handle UDP handshake: {}", e);
                            }
                        }
                    }
                    Err(e) => error!("UDP recv error: {}", e),
                }
            }
        });

        // Очистка клиентов
        let udp_clients_for_cleanup = self.udp_clients.clone();
        let ip_to_addr_for_cleanup = self.ip_to_addr.clone();
        let client_id_to_ip_for_cleanup = self.client_id_to_ip.clone();
        let ip_pool_for_cleanup = self.ip_pool.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                let now = std::time::Instant::now();
                let mut udp_clients = udp_clients_for_cleanup.lock().await;
                let mut to_remove = Vec::new();

                for (addr, client) in udp_clients.iter() {
                    if now.duration_since(client.last_seen) > Duration::from_secs(60) {
                        to_remove.push(*addr);
                    }
                }

                for addr in to_remove {
                    if let Some(client) = udp_clients.remove(&addr) {
                        if let Ok(ip) = client.assigned_ip.parse() {
                            ip_pool_for_cleanup.release(ip);
                        }

                        // Удаляем из ip_to_addr
                        let mut ip_to_addr = ip_to_addr_for_cleanup.lock().await;
                        ip_to_addr.remove(&client.assigned_ip);

                        // Удаляем из client_id_to_ip
                        let mut client_id_to_ip = client_id_to_ip_for_cleanup.lock().await;
                        client_id_to_ip.remove(&client.client_id);

                        info!(
                            "Removed inactive client: {} (IP: {})",
                            addr, client.assigned_ip
                        );
                    }
                }
            }
        });

        // TLS Auth
        while let Ok((socket, _)) = tcp_listener.accept().await {
            let acceptor = self.tls_acceptor.clone();
            let ip_pool = self.ip_pool.clone();
            let auth_phrase = self.cfg.auth_phrase.clone();
            let udp_port = self.cfg.udp_port;
            let uid_to_key = self.uid_to_key.clone();
            let client_id_to_ip = self.client_id_to_ip.clone();

            tokio::spawn(async move {
                match acceptor.accept(socket).await {
                    Ok(tls_stream) => {
                        if let Err(e) = handle_tls_auth(
                            tls_stream,
                            ip_pool,
                            auth_phrase,
                            udp_port,
                            uid_to_key,
                            client_id_to_ip,
                        )
                        .await
                        {
                            error!("Error handling TLS auth: {}", e);
                        }
                    }
                    Err(e) => error!("TLS accept failed: {}", e),
                }
            });
        }

        Ok(())
    }

    async fn handle_udp_handshake(
        udp_clients: Arc<Mutex<HashMap<SocketAddr, UdpClient>>>,
        uid_to_key: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        ip_to_addr: Arc<Mutex<HashMap<String, SocketAddr>>>,
        client_id_to_ip: Arc<Mutex<HashMap<String, String>>>,
        data: Vec<u8>,
        addr: SocketAddr,
    ) -> anyhow::Result<()> {
        let message: AnetMessage = Message::decode(Bytes::from(data))?;

        match message.content {
            Some(Content::UdpHandshake(handshake)) => {
                // Проверяем timestamp для защиты от replay-атак
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs();

                if now - handshake.timestamp > 30 {
                    anyhow::bail!("Handshake timestamp too old");
                }
                // Ключ шифрования
                let crypto_key = uid_to_key.lock().await.get(&handshake.client_id).cloned();
                if crypto_key.is_none() {
                    anyhow::bail!("Missing client key for client_id: {}", handshake.client_id);
                }
                // Выделенный IP
                let assigned_ip = client_id_to_ip
                    .lock()
                    .await
                    .get(&handshake.client_id)
                    .cloned();
                if assigned_ip.is_none() {
                    anyhow::bail!("No IP allocated for client_id: {}", handshake.client_id);
                }

                let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&crypto_key.unwrap()));
                let assigned_ip = assigned_ip.unwrap();

                // Добавляем клиента
                let mut clients = udp_clients.lock().await;
                clients.insert(
                    addr,
                    UdpClient {
                        cipher,
                        last_seen: std::time::Instant::now(),
                        client_id: handshake.client_id.clone(),
                        assigned_ip: assigned_ip.clone(),
                    },
                );

                // Добавляем в ip_to_addr
                ip_to_addr.lock().await.insert(assigned_ip.clone(), addr);

                info!("New UDP client connected: {} (IP: {})", addr, assigned_ip);
                Ok(())
            }
            _ => anyhow::bail!("Expected UDP handshake"),
        }
    }

    async fn handle_udp_data(
        data: Vec<u8>,
        client: UdpClient,
        tx_to_tun: mpsc::Sender<Vec<u8>>,
    ) -> anyhow::Result<()> {
        if data.is_empty() {
            return Err(anyhow::anyhow!("Empty UDP packet"));
        }

        let packet_type = data[0];
        let packet_data = &data[1..];

        match packet_type {
            PACKET_TYPE_DATA => {
                //  [sequence: 8 байт][зашифрованные данные]
                if packet_data.len() < 8 {
                    return Err(anyhow::anyhow!("Data packet too short"));
                }

                let sequence_bytes: [u8; 8] = packet_data[0..8].try_into().unwrap();
                let sequence = u64::from_be_bytes(sequence_bytes);
                let encrypted_data = &packet_data[8..];

                // Расшифровываем пакет
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[4..].copy_from_slice(&sequence.to_be_bytes());
                let nonce = GenericArray::from_slice(&nonce_bytes);

                let mut decrypted_data = encrypted_data.to_vec();
                if let Err(e) = client
                    .cipher
                    .decrypt_in_place(nonce, b"", &mut decrypted_data)
                {
                    error!("Decryption failed: {}", e);
                    return Err(anyhow::anyhow!("Decryption failed: {}", e));
                }

                // -> TUN
                if let Err(e) = tx_to_tun.send(decrypted_data.to_vec()).await {
                    error!("Failed to send to TUN: {}", e);
                    return Err(anyhow::anyhow!("Failed to send to TUN: {}", e));
                }

                Ok(())
            }
            PACKET_TYPE_HANDSHAKE => {
                // Handshake
                let message: AnetMessage = Message::decode(Bytes::from(packet_data.to_vec()))?;
                match message.content {
                    Some(Content::UdpHandshake(handshake)) => {
                        error!(
                            "NEVER MUST CALLED! Handshake received: {}",
                            handshake.client_id
                        );
                        Ok(())
                    }
                    _ => Err(anyhow::anyhow!("Expected UDP handshake")),
                }
            }
            _ => Err(anyhow::anyhow!("Unknown packet type: {}", packet_type)),
        }
    }
}

async fn handle_tls_auth(
    tls_stream: TlsStream<TcpStream>,
    ip_pool: IpPool,
    auth_phrase: String,
    udp_port: u32,
    uid_to_key: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    client_id_to_ip: Arc<Mutex<HashMap<String, String>>>,
) -> anyhow::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(tls_stream);

    // Читаем аутентификационный запрос
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let msg_len = u32::from_be_bytes(len_buf) as usize;

    let mut msg_buf = vec![0u8; msg_len];
    reader.read_exact(&mut msg_buf).await?;

    let message: AnetMessage = Message::decode(Bytes::from(msg_buf))?;

    let assigned_ip = match message.content {
        Some(Content::AuthRequest(auth_request)) => {
            if auth_request.key != auth_phrase {
                anyhow::bail!("Auth failed: wrong auth phrase");
            }

            ip_pool.allocate().context("No free IPs")?
        }
        _ => anyhow::bail!("First message must be AuthRequest"),
    };

    let crypto_key = generate_crypto_key().to_vec();
    let client_id = generate_uid();

    // Сохраняем ключ и привязку client_id к IP
    uid_to_key
        .lock()
        .await
        .insert(client_id.clone(), crypto_key.clone());
    client_id_to_ip
        .lock()
        .await
        .insert(client_id.clone(), assigned_ip.to_string());

    let response = AnetMessage {
        content: Some(Content::AuthResponse(AuthResponse {
            ip: assigned_ip.to_string(),
            netmask: ip_pool.netmask.to_string(),
            gateway: ip_pool.gateway.to_string(),
            mtu: ip_pool.mtu as i32,
            crypto_key,
            udp_port,
            client_id: client_id.clone(),
        })),
    };

    let mut response_data = Vec::new();
    response.encode(&mut response_data)?;

    writer
        .write_all(&(response_data.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(&response_data).await?;

    Ok(())
}

fn load_tls_config(cert_path: &str, key_path: &str) -> anyhow::Result<ServerConfig> {
    let cert_file =
        File::open(cert_path).context(format!("Failed to open certificate file: {}", cert_path))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<CertificateDer>, _>>()
        .context("Failed to parse certificate")?;

    let key_file =
        File::open(key_path).context(format!("Failed to open key file: {}", key_path))?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("Failed to read private key")?
        .context("No private key found")?;

    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to create server config")?;

    cfg.alpn_protocols = vec![b"h2".to_vec()];

    Ok(cfg)
}
