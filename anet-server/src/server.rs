use std::collections::HashMap;
use std::{fs::File, io::BufReader, sync::Arc};

use crate::atun_server::TunManager;
use crate::config::Config;
use crate::ip_pool::IpPool;
use crate::utils::{generate_crypto_key, generate_uid};
use anet_common::AuthResponse;
use anet_common::encryption::Cipher;
use anet_common::consts::{MAX_PACKET_SIZE, PACKET_TYPE_DATA, PACKET_TYPE_HANDSHAKE};
use anet_common::protocol::{Message as AnetMessage, message::Content};
use anet_common::tun_params::TunParams;
use anyhow::Context;
use bytes::{BufMut, Bytes, BytesMut};
use log::{debug, error, info, warn};
use prost::Message;
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio::time::{Duration, interval};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tokio_uring::net::UdpSocket;

#[derive(Clone)]
struct UdpClient {
    cipher: Cipher,
    last_seen: std::time::Instant,
    client_id: String,
    assigned_ip: String,
}

pub struct ANetServer {
    tls_acceptor: TlsAcceptor,
    ip_pool: IpPool,
    cfg: Config,
    udp_clients: Arc<Mutex<HashMap<SocketAddr, UdpClient>>>,
    uid_to_key: Arc<Mutex<HashMap<String, [u8; 32]>>>,
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
        let tun_manager = TunManager::new(params, cfg.net.parse()?);
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
            UdpSocket::bind(format!("0.0.0.0:{}", self.cfg.udp_port).parse().unwrap()).await?;

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

        tokio_uring::spawn(async move {
            while let Some(packet) = rx_from_tun.recv().await {
                if packet.len() < 20 {
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
                        let nonce = Cipher::generate_nonce(sequence);

                        // Шифруем пакет
                        match client.cipher.encrypt(&nonce, packet) {
                            Ok(encrypted_data) => {
                                // Формируем пакет: [тип: 1 байт][sequence: 8 байт][зашифрованные данные]
                                let mut data = BytesMut::with_capacity(1 + 8 + encrypted_data.len());
                                data.put_u8(PACKET_TYPE_DATA);
                                data.put_u64(sequence);
                                data.extend_from_slice(&encrypted_data);

                                // Отправляем
                                let (sended, _) = udp_socket_for_tun.send_to(data.to_vec(), addr).await;
                                match sended {
                                    Ok(_) => (),
                                    Err(e) => {
                                        error!("Failed to send UDP packet: {}", e);
                                        let mut seq_nums = sequence_numbers.lock().await;
                                        seq_nums.remove(&addr);
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Encryption failed: {}", e);
                            }
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

        tokio_uring::spawn(async move {
            let mut buffer = vec![0u8; MAX_PACKET_SIZE];
            loop {

                let (result, buf) = udp_socket_for_task.recv_from(buffer).await;
                buffer = buf;

                match result {
                    Ok((len, addr)) => {
                        let data = Bytes::copy_from_slice(&buffer[..len]);
                        let mut clients = udp_clients_for_task.lock().await;

                        if let Some(client) = clients.get_mut(&addr) {
                            client.last_seen = std::time::Instant::now();

                            // Создаем копию клиента для обработки
                            let client_clone = client.clone();

                            // Освобождаем Mutex перед асинхронной обработкой
                            drop(clients);

                            // Обрабатываем пакет
                            if let Err(e) =
                                Self::handle_udp_data(data, client_clone, tx_to_tun.clone()).await
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

        tokio_uring::spawn(async move {
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

            tokio_uring::spawn(async move {
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
        uid_to_key: Arc<Mutex<HashMap<String, [u8; 32]>>>,
        ip_to_addr: Arc<Mutex<HashMap<String, SocketAddr>>>,
        client_id_to_ip: Arc<Mutex<HashMap<String, String>>>,
        data: Bytes,
        addr: SocketAddr,
    ) -> anyhow::Result<()> {
        let message: AnetMessage = Message::decode(data)?;

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

                let cipher = Cipher::new(&crypto_key.unwrap());
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
        data: Bytes,
        client: UdpClient,
        tx_to_tun: mpsc::Sender<Bytes>,
    ) -> anyhow::Result<()> {
        if data.is_empty() {
            return Err(anyhow::anyhow!("Empty UDP packet"));
        }

        let packet_type = data[0];
        let packet_data = data.slice(1..);

        match packet_type {
            PACKET_TYPE_DATA => {
                //  [sequence: 8 байт][зашифрованные данные]
                if packet_data.len() < 8 {
                    return Err(anyhow::anyhow!("Data packet too short"));
                }

                let sequence_bytes: [u8; 8] = packet_data[0..8].try_into()?;
                let sequence = u64::from_be_bytes(sequence_bytes);

                // Расшифровываем пакет
                let nonce = Cipher::generate_nonce(sequence);
                let encrypted_data = packet_data.slice(8..);
                match client.cipher.decrypt(&nonce, encrypted_data) {
                    Ok(decrypted) => {
                        // -> TUN
                        if let Err(e) = tx_to_tun.send(decrypted).await {
                            error!("Failed to send to TUN: {}", e);
                            return Err(anyhow::anyhow!("Failed to send to TUN: {}", e));
                        }
                    }
                    Err(e) => {
                        error!("Decryption failed: {}", e);
                        return Err(anyhow::anyhow!("Decryption failed: {}", e));
                    }
                }
                Ok(())
            }
            PACKET_TYPE_HANDSHAKE => {
                // Handshake
                let message: AnetMessage = Message::decode(packet_data)?;
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
    uid_to_key: Arc<Mutex<HashMap<String, [u8; 32]>>>,
    client_id_to_ip: Arc<Mutex<HashMap<String, String>>>,
) -> anyhow::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(tls_stream);

    // Читаем аутентификационный запрос
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let msg_len = u32::from_be_bytes(len_buf) as usize;

    if msg_len > MAX_PACKET_SIZE {
        return Err(anyhow::anyhow!("msg_len > MAX_PACKET_SIZE"));
    }

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

    let crypto_key = generate_crypto_key();
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
    let crypto_key = crypto_key.to_vec();
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