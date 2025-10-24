use std::collections::HashMap;
use std::{fs::File, io::BufReader, sync::Arc};

use crate::atun_server::TunManager;
use crate::config::Config;
use crate::ip_pool::IpPool;
use crate::utils::{generate_crypto_key, generate_uid};
use anet_common::AuthResponse;
use anet_common::consts::{
    BATCH_SEND_SIZE, MAX_PACKET_SIZE, PACKET_TYPE_DATA, PACKET_TYPE_PING, PACKET_TYPE_PONG,
    UDP_HANDSHAKE_TIMEOUT_SECONDS, PING_PONG_INTERVAL
};
use anet_common::encryption::Cipher;
use anet_common::protocol::{Message as AnetMessage, message::Content};
use anet_common::tun_params::TunParams;
use anyhow::Context;
use bytes::{Bytes, BytesMut};
use log::{error, info, debug};
use prost::Message;
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio::time::{Duration, interval};
use tokio_rustls::TlsAcceptor;

#[derive(Clone)]
struct UdpClient {
    cipher: Cipher,
    last_seen: std::time::Instant,
    client_id: String,
    addr: SocketAddr,
    sequence: u64,
    pending_ping: bool, // Ожидает ли ответ на PING
}

pub struct ANetServer {
    tls_acceptor: TlsAcceptor,
    ip_pool: IpPool,
    cfg: Config,
    tun_manager: TunManager,
    uid_to_key: Arc<Mutex<HashMap<String, [u8; 32]>>>,
    client_id_to_ip: Arc<Mutex<HashMap<String, String>>>,
    clients_by_ip: Arc<Mutex<HashMap<String, UdpClient>>>,
    addr_to_ip: Arc<Mutex<HashMap<SocketAddr, String>>>,
}

impl ANetServer {
    pub fn new(cfg: &Config) -> anyhow::Result<Self> {
        let tls_cfg = load_tls_config(cfg.cert_path.as_str(), cfg.key_path.as_str())?;
        let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));
        let params = TunParams {
            netmask: cfg.mask.parse()?,
            gateway: cfg.gateway.parse()?,
            address: cfg.self_ip.parse()?,
            name: cfg.if_name.clone(),
            mtu: cfg.mtu,
        };
        let tun_manager = TunManager::new(params, cfg.net.parse()?);
        let ip_pool = IpPool::new(
            cfg.net.parse()?,
            cfg.mask.parse()?,
            cfg.gateway.parse()?,
            cfg.self_ip.parse()?,
            cfg.mtu,
        );
        info!("Server TUN configuration: {}", tun_manager.get_info());

        Ok(Self {
            tls_acceptor: acceptor,
            ip_pool,
            cfg: cfg.clone(),
            tun_manager,
            uid_to_key: Arc::new(Mutex::new(HashMap::new())),
            client_id_to_ip: Arc::new(Mutex::new(HashMap::new())),
            clients_by_ip: Arc::new(Mutex::new(HashMap::new())),
            addr_to_ip: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let tcp_listener = TcpListener::bind(self.cfg.bind_to.as_str()).await?;
        let udp_addr = self.cfg.bind_to.as_str().split(':').collect::<Vec<&str>>()[0];
        let udp_socket = UdpSocket::bind(format!("{}:{}", udp_addr, self.cfg.udp_port)).await?;

        info!(
            "Bind on {} for TCP, and {}:{} for UDP",
            self.cfg.bind_to.as_str(),
            udp_addr,
            self.cfg.udp_port
        );
        let udp_socket = Arc::new(udp_socket);
        let (tx_to_tun, mut rx_from_tun) = self.tun_manager.run().await?;

        self.tun_manager
            .setup_tun_routing(self.cfg.external_if.as_str())
            .await?;

        // TUN -> UDP
        let udp_socket_for_tun = udp_socket.clone();
        let clients_by_ip_for_tun = self.clients_by_ip.clone();
        tokio::spawn(async move {
            let mut batch_to_send: Vec<(Bytes, SocketAddr)> = Vec::with_capacity(BATCH_SEND_SIZE);
            while let Some(packet) = rx_from_tun.recv().await {
                batch_to_send.clear();
                if let Some(processed) =
                    process_packet_for_sending(&clients_by_ip_for_tun, packet).await
                {
                    batch_to_send.push(processed);
                }

                for _ in 0..(BATCH_SEND_SIZE - 1) {
                    match rx_from_tun.try_recv() {
                        Ok(packet) => {
                            if let Some(processed) =
                                process_packet_for_sending(&clients_by_ip_for_tun, packet).await
                            {
                                batch_to_send.push(processed);
                            }
                        }
                        Err(_) => break,
                    }
                }

                for (data, addr) in &batch_to_send {
                    if let Err(e) = udp_socket_for_tun.send_to(data, *addr).await {
                        error!("Failed to send UDP packet to {}: {}", addr, e);
                    }
                }
            }
        });

        // UDP -> TUN
        let clients_by_ip_for_udp = self.clients_by_ip.clone();
        let addr_to_ip_for_udp = self.addr_to_ip.clone();
        let uid_to_key_for_udp = self.uid_to_key.clone();
        let tx_to_tun_for_udp = tx_to_tun.clone();
        let client_id_to_ip_for_udp = self.client_id_to_ip.clone();
        let udp_socket_for_task = udp_socket.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; MAX_PACKET_SIZE];
            loop {
                match udp_socket_for_task.recv_from(&mut buffer).await {
                    Ok((len, addr)) => {
                        let data = Bytes::copy_from_slice(&buffer[..len]);

                        let client_ip = { addr_to_ip_for_udp.lock().await.get(&addr).cloned() };

                        if let Some(ip) = client_ip {
                            let cipher = {
                                let mut clients = clients_by_ip_for_udp.lock().await;

                                if let Some(client) = clients.get_mut(&ip) {
                                    client.last_seen = std::time::Instant::now();
                                    Some(client.cipher.clone())
                                } else {
                                    None
                                }
                            };
                            if let Some(cipher) = cipher {
                                if let Err(e) =
                                    Self::handle_udp_data(data, cipher, tx_to_tun_for_udp.clone(), clients_by_ip_for_udp.clone(), ip).await
                                {
                                    error!("Failed to handle UDP packet from {}: {}", addr, e);
                                }
                            }
                        } else if let Err(e) = Self::handle_udp_handshake(
                            clients_by_ip_for_udp.clone(),
                            addr_to_ip_for_udp.clone(),
                            uid_to_key_for_udp.clone(),
                            client_id_to_ip_for_udp.clone(),
                            data,
                            addr,
                        )
                            .await
                        {
                            error!("Failed to handle UDP handshake from {}: {}", addr, e);
                        }
                    }
                    Err(e) => error!("UDP recv error: {}", e),
                }
            }
        });

        // Задача для отправки PING и проверки PONG
        let clients_by_ip_for_ping = self.clients_by_ip.clone();
        let addr_to_ip_for_ping = self.addr_to_ip.clone();
        let ip_pool_for_ping = self.ip_pool.clone();
        let udp_socket_for_ping = udp_socket.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(PING_PONG_INTERVAL));
            loop {
                interval.tick().await;

                let mut clients_to_remove = Vec::new();
                let mut ping_sent_count = 0;
                let mut pong_pending_count = 0;

                {
                    let mut clients_by_ip = clients_by_ip_for_ping.lock().await;

                    for (ip, client) in clients_by_ip.iter_mut() {
                        if client.pending_ping {
                            // Клиент не ответил на предыдущий PING
                            pong_pending_count += 1;
                            clients_to_remove.push((ip.clone(), client.addr, client.client_id.clone()));
                            info!("Client {} (IP: {}) did not respond to PING", client.addr, ip);
                        } else {
                            // Отправляем новый PING
                            let ping_packet = vec![PACKET_TYPE_PING];
                            if let Err(e) = udp_socket_for_ping.send_to(&ping_packet, client.addr).await {
                                error!("Failed to send PING to {}: {}", client.addr, e);
                                clients_to_remove.push((ip.clone(), client.addr, client.client_id.clone()));
                            } else {
                                client.pending_ping = true;
                                ping_sent_count += 1;
                                debug!("Sent PING to client {} (IP: {})", client.addr, ip);
                            }
                        }
                    }
                }

                // Логируем статистику
                if ping_sent_count > 0 || pong_pending_count > 0 {
                    info!("PING/PONG: sent {} PINGs, {} clients pending PONG", ping_sent_count, pong_pending_count);
                }

                // Удаляем клиентов, которые не ответили на PING
                if !clients_to_remove.is_empty() {
                    let mut clients_by_ip = clients_by_ip_for_ping.lock().await;
                    let mut addr_to_ip = addr_to_ip_for_ping.lock().await;

                    for (ip_str, addr, client_id) in &clients_to_remove {
                        clients_by_ip.remove(ip_str);
                        addr_to_ip.remove(addr);

                        if let Ok(ip_addr) = ip_str.parse() {
                            ip_pool_for_ping.release(ip_addr);
                        }

                        info!("Removed inactive client: {} (IP: {}, ClientID: {})", addr, ip_str, client_id);
                    }

                    info!("Removed {} inactive clients", clients_to_remove.len());
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
                if let Err(e) = handle_tls_auth(
                    socket,
                    acceptor,
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
            });
        }

        Ok(())
    }

    async fn handle_udp_handshake(
        clients_by_ip: Arc<Mutex<HashMap<String, UdpClient>>>,
        addr_to_ip: Arc<Mutex<HashMap<SocketAddr, String>>>,
        uid_to_key: Arc<Mutex<HashMap<String, [u8; 32]>>>,
        client_id_to_ip: Arc<Mutex<HashMap<String, String>>>,
        data: Bytes,
        addr: SocketAddr,
    ) -> anyhow::Result<()> {
        let message: AnetMessage = Message::decode(data)?;
        if let Some(Content::UdpHandshake(handshake)) = message.content {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();

            if now.saturating_sub(handshake.timestamp) > UDP_HANDSHAKE_TIMEOUT_SECONDS {
                anyhow::bail!("Handshake timestamp too old from {}", addr);
            }

            let crypto_key = { uid_to_key.lock().await.get(&handshake.client_id).cloned() };

            let assigned_ip = {
                client_id_to_ip
                    .lock()
                    .await
                    .get(&handshake.client_id)
                    .cloned()
            };

            if let (Some(key), Some(ip)) = (crypto_key, assigned_ip) {
                let client = UdpClient {
                    cipher: Cipher::new(&key),
                    last_seen: std::time::Instant::now(),
                    client_id: handshake.client_id.clone(),
                    addr,
                    sequence: 0,
                    pending_ping: false,
                };

                clients_by_ip.lock().await.insert(ip.clone(), client);
                addr_to_ip.lock().await.insert(addr, ip.clone());

                info!("New UDP client connected: {} (IP: {})", addr, ip);

                Ok(())
            } else {
                anyhow::bail!("Client info not found for handshake from {}", addr)
            }
        } else {
            anyhow::bail!("Expected UDP handshake from {}", addr)
        }
    }

    async fn handle_udp_data(
        data: Bytes,
        cipher: Cipher,
        tx_to_tun: mpsc::Sender<Bytes>,
        clients_by_ip: Arc<Mutex<HashMap<String, UdpClient>>>,
        client_ip: String,
    ) -> anyhow::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let packet_type = data[0];

        match packet_type {
            PACKET_TYPE_PONG => {
                // Обработка PONG от клиента
                 let mut clients = clients_by_ip.lock().await;
                    if let Some(client) = clients.get_mut(&client_ip) {
                    client.pending_ping = false;
                    client.last_seen = std::time::Instant::now();
                    info!("Received PONG from client {} (IP: {})", client.addr, client_ip);

                }
                Ok(())
            }
            PACKET_TYPE_DATA => {
                if data.len() < 9 {
                    anyhow::bail!("Data packet too short");
                }

                let sequence = u64::from_be_bytes(data[1..9].try_into()?);
                let encrypted_data = data.slice(9..);
                let nonce = Cipher::generate_nonce(sequence);
                let decrypted = cipher.decrypt(&nonce, encrypted_data)?;

                tx_to_tun.send(decrypted).await?;
                Ok(())
            }
            _ => anyhow::bail!("Unexpected packet type"),
        }
    }
}

async fn handle_tls_auth(
    socket: TcpStream,
    acceptor: TlsAcceptor,
    ip_pool: IpPool,
    auth_phrase: String,
    udp_port: u32,
    uid_to_key: Arc<Mutex<HashMap<String, [u8; 32]>>>,
    client_id_to_ip: Arc<Mutex<HashMap<String, String>>>,
) -> anyhow::Result<()> {
    let tls_stream = acceptor.accept(socket).await?;

    let (mut reader, mut writer) = tokio::io::split(tls_stream);

    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;

    let msg_len = u32::from_be_bytes(len_buf) as usize;

    if msg_len > MAX_PACKET_SIZE {
        anyhow::bail!("msg_len > MAX_PACKET_SIZE");
    }

    let mut msg_buf = vec![0u8; msg_len];
    reader.read_exact(&mut msg_buf).await?;

    let message: AnetMessage = Message::decode(Bytes::from(msg_buf))?;

    let assigned_ip = match message.content {
        Some(Content::AuthRequest(req)) if req.key == auth_phrase => {
            ip_pool.allocate().context("No free IPs available")?
        }
        _ => anyhow::bail!("Authentication failed"),
    };

    let crypto_key = generate_crypto_key();
    let client_id = generate_uid();

    uid_to_key
        .lock()
        .await
        .insert(client_id.clone(), crypto_key);
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
            crypto_key: crypto_key.to_vec(),
            udp_port,
            client_id,
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
        File::open(cert_path).context(format!("Failed to open cert file: {}", cert_path))?;

    let certs = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<CertificateDer>, _>>()?;

    let key_file =
        File::open(key_path).context(format!("Failed to open key file: {}", key_path))?;

    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))?
        .context("No private key found in file")?;

    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"h2".to_vec()];

    Ok(cfg)
}

async fn process_packet_for_sending(
    clients_by_ip: &Arc<Mutex<HashMap<String, UdpClient>>>,
    packet: Bytes,
) -> Option<(Bytes, SocketAddr)> {
    if packet.len() < 20 {
        return None;
    }

    let dst_ip = format!(
        "{}.{}.{}.{}",
        packet[16], packet[17], packet[18], packet[19]
    );

    let (cipher, sequence, addr) = {
        let mut clients_lock = clients_by_ip.lock().await;
        if let Some(client) = clients_lock.get_mut(&dst_ip) {
            client.sequence += 1;
            (client.cipher.clone(), client.sequence, client.addr)
        } else {
            return None;
        }
    };

    let nonce = Cipher::generate_nonce(sequence);

    match cipher.encrypt(&nonce, packet) {
        Ok(encrypted_data) => {
            let mut data = BytesMut::with_capacity(1 + 8 + encrypted_data.len());
            data.extend_from_slice(&[PACKET_TYPE_DATA]);
            data.extend_from_slice(&sequence.to_be_bytes());
            data.extend_from_slice(&encrypted_data);
            Some((data.freeze(), addr))
        }
        Err(e) => {
            error!("Encryption failed for client at {}: {}", addr, e);
            None
        }
    }
}