use crate::config::Config;
use crate::ip_pool::IpPool;
use crate::utils::{extract_ip_dst, generate_crypto_key, generate_seid};
use anet_common::anet_udp_socket::TokioUdpPoller;
use anet_common::atun::TunManager;
use anet_common::consts::MAX_PACKET_SIZE;
use anet_common::encryption::Cipher;
use anet_common::protocol::{AuthResponse, Message as AnetMessage, message::Content};
use anet_common::quic_settings::build_transport_config;
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anet_common::transport;
use anet_common::tun_params::TunParams;
use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use log::{error, info, warn};
use prost::Message;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::udp::RecvMeta;
use quinn::{
    AsyncUdpSocket, Endpoint, EndpointConfig, Incoming, ServerConfig as QuinnServerConfig,
    TokioRuntime, UdpPoller, udp::Transmit,
};
use rustls::ServerConfig as RustlsServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::io::{self, BufReader, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as StdContext, Poll};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

type StreamSender = mpsc::Sender<Bytes>;

#[derive(Clone)]
struct ClientTransportInfo {
    cipher: Arc<Cipher>,
    addr: Option<SocketAddr>,
    sequence: Arc<AtomicU64>,
    assigned_ip: String,
    session_id: String,
    session_id_bytes: [u8; 16],
    handshake_received: bool,
}

// Упрощенный MultiKeyAnetUdpSocket - используем ту же структуру клиентов что и ANetServer
struct MultiKeyAnetUdpSocket {
    io: Arc<UdpSocket>,
    clients: Arc<Mutex<HashMap<String, ClientTransportInfo>>>, // Теперь используем String ключи для совместимости
    pending_handshakes: Arc<Mutex<HashMap<SocketAddr, String>>>, // Сохраняем IP -> session_id mapping
}

impl MultiKeyAnetUdpSocket {
    fn new(io: Arc<UdpSocket>, clients: Arc<Mutex<HashMap<String, ClientTransportInfo>>>) -> Self {
        Self {
            io,
            clients,
            pending_handshakes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Обрабатывает входящий handshake
    fn handle_handshake(&self, remote_addr: SocketAddr, packet_data: &[u8]) -> Option<String> {
        let clients_guard = self.clients.lock().expect("Client mutex poisoned");

        info!("Processing handshake from {}, available clients: {}", remote_addr, clients_guard.len());

        // Пробуем все известные клиенты для расшифровки handshake
        for (session_id_str, client_info) in clients_guard.iter() {
            info!("Trying client with session_id: {}", session_id_str);

            if let Ok((_client_id, timestamp)) =
                transport::unwrap_handshake(&client_info.cipher, client_info.session_id_bytes, packet_data)
            {
                // Проверяем timestamp для защиты от replay атак
                let current_time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                if current_time.abs_diff(timestamp) > 30 {
                    warn!("Handshake timestamp too old from {}: {} vs {}", remote_addr, timestamp, current_time);
                    continue;
                }

                info!("Handshake received from {} for session {}", remote_addr, session_id_str);

                // Сохраняем сопоставление адреса и session_id
                {
                    let mut pending = self.pending_handshakes.lock().unwrap();
                    pending.insert(remote_addr, session_id_str.clone());
                }

                return Some(session_id_str.clone());
            } else {
                info!("Failed to decrypt with session_id: {}", session_id_str);
            }
        }

        warn!("No matching session found for handshake from {}", remote_addr);
        None
    }
}

impl Debug for MultiKeyAnetUdpSocket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiKeyAnetUdpSocket")
            .field("local_addr", &self.io.local_addr())
            .finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for MultiKeyAnetUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(TokioUdpPoller {
            io: self.io.clone(),
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let destination_addr = transmit.destination;
        let seq;
        let cipher;
        let session_id_bytes;

        let clients_guard = self.clients.lock().expect("Client mutex poisoned");

        // Сначала ищем по pending handshakes
        let pending_guard = self.pending_handshakes.lock().unwrap();
        if let Some(session_id_str) = pending_guard.get(&destination_addr) {
            if let Some(client_info) = clients_guard.get(session_id_str) {
                seq = client_info.sequence.fetch_add(1, Ordering::Relaxed);
                cipher = client_info.cipher.clone();
                session_id_bytes = client_info.session_id_bytes;
            } else {
                info!("1 No client found for destination: {}", destination_addr);
                return Ok(());
            }
        } else {
            // Ищем клиента по адресу
            let client_info = clients_guard.values().find(|info| info.addr == Some(destination_addr));

            if let Some(info) = client_info {
                seq = info.sequence.fetch_add(1, Ordering::Relaxed);
                cipher = info.cipher.clone();
                session_id_bytes = info.session_id_bytes;
            } else {
                info!("2 No client found for destination: {}", destination_addr);
                return Ok(());
            }
        }

        let packet = transport::wrap_packet(&cipher, session_id_bytes, seq, Bytes::copy_from_slice(transmit.contents));

        match packet {
            Ok(wrapped_packet) => match self.io.try_send_to(&wrapped_packet, destination_addr) {
                Ok(_) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
                Err(e) => {
                    error!("MultiKeyAnetUdpSocket failed to send: {}", e);
                    Ok(())
                }
            },
            Err(e) => {
                error!("Failed to wrap outgoing packet: {}", e);
                Ok(())
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut StdContext<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut recv_buf = vec![0u8; 65535];
        let mut read_buf = tokio::io::ReadBuf::new(&mut recv_buf);

        match self.io.poll_recv_from(cx, &mut read_buf) {
            Poll::Ready(Ok(remote_addr)) => {
                let filled_len = read_buf.filled().len();
                if filled_len == 0 {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }

                let packet_slice = &recv_buf[..filled_len];

                // Сначала проверяем, знаем ли мы уже этот адрес
                let session_id_opt = {
                    let pending_guard = self.pending_handshakes.lock().unwrap();
                    pending_guard.get(&remote_addr).cloned()
                };

                let mut unwrapped_data: Option<Bytes> = None;
                let mut found_session_id = None;

                if let Some(session_id_str) = session_id_opt {
                    // Уже есть сопоставление - пробуем расшифровать как data packet
                    let clients_guard = self.clients.lock().expect("Client mutex poisoned");
                    if let Some(client_info) = clients_guard.get(&session_id_str) {
                        if let Ok(data_packet) =
                            transport::unwrap_packet(&client_info.cipher, client_info.session_id_bytes, packet_slice)
                        {
                            unwrapped_data = Some(data_packet);
                            found_session_id = Some(session_id_str);
                        }
                    }
                } else {
                    // Нет сопоставления - пробуем обработать как handshake
                    if let Some(session_id_str) = self.handle_handshake(remote_addr, packet_slice) {
                        info!("Handshake processed for: {}, SEID: {}", remote_addr, session_id_str);
                        cx.waker().wake_by_ref();
                        return Poll::Pending; // Handshake пакет не содержит QUIC данных
                    }

                    // Если не handshake, пробуем все известные клиенты для data packets
                    let clients_guard = self.clients.lock().expect("Client mutex poisoned");
                    for (session_id_str, client_info) in clients_guard.iter() {
                        if let Ok(data_packet) =
                            transport::unwrap_packet(&client_info.cipher, client_info.session_id_bytes, packet_slice)
                        {
                            unwrapped_data = Some(data_packet);
                            found_session_id = Some(session_id_str.clone());

                            // Обновляем адрес клиента
                            {
                                let mut pending = self.pending_handshakes.lock().unwrap();
                                pending.insert(remote_addr, session_id_str.clone());
                            }
                            break;
                        }
                    }
                }

                if let (Some(data), Some(session_id_str)) = (unwrapped_data, found_session_id) {
                    if bufs.is_empty() {
                        return Poll::Ready(Ok(0));
                    }

                    let copy_len = std::cmp::min(data.len(), bufs[0].len());
                    bufs[0][..copy_len].copy_from_slice(&data[..copy_len]);

                    meta[0] = RecvMeta {
                        addr: remote_addr,
                        len: copy_len,
                        stride: copy_len,
                        dst_ip: None,
                        ecn: None,
                    };

                    // Обновляем адрес в основной структуре клиентов
                    {
                        let mut clients_guard = self.clients.lock().expect("Client mutex poisoned");
                        if let Some(client_info) = clients_guard.get_mut(&session_id_str) {
                            client_info.addr = Some(remote_addr);
                        }
                    }

                    Poll::Ready(Ok(1))
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Poll::Ready(Err(e)) => {
                error!("Error receiving from socket: {}", e);
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
}

pub struct ANetServer {
    cfg: Config,
    tls_acceptor: TlsAcceptor,
    ip_pool: IpPool,
    tun_manager: TunManager,
    // Теперь используем единую структуру клиентов
    clients: Arc<Mutex<HashMap<String, ClientTransportInfo>>>,
    quic_router: Arc<TokioMutex<HashMap<String, StreamSender>>>,
}

impl ANetServer {
    pub fn new(cfg: &Config) -> Result<Self> {
        let tls_cfg =
            load_rustls_config_for_auth(cfg.server.cert.as_str(), cfg.server.key.as_str())?;
        let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));

        let tun_params = TunParams {
            netmask: cfg.network.mask.parse()?,
            gateway: cfg.network.gateway.parse()?,
            address: cfg.network.self_ip.parse()?,
            name: cfg.network.if_name.clone(),
            mtu: cfg.network.mtu,
            network: Some(cfg.network.net.parse()?),
        };
        let tun_manager = TunManager::new(tun_params)?;

        let ip_pool = IpPool::new(
            cfg.network.net.parse()?,
            cfg.network.mask.parse()?,
            cfg.network.gateway.parse()?,
            cfg.network.self_ip.parse()?,
            cfg.network.mtu,
        );

        Ok(Self {
            cfg: cfg.clone(),
            tls_acceptor: acceptor,
            ip_pool,
            clients: Arc::new(Mutex::new(HashMap::new())),
            tun_manager,
            quic_router: Arc::new(TokioMutex::new(HashMap::new())),
        })
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let auth_task = self.run_auth_listener();
        let vpn_task = self.run_quic_vpn_server();
        tokio::try_join!(auth_task, vpn_task)?;
        Ok(())
    }

    async fn run_auth_listener(&self) -> Result<()> {
        let listener = TcpListener::bind(self.cfg.server.bind_to.as_str()).await?;
        info!(
            "Authentication server listening on {}",
            self.cfg.server.bind_to
        );

        while let Ok((socket, addr)) = listener.accept().await {
            let acceptor = self.tls_acceptor.clone();
            let ip_pool = self.ip_pool.clone();
            let clients = self.clients.clone();
            let auth_phrase = self.cfg.server.auth_phrase.clone();
            let udp_port = self.cfg.server.udp_port;

            tokio::spawn(async move {
                if let Err(e) = handle_auth_connection(
                    socket,
                    acceptor,
                    ip_pool.clone(),
                    clients,
                    auth_phrase,
                    udp_port,
                )
                    .await
                {
                    error!("[{}] Auth connection failed: {}", addr, e);
                }
            });
        }
        Ok(())
    }

    async fn run_quic_vpn_server(&self) -> Result<()> {
        let udp_listen_addr = format!(
            "{}:{}",
            self.cfg.server.bind_to.split(':').next().unwrap(),
            self.cfg.server.udp_port
        );
        let real_socket = Arc::new(UdpSocket::bind(&udp_listen_addr).await?);

        // Используем единую структуру клиентов
        let anet_socket = Arc::new(MultiKeyAnetUdpSocket::new(
            real_socket,
            self.clients.clone(),
        ));

        let server_config = self.build_quinn_server_config()?;
        let endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(server_config),
            anet_socket,
            Arc::new(TokioRuntime),
        )?;
        info!(
            "QUIC VPN server listening via ANET transport on {}",
            udp_listen_addr
        );

        let (tx_to_tun, rx_from_tun) = self.tun_manager.run().await?;
        self.tun_manager
            .setup_tun_routing(self.cfg.server.external_if.as_str())
            .await?;

        let quic_router = self.quic_router.clone();

        let incoming_task = tokio::spawn(handle_incoming_quic(
            endpoint.clone(),
            tx_to_tun.clone(),
            self.clients.clone(),
            quic_router.clone(),
            self.ip_pool.clone(),
        ));

        let router_task = tokio::spawn(route_tun_to_quic(rx_from_tun, quic_router.clone()));

        let _ = tokio::try_join!(incoming_task, router_task)?;

        Ok(())
    }

    fn build_quinn_server_config(&self) -> Result<QuinnServerConfig> {
        let (certs, key) =
            load_cert_and_key(self.cfg.server.cert.as_str(), self.cfg.server.key.as_str())?;

        let server_crypto = RustlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        let quic_crypto = QuicServerConfig::try_from(Arc::new(server_crypto))?;

        let mut cfg = QuinnServerConfig::with_crypto(Arc::new(quic_crypto));

        let mtu = self.cfg.network.mtu;
        let transport_config = build_transport_config(&self.cfg.quic_transport, mtu)?;
        cfg.transport_config(Arc::new(transport_config));

        Ok(cfg)
    }
}

async fn handle_auth_connection(
    socket: TcpStream,
    acceptor: TlsAcceptor,
    ip_pool: IpPool,
    clients: Arc<Mutex<HashMap<String, ClientTransportInfo>>>,
    auth_phrase: String,
    udp_port: u32,
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
    let session_id = generate_seid();

    // Декодируем session_id в байты для транспортного уровня
    let session_id_bytes = general_purpose::STANDARD.decode(&session_id)
        .context("Failed to decode session_id")?;
    if session_id_bytes.len() != 16 {
        anyhow::bail!("Invalid session_id length, expected 16 bytes, got {}", session_id_bytes.len());
    }
    let mut session_id_bytes_array = [0u8; 16];
    session_id_bytes_array.copy_from_slice(&session_id_bytes[..16]);

    let client_ip_str = assigned_ip.to_string();

    let info = ClientTransportInfo {
        cipher: Arc::new(Cipher::new(&crypto_key)),
        addr: None,
        sequence: Arc::new(AtomicU64::new(0)),
        assigned_ip: client_ip_str.clone(),
        session_id: session_id.clone(),
        session_id_bytes: session_id_bytes_array,
        handshake_received: false,
    };

    clients
        .lock()
        .expect("Client mutex poisoned")
        .insert(session_id.clone(), info);


    let response = AnetMessage {
        content: Some(Content::AuthResponse(AuthResponse {
            ip: client_ip_str.clone(),
            netmask: ip_pool.netmask.to_string(),
            gateway: ip_pool.gateway.to_string(),
            mtu: ip_pool.mtu as i32,
            crypto_key: crypto_key.to_vec(),
            udp_port,
            session_id: session_id.clone(),
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

async fn handle_incoming_quic(
    endpoint: Endpoint,
    tx_to_tun: StreamSender,
    clients_transport_info: Arc<Mutex<HashMap<String, ClientTransportInfo>>>,
    quic_router: Arc<TokioMutex<HashMap<String, StreamSender>>>,
    ip_pool: IpPool,
) -> Result<()> {
    while let Some(conn) = endpoint.accept().await {
        let fut = handle_connection(
            conn,
            tx_to_tun.clone(),
            clients_transport_info.clone(),
            quic_router.clone(),
            ip_pool.clone(),
        );
        tokio::spawn(async move {
            if let Err(e) = fut.await {
                error!("QUIC connection failed: {}", e);
            }
        });
    }
    Ok(())
}

async fn handle_connection(
    incoming: Incoming,
    tx_to_tun: StreamSender,
    clients_transport_info: Arc<Mutex<HashMap<String, ClientTransportInfo>>>,
    quic_router: Arc<TokioMutex<HashMap<String, StreamSender>>>,
    ip_pool: IpPool,
) -> Result<()> {
    let connection = incoming.await?;
    let remote_addr = connection.remote_address();
    info!("QUIC negotiation started with peer: {}", remote_addr);

    let (send_stream, recv_stream) = connection.accept_bi().await?;

    let established_remote_addr = connection.remote_address();

    // Ищем клиента по адресу
    let client = {
        let clients = clients_transport_info.lock().expect("Client mutex poisoned");
        clients
            .values()
            .find(|info| info.addr == Some(established_remote_addr))
            .map(|info| info.clone())
    };

    let client = match client {
        Some(client) => client,
        None => {
            error!(
                "QUIC connection established but client VPN IP not resolved from transport info (Final Addr: {}). Connection rejected.",
                established_remote_addr
            );
            connection.close(0u32.into(), b"Transport layer association failed");
            return Err(anyhow::anyhow!("IP not found for QUIC connection"));
        }
    };

    info!(
        "QUIC session accepted for client VPN IP: {} ({}), SEID: {}",
        client.assigned_ip, established_remote_addr, client.session_id
    );

    let (tx_router, mut rx_router) = mpsc::channel::<Bytes>(1024); // Увеличиваем буфер

    // Добавляем клиента в роутер
    {
        let mut router = quic_router.lock().await;
        router.insert(client.assigned_ip.clone(), tx_router);
        info!("Client {} added to quic_router. Total clients: {}",
              client.assigned_ip, router.len());
    }

    let ip_for_log_tx = client.assigned_ip.clone();

    // Задача: отправка данных из роутера в QUIC стрим
    let tx_task = tokio::spawn(async move {
        let mut stream = send_stream;

        while let Some(packet) = rx_router.recv().await {

            // Оборачиваем пакет в транспортный фрейм
            let framed_packet = frame_packet(packet);

            if let Err(e) = stream.write_all(&framed_packet).await {
                error!(
                    "QUIC stream write failed for {}  {}",
                    ip_for_log_tx, e
                );
                break;
            }

            // Flush для гарантии отправки
            if let Err(e) = stream.flush().await {
                error!("QUIC stream flush failed for {}: {}", ip_for_log_tx, e);
                break;
            }

        }

        if let Err(e) = stream.finish() {
            error!("Error finishing QUIC stream for {}: {}", ip_for_log_tx, e);
        }

    });

    // Задача: чтение данных из QUIC стрима в TUN
    let tx_to_tun_for_rx = tx_to_tun.clone();
    let ip_for_log_rx = client.assigned_ip.clone();
    let rx_task = tokio::spawn(async move {
        let mut stream = recv_stream;

        loop {
            match read_next_packet(&mut stream).await {
                Ok(Some(packet)) => {

                    if let Err(e) = tx_to_tun_for_rx.send(packet).await {
                        error!(
                            "TUN channel write failed for {}  {}",
                            ip_for_log_rx,  e
                        );
                        break;
                    }
                }
                Ok(None) => {
                    break;
                }
                Err(e) => {
                    error!(
                        "Error reading QUIC stream from {} {}",
                        ip_for_log_rx, e
                    );
                    break;
                }
            }
        }

    });

    tokio::select! {
        _ = tx_task => info!("TX stream task finished for {}.", client.assigned_ip),
        _ = rx_task => info!("RX stream task finished for {}.", client.assigned_ip),
        _ = connection.closed() => info!("QUIC connection closed for {}.", client.assigned_ip),
    }

    // Очистка
    let assigned_ip_clone = client.assigned_ip.clone();
    let session_id_clone = client.session_id.clone();

    {
        let mut router = quic_router.lock().await;
        router.remove(&client.assigned_ip);
        info!("Removed client {} from quic_router. Remaining clients: {}",
              client.assigned_ip, router.len());
    }

    clients_transport_info
        .lock()
        .expect("Client mutex poisoned")
        .remove(&session_id_clone);

    if let Ok(ip_addr) = assigned_ip_clone.parse() {
        ip_pool.release(ip_addr);
    }

    Ok(())
}

// В функции route_tun_to_quic заменим:
async fn route_tun_to_quic(
    mut rx_from_tun: mpsc::Receiver<Bytes>,
    quic_router: Arc<TokioMutex<HashMap<String, StreamSender>>>,
) -> Result<()> {

    while let Some(packet) = rx_from_tun.recv().await {

        // Проверяем что это IP пакет
        if packet.len() < 20 {
            error!("Dropping non-IP packet: {} bytes", packet.len());
            continue;
        }

        let version = packet[0] >> 4;
        if version != 4 && version != 6 {
            warn!("Dropping packet with unknown IP version: {}", version);
            continue;
        }

        let dst_ip = match extract_ip_dst(&packet) {
            Some(ip) => ip.to_string(),
            None => {
                warn!("Cannot extract destination IP from packet");
                continue;
            }
        };


        let sender_opt = {
            let router = quic_router.lock().await;
            router.get(&dst_ip).cloned()
        };

        if let Some(sender) = sender_opt {
            match sender.send(packet).await {
                Ok(()) => {
                }
                Err(e) => {
                    warn!("Failed to route packet to {}: {}", dst_ip, e);
                }
            }
        } else {
            warn!("Dropping packet to {}: no active QUIC session. Available sessions: {:?}",
                      dst_ip, quic_router.lock().await.keys().collect::<Vec<_>>());
        }

    }

    Ok(())
}

fn load_rustls_config_for_auth(
    cert_pem: &str,
    key_pem: &str,
) -> anyhow::Result<RustlsServerConfig> {
    let mut cert_reader = BufReader::new(cert_pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<CertificateDer>, std::io::Error>>()
        .context("Failed to read or parse certificates from PEM string")?;

    let mut key_reader = BufReader::new(key_pem.as_bytes());
    let key_der = rustls_pemfile::private_key(&mut key_reader)?
        .context("No private key found in PEM string")?;
    let key: PrivateKeyDer<'static> = key_der.into();

    let mut cfg = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"h2".to_vec()];

    Ok(cfg)
}

fn load_cert_and_key(
    cert_pem: &str,
    key_pem: &str,
) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let mut cert_reader = BufReader::new(cert_pem.as_bytes());
    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<_, std::io::Error>>()
        .context("Failed to read or parse certificates from PEM string")?;

    let mut key_reader = BufReader::new(key_pem.as_bytes());
    let key_der = rustls_pemfile::private_key(&mut key_reader)?
        .context("No private key found in PEM string")?;
    let key: PrivateKeyDer<'static> = key_der.into();

    Ok((certs, key))
}
