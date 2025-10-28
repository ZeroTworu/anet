use std::io::IoSliceMut;
use crate::config::Config;
use crate::ip_pool::IpPool;
use rustls::ServerConfig as RustlsServerConfig;
use crate::utils::{extract_ip_dst, generate_crypto_key, generate_uid};
use anyhow::{anyhow, Context, Result};
use anet_common::atun::TunManager;
use anet_common::encryption::Cipher;
use anet_common::protocol::{message::Content, AuthResponse, Message as AnetMessage};
use anet_common::anet_udp_socket::{AnetUdpSocket, TokioUdpPoller};
use anet_common::tun_params::TunParams;
use bytes::{Buf, Bytes, BytesMut};
use log::{error, info};
use prost::Message;
use quinn::{AsyncUdpSocket, Endpoint, EndpointConfig, ServerConfig as QuinnServerConfig, TokioRuntime, udp::Transmit, UdpPoller, Incoming};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use quinn::udp::RecvMeta;
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use std::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use anet_common::consts::MAX_PACKET_SIZE;
use anet_common::transport::AnetVpnPacket;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context as StdContext, Poll};
use quinn::crypto::rustls::QuicServerConfig;
use tokio::sync::Mutex as TokioMutex;


#[derive(Clone)]
struct ClientTransportInfo {
    cipher: Arc<Cipher>,
    addr: Option<SocketAddr>,       // Фактический UDP адрес клиента (изначально None)
    sequence: Arc<AtomicU64>,       // Счетчик для исходящей обфускации
    assigned_ip: String,            // Назначенный VPN IP
    // client_id: String,
}

// Новый тип для роутера
type StreamSender = mpsc::Sender<Bytes>;

struct MultiKeyAnetUdpSocket {
    io: Arc<UdpSocket>,
    // Маппинг VPN IP -> Transport Info (Включая Cipher и Seq)
    clients: Arc<Mutex<HashMap<String, ClientTransportInfo>>>,
}

impl MultiKeyAnetUdpSocket {
    fn new(io: Arc<UdpSocket>, clients: Arc<Mutex<HashMap<String, ClientTransportInfo>>>) -> Self {
        // Мы убрали 'sequence' на уровне MultiKeyAnetUdpSocket,
        // теперь sequence индивидуален для каждого клиента в ClientTransportInfo
        Self { io, clients }
    }
}

impl Debug for MultiKeyAnetUdpSocket {
    fn fmt(&self, _: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl AsyncUdpSocket for MultiKeyAnetUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(TokioUdpPoller { io: self.io.clone() })
    }

    // Server Outbound Path (QUIC -> Wrapped/Encrypted ANET Transport)
    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let destination_addr = transmit.destination;
        let seq;
        let cipher;

        // Поиск ключа по SocketAddr. Достаточно блокирующего лок-а
        let clients_guard = self.clients.lock().expect("Client mutex poisoned");

        // Итерируем по всем клиентам, чтобы найти тот, чей текущий SocketAddr совпадает с назначением
        match clients_guard.values().find(|info| info.addr == Some(destination_addr)) {
            Some(info) => {
                seq = info.sequence.fetch_add(1, Ordering::Relaxed);
                cipher = info.cipher.clone();
            }
            None => {
                // Если не нашли соответствия, то, возможно, QUIC пытается отправить
                // пакет до того, как мы замаппили адрес (или пакет старому, отключенному клиенту).
                // Просто игнорируем отправку обернутого пакета.
                log::trace!("Failed to find transport key for destination: {}", destination_addr);
                return Ok(());
            }
        }

        let packet = AnetVpnPacket::new_data(
            seq,
            Bytes::copy_from_slice(transmit.contents)
        );

        match packet.wrap_and_encrypt(&cipher) {
            Ok(wrapped_packet) => {
                match self.io.try_send_to(&wrapped_packet, destination_addr) {
                    Ok(_) => Ok(()),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
                    Err(e) => {
                        log::error!("MultiKeyAnetUdpSocket failed to send wrapped packet to {}: {}", destination_addr, e);
                        Ok(()) // QUIC справится с ошибкой
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to wrap outgoing QUIC packet: {}", e);
                Ok(())
            }
        }
    }

    // Server Inbound Path (Network -> ANET Decrypt/Unwrap -> QUIC)
    fn poll_recv(
        &self,
        cx: &mut StdContext<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut recv_buf = vec![0u8; MAX_PACKET_SIZE];
        let mut read_buf = tokio::io::ReadBuf::new(&mut recv_buf);

        match self.io.poll_recv_from(cx, &mut read_buf) {
            Poll::Ready(Ok(remote_addr)) => {
                let filled_len = read_buf.filled().len();
                if filled_len == 0 {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }

                let packet_slice = &recv_buf[..filled_len];
                let mut unwrapped_data: Option<Bytes> = None;

                let mut clients_guard = self.clients.lock().expect("Client mutex poisoned");

                // Перебираем ВСЕ ключи. Находим, чей ключ дешифрует пакет.
                for (ip_key, info) in clients_guard.iter_mut() {

                    // Если адрес уже известен, проверяем совпадение (для Connection Migration можно игнорировать).
                    // Для первой проверки:
                    let is_matching_address = info.addr.map(|addr| addr == remote_addr).unwrap_or(true);

                    // Пытаемся расшифровать
                    if is_matching_address {
                        if let Ok(anet_packet) = AnetVpnPacket::unwrap_and_decrypt(&info.cipher, packet_slice) {

                            unwrapped_data = Some(anet_packet.payload);

                            // Ассоциируем SocketAddr, если он еще не был известен
                            if info.addr.is_none() {
                                info.addr = Some(remote_addr);
                                log::info!("QUIC established transport layer mapping: {} -> (IP: {})", remote_addr, ip_key);
                            }
                            break;
                        }
                    }
                }

                if let Some(unwrapped_payload) = unwrapped_data {
                    // Успех! Передаем дешифрованные QUIC данные в Quinn.
                    if bufs.is_empty() { return Poll::Ready(Ok(0)); }

                    let copy_len = std::cmp::min(unwrapped_payload.len(), bufs[0].len());
                    bufs[0][..copy_len].copy_from_slice(&unwrapped_payload[..copy_len]);

                    meta[0] = RecvMeta { addr: remote_addr, len: copy_len, stride: copy_len, dst_ip: None, ecn: None };
                    cx.waker().wake_by_ref();
                    Poll::Ready(Ok(1))
                } else {
                    // Пакет не расшифрован ни одним из известных ключей. Игнорируем.
                    log::trace!("Ignoring incoming UDP packet (cannot decrypt) from {}. Len: {}", remote_addr, filled_len);
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> { self.io.local_addr() }
}


pub struct ANetServer {
    cfg: Config,
    tls_acceptor: TlsAcceptor,
    ip_pool: IpPool,
    tun_manager: TunManager,

    clients: Arc<Mutex<HashMap<String, ClientTransportInfo>>>, // Client Transport Info (IP -> Cipher, Seq, Addr)
    quic_router: Arc<TokioMutex<HashMap<String, StreamSender>>>, // Router: VPN IP -> Sender Stream Handle
}

impl ANetServer {
    pub fn new(cfg: &Config) -> anyhow::Result<Self> {
        let tls_cfg = load_rustls_config_for_auth(cfg.cert_path.as_str(), cfg.key_path.as_str())?;
        let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));

        let tun_params = TunParams {
            netmask: cfg.mask.parse()?,
            gateway: cfg.gateway.parse()?,
            address: cfg.self_ip.parse()?,
            name: cfg.if_name.clone(),
            mtu: cfg.mtu,
            network: Some(cfg.net.parse()?),
        };
        let tun_manager = TunManager::new(tun_params);

        let ip_pool = IpPool::new(
            cfg.net.parse()?, cfg.mask.parse()?, cfg.gateway.parse()?,
            cfg.self_ip.parse()?, cfg.mtu,
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
        let listener = TcpListener::bind(self.cfg.bind_to.as_str()).await?;
        info!("Authentication server listening on {}", self.cfg.bind_to);

        while let Ok((socket, addr)) = listener.accept().await {
            let acceptor = self.tls_acceptor.clone();
            let ip_pool = self.ip_pool.clone();
            let clients = self.clients.clone();
            let auth_phrase = self.cfg.auth_phrase.clone();
            let udp_port = self.cfg.udp_port;

            tokio::spawn(async move {
                if let Err(e) =
                    handle_auth_connection(socket, acceptor, ip_pool.clone(), clients, auth_phrase, udp_port).await {
                    error!("[{}] Auth connection failed: {}", addr, e);
                    // Важно: если auth failed после allocate, IP должен быть освобожден!
                }
            });
        }
        Ok(())
    }

    async fn run_quic_vpn_server(&self) -> Result<()> {
        // 1. Setup QUIC Endpoint and ANET socket wrapper
        let udp_listen_addr = format!("{}:{}", self.cfg.bind_to.split(':').next().unwrap(), self.cfg.udp_port);
        let real_socket = Arc::new(UdpSocket::bind(&udp_listen_addr).await?);

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
        info!("QUIC VPN server listening via ANET transport on {}", udp_listen_addr);

        // 2. Setup TUN and routing rules
        let (tx_to_tun, rx_from_tun) = self.tun_manager.run().await?;
        self.tun_manager
            .setup_tun_routing(self.cfg.external_if.as_str())
            .await?;

        let quic_router = self.quic_router.clone();

        // A. QUIC Listener (Handling new connections)
        let incoming_task = tokio::spawn(handle_incoming_quic(
            endpoint.clone(),
            tx_to_tun.clone(),
            self.clients.clone(),
            quic_router.clone(),
            self.ip_pool.clone(),
        ));

        // B. TUN to QUIC Router (Receives IP packets from TUN and routes them to the right Stream)
        let router_task = tokio::spawn(route_tun_to_quic(
            rx_from_tun,
            quic_router.clone(),
        ));

        tokio::try_join!(incoming_task, router_task)?;

        Ok(())
    }

    // load_rustls_config_for_auth and build_quinn_server_config are preserved from your original draft

    fn build_quinn_server_config(&self) -> Result<QuinnServerConfig> {
        let (certs, key) = load_cert_and_key(&self.cfg.cert_path, &self.cfg.key_path)?;
        let server_crypto = RustlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        // Оборачиваем RustlsServerConfig в QuicServerConfig для совместимости с Quinn
        let quic_crypto = QuicServerConfig::try_from(Arc::new(server_crypto))?;
        // quic_crypto.alpn_protocols = vec![b"hq-29".to_vec()]; // ALPN для QUIC

        Ok(QuinnServerConfig::with_crypto(Arc::new(quic_crypto)))
    }
}



// ---------------------- По человечески это надо в отдельный файл -------------------------------------------------------
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
        .lock().expect("Client mutex poisoned")
        .insert(client_id.clone(), crypto_key);
    client_id_to_ip
        .lock().expect("Client mutex poisoned")
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

async fn handle_auth_connection(
    socket: TcpStream,
    acceptor: TlsAcceptor,
    ip_pool: IpPool,
    clients: Arc<Mutex<HashMap<String, ClientTransportInfo>>>,
    auth_phrase: String,
    udp_port: u32,
) -> anyhow::Result<()> {
    // NOTE: В оригинальном коде была отдельная функция handle_tls_auth.
    // Переносим ее тело сюда для соответствия структуре вызова run_auth_listener.

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

    let client_ip_str = assigned_ip.to_string();

    // Создаем PLACEHOLDER запись для ClientTransportInfo. Addr пока None.
    let info = ClientTransportInfo {
        cipher: Arc::new(Cipher::new(&crypto_key)),
        addr: None,
        sequence: Arc::new(AtomicU64::new(0)),
        // client_id нужен для передачи в QUIC handshake, чтобы клиент знал, с кем его ассоциировать
        // но здесь мы используем IP в качестве ключа.
        assigned_ip: client_ip_str.clone(),
    };

    clients.lock().expect("Client mutex poisoned").insert(client_ip_str.clone(), info.clone());

    info!(
        "Client authorized. Assigned IP: {}, Waiting for QUIC on port {}",
        client_ip_str, udp_port
    );

    let response = AnetMessage {
        content: Some(Content::AuthResponse(AuthResponse {
            ip: client_ip_str.clone(),
            netmask: ip_pool.netmask.to_string(),
            gateway: ip_pool.gateway.to_string(),
            mtu: ip_pool.mtu as i32,
            crypto_key: crypto_key.to_vec(),
            udp_port,
            client_id, // Client ID все еще передаем, если в будущем он будет использоваться QUIC-клиентом
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
    tx_to_tun: mpsc::Sender<Bytes>,
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
    tx_to_tun: mpsc::Sender<Bytes>,
    clients_transport_info: Arc<Mutex<HashMap<String, ClientTransportInfo>>>,
    quic_router: Arc<TokioMutex<HashMap<String, StreamSender>>>,
    ip_pool: IpPool,
) -> Result<()> {
    let connection = incoming.await?;
    let remote_addr = connection.remote_address();
    info!("QUIC negotiation started with peer: {}", remote_addr);

    // Дожидаемся QUIC-соединения. Поскольку мы используем accept_bi,
    // к моменту вызова accept_bi() соединение должно быть в рабочем состоянии.

    // 2. Ожидаем открытия клиентом единственного Bi-Directional Stream
    let (mut send_stream, mut recv_stream) = connection.accept_bi().await?;

    // Если поток был принят, и мы до сих пор здесь, QUIC хендшейк успешен.
    // Нам нужен актуальный SocketAddr для поиска
    let established_remote_addr = connection.remote_address();

    // Находим VPN IP клиента. Мы должны использовать установленный established_remote_addr,
    // поскольку MultiKeyAnetUdpSocket должен был обновить `ClientTransportInfo.addr` при получении первого пакета.
    let assigned_ip = {
        let clients = clients_transport_info.lock().expect("Client mutex poisoned");
        clients.values()
            .find(|info| info.addr == Some(established_remote_addr))
            .map(|info| info.assigned_ip.clone())
    };

    let assigned_ip = match assigned_ip {
        Some(ip) => ip,
        None => {
            error!("QUIC connection established but client VPN IP not resolved from transport info (Final Addr: {}). Connection rejected.", established_remote_addr);
            connection.close(0u32.into(), b"Transport layer association failed");
            return Err(anyhow::anyhow!("IP not found for QUIC connection"));
        }
    };

    info!("QUIC session accepted for client VPN IP: {} ({})", assigned_ip, established_remote_addr);


    // ... (3 - 8. Логика роутинга и очистки остается прежней)

    // 3. Создаем канал для роутинга пакетов с TUN на этот стрим
    let (tx_router, mut rx_router) = mpsc::channel::<Bytes>(64);

    // 4. Регистрируем Sender handle в глобальном роутере
    quic_router.lock().await.insert(assigned_ip.clone(), tx_router);

    let ip_for_log_tx = assigned_ip.clone();

    // 5. Задача Stream TX: Отправляет данные, пришедшие из TUN, по QUIC стриму
    let tx_task = tokio::spawn(async move {
        while let Some(packet) = rx_router.recv().await {
            if send_stream.write_all(&packet).await.is_err() {
                error!("QUIC stream write failed. TUN->QUIC Stream TX closing for {}", ip_for_log_tx);
                break;
            }
        }
        let _ = send_stream.finish().unwrap();
    });

    // 6. Задача Stream RX: Читает данные со стрима и отправляет их в TUN
    let tx_to_tun_for_rx = tx_to_tun.clone();
    let ip_for_log_rx = assigned_ip.clone();
    let rx_task = tokio::spawn(async move {
        let mut buf = BytesMut::with_capacity(MAX_PACKET_SIZE);
        loop {
            match recv_stream.read_buf(&mut buf).await {
                Ok(n) if n > 0 => {
                    if tx_to_tun_for_rx.send(buf.copy_to_bytes(n)).await.is_err() {
                        error!("TUN channel write failed. QUIC->TUN task closing for {}", ip_for_log_rx);
                        break;
                    }
                }
                Ok(_) => {
                    info!("QUIC receive stream closed by client {}.", ip_for_log_rx);
                    break;
                }
                Err(e) => {
                    error!("Error reading from QUIC stream ({}): {}", ip_for_log_rx, e);
                    break;
                }
            }
        }
    });

    // 7. Ждем закрытия соединения (по таймауту или явно клиентом)
    tokio::select! {
        _ = tx_task => info!("TX stream task finished for {}.", assigned_ip),
        _ = rx_task => info!("RX stream task finished for {}.", assigned_ip),
        _ = connection.closed() => info!("Connection explicitly closed by QUIC layer for {}.", assigned_ip),
    }

    // Принудительная остановка оставшейся задачи

    // tx_task.abort();
    // rx_task.abort();

    // 8. Очистка состояния
    let assigned_ip_clone = assigned_ip.clone();

    quic_router.lock().await.remove(&assigned_ip);
    clients_transport_info.lock().expect("Client mutex poisoned").remove(&assigned_ip);

    if let Ok(ip_addr) = assigned_ip_clone.parse() {
        ip_pool.release(ip_addr);
        info!("Released VPN IP {}", assigned_ip_clone);
    }

    Ok(())
}


async fn route_tun_to_quic(
    mut rx_from_tun: mpsc::Receiver<Bytes>,
    quic_router: Arc<TokioMutex<HashMap<String, StreamSender>>>,
) -> Result<()> {

    while let Some(packet) = rx_from_tun.recv().await {
        let dst_ip = match extract_ip_dst(&packet) {
            Some(ip) => ip.to_string(),
            None => continue, // Игнорируем не-IP трафик
        };

        let sender_opt = { quic_router.lock().await.get(&dst_ip).cloned() };

        if let Some(sender) = sender_opt {
            // Отправляем IP пакет во внутренний канал Stream TX задачи
            if let Err(_e) = sender.send(packet).await {
                // Если send fails, канал закрыт. Соединение, скорее всего, закрыто или находится в процессе закрытия.
                // handle_connection должен позаботиться об очистке router entry.
                log::trace!("Failed to route packet to {}. Stream closed.", dst_ip);
            }
        } else {
            log::trace!("Dropping packet to {}: no active QUIC session.", dst_ip);
        }
    }
    Ok(())
}


fn load_rustls_config_for_auth(cert_path: &str, key_path: &str) -> anyhow::Result<RustlsServerConfig> {
    let cert_file =
        File::open(cert_path).context(format!("Failed to open cert file: {}", cert_path))?;

    let certs = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<anyhow::Result<Vec<CertificateDer>, _>>()?;

    let key_file =
        File::open(key_path).context(format!("Failed to open key file: {}", key_path))?;

    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))?
        .context("No private key found in file")?;

    let mut cfg = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"h2".to_vec()];

    Ok(cfg)
}



fn load_cert_and_key(cert_path: &str, key_path: &str) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {

    // 1. Загрузка сертификатов
    let cert_file = File::open(cert_path).context("Failed to open cert file")?;

    // Мы должны собрать все сертификаты, а затем применить ? к Result от collect.
    // Если в процессе чтения встретится I/O ошибка, collect вернет Err.
    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<std::result::Result<_, std::io::Error>>() // Собираем Result<Vec<Cert>, IO Error>
        .context("Failed to read or parse certificates from file")?; // Преобразуем IO Error в anyhow::Error

    // 2. Загрузка ключа
    let key_file = File::open(key_path).context("Failed to open key file")?;

    // Ключ возвращает Option<Result<...>> (где Result необходим только в старых версиях rustls-pemfile,
    // но сейчас это упрощается). Нам нужен `private_key()`, который возвращает Result<Option<...>, IoError>

    // Новую версию rustls-pemfile мы вызываем так:
    let key_der = rustls_pemfile::private_key(&mut BufReader::new(key_file))?
        .context("No private key found in file or failed to read")?; // Option -> Context<No Key Found>

    let key: PrivateKeyDer<'static> = key_der.into();

    Ok((certs, key))
}