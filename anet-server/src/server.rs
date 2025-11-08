use crate::config::Config;
use crate::ip_pool::IpPool;
use crate::utils::{extract_ip_dst, generate_crypto_key, generate_seid};
use crate::multikey_udp_socket::{ClientTransportInfo, StreamSender, MultiKeyAnetUdpSocket};
use anet_common::atun::TunManager;
use anet_common::consts::MAX_PACKET_SIZE;
use anet_common::encryption::Cipher;
use anet_common::protocol::{AuthResponse, Message as AnetMessage, message::Content};
use anet_common::quic_settings::build_transport_config;
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anet_common::tun_params::TunParams;
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose};
use bytes::Bytes;
use dashmap::DashMap;
use log::{error, info, warn};
use prost::Message;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{
    Endpoint, EndpointConfig, Incoming, ServerConfig as QuinnServerConfig,
    TokioRuntime,
};
use rustls::ServerConfig as RustlsServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io::BufReader;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;




pub struct ANetServer {
    cfg: Config,
    tls_acceptor: TlsAcceptor,
    ip_pool: IpPool,
    tun_manager: TunManager,
    // Теперь используем единую структуру клиентов
    clients: Arc<DashMap<String, ClientTransportInfo>>,
    quic_router: Arc<DashMap<String, StreamSender>>,
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
            clients: Arc::new(DashMap::new()),
            tun_manager,
            quic_router: Arc::new(DashMap::new()),
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
    clients: Arc<DashMap<String, ClientTransportInfo>>, // ИЗМЕНЕНО
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
    let session_id_bytes = general_purpose::STANDARD
        .decode(&session_id)
        .context("Failed to decode session_id")?;
    if session_id_bytes.len() != 16 {
        anyhow::bail!(
            "Invalid session_id length, expected 16 bytes, got {}",
            session_id_bytes.len()
        );
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
    };

    //вставка в DashMap (без блокировки мьютекса)
    clients.insert(session_id.clone(), info);

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
    clients_transport_info: Arc<DashMap<String, ClientTransportInfo>>,
    quic_router: Arc<DashMap<String, StreamSender>>,
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
    clients_transport_info: Arc<DashMap<String, ClientTransportInfo>>, // ИЗМЕНЕНО
    quic_router: Arc<DashMap<String, StreamSender>>,
    ip_pool: IpPool,
) -> Result<()> {
    let connection = incoming.await?;
    let remote_addr = connection.remote_address();
    info!("QUIC negotiation started with peer: {}", remote_addr);

    let (send_stream, recv_stream) = connection.accept_bi().await?;

    let established_remote_addr = connection.remote_address();

    // Ищем клиента по адресу, используем итератор DashMap)
    let client = {
        clients_transport_info
            .iter()
            .find(|entry| entry.addr == Some(established_remote_addr))
            .map(|entry| entry.value().clone())
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

    let (tx_router, mut rx_router) = mpsc::channel::<Bytes>(1024);

    // Добавляем клиента в роутер
    {
        quic_router.insert(client.assigned_ip.clone(), tx_router);
        info!(
            "Client {} added to quic_router. Total clients: {}",
            client.assigned_ip,
            quic_router.len()
        );
    }

    let ip_for_log_tx = client.assigned_ip.clone();

    // Задача: отправка данных из роутера в QUIC стрим
    let tx_task = tokio::spawn(async move {
        let mut stream = send_stream;

        while let Some(packet) = rx_router.recv().await {
            // Оборачиваем пакет в транспортный фрейм
            let framed_packet = frame_packet(packet);

            if let Err(e) = stream.write_all(&framed_packet).await {
                error!("QUIC stream write failed for {}  {}", ip_for_log_tx, e);
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
                        error!("TUN channel write failed for {}  {}", ip_for_log_rx, e);
                        break;
                    }
                }
                Ok(None) => {
                    break;
                }
                Err(e) => {
                    error!("Error reading QUIC stream from {} {}", ip_for_log_rx, e);
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

    let assigned_ip_clone = client.assigned_ip.clone();
    let session_id_clone = client.session_id.clone();

    {
        quic_router.remove(&client.assigned_ip);
        info!(
            "Removed client {} from quic_router. Remaining clients: {}",
            client.assigned_ip,
            quic_router.len()
        );
    }

    clients_transport_info.remove(&session_id_clone);

    if let Ok(ip_addr) = assigned_ip_clone.parse() {
        ip_pool.release(ip_addr);
    }

    Ok(())
}

// В функции route_tun_to_quic заменим:
async fn route_tun_to_quic(
    mut rx_from_tun: mpsc::Receiver<Bytes>,
    quic_router: Arc<DashMap<String, StreamSender>>,
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
            quic_router.get(&dst_ip)
        };

        if let Some(sender) = sender_opt {
            match sender.send(packet).await {
                Ok(()) => {}
                Err(e) => {
                    warn!("Failed to route packet to {}: {}", dst_ip, e);
                }
            }
        } else {
            warn!(
                "Dropping packet to {}: no active QUIC session. Available sessions: {:?}",
                dst_ip,
                quic_router.iter().map(|val| val.key().clone()).collect::<Vec<_>>()
            );
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
