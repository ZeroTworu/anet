use crate::auth_handler::run_auth_handler;
use crate::config::Config;
use crate::ip_pool::IpPool;
use crate::multikey_udp_socket::{
    ClientTransportInfo, HandshakeData, MultiKeyAnetUdpSocket, StreamSender, TempDHInfo,
};
use crate::utils::extract_ip_dst;
use anet_common::atun::TunManager;
use anet_common::consts::MAX_PACKET_SIZE;
use anet_common::quic_settings::build_transport_config;
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anet_common::tun_params::TunParams;
use anyhow::{Context, Result};
use base64::prelude::*;
use bytes::Bytes;
use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use log::{debug, error, info, warn};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, EndpointConfig, Incoming, ServerConfig as QuinnServerConfig, TokioRuntime};
use rustls::ServerConfig as RustlsServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io::BufReader;
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub struct ANetServer {
    cfg: Config,
    ip_pool: IpPool,
    tun_manager: TunManager,
    clients_by_prefix: Arc<DashMap<[u8; 4], Arc<ClientTransportInfo>>>,
    clients_by_addr: Arc<DashMap<SocketAddr, Arc<ClientTransportInfo>>>,
    temp_dh_map: Arc<DashMap<SocketAddr, TempDHInfo>>,
    quic_router: Arc<DashMap<String, StreamSender>>,
    quic_cert_pem: String,
    server_signing_key: SigningKey,
}

impl ANetServer {
    pub fn new(cfg: &Config) -> Result<Self> {
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

        // Загрузка ключа подписи сервера
        let server_signing_key_bytes = BASE64_STANDARD
            .decode(&cfg.crypto.server_signing_key)
            .context("Failed to decode server signing key")?;
        let server_signing_key = SigningKey::from_bytes(
            &server_signing_key_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid server signing key length"))?,
        );

        Ok(Self {
            cfg: cfg.clone(),
            ip_pool,
            clients_by_prefix: Arc::new(DashMap::new()),
            clients_by_addr: Arc::new(DashMap::new()),
            temp_dh_map: Arc::new(DashMap::new()),
            tun_manager,
            quic_router: Arc::new(DashMap::new()),
            quic_cert_pem: cfg.crypto.quic_cert.clone(),
            server_signing_key,
        })
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        self.run_unified_vpn_server().await
    }

    async fn run_unified_vpn_server(&mut self) -> Result<()> {
        let listen_addr = &self.cfg.server.bind_to;

        let real_socket = Arc::new(UdpSocket::bind(listen_addr).await?);
        let server_config = self.build_quinn_server_config()?;
        info!(
            "Unified UDP listener (Auth/QUIC) started on {}",
            listen_addr
        );
        let (tx_to_tun, rx_from_tun) = self.tun_manager.run().await?;
        self.tun_manager
            .setup_server_tun_routing(self.cfg.server.external_if.as_str())
            .await?;

        // Создание канала для Auth трафика
        let (tx_to_auth, rx_from_auth) = mpsc::channel::<HandshakeData>(MAX_PACKET_SIZE);

        // Инициализация диспетчера MultiKeyAnetUdpSocket
        let anet_socket = Arc::new(MultiKeyAnetUdpSocket::new(
            real_socket.clone(),
            self.clients_by_prefix.clone(),
            self.clients_by_addr.clone(),
            tx_to_auth,
        ));

        // Подъем QUINN Endpoints
        let endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(server_config),
            anet_socket,
            Arc::new(TokioRuntime),
        )?;

        // Задачи
        let incoming_quic_task = tokio::spawn(handle_incoming_quic(
            endpoint.clone(),
            tx_to_tun.clone(),
            self.quic_router.clone(),
            self.ip_pool.clone(),
            self.clients_by_prefix.clone(),
            self.clients_by_addr.clone(),
        ));

        let router_task = tokio::spawn(route_tun_to_quic(rx_from_tun, self.quic_router.clone()));

        let auth_handler_task = tokio::spawn(run_auth_handler(
            rx_from_auth,
            real_socket.clone(),
            self.ip_pool.clone(),
            self.clients_by_prefix.clone(),
            self.clients_by_addr.clone(),
            self.temp_dh_map.clone(),
            self.cfg.authentication.allowed_clients.clone(),
            self.server_signing_key.clone(),
            self.quic_cert_pem.clone(),
        ));

        let cleanup_temp_dh_task =
            tokio::spawn(clear_expired_dh_sessions(self.temp_dh_map.clone()));

        let _ = tokio::try_join!(
            incoming_quic_task,
            router_task,
            auth_handler_task,
            cleanup_temp_dh_task,
        )?;
        Ok(())
    }

    fn build_quinn_server_config(&self) -> Result<QuinnServerConfig> {
        let (certs, key) = load_cert_and_key(
            self.cfg.crypto.quic_cert.as_str(),
            self.cfg.crypto.quic_key.as_str(),
        )?;

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

async fn handle_incoming_quic(
    endpoint: Endpoint,
    tx_to_tun: StreamSender,
    quic_router: Arc<DashMap<String, StreamSender>>,
    ip_pool: IpPool,
    clients_by_prefix: Arc<DashMap<[u8; 4], Arc<ClientTransportInfo>>>,
    clients_by_addr: Arc<DashMap<SocketAddr, Arc<ClientTransportInfo>>>,
) -> Result<()> {
    while let Some(conn) = endpoint.accept().await {
        let fut = handle_connection(
            conn,
            tx_to_tun.clone(),
            quic_router.clone(),
            ip_pool.clone(),
            clients_by_prefix.clone(),
            clients_by_addr.clone(),
        );
        tokio::spawn(async move {
            if let Err(e) = fut.await {
                error!("QUIC connection failed: {}", e);
            }
        });
    }
    Ok(())
}

const TEMP_DH_TIMEOUT: Duration = Duration::from_secs(30);
const TEMP_DH_CLEANUP_INTERVAL: Duration = Duration::from_secs(10);

async fn clear_expired_dh_sessions(temp_dh_map: Arc<DashMap<SocketAddr, TempDHInfo>>) {
    info!("Temporary DH state cleanup task started.");
    loop {
        tokio::time::sleep(TEMP_DH_CLEANUP_INTERVAL).await;

        let expired_keys: Vec<SocketAddr> = temp_dh_map
            .iter()
            .filter_map(|entry| {
                if entry.created_at.elapsed() > TEMP_DH_TIMEOUT {
                    Some(*entry.key())
                } else {
                    None
                }
            })
            .collect();

        for key in expired_keys {
            if temp_dh_map.remove(&key).is_some() {
                debug!("Expired DH session cleared for {}", key);
            }
        }

        if !temp_dh_map.is_empty() {
            debug!("Active temporary DH sessions: {}", temp_dh_map.len());
        }
    }
}

async fn handle_connection(
    incoming: Incoming,
    tx_to_tun: StreamSender,
    quic_router: Arc<DashMap<String, StreamSender>>,
    ip_pool: IpPool,
    clients_by_prefix: Arc<DashMap<[u8; 4], Arc<ClientTransportInfo>>>,
    clients_by_addr: Arc<DashMap<SocketAddr, Arc<ClientTransportInfo>>>,
) -> Result<()> {
    let connection = incoming.await?;
    let destination_addr = connection.remote_address();
    info!("QUIC negotiation started with peer: {}", destination_addr);

    // Ищем клиента по адресу, используя O(1) Lookup
    let client = clients_by_addr
        .get(&destination_addr)
        .map(|entry| entry.value().clone());

    let client = match client {
        Some(client) => client,
        None => {
            error!(
                "QUIC connection established but client VPN IP not resolved from transport info (Final Addr: {}). Connection rejected.",
                destination_addr
            );
            connection.close(0u32.into(), b"Transport layer association failed");
            return Err(anyhow::anyhow!("IP not found for QUIC connection"));
        }
    };

    let remote_addr_guard = client.remote_addr.load();
    let real_remote_addr = remote_addr_guard.deref();

    info!(
        "QUIC session accepted for client VPN IP: {} ({}), SEID: {}",
        client.assigned_ip, real_remote_addr, client.session_id
    );

    let (send_stream, recv_stream) = connection.accept_bi().await?;

    let (tx_router, mut rx_router) = mpsc::channel::<Bytes>(1024);

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
    let nonce_prefix_clone = client.nonce_prefix;
    let remote_addr_clone = real_remote_addr;

    {
        quic_router.remove(&client.assigned_ip);
        clients_by_prefix.remove(&nonce_prefix_clone);
        clients_by_addr.remove(remote_addr_clone.deref());

        info!(
            "Removed client {} from quic_router. Remaining clients: {}",
            client.assigned_ip,
            quic_router.len()
        );
    }

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

        let sender_opt = { quic_router.get(&dst_ip) };

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
                quic_router
                    .iter()
                    .map(|val| val.key().clone())
                    .collect::<Vec<_>>()
            );
        }
    }

    Ok(())
}

fn load_cert_and_key(
    cert_pem: &str,
    key_pem: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
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
