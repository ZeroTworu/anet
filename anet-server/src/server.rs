use crate::auth_handler::run_auth_handler;
use crate::config::Config;
use crate::ip_pool::IpPool;
use crate::multikey_udp_socket::StreamSender;
use crate::multikey_udp_socket::{
    ClientTransportInfo, HandshakeData, MultiKeyAnetUdpSocket, TempDHInfo,
};
use crate::vpn_handler::run_vpn_handler; // <-- ИМПОРТИРУЕМ НОВЫЙ ОБРАБОТЧИК
use anet_common::atun::TunManager;
use anet_common::consts::MAX_PACKET_SIZE;
use anet_common::quic_settings::build_transport_config;
use anet_common::tun_params::TunParams;
use anyhow::{Context, Result};
use base64::prelude::*;
use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use log::{debug, info};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, EndpointConfig, ServerConfig as QuinnServerConfig, TokioRuntime};
use rustls::ServerConfig as RustlsServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const TEMP_DH_TIMEOUT: Duration = Duration::from_secs(30);
const TEMP_DH_CLEANUP_INTERVAL: Duration = Duration::from_secs(10);

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

    pub async fn run(&mut self) -> Result<()> {
        let listen_addr = &self.cfg.server.bind_to;

        let real_socket = Arc::new(UdpSocket::bind(listen_addr).await?);
        let server_config = build_quinn_server_config(&self.cfg)?;
        info!(
            "Unified UDP listener (Auth/QUIC) started on {}",
            listen_addr
        );

        let (tx_to_tun, rx_from_tun) = self.tun_manager.run().await?;
        self.tun_manager
            .setup_server_tun_routing(self.cfg.server.external_if.as_str())
            .await?;

        let (tx_to_auth, rx_from_auth) = mpsc::channel::<HandshakeData>(MAX_PACKET_SIZE);

        let anet_socket = Arc::new(MultiKeyAnetUdpSocket::new(
            real_socket.clone(),
            self.clients_by_prefix.clone(),
            self.clients_by_addr.clone(),
            tx_to_auth,
        ));

        let endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(server_config),
            anet_socket,
            Arc::new(TokioRuntime),
        )?;

        // --- ЗАПУСК ОБРАБОТЧИКОВ ---

        // 1. Обработчик VPN (QUIC)
        let vpn_handler_task = tokio::spawn(run_vpn_handler(
            endpoint.clone(),
            tx_to_tun,
            rx_from_tun,
            self.quic_router.clone(),
            self.ip_pool.clone(),
            self.clients_by_prefix.clone(),
            self.clients_by_addr.clone(),
        ));

        // 2. Обработчик аутентификации (DH)
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
        // 3. Задача очистки устаревших сессий DH
        let cleanup_temp_dh_task =
            tokio::spawn(clear_expired_dh_sessions(self.temp_dh_map.clone()));

        // Ожидаем завершения всех основных задач
        let _ = tokio::try_join!(vpn_handler_task, auth_handler_task, cleanup_temp_dh_task)?;

        Ok(())
    }
}

async fn clear_expired_dh_sessions(temp_dh_map: Arc<DashMap<SocketAddr, TempDHInfo>>) {
    info!("Temporary DH state cleanup task started.");
    loop {
        tokio::time::sleep(TEMP_DH_CLEANUP_INTERVAL).await;
        temp_dh_map.retain(|_, v| v.created_at.elapsed() <= TEMP_DH_TIMEOUT);
        if !temp_dh_map.is_empty() {
            debug!("Active temporary DH sessions: {}", temp_dh_map.len());
        }
    }
}

fn build_quinn_server_config(cfg: &Config) -> Result<QuinnServerConfig> {
    let (certs, key) =
        load_cert_and_key(cfg.crypto.quic_cert.as_str(), cfg.crypto.quic_key.as_str())?;

    let server_crypto = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    let quic_crypto = QuicServerConfig::try_from(Arc::new(server_crypto))?;
    let mut server_cfg = QuinnServerConfig::with_crypto(Arc::new(quic_crypto));
    let transport_config = build_transport_config(&cfg.quic_transport, cfg.network.mtu)?;
    server_cfg.transport_config(Arc::new(transport_config));

    Ok(server_cfg)
}

fn load_cert_and_key(
    cert_pem: &str,
    key_pem: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let mut cert_reader = BufReader::new(cert_pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("Failed to read certificates from PEM")?;

    let mut key_reader = BufReader::new(key_pem.as_bytes());
    let key_der = rustls_pemfile::private_key(&mut key_reader)?
        .context("No private key found in PEM string")?;

    Ok((certs, key_der.into()))
}
