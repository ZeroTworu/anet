use crate::auth_handler::ServerAuthHandler;
use crate::auth_provider::AuthProvider;
use crate::client_registry::ClientRegistry;
use crate::config::Config;
use crate::ip_pool::IpPool;
use crate::multikey_udp_socket::{HandshakeData, MultiKeyAnetUdpSocket, TempDHInfo};
use crate::ssh_server;
use crate::vpn_handler::ServerVpnHandler;
use anet_common::atun::TunManager;
use anet_common::consts::CHANNEL_BUFFER_SIZE;
use anet_common::quic_settings::build_transport_config;
use anet_common::tun_params::TunParams;
use anyhow::{Context, Result};
use base64::prelude::*;
use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use log::{debug, error, info};
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
    registry: Arc<ClientRegistry>,
    temp_dh_map: Arc<DashMap<SocketAddr, TempDHInfo>>,
    tun_manager: TunManager,
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

        let registry = Arc::new(ClientRegistry::new(ip_pool));

        let server_signing_key_bytes = BASE64_STANDARD.decode(&cfg.crypto.server_signing_key)?;
        let server_signing_key = SigningKey::from_bytes(
            &server_signing_key_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid key length"))?,
        );

        Ok(Self {
            cfg: cfg.clone(),
            registry,
            temp_dh_map: Arc::new(DashMap::new()),
            tun_manager,
            server_signing_key,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        let listen_addr = &self.cfg.server.quic_bind_to;
        let real_socket = Arc::new(UdpSocket::bind(listen_addr).await?);
        let server_config = self.build_quinn_server_config()?;
        info!("Unified UDP listener started on {}", listen_addr);

        let (tx_to_tun, rx_from_tun) = self.tun_manager.run().await?;

        let (tx_to_auth, rx_from_auth) = mpsc::channel::<HandshakeData>(CHANNEL_BUFFER_SIZE);

        let anet_socket = Arc::new(MultiKeyAnetUdpSocket::new(
            real_socket.clone(),
            self.registry.clone(),
            tx_to_auth,
            self.cfg.stealth.clone(),
        ));

        let endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(server_config),
            anet_socket,
            Arc::new(TokioRuntime),
        )?;

        let cfg_arc = Arc::new(self.cfg.clone());

        // --- VPN HANDLER ---
        let vpn_handler =
            ServerVpnHandler::new(endpoint.clone(), self.registry.clone(), cfg_arc.clone());
        let quic_tx_to_tun = tx_to_tun.clone();
        let vpn_handler_task = tokio::spawn(async move {
            if let Err(e) = vpn_handler.run(quic_tx_to_tun, rx_from_tun).await {
                error!("VPN Handler critical error: {}", e);
            }
        });

        let auth_provider = Arc::new(AuthProvider::new(
            self.cfg.authentication.allowed_clients.clone(),
            self.cfg.authentication.auth_servers.clone(),
            self.cfg.authentication.auth_server_token.clone(),
        ));

        // --- AUTH HANDLER ---
        let auth_handler = ServerAuthHandler::new(
            real_socket,
            self.registry.clone(),
            self.temp_dh_map.clone(),
            auth_provider,
            self.server_signing_key.clone(),
            self.cfg.crypto.quic_cert.clone(),
            self.cfg.stealth.padding_step,
        );

        let ssh_auth_handler = auth_handler.clone();

        // Запускаем цикл в таске
        let auth_handler_task = tokio::spawn(async move {
            auth_handler.run(rx_from_auth).await;
        });

        let cleanup_temp_dh_task =
            tokio::spawn(clear_expired_dh_sessions(self.temp_dh_map.clone()));

        // SSH Fallback
        let ssh_config = Arc::new(self.cfg.clone());
        let ssh_registry = self.registry.clone();
        let ssh_tun_tx = tx_to_tun.clone();

        let ssh_task = tokio::spawn(async move {
            if let Err(e) =
                ssh_server::run_ssh_server(ssh_config, ssh_registry, ssh_tun_tx, ssh_auth_handler)
                    .await
            {
                error!("SSH Server failed: {}", e);
            }
        });

        let _ = tokio::try_join!(vpn_handler_task, auth_handler_task, cleanup_temp_dh_task, ssh_task)?;
        Ok(())
    }

    fn build_quinn_server_config(&self) -> Result<QuinnServerConfig> {
        let (certs, key) =
            load_cert_and_key(&self.cfg.crypto.quic_cert, &self.cfg.crypto.quic_key)?;
        let server_crypto = RustlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        let mut cfg =
            QuinnServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
        let transport_config =
            build_transport_config(&self.cfg.quic_transport, self.cfg.network.mtu)?;
        cfg.transport_config(Arc::new(transport_config));
        Ok(cfg)
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

fn load_cert_and_key(
    cert_pem: &str,
    key_pem: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(cert_pem.as_bytes()))
        .collect::<Result<_, _>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_pem.as_bytes()))?
        .context("No private key found")?;
    Ok((certs, key.into()))
}
