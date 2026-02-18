//! Unified server accepting all transport types

use crate::auth_provider::AuthProvider;
use crate::client_registry::{ClientRegistry, ClientTransportInfo};
use crate::config::Config;
use crate::ip_pool::IpPool;
use crate::vpn_handler::ServerVpnHandler;
use anet_common::atun::TunManager;
use anet_common::config::StealthConfig;
use anet_common::encryption::Cipher;
use anet_common::protocol::AuthResponse;
use anet_common::transport::{
    ConnectionId, TransportAcceptor, VpnStream,
    ssh_server::SshTransportAcceptor,
    tcp_tls_server::TlsTransportAcceptor,
};
use anyhow::Result;
use arc_swap::ArcSwap;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Instant;
use tokio::sync::mpsc;

/// Shared state for all transports
pub struct UnifiedServerState {
    pub registry: Arc<ClientRegistry>,
    pub ip_pool: IpPool,
    pub auth_provider: Arc<AuthProvider>,
    pub server_signing_key: ed25519_dalek::SigningKey,
    pub quic_cert_pem: String,
    pub stealth: StealthConfig,
}

/// Unified server handling all transports
pub struct UnifiedServer {
    state: Arc<UnifiedServerState>,
    // QUIC/UDP
    quic_endpoint: Option<quinn::Endpoint>,
    // TCP/TLS
    tls_acceptor: Option<TlsTransportAcceptor>,
    // TCP/SSH
    ssh_acceptor: Option<SshTransportAcceptor>,
    // TUN
    tun_manager: TunManager,
}

impl UnifiedServer {
    pub fn new(config: &Config) -> Result<Self> {
        let tun_params = anet_common::tun_params::TunParams {
            netmask: config.network.mask.parse()?,
            gateway: config.network.gateway.parse()?,
            address: config.network.self_ip.parse()?,
            name: config.network.if_name.clone(),
            mtu: config.network.mtu,
            network: Some(config.network.net.parse()?),
        };

        let tun_manager = TunManager::new(tun_params)?;

        let ip_pool = IpPool::new(
            config.network.net.parse()?,
            config.network.mask.parse()?,
            config.network.gateway.parse()?,
            config.network.self_ip.parse()?,
            config.network.mtu,
        );

        let registry = Arc::new(ClientRegistry::new(ip_pool.clone()));

        let server_signing_key_bytes = base64::decode(&config.crypto.server_signing_key)?;
        let server_signing_key = ed25519_dalek::SigningKey::from_bytes(
            &server_signing_key_bytes.as_slice().try_into()?
        );

        let auth_provider = Arc::new(AuthProvider::new(
            config.authentication.allowed_clients.clone(),
            config.authentication.auth_servers.clone(),
            config.authentication.auth_server_token.clone(),
        ));

        let state = Arc::new(UnifiedServerState {
            registry,
            ip_pool,
            auth_provider,
            server_signing_key,
            quic_cert_pem: config.crypto.quic_cert.clone(),
            stealth: config.stealth.clone(),
        });

        // Initialize transport acceptors based on config
        let quic_endpoint = Self::init_quic(config, state.clone())?;
        let tls_acceptor = Self::init_tls(config, state.clone())?;
        let ssh_acceptor = Self::init_ssh(config, state.clone())?;

        Ok(Self {
            state,
            quic_endpoint,
            tls_acceptor,
            ssh_acceptor,
            tun_manager,
        })
    }

    fn init_quic(config: &Config, state: Arc<UnifiedServerState>) -> Result<Option<quinn::Endpoint>> {
        // Existing QUIC initialization...
        todo!()
    }

    fn init_tls(config: &Config, state: Arc<UnifiedServerState>) -> Result<Option<TlsTransportAcceptor>> {
        if !config.server.enable_tcp_tls {
            return Ok(None);
        }
        TlsTransportAcceptor::new(config, state)
    }

    fn init_ssh(config: &Config, state: Arc<UnifiedServerState>) -> Result<Option<SshTransportAcceptor>> {
        if !config.server.enable_tcp_ssh {
            return Ok(None);
        }
        SshTransportAcceptor::new(config, state)
    }

    pub async fn run(&self) -> Result<()> {
        let (tx_to_tun, rx_from_tun) = self.tun_manager.run().await?;

        // Spawn transport-specific acceptors
        let mut handles = vec![];

        // QUIC
        if let Some(endpoint) = &self.quic_endpoint {
            let state = self.state.clone();
            let endpoint = endpoint.clone();
            handles.push(tokio::spawn(async move {
                Self::run_quic_acceptor(endpoint, state, tx_to_tun.clone()).await
            }));
        }

        // TLS
        if let Some(acceptor) = &self.tls_acceptor {
            let state = self.state.clone();
            let acceptor = acceptor.clone();
            handles.push(tokio::spawn(async move {
                Self::run_transport_acceptor(acceptor, state, tx_to_tun.clone()).await
            }));
        }

        // SSH
        if let Some(acceptor) = &self.ssh_acceptor {
            let state = self.state.clone();
            let acceptor = acceptor.clone();
            handles.push(tokio::spawn(async move {
                Self::run_transport_acceptor(acceptor, state, tx_to_tun.clone()).await
            }));
        }

        // TUN router (common for all)
        let router_handle = tokio::spawn({
            let state = self.state.clone();
            async move {
                Self::route_tun_to_clients(rx_from_tun, state).await
            }
        });

        // Wait for any to complete (or fail)
        tokio::select! {
            result = futures::future::try_join_all(handles) => {
                result?;
            }
            _ = router_handle => {}
        }

        Ok(())
    }

    /// Generic acceptor for TLS/SSH transports
    async fn run_transport_acceptor<A>(
        acceptor: A,
        state: Arc<UnifiedServerState>,
        tx_to_tun: mpsc::Sender<bytes::Bytes>,
    ) -> Result<()>
    where
        A: TransportAcceptor + Clone + Send + 'static,
    {
        loop {
            let (stream, auth_response, cipher, conn_id) = acceptor.accept().await?;

            let client_info = Arc::new(ClientTransportInfo {
                cipher: Arc::new(cipher.clone()),
                sequence: Arc::new(AtomicU64::new(0)),
                assigned_ip: auth_response.ip.clone(),
                session_id: auth_response.session_id.clone(),
                nonce_prefix: auth_response.nonce_prefix.as_slice().try_into()?,
                remote_addr: ArcSwap::new(Arc::new(stream.peer_addr()?)),
            });

            state.registry.pre_register_client(client_info.clone());

            // Create channels for this client
            let (tx_router, rx_router) = mpsc::channel(65535);
            state.registry.finalize_client(&auth_response.ip, tx_router);

            // Spawn bidirectional bridge
            let stealth = state.stealth.clone();
            let registry = state.registry.clone();
            let client_info_for_cleanup = client_info.clone();

            tokio::spawn(async move {
                let result = Self::handle_client_stream(
                    stream,
                    rx_router,
                    tx_to_tun,
                    stealth,
                    conn_id,
                ).await;

                // Cleanup on disconnect
                registry.remove_client(&client_info_for_cleanup);
                result
            });
        }
    }

    async fn handle_client_stream<S>(
        mut stream: S,
        mut rx_from_router: mpsc::Receiver<bytes::Bytes>,
        tx_to_tun: mpsc::Sender<bytes::Bytes>,
        stealth: StealthConfig,
        conn_id: ConnectionId,
    ) -> Result<()>
    where
        S: VpnStream,
    {
        use anet_common::transport::{bridge_stream_to_tun, bridge_tun_to_stream};

        // Client -> TUN
        let client_to_tun = async {
            bridge_stream_to_tun(&mut stream, tx_to_tun).await
        };

        // TUN -> Client
        let tun_to_client = bridge_tun_to_stream(rx_from_router, stream, stealth);

        // Run both directions
        tokio::select! {
            result = client_to_tun => result,
            result = tun_to_client => result,
        }
    }

    async fn route_tun_to_clients(
        mut rx_from_tun: mpsc::Receiver<bytes::Bytes>,
        state: Arc<UnifiedServerState>,
    ) -> Result<()> {
        use anet_common::transport::utils::extract_ip_dst;

        while let Some(packet) = rx_from_tun.recv().await {
            if let Some(dst_ip) = extract_ip_dst(&packet) {
                state.registry
                    .route_packet_to_client(&dst_ip.to_string(), packet)
                    .await;
            }
        }
        Ok(())
    }

    async fn run_quic_acceptor(
        endpoint: quinn::Endpoint,
        state: Arc<UnifiedServerState>,
        tx_to_tun: mpsc::Sender<bytes::Bytes>,
    ) -> Result<()> {
        // Delegate to existing ServerVpnHandler with adaptation
        todo!("Adapt existing QUIC handler to VpnStream trait")
    }
}
