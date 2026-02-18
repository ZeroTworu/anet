//! SSH server acceptor

use anet_common::transport::{ConnectionId, TransportAcceptor, VpnStream};
use anet_common::encryption::Cipher;
use anet_common::protocol::AuthResponse;
use crate::unified_server::UnifiedServerState;
use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use russh::{
    server::{self, Auth, Handle, Msg, Session, Sig},
    ChannelId, ChannelMsg, CryptoVec, Disconnect,
};
use russh_keys::key::PublicKey;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as StdContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Mutex, mpsc};

/// SSH server configuration
pub struct SshServerConfig {
    pub bind_addr: SocketAddr,
    pub host_key: String, // PEM private key
    pub authorized_keys: Vec<String>,
}

/// SSH transport acceptor
#[derive(Clone)]
pub struct SshTransportAcceptor {
    config: Arc<SshServerConfig>,
    state: Arc<UnifiedServerState>,
    // Internal channel for passing authenticated connections
    connection_tx: Arc<Mutex<mpsc::Sender<AuthenticatedConnection>>>,
    connection_rx: Arc<Mutex<mpsc::Receiver<AuthenticatedConnection>>>,
}

struct AuthenticatedConnection {
    channel: russh::Channel<Msg>,
    session: Handle<SshServerHandler>,
    peer_addr: SocketAddr,
}

impl SshTransportAcceptor {
    pub fn new(config: &crate::config::Config, state: Arc<UnifiedServerState>) -> Result<Self> {
        let ssh_config = SshServerConfig {
            bind_addr: format!("{}:{}", config.server.bind_to, 2222).parse()?, // SSH on different port
            host_key: config.crypto.server_signing_key.clone(), // Reuse or separate key
            authorized_keys: config.authentication.allowed_clients.clone(), // Map fingerprints to keys
        };

        let (tx, rx) = mpsc::channel(100);

        Ok(Self {
            config: Arc::new(ssh_config),
            state,
            connection_tx: Arc::new(Mutex::new(tx)),
            connection_rx: Arc::new(Mutex::new(rx)),
        })
    }

    /// Start SSH server (call before accept())
    pub async fn start_server(&self) -> Result<()> {
        let config = russh::server::Config {
            keys: vec![russh_keys::decode_secret_key(&self.config.host_key, None)?],
            ..Default::unwrap_or_default()
        };

        let server = SshServer {
            state: self.state.clone(),
            connection_tx: self.connection_tx.clone(),
        };

        let listener = tokio::net::TcpListener::bind(self.config.bind_addr).await?;

        tokio::spawn(async move {
            loop {
                let (socket, addr) = listener.accept().await?;
                let config = config.clone();
                let server = server.clone();

                tokio::spawn(async move {
                    let _ = russh::server::run_stream(config, socket, server).await;
                });
            }
        });

        Ok(())
    }
}

#[async_trait]
impl TransportAcceptor for SshTransportAcceptor {
    async fn accept(
        &self,
    ) -> Result<(
        Box<dyn VpnStream>,
        AuthResponse,
        Cipher,
        ConnectionId,
    )> {
        // Wait for authenticated connection from SSH server
        let conn = self.connection_rx.lock().await.recv().await
            .context("SSH server shut down")?;

        // Perform ASTP authentication over SSH channel
        let (auth_response, shared_key) = self
            .authenticate_over_channel(&conn.channel, conn.peer_addr)
            .await?;

        let cipher = Cipher::new(&shared_key);
        let stream = SshServerStream::new(
            conn.channel,
            conn.session,
            cipher.clone(),
            conn.peer_addr,
        );

        let conn_id = stream.connection_id();

        Ok((Box::new(stream), auth_response, cipher, conn_id))
    }
}

/// SSH server handler for russh
#[derive(Clone)]
struct SshServer {
    state: Arc<UnifiedServerState>,
    connection_tx: Arc<Mutex<mpsc::Sender<AuthenticatedConnection>>>,
}

impl server::Handler for SshServer {
    type Error = anyhow::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        // Verify against allowed clients
        let fingerprint = base64::encode(public_key.public_key_bytes());

        if self.state.auth_provider.is_client_allowed(&fingerprint).await {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::Reject {
                proceed_with_methods: None,
            })
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // Store channel for later use
        // Actual VPN setup happens in subsystem request
        Ok(true)
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name != "vpn" {
            return Ok(());
        }

        let channel = session.channel(channel_id)?;
        let peer_addr = session.remote_address().unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());

        let conn = AuthenticatedConnection {
            channel,
            session: session.handle(),
            peer_addr,
        };

        // Send to acceptor
        let _ = self.connection_tx.lock().await.send(conn).await;

        Ok(())
    }
}

/// Server-side SSH channel stream
pub struct SshServerStream {
    channel: Arc<Mutex<russh::Channel<Msg>>>,
    session: Arc<Mutex<Handle<SshServer>>>,
    cipher: Cipher,
    nonce_counter: u64,
    peer_addr: SocketAddr,

    read_buffer: Vec<u8>,
    read_decrypted: Vec<u8>,
    read_offset: usize,
    write_buffer: Vec<u8>,
}

impl SshServerStream {
    fn new(
        channel: russh::Channel<Msg>,
        session: Handle<SshServer>,
        cipher: Cipher,
        peer_addr: SocketAddr,
    ) -> Self {
        Self {
            channel: Arc::new(Mutex::new(channel)),
            session: Arc::new(Mutex::new(session)),
            cipher,
            nonce_counter: 0,
            peer_addr,
            read_buffer: Vec::with_capacity(65535),
            read_decrypted: Vec::with_capacity(65535),
            read_offset: 0,
            write_buffer: Vec::with_capacity(65535),
        }
    }

    fn connection_id(&self) -> ConnectionId {
        ConnectionId(format!("ssh-server-{}-{}", self.peer_addr, self.nonce_counter))
    }
}

impl VpnStream for SshServerStream {
    fn peer_addr(&self) -> Result<SocketAddr> {
        Ok(self.peer_addr)
    }

    fn connection_id(&self) -> ConnectionId {
        self.connection_id()
    }

    fn shutdown(&mut self) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            let ch = self.channel.lock().await;
            ch.eof().await?;
            ch.close().await?;
            Ok(())
        })
    }
}

// AsyncRead/AsyncWrite implementation - identical to client version
// but with server-side decryption logic...