//! SSH client transport with ASTP authentication tunneling

use super::super::config::StealthConfig;
use super::super::encryption::Cipher;
use super::super::protocol::AuthResponse;
use super::super::stream_framing::{frame_packet, read_next_packet};
use super::super::transports::{
    ConnectionId, TransportConnector, VpnStream, EncryptedStream,
};
use super::super::crypto_utils;
use super::super::generated::{
    AuthRequest, DhClientExchange, DhServerExchange,
    EncryptedAuthRequest, EncryptedAuthResponse, Message, message::Content,
};
use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use bytes::Bytes;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as StdContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;

use russh::{
    client::{self, Handle, Msg, Session},
    ChannelId, ChannelMsg, CryptoVec, Disconnect,
};
// Исправленный импорт для russh 0.49+
use russh_keys::key::PrivateKey;

use crate::config::CoreConfig;

/// SSH client configuration
#[derive(Clone)]
pub struct SshClientConfig {
    pub server_addr: SocketAddr,
    pub username: String,
    pub private_key: String,
    pub server_public_key: Option<String>,
    pub channel_name: String,
}

impl SshClientConfig {
    pub fn from_core_config(cfg: &CoreConfig, ssh_key: &str) -> Result<Self> {
        Ok(Self {
            server_addr: cfg.main.address.parse()?,
            username: "anet".to_string(),
            private_key: ssh_key.to_string(),
            server_public_key: None,
            channel_name: "vpn".to_string(),
        })
    }
}

/// SSH transport connector
pub struct SshTransportConnector {
    config: SshClientConfig,
    core_config: CoreConfig,
}

impl SshTransportConnector {
    pub fn new(core_cfg: &CoreConfig, ssh_key: &str) -> Result<Self> {
        let ssh_config = SshClientConfig::from_core_config(core_cfg, ssh_key)?;

        Ok(Self {
            config: ssh_config,
            core_config: core_cfg.clone(),
        })
    }
}

#[async_trait]
impl TransportConnector for SshTransportConnector {
    async fn connect(
        &self,
    ) -> Result<(
        Box<dyn VpnStream>,
        AuthResponse,
        Cipher,
    )> {
        // Parse SSH key - используем PrivateKey вместо KeyPair
        let private_key = russh_keys::decode_secret_key(&self.config.private_key, None)
            .context("Failed to decode SSH private key")?;

        // Create SSH client handler
        let client_handler = SshClientHandler::new(self.config.server_public_key.clone());

        // Connect SSH
        let mut session = russh::client::connect(
            russh::client::Config::default(),
            self.config.server_addr,
            client_handler,
        )
            .await
            .context("SSH connection failed")?;

        // Authenticate - используем private_key напрямую
        let auth_result = session
            .authenticate_publickey(
                self.config.username.clone(),
                Arc::new(private_key),
            )
            .await;

        if !auth_result {
            bail!("SSH public key authentication failed");
        }

        // Open VPN channel
        let channel = session
            .channel_open_session()
            .await
            .context("Failed to open SSH channel")?;

        // Request VPN subsystem
        channel
            .request_subsystem(true, &self.config.channel_name)
            .await
            .context("Failed to start VPN subsystem")?;

        // Perform ASTP authentication over SSH channel
        let (auth_response, shared_key) = self
            .authenticate_over_channel(&channel, &session)
            .await?;

        // Create encrypted stream with post-auth cipher
        let cipher = Cipher::new(&shared_key);

        // Wrap SSH channel in EncryptedStream, then in SshVpnStream
        let encrypted = EncryptedStream::new(
            SshChannelRaw::new(channel, session),
            cipher.clone(),
        );

        let stream = SshVpnStream::new(encrypted, self.config.server_addr);

        Ok((Box::new(stream), auth_response, cipher))
    }
}

// ... остальной код без изменений ...