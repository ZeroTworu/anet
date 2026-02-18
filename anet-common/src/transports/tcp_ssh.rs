//! TCP + SSH transport using SSH channels for VPN tunneling

use super::VpnStream;
use crate::auth::AuthHandler;
use anyhow::Result;
use bytes::Bytes;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use async_ssh::{Client as SshClient, Channel};

/// SSH-based transport using direct-tcpip or custom channel
pub struct SshVpnClient {
    auth_handler: AuthHandler, // ← Same auth reuse
    ssh_client: SshClient,
    remote_addr: SocketAddr,
}

impl SshVpnClient {
    pub async fn connect(
        cfg: &CoreConfig,
        ssh_key: &str,
    ) -> Result<(Box<dyn VpnStream>, AuthResponse, Cipher)> {
        // 1. SSH connect
        let ssh = SshClient::connect(cfg.main.address.parse()?).await?;
        ssh.authenticate_key("anet", ssh_key).await?;

        // 2. Open custom channel for VPN (or use direct-tcpip to local port)
        let channel = ssh.open_channel("vpn@anet").await?;

        // 3. ASTP auth over SSH channel
        let (auth_response, shared_key) = Self::auth_over_channel(&channel, cfg).await?;

        // 4. Post-auth encryption layer (defense in depth)
        let cipher = Cipher::new(&shared_key);
        let stream = Box::new(SshChannelStream::new(channel, cipher));

        Ok((stream, auth_response, cipher))
    }

    async fn auth_over_channel(
        channel: &Channel,
        cfg: &CoreConfig,
    ) -> Result<(AuthResponse, [u8; 32])> {
        // Same 4-phase auth but framed over SSH channel
        todo!()
    }
}
