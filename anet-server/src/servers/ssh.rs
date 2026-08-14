use crate::auth_handler::ServerAuthHandler;
use crate::client_registry::{ClientRegistry, ClientTransportInfo};
use crate::config::Config;
use anet_common::consts::CHANNEL_BUFFER_SIZE;
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anyhow::{Context, Result};
use bytes::Bytes;
use log::{info, warn};
use russh::{Channel, ChannelId, server};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

const ASTP_AUTH_TIMEOUT: Duration = Duration::from_secs(30);
const SSH_CHANNEL_WINDOW_SIZE: u32 = 4 * 1024 * 1024;
const SSH_MAX_PACKET_SIZE: u32 = 32 * 1024;

struct AnetSshHandler {
    remote_addr: SocketAddr,
    config: Arc<Config>,
    registry: Arc<ClientRegistry>,
    tun_tx: mpsc::Sender<Bytes>,
    auth_handler: ServerAuthHandler,
    pending_channels: HashMap<ChannelId, Channel<server::Msg>>,
}

impl AnetSshHandler {
    fn new(
        remote_addr: SocketAddr,
        config: Arc<Config>,
        registry: Arc<ClientRegistry>,
        tun_tx: mpsc::Sender<Bytes>,
        auth_handler: ServerAuthHandler,
    ) -> Self {
        Self {
            remote_addr,
            config,
            registry,
            tun_tx,
            auth_handler,
            pending_channels: HashMap::new(),
        }
    }
}

impl server::Handler for AnetSshHandler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let channel_id = channel.id();
        reply.accept().await;
        self.pending_channels.insert(channel_id, channel);
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel_id: ChannelId,
        command: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if command != b"anet-vpn" {
            self.pending_channels.remove(&channel_id);
            session.channel_failure(channel_id)?;
            session.close(channel_id)?;
            return Ok(());
        }
        let Some(channel) = self.pending_channels.remove(&channel_id) else {
            session.channel_failure(channel_id)?;
            return Ok(());
        };
        session.channel_success(channel_id)?;

        let registry = self.registry.clone();
        let config = self.config.clone();
        let tun_tx = self.tun_tx.clone();
        let remote_addr = self.remote_addr;
        let auth_handler = self.auth_handler.clone();

        tokio::spawn(async move {
            if let Err(error) = handle_ssh_vpn_session(
                channel.into_stream(),
                registry,
                config,
                tun_tx,
                remote_addr,
                auth_handler,
            )
            .await
            {
                warn!("[SSH] Session {remote_addr} stopped: {error:#}");
            }
        });
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel_id: ChannelId,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.pending_channels.remove(&channel_id);
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }
}

async fn handle_ssh_vpn_session<S>(
    mut stream: S,
    registry: Arc<ClientRegistry>,
    config: Arc<Config>,
    tun_tx: mpsc::Sender<Bytes>,
    remote_addr: SocketAddr,
    auth_handler: ServerAuthHandler,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let client_info = tokio::time::timeout(
        ASTP_AUTH_TIMEOUT,
        authenticate(&mut stream, remote_addr, &auth_handler),
    )
    .await
    .context("ASTP authentication timed out")??;
    info!(
        "[SSH] ASTP authenticated for {}; assigned IP {}",
        remote_addr, client_info.assigned_ip
    );

    let (router_tx, router_rx) = mpsc::channel(CHANNEL_BUFFER_SIZE);
    registry.finalize_client(&client_info.assigned_ip, router_tx);
    let (reader, writer) = tokio::io::split(stream);
    let mut inbound = tokio::spawn(receive_from_client(reader, tun_tx, client_info.clone()));
    let mut outbound = tokio::spawn(anet_common::jitter::bridge_crypto_stream_with_jitter(
        router_rx,
        writer,
        config.stealth.clone(),
        client_info.cipher.clone(),
        client_info.sequence.clone(),
        client_info.nonce_prefix,
    ));

    let result = tokio::select! {
        result = &mut inbound => flatten_worker_result("reader", result),
        result = &mut outbound => flatten_worker_result("writer", result),
    };
    inbound.abort();
    outbound.abort();
    let _ = inbound.await;
    let _ = outbound.await;
    registry.remove_client(&client_info);
    result
}

async fn authenticate<S>(
    stream: &mut S,
    remote_addr: SocketAddr,
    auth_handler: &ServerAuthHandler,
) -> Result<Arc<ClientTransportInfo>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let packet = read_next_packet(stream)
            .await?
            .context("client disconnected during ASTP authentication")?;
        let (response, result) = auth_handler
            .process_handshake_packet(packet, remote_addr)
            .await?;

        if let Some(response) = response {
            stream.write_all(&frame_packet(response)).await?;
            stream.flush().await?;
        }
        if let Some((client_info, _)) = result {
            return Ok(client_info);
        }
    }
}

async fn receive_from_client<R>(
    mut reader: R,
    tun_tx: mpsc::Sender<Bytes>,
    client_info: Arc<ClientTransportInfo>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    while let Some(encrypted) = read_next_packet(&mut reader).await? {
        let packet =
            anet_common::transport::unwrap_packet_bytes_in_place(&client_info.cipher, encrypted)?;
        tun_tx
            .send(packet)
            .await
            .context("TUN input queue closed")?;
    }
    Ok(())
}

fn flatten_worker_result(
    worker: &'static str,
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> Result<()> {
    result.with_context(|| format!("SSH {worker} task failed"))?
}

pub async fn run_ssh_server(
    config: Arc<Config>,
    registry: Arc<ClientRegistry>,
    tun_tx: mpsc::Sender<Bytes>,
    auth_handler: ServerAuthHandler,
) -> Result<()> {
    let host_key = russh::keys::load_secret_key(&config.server.ssh_host_key, None)?;
    let ssh_config = Arc::new(server::Config {
        keys: vec![host_key],
        window_size: SSH_CHANNEL_WINDOW_SIZE,
        maximum_packet_size: SSH_MAX_PACKET_SIZE,
        channel_buffer_size: CHANNEL_BUFFER_SIZE,
        nodelay: true,
        ..Default::default()
    });

    info!("[SSH] Listening on {}", config.server.ssh_bind_to);
    let listener = tokio::net::TcpListener::bind(&config.server.ssh_bind_to).await?;
    loop {
        let (stream, remote_addr) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let ssh_config = ssh_config.clone();
        let handler = AnetSshHandler::new(
            remote_addr,
            config.clone(),
            registry.clone(),
            tun_tx.clone(),
            auth_handler.clone(),
        );

        tokio::spawn(async move {
            if let Err(error) = server::run_stream(ssh_config, stream, handler).await {
                warn!("[SSH] Connection {remote_addr} stopped: {error:#}");
            }
        });
    }
}
