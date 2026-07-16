use super::{ClientTransport, ConnectionResult, MutexVpnStream};
use crate::config::{CoreConfig, ServerConfig};
use crate::auth::{AuthHandler, StreamAuthChannel};
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use log::{info, error};
use russh::client::Handler;
use russh::{Channel, ChannelMsg};
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex};
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anet_common::consts::{CHANNEL_BUFFER_SIZE, MAX_PACKET_SIZE};
use std::future::ready;
struct ClientHandler;
#[async_trait]
impl Handler for ClientHandler {
    type Error = russh::Error;
    fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        ready(Ok(true))
    }
}

pub struct SshTransport {
    config: CoreConfig,
    server: ServerConfig,
}

impl SshTransport {
    pub fn new(config: CoreConfig, server: ServerConfig) -> Self {
        Self { config, server }
    }
}

#[async_trait]
impl ClientTransport for SshTransport {
    async fn connect(&self) -> Result<ConnectionResult> {
        let addr_str = &self.server.address;
        let addr: SocketAddr = addr_str.to_socket_addrs()?.next().ok_or(anyhow::anyhow!("Invalid server address"))?;

        let user = self.server.ssh_user.as_deref()
            .or(self.config.transport.ssh_user.as_deref())
            .unwrap_or("root");

        let mut config_base = russh::client::Config::default();
        config_base.window_size = 2_000_000;
        config_base.maximum_packet_size = MAX_PACKET_SIZE as u32;

        let config = Arc::new(config_base);
        let mut session = russh::client::connect(config, addr, ClientHandler).await?;

        if !session.authenticate_none(user).await?.success() {
            anyhow::bail!("SSH Authentication failed (auth_none rejected)");
        }
        info!("[SSH] Authenticated. Opening VPN channel...");

        let channel = session.channel_open_session().await?;
        channel.exec(true, "anet-vpn").await?;

        // Передаем сессию по значению с конкретным типом Handle<ClientHandler>
        let raw_stream = SshStreamAdapter::new(channel, session);
        let stream_arc = Arc::new(Mutex::new(raw_stream));
        let auth_channel = StreamAuthChannel::new(stream_arc.clone());

        let auth_handler = AuthHandler::new(&self.config, self.server.server_pub_key.as_deref())?;
        let (auth_response, shared_key) = auth_handler.authenticate(&auth_channel).await?;
        info!("[SSH] Handshake complete. Assigned IP: {}", auth_response.ip);

        drop(auth_channel);
        let active_tcp_stream = Arc::try_unwrap(stream_arc).map_err(|_| anyhow::anyhow!("Internal ref dropped"))?.into_inner();
        let (tcp_reader,  tcp_writer) = tokio::io::split(active_tcp_stream);

        let (client_stream, internal_router) = tokio::io::duplex(65535 * 10);
        let (mut tunnel_read, mut tunnel_write) = tokio::io::split(internal_router);

        let sequence_tx = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let cipher_tx = Arc::new(anet_common::encryption::Cipher::new(&shared_key));
        let cipher_rx = Arc::new(anet_common::encryption::Cipher::new(&shared_key));
        let nonce_prefix: [u8; 4] = auth_response.nonce_prefix.as_slice().try_into().unwrap_or([0,0,0,0]);
        let stealth_cfg = self.config.stealth.clone();

        let (tx_bridge, rx_bridge) = mpsc::channel(CHANNEL_BUFFER_SIZE);

        tokio::spawn(async move {
            while let Ok(Some(packet)) = read_next_packet(&mut tunnel_read).await {
                if tx_bridge.send(packet).await.is_err() { break; }
            }
        });

        let stealth_clone = stealth_cfg.clone();
        let cipher_tx_worker = cipher_tx.clone();
        let seq_worker = sequence_tx.clone();
        let np = nonce_prefix;

        tokio::spawn(async move {
            let _ = anet_common::jitter::bridge_crypto_stream_with_jitter(
                rx_bridge,
                tcp_writer,
                stealth_clone,
                cipher_tx_worker,
                seq_worker,
                np,
            ).await;
        });

        let (tx_in, mut rx_in) = mpsc::channel(CHANNEL_BUFFER_SIZE);
        let cipher_rx_worker = cipher_rx.clone();

        tokio::spawn(async move {
            let _ = anet_common::jitter::receive_crypto_stream(
                tcp_reader,
                tx_in,
                cipher_rx_worker
            ).await;
        });

        tokio::spawn(async move {
            while let Some(packet) = rx_in.recv().await {
                let framed = frame_packet(packet);
                if tokio::io::AsyncWriteExt::write_all(&mut tunnel_write, &framed).await.is_err() {
                    break;
                }
            }
        });

        let output_stream = Arc::new(Mutex::new(client_stream));

        Ok(ConnectionResult {
            auth_response: auth_response,
            vpn_stream: Box::new(MutexVpnStream(output_stream)),
            endpoint: None,
            connection: None
        })
    }
}

pub struct SshStreamAdapter {
    read_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    write_tx: mpsc::UnboundedSender<Vec<u8>>,
    read_buffer: std::io::Cursor<Bytes>,
    task_handle: tokio::task::JoinHandle<()>,
    // Используем конкретный тип Handle<ClientHandler>
    session: Option<russh::client::Handle<ClientHandler>>,
}

impl SshStreamAdapter {
    fn new(mut channel: Channel<russh::client::Msg>, session: russh::client::Handle<ClientHandler>) -> Self {
        let (read_tx, read_rx) = mpsc::unbounded_channel();
        let (write_tx, mut write_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        let task_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = channel.wait() => {
                        match msg {
                            Some(ChannelMsg::Data { data }) => { let _ = read_tx.send(data.to_vec()); }
                            Some(ChannelMsg::WindowAdjusted { .. }) => {}
                            Some(ChannelMsg::ExtendedData { .. }) => {}
                            Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                            _ => {}
                        }
                    }
                    data_to_send = write_rx.recv() => {
                        if let Some(data) = data_to_send {
                            if let Err(e) = channel.data(&data[..]).await {
                                error!("Underground tcp loop failure to deliver byte bounds: {}", e);
                                break;
                            }
                        } else { break; }
                    }
                }
            }
        });

        Self { read_rx, write_tx, read_buffer: std::io::Cursor::new(Bytes::new()), task_handle, session: Some(session) }
    }
}

impl Drop for SshStreamAdapter {
    fn drop(&mut self) {
        log::info!("SshStreamAdapter: Dropping adapter, aborting task.");
        self.task_handle.abort();

        // Забираем и закрываем физическую сессию Handle<ClientHandler>
        if let Some(session) = self.session.take() {
            tokio::spawn(async move {
                info!("SshStreamAdapter: Sending disconnect packet...");
                let _ = session.disconnect(russh::Disconnect::ByApplication, "Closed by ANet", "en");
            });
        }
    }
}

impl AsyncRead for SshStreamAdapter {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        if self.read_buffer.position() < self.read_buffer.get_ref().len() as u64 {
            let n = std::io::Read::read(&mut self.read_buffer, buf.initialize_unfilled())?;
            buf.advance(n);
            return Poll::Ready(Ok(()));
        }
        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let len = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..len]);
                if len < data.len() {
                    self.read_buffer = std::io::Cursor::new(Bytes::copy_from_slice(&data[len..]));
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for SshStreamAdapter {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        match self.write_tx.send(buf.to_vec()) {
            Ok(_) => std::task::Poll::Ready(Ok(buf.len())),
            Err(_) => std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Ssh Write Link Snapped"))),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}
