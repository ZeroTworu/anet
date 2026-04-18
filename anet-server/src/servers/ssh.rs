use crate::client_registry::ClientRegistry;
use crate::config::Config;
use crate::auth_handler::ServerAuthHandler;
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anet_common::consts::CHANNEL_BUFFER_SIZE;
use anyhow::Result;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use log::{error, info};
use russh::{server, Channel, ChannelId, CryptoVec};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Адаптер для превращения SSH канала в AsyncRead + AsyncWrite
struct SshChannelAdapter {
    id: ChannelId,
    handle: server::Handle,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    read_buf: BytesMut,
}

impl SshChannelAdapter {
    fn new(id: ChannelId, handle: server::Handle, rx: mpsc::UnboundedReceiver<Vec<u8>>) -> Self {
        Self { id, handle, rx, read_buf: BytesMut::new() }
    }
}

impl AsyncRead for SshChannelAdapter {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        if !self.read_buf.is_empty() {
            let len = std::cmp::min(self.read_buf.len(), buf.remaining());
            buf.put_slice(&self.read_buf.split_to(len));
            return Poll::Ready(Ok(()));
        }
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let len = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..len]);
                if len < data.len() {
                    self.read_buf.extend_from_slice(&data[len..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for SshChannelAdapter {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        let handle = self.handle.clone();
        let id = self.id;
        let data = CryptoVec::from_slice(buf);
        tokio::spawn(async move { let _ = handle.data(id, data).await; });
        std::task::Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        let handle = self.handle.clone();
        let id = self.id;
        tokio::spawn(async move { let _ = handle.close(id).await; });
        std::task::Poll::Ready(Ok(()))
    }
}

struct AnetSshHandler {
    remote_addr: SocketAddr,
    config: Arc<Config>,
    registry: Arc<ClientRegistry>,
    tun_tx: mpsc::Sender<Bytes>,
    session_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    auth_handler: ServerAuthHandler,
}

impl AnetSshHandler {
    fn new(
        remote_addr: SocketAddr,
        config: Arc<Config>,
        registry: Arc<ClientRegistry>,
        tun_tx: mpsc::Sender<Bytes>,
        session_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
        auth_handler: ServerAuthHandler,
    ) -> Self {
        Self {
            remote_addr,
            config,
            registry,
            tun_tx,
            session_tx,
            auth_handler,
        }
    }
}

#[async_trait]
impl server::Handler for AnetSshHandler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, _: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    // РОУТ ПРИЕМА SSH
    async fn channel_open_session(&mut self, channel: Channel<server::Msg>, session: &mut server::Session) -> Result<bool, Self::Error> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.session_tx = Some(tx);

        let adapter = SshChannelAdapter::new(channel.id(), session.handle(), rx);

        let registry = self.registry.clone();
        let config = self.config.clone();
        let tun_tx = self.tun_tx.clone();
        let remote_addr = self.remote_addr;
        let auth_handler = self.auth_handler.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_ssh_vpn_session(adapter, registry, config, tun_tx, remote_addr, auth_handler).await {
                error!("SSH Session disconnected abruptly: {}", e);
            }
        });
        Ok(true)
    }

    async fn data(&mut self, _channel: ChannelId, data: &[u8], _session: &mut server::Session) -> Result<(), Self::Error> {
        if let Some(tx) = &self.session_tx {
            let _ = tx.send(data.to_vec());
        }
        Ok(())
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut server::Session) -> Result<(), Self::Error> {
        session.data(channel, CryptoVec::from_slice(b"Welcome to Simple SSH Server.\r\n"));
        session.close(channel);
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
    info!("SSH VPN: Handshake sequence engaging with {:?}", remote_addr);
    loop {
        let packet = match read_next_packet(&mut stream).await? {
            Some(p) => p,
            None => return Ok(()),
        };

        let (resp, result) = auth_handler.process_handshake_packet(packet, remote_addr).await?;

        if let Some(r) = resp {
            stream.write_all(&frame_packet(r)).await?;
            stream.flush().await?;
        }

        if let Some((client_info, _auth_resp)) = result {
            info!("SSH VPN:  IP Route {} Assigned", client_info.assigned_ip);

            let (tx_router, rx_router) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
            registry.finalize_client(&client_info.assigned_ip, tx_router);

            let (mut reader, writer) = tokio::io::split(stream);

            // ВЕРТИМ КРИПТУ ПРЯМ ТУТ В ВОРКЕРАХ

            let tun_tx_clone = tun_tx.clone();
            let rx_client_info = client_info.clone();
            let reader_task = tokio::spawn(async move {
                loop {
                    match read_next_packet(&mut reader).await {
                        Ok(Some(framed_packet)) => {
                            if let Ok(tun_data) = anet_common::transport::unwrap_packet(&rx_client_info.cipher, &framed_packet) {
                                if tun_tx_clone.send(tun_data).await.is_err() { break; }
                            }
                        }
                        _ => break,
                    }
                }
            });

            // OUTBOUND. Туннель ОС скидывает IPшник для этого клиета -> зажевать -> чача20 -> отправить в рушх.
            let stealth_config = config.stealth.clone();
            let tx_client_info = client_info.clone();

            let writer_task = tokio::spawn(async move {
                let _ = anet_common::jitter::bridge_crypto_stream_with_jitter(
                    rx_router,
                    writer,
                    stealth_config,
                    tx_client_info.cipher.clone(),
                    tx_client_info.sequence.clone(),
                    tx_client_info.nonce_prefix,
                ).await;
            });

            let _ = tokio::select! {
                _ = reader_task => info!("SSH Reader task finished for {}", client_info.assigned_ip),
                _ = writer_task => info!("SSH Writer task finished for {}", client_info.assigned_ip),
            };


            info!("SSH VPN Stream cleanly wiped down: {:?}", client_info.assigned_ip);
            registry.remove_client(&client_info);
            return Ok(());
        }
    }
}

pub async fn run_ssh_server(
    config: Arc<Config>,
    registry: Arc<ClientRegistry>,
    tun_tx: mpsc::Sender<Bytes>,
    auth_handler: ServerAuthHandler,
) -> Result<()> {
    let mut sh_config = server::Config::default();

    let key = russh_keys::load_secret_key(&config.server.ssh_host_key, None)?;
    sh_config.keys.push(key);
    let sh_config = Arc::new(sh_config);

    info!("SSH Started On: {}", config.server.ssh_bind_to);

    let socket = tokio::net::TcpListener::bind(config.server.ssh_bind_to.clone()).await?;

    loop {
        let (tcp, addr) = socket.accept().await?;
        let s_conf = sh_config.clone();
        let registry = registry.clone();
        let c_config = config.clone();
        let tun_tx = tun_tx.clone();
        let a_handler = auth_handler.clone();

        tokio::spawn(async move {
            let h = AnetSshHandler::new(addr, c_config, registry, tun_tx, None, a_handler);
            let _ = server::run_stream(s_conf, tcp, h).await;
        });
    }
}
