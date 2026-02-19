use super::ClientTransport;
use crate::config::CoreConfig;
use crate::auth::{AuthHandler, StreamAuthChannel};
use anet_common::transport_trait::VpnStream;
use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use futures::Stream;
use log::{info, error, warn};
use russh::client::{Handler, Session};
use russh::{Channel, ChannelMsg};
use russh_keys::key;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex};

struct ClientHandler;
#[async_trait]
impl Handler for ClientHandler {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        _server_public_key: &russh_keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

pub struct SshTransport {
    config: CoreConfig,
}

impl SshTransport {
    pub fn new(config: CoreConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ClientTransport for SshTransport {
    async fn connect(&self) -> Result<(anet_common::protocol::AuthResponse, Box<dyn VpnStream>)> {
        let addr_str = &self.config.main.address;
        let addr: SocketAddr = addr_str.parse().context("Invalid server address")?;
        let user = self.config.transport.ssh_user.as_deref().unwrap_or("root");

        info!("[SSH] Connecting to {} as {}", addr, user);

        let config = Arc::new(russh::client::Config::default());
        let mut session = russh::client::connect(config, addr, ClientHandler).await?;

        if !session.authenticate_none(user).await? {
            anyhow::bail!("SSH Authentication failed (auth_none rejected)");
        }

        info!("[SSH] Authenticated. Opening VPN channel...");

        let mut channel = session.channel_open_session().await?;
        channel.exec(true, "anet-vpn").await?;

        // 1. Создаем VpnStream СРАЗУ
        let vpn_stream = SshStreamAdapter::new(channel);
        let stream_arc = Arc::new(Mutex::new(vpn_stream));
        let auth_channel = StreamAuthChannel::new(stream_arc.clone());

        // 2. Запускаем аутентификацию (через адаптер)
        // AuthHandler сам отправит AuthRequest и прочитает AuthResponse
        let auth_handler = AuthHandler::new(&self.config)?;
        let (auth_response, _shared_key) = auth_handler.authenticate(&auth_channel).await?;
        info!("[SSH] Handshake complete. Assigned IP: {}", auth_response.ip);

        // 4. Возвращаем поток для данных
        Ok((auth_response, Box::new(MutexVpnStream(stream_arc))))
    }
}

struct SshStreamAdapter {
    read_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    write_tx: mpsc::UnboundedSender<Vec<u8>>,
    read_buffer: std::io::Cursor<Bytes>,
}


impl SshStreamAdapter {
    // Принимаем Channel<Msg>
    fn new(mut channel: Channel<russh::client::Msg>) -> Self {
        let (read_tx, read_rx) = mpsc::unbounded_channel();
        let (write_tx, mut write_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        // Актор канала
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Чтение из SSH
                    msg = channel.wait() => {
                        match msg {
                            Some(ChannelMsg::Data { data }) => {
                                let _ = read_tx.send(data.to_vec());
                            }
                            Some(ChannelMsg::ExtendedData { .. }) => {
                                info!("ChannelMsg::ExtendedData");
                            }

                            // WindowAdjust - это норма!
                            Some(ChannelMsg::WindowAdjusted { .. }) => {
                                info!("ChannelMsg::WindowAdjusted");
                            }

                            Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                                warn!("ChannelMsg::Close: end loop");
                                break; // EOF
                            }
                            // Другие сообщения (Success/Failure и т.д.)
                            msg => {
                                // Лучше залогировать, ЧТО именно пришло, прежде чем паниковать
                                warn!("[SSH] Ignored channel message: {:?}", msg);
                                // Не делаем break! Продолжаем.
                            }
                        }
                    }
                    // Запись в SSH
                    data_to_send = write_rx.recv() => {
                        if let Some(data) = data_to_send {
                            // &[u8] реализует AsyncRead
                            if let Err(e) = channel.data(&data[..]).await {
                                error!("[SSH] Write error: {}", e);
                                break;
                            }
                        } else {
                            // Write канал закрыт, выходим
                            break;
                        }
                    }
                }
            }
            let _ = channel.close().await;
        });

        Self {
            read_rx,
            write_tx,
            read_buffer: std::io::Cursor::new(Bytes::new()),
        }
    }
}

impl AsyncRead for SshStreamAdapter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
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
                    let remaining = Bytes::copy_from_slice(&data[len..]);
                    self.read_buffer = std::io::Cursor::new(remaining);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for SshStreamAdapter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.write_tx.send(buf.to_vec()) {
            Ok(_) => std::task::Poll::Ready(Ok(buf.len())),
            Err(_) => std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "SSH closed"))),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> { std::task::Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> { std::task::Poll::Ready(Ok(())) }
}

struct MutexVpnStream<S>(Arc<Mutex<S>>);
impl<S: AsyncRead + Unpin + Send> AsyncRead for MutexVpnStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        let mut guard = futures::ready!(Box::pin(self.0.lock()).as_mut().poll(cx));
        Pin::new(&mut *guard).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin + Send> AsyncWrite for MutexVpnStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        let mut guard = futures::ready!(Box::pin(self.0.lock()).as_mut().poll(cx));
        Pin::new(&mut *guard).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        let mut guard = futures::ready!(Box::pin(self.0.lock()).as_mut().poll(cx));
        Pin::new(&mut *guard).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        let mut guard = futures::ready!(Box::pin(self.0.lock()).as_mut().poll(cx));
        Pin::new(&mut *guard).poll_shutdown(cx)
    }
}
