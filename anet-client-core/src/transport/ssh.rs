use super::{ClientTransport, ConnectionResult, MutexVpnStream};
use crate::config::CoreConfig;
use crate::auth::{AuthHandler, StreamAuthChannel};
use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use log::{info, error};
use russh::client::Handler;
use russh::{Channel, ChannelMsg};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex};
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anet_common::consts::CHANNEL_BUFFER_SIZE;


struct ClientHandler;
#[async_trait]
impl Handler for ClientHandler {
    type Error = russh::Error;
    async fn check_server_key(&mut self, _server_public_key: &russh_keys::PublicKey) -> Result<bool, Self::Error> {
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
    async fn connect(&self) -> Result<ConnectionResult> {
        let addr_str = &self.config.main.address;
        let addr: SocketAddr = addr_str.parse().context("Invalid server address")?;
        let user = self.config.transport.ssh_user.as_deref().unwrap_or("root");

        // Хак лимита (на максимум возможный в протоколе, спасает от затыков).
        let mut config_base = russh::client::Config::default();
        config_base.window_size = 10_000_000;
        config_base.maximum_packet_size = 65535;

        let config = Arc::new(config_base);
        let mut session = russh::client::connect(config, addr, ClientHandler).await?;

        if !session.authenticate_none(user).await? {
            anyhow::bail!("SSH Authentication failed (auth_none rejected)");
        }
        info!("[SSH] Authenticated. Opening VPN channel...");

        let channel = session.channel_open_session().await?;
        channel.exec(true, "anet-vpn").await?;

        // 1. Адаптер (Абсолютно честный родной адаптер для SSH).
        let raw_stream = SshStreamAdapter::new(channel);
        let stream_arc = Arc::new(Mutex::new(raw_stream));
        let auth_channel = StreamAuthChannel::new(stream_arc.clone());

        // 2. Аутентификация
        let auth_handler = AuthHandler::new(&self.config)?;
        let (auth_response, shared_key) = auth_handler.authenticate(&auth_channel).await?;
        info!("[SSH] Handshake complete. Assigned IP: {}", auth_response.ip);

        // 3. Высвобождаем Адаптер и делаем Проксификатор: Теневой туннель через локальную Дюплекс-Трубу.
        drop(auth_channel);
        let active_tcp_stream = Arc::try_unwrap(stream_arc).map_err(|_| anyhow::anyhow!("Internal ref dropped"))?.into_inner();
        let (tcp_reader,  tcp_writer) = tokio::io::split(active_tcp_stream);

        // Дуплекс пайп. Левую сторону (client_stream) мы тупо возвращаем Кору для чтения/отправки чистых пакетов!
        let (client_stream, internal_router) = tokio::io::duplex(65535 * 10);
        let (mut tunnel_read, mut tunnel_write) = tokio::io::split(internal_router);

        let sequence_tx = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let cipher_tx = Arc::new(anet_common::encryption::Cipher::new(&shared_key));
        let cipher_rx = Arc::new(anet_common::encryption::Cipher::new(&shared_key));
        let nonce_prefix: [u8; 4] = auth_response.nonce_prefix.as_slice().try_into().unwrap_or([0,0,0,0]);
        let stealth_cfg = self.config.stealth.clone();

        let (tx_bridge, rx_bridge) = mpsc::channel(CHANNEL_BUFFER_SIZE);

        // Воркер-адаптер: Читает из виртуального DuplexStream ядра и перекладывает в канал
        tokio::spawn(async move {
            while let Ok(Some(packet)) = read_next_packet(&mut tunnel_read).await {
                if tx_bridge.send(packet).await.is_err() { break; }
            }
        });

        let stealth_clone = stealth_cfg.clone();
        let cipher_tx_worker = cipher_tx.clone();
        let seq_worker = sequence_tx.clone();
        let np = nonce_prefix;

        // Запускаем универсальный крипто-джиттер из anet-common
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

        // -------------------------------------------------------------
        // ВХОДЯЩИЙ ТРАФИК (RX): receive_crypto_stream -> mpsc -> Duplex
        // -------------------------------------------------------------
        let (tx_in, mut rx_in) = mpsc::channel(CHANNEL_BUFFER_SIZE);
        let cipher_rx_worker = cipher_rx.clone();

        // Запускаем универсальный дешифратор из anet-common
        tokio::spawn(async move {
            let _ = anet_common::jitter::receive_crypto_stream(
                tcp_reader,
                tx_in,
                cipher_rx_worker
            ).await;
        });

        // Воркер-адаптер: Читает расшифрованные пакеты из канала и пишет в виртуальный DuplexStream ядра
        tokio::spawn(async move {
            while let Some(packet) = rx_in.recv().await {
                let framed = frame_packet(packet);
                if tokio::io::AsyncWriteExt::write_all(&mut tunnel_write, &framed).await.is_err() {
                    break;
                }
            }
        });

        // -------------------------------------------------------------
        // ВОЗВРАТ РЕЗУЛЬТАТА ЯДРУ
        // -------------------------------------------------------------
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
}

impl SshStreamAdapter {
    fn new(mut channel: Channel<russh::client::Msg>) -> Self {
        let (read_tx, read_rx) = mpsc::unbounded_channel();
        let (write_tx, mut write_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        tokio::spawn(async move {
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
            let _ = channel.close().await;
        });

        Self { read_rx, write_tx, read_buffer: std::io::Cursor::new(Bytes::new()) }
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
