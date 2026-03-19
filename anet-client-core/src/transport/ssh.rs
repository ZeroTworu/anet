use super::{ClientTransport, ConnectionResult};
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
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Mutex};
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anet_common::padding_utils::calculate_padding_needed;
use rand::Rng;

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
        let (mut tcp_reader, mut tcp_writer) = tokio::io::split(active_tcp_stream);

        // Дуплекс пайп. Левую сторону (client_stream) мы тупо возвращаем Кору для чтения/отправки чистых пакетов!
        let (client_stream, internal_router) = tokio::io::duplex(65535 * 10);
        let (mut tunnel_read, mut tunnel_write) = tokio::io::split(internal_router);

        // Инструменты Зла
        let sequence_tx = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let cipher_tx = Arc::new(anet_common::encryption::Cipher::new(&shared_key));
        let cipher_rx = Arc::new(anet_common::encryption::Cipher::new(&shared_key));
        let nonce_prefix: [u8; 4] = auth_response.nonce_prefix.as_slice().try_into().unwrap_or([0,0,0,0]);
        let stealth_cfg = self.config.stealth.clone();
        let p_step = stealth_cfg.padding_step;

        // ---------- ТАСК TX: ИСХОДЯЩИЙ ПОТОК (С КЛИЕНТА НА СЕРВЕР). -----------
        // 1. Из туннеля-Core выходит чисто [ДЛИНА 2б | Истинный IP]. Дешифровка идет от read_next_packet!
        // 2. Включается задержка, потом Чача-Джигл и запаковка нового [ДЛИНА ОБФ | БЛОК ШИФРА].
        let _t_tx = tokio::spawn(async move {
            let (tx_ready, mut rx_ready) = mpsc::channel::<Bytes>(1024);

            let dt_stealth = stealth_cfg.clone();
            let dispatch = tokio::spawn(async move {
                let mut rng = rand::rngs::OsRng;
                loop {
                    // Парсит голый внутренний трафик от CORE.
                    match read_next_packet(&mut tunnel_read).await {
                        Ok(Some(raw_ip_pkg)) => {
                            if raw_ip_pkg.len() < 20 { continue; }

                            let tx = tx_ready.clone();
                            let delay = if dt_stealth.max_jitter_ns > dt_stealth.min_jitter_ns {
                                rng.gen_range(dt_stealth.min_jitter_ns..=dt_stealth.max_jitter_ns)
                            } else { 0 };

                            tokio::spawn(async move {
                                if delay > 0 { tokio::time::sleep(std::time::Duration::from_nanos(delay)).await; }
                                let _ = tx.send(raw_ip_pkg).await;
                            });
                        },
                        _ => break // core detached.
                    }
                }
            });

            while let Some(pure_data) = rx_ready.recv().await {
                let seq = sequence_tx.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let total_len = pure_data.len() + 38;
                let padding = calculate_padding_needed(total_len, p_step);
                let safe_padd = if total_len + (padding as usize) > anet_common::consts::PADDING_MTU { 0 } else { padding };

                match anet_common::transport::wrap_packet(&cipher_tx, &nonce_prefix, seq, pure_data, safe_padd) {
                    Ok(crypted) => {
                        let outgoing_frame = frame_packet(crypted); // Приматываем новый размер к обфусцированному.
                        if tcp_writer.write_all(&outgoing_frame).await.is_err() || tcp_writer.flush().await.is_err() { break; }
                    }
                    Err(e) => error!("SSH wrap payload crashed: {}", e),
                }
            }
            dispatch.abort();
            info!("[SSH proxy] Inner Jitter&TX channel stopped.");
        });

        // ----------- ТАСК RX: ВХОДЯЩИЙ (С СЕРВЕРА К НАМ НА КЛИЕНТ) ---------------
        let _t_rx = tokio::spawn(async move {
            loop {
                // Из интернета падает Frame -> Из него достаётся блок шума.
                match read_next_packet(&mut tcp_reader).await {
                    Ok(Some(cipher_packet)) => {
                        // Чистится, чекается тэг от Поли1305.
                        if let Ok(raw_decrypted) = anet_common::transport::unwrap_packet(&cipher_rx, &cipher_packet) {
                            // Форматируется для "чистой трубы" Корa и скидывается.
                            let frame_in_tun = frame_packet(raw_decrypted);
                            if tunnel_write.write_all(&frame_in_tun).await.is_err() { break; }
                        }
                    },
                    Ok(None) => break, // штатное закрытие.
                    Err(_) => break // обрыв.
                }
            }
            info!("[SSH proxy] Outer crypto loop terminated");
        });

        // Теперь отдаем сам client_stream ядру - а оно уже обмазано "дуплексным шлюзом". Оно идентично старому `Box VpnStream`
        Ok(ConnectionResult{
            auth_response,
            vpn_stream: Box::new(MutexVpnStream(Arc::new(Mutex::new(client_stream)))),
            endpoint: None,
            connection: None
        })
    }
}


struct SshStreamAdapter {
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
