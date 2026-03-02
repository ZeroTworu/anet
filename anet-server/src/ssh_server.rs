use crate::client_registry::ClientRegistry;
use crate::config::Config;
use crate::auth_handler::ServerAuthHandler;
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anet_common::padding_utils::calculate_padding_needed;
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

    async fn shell_request(&mut self, channel: ChannelId, session: &mut server::Session ) -> Result<(), Self::Error> {
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
where S: AsyncRead + AsyncWrite + Unpin + Send + 'static
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

            let (tx_router, mut rx_router) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
            registry.finalize_client(&client_info.assigned_ip, tx_router);

            let (mut reader, mut writer) = tokio::io::split(stream);

            // ВЕРТИМ КРИПТУ ПРЯМ ТУТ В ВОРКЕРАХ

            let tun_tx_clone = tun_tx.clone();
            let rx_client_info = client_info.clone();
            let t1 = tokio::spawn(async move {
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
            let padding_step = stealth_config.padding_step;
            let tx_client_info = client_info.clone();

            let t2 = tokio::spawn(async move {
                let (tx_ready, mut rx_ready) = mpsc::channel::<Bytes>(1024);

                let dispatch_task = tokio::spawn(async move {
                    use rand::Rng;
                    let mut rng = rand::rngs::OsRng;
                    while let Some(packet) = rx_router.recv().await {
                        if packet.len() < 20 { continue; }

                        let tx = tx_ready.clone();
                        let delay = if stealth_config.max_jitter_ns > stealth_config.min_jitter_ns {
                            rng.gen_range(stealth_config.min_jitter_ns..=stealth_config.max_jitter_ns)
                        } else { 0 };

                        tokio::spawn(async move {
                            if delay > 0 { tokio::time::sleep(std::time::Duration::from_nanos(delay)).await; }
                            let _ = tx.send(packet).await;
                        });
                    }
                });

                while let Some(packet) = rx_ready.recv().await {
                    let seq = tx_client_info.sequence.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let t_len = packet.len() + 38;
                    let pdd = calculate_padding_needed(t_len, padding_step);
                    let spdd = if t_len + (pdd as usize) > anet_common::consts::PADDING_MTU { 0 } else { pdd };

                    match anet_common::transport::wrap_packet(&tx_client_info.cipher, &tx_client_info.nonce_prefix, seq, packet, spdd) {
                        Ok(crypted) => {
                            if writer.write_all(&frame_packet(crypted)).await.is_err() || writer.flush().await.is_err() { break; }
                        }
                        Err(_) => break,
                    }
                }
                dispatch_task.abort();
            });

            let _ = tokio::join!(t1, t2);

            info!("VPN Stream cleanly wiped down: {:?}", client_info.assigned_ip);
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

    // ОТКРЫВАЕМ ХАЙВЕИ ПО ПРЯМОЙ ЧТОБЫ TCP НЕ ДОХ СТОЯ
    // sh_config.window_size = 2_000_000_000;
    // sh_config.maximum_packet_size = 200_000_000;

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
            let h = AnetSshHandler { remote_addr: addr, config: c_config, registry, tun_tx, session_tx: None, auth_handler: a_handler };
            let _ = server::run_stream(s_conf, tcp, h).await;
        });
    }
}