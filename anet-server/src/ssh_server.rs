use crate::client_registry::ClientRegistry;
use crate::config::Config;
use crate::auth_handler::ServerAuthHandler;
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anet_common::protocol::{Message as AnetMessage, message::Content};
use anet_common::crypto_utils;
use anet_common::encryption::Cipher;
use anet_common::consts::{MAX_PACKET_SIZE, CHANNEL_BUFFER_SIZE};
use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use log::{debug, error, info, warn};
use prost::Message;
use russh::{server, Channel, ChannelId, CryptoVec};
use russh_keys::key;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// Адаптер для превращения SSH канала в AsyncRead + AsyncWrite
/// Чтобы мы могли скармливать его общей логике VPN
struct SshChannelAdapter {
    id: ChannelId,
    handle: server::Handle,
    rx: mpsc::UnboundedReceiver<Vec<u8>>, // Входящие данные от Handler
    read_buf: BytesMut,
}

impl SshChannelAdapter {
    fn new(id: ChannelId, handle: server::Handle, rx: mpsc::UnboundedReceiver<Vec<u8>>) -> Self {
        Self {
            id,
            handle,
            rx,
            read_buf: BytesMut::new(),
        }
    }
}

// Реализация AsyncRead для адаптера
impl AsyncRead for SshChannelAdapter {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;

        // Если есть остатки в буфере - отдаем их
        if !self.read_buf.is_empty() {
            let len = std::cmp::min(self.read_buf.len(), buf.remaining());
            buf.put_slice(&self.read_buf.split_to(len));
            return Poll::Ready(Ok(()));
        }

        // Читаем из канала
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

// Реализация AsyncWrite для адаптера
impl AsyncWrite for SshChannelAdapter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        // Russh handle.data() возвращает Future, но мы в poll_write.
        // Это проблема. Russh - это async, а poll_write должен быть non-blocking.
        // ХАК: Мы просто спавним отправку. Это не совсем корректно для backpressure,
        // но для VPN сойдет.
        let handle = self.handle.clone();
        let id = self.id;
        let data = CryptoVec::from_slice(buf);

        tokio::spawn(async move {
            let _ = handle.data(id, data).await;
        });

        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        let handle = self.handle.clone();
        let id = self.id;
        tokio::spawn(async move {
            let _ = handle.close(id).await;
        });
        std::task::Poll::Ready(Ok(()))
    }
}

/// Обработчик событий SSH сервера
struct AnetSshHandler {
    remote_addr: SocketAddr,
    config: Arc<Config>,
    registry: Arc<ClientRegistry>,
    tun_tx: mpsc::Sender<Bytes>,

    // Канал для передачи данных в задачу обработки (Session Loop)
    session_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    auth_handler: ServerAuthHandler,
}

#[async_trait]
impl server::Handler for AnetSshHandler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, _: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }
    async fn auth_password(&mut self, _: &str, _: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }
    // Пускаем всех. У нас своя аутентификация.
    async fn auth_publickey(&mut self, _: &str, _: &key::PublicKey) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    // Клиент открывает сессию
    async fn channel_open_session(&mut self, channel: Channel<server::Msg>, session: &mut server::Session) -> Result<bool, Self::Error> {
        // Создаем канал связи
        let (tx, rx) = mpsc::unbounded_channel();
        self.session_tx = Some(tx);

        let adapter = SshChannelAdapter::new(channel.id(), session.handle(), rx);

        // Запускаем логику VPN для этой сессии
        let registry = self.registry.clone();
        let config = self.config.clone();
        let tun_tx = self.tun_tx.clone();
        let remote_addr = self.remote_addr;
        let auth_handler = self.auth_handler.clone();

        // ВАЖНО: Мы клонируем данные для подписи из AuthHandler?
        // Или создаем новый AuthProcessor?
        // Нам нужны server_signing_key и quic_cert из конфига/AuthHandler.
        // Для простоты, предположим мы имеем доступ к ним (передадим в конструктор Handler).

        tokio::spawn(async move {
            if let Err(e) = handle_ssh_vpn_session(adapter, registry, config, tun_tx, remote_addr, auth_handler).await {
                warn!("SSH VPN session ended with error: {}", e);
            }
        });

        Ok(true)
    }

    // Данные от клиента -> в канал адаптера
    async fn data(&mut self, _channel: ChannelId, data: &[u8], _session: &mut server::Session) -> Result<(), Self::Error> {
        if let Some(tx) = &self.session_tx {
            let _ = tx.send(data.to_vec());
        }
        Ok(())
    }

    // Обработка запроса Shell/Exec (для баннера)
    async fn shell_request(&mut self, channel: ChannelId, session: &mut server::Session ) -> Result<(), Self::Error> {
        session.data(channel, CryptoVec::from_slice(b"Welcome to Simpe SSH Server.\r\n"));
        session.close(channel);
        Ok(())
    }
}

/// Основная логика сессии VPN внутри SSH
/// Это аналог vpn_handler, но поверх Stream (SSH), а не Datagram (QUIC)
async fn handle_ssh_vpn_session<S>(
    mut stream: S,
    registry: Arc<ClientRegistry>,
    config: Arc<Config>,
    tun_tx: mpsc::Sender<Bytes>,
    remote_addr: SocketAddr,
    auth_handler: ServerAuthHandler, // Передаем копию
) -> Result<()>
where S: AsyncRead + AsyncWrite + Unpin + Send + 'static
{
    info!("SSH VPN: Handshake started with {}", remote_addr);

    // 1. Handshake Loop
    // Нам нужно читать и писать фреймы, пока не получим успех
    loop {
        let packet = match read_next_packet(&mut stream).await? {
            Some(p) => p,
            None => {
                info!("SSH client disconnected during handshake");
                return Ok(());
            }
        };

        // Обработка пакета
        let (resp, result) = auth_handler.process_handshake_packet(packet, remote_addr).await?;

        // Отправка ответа
        if let Some(r) = resp {
            stream.write_all(&frame_packet(r)).await?;
            stream.flush().await?;
        }

        // Если успех - переходим к Data Loop
        if let Some((client_info, _auth_resp)) = result {
            info!("SSH VPN Handshake Success! Client: {}", client_info.assigned_ip);

            // Для SSH не нужно регистрировать в registry для UDP сокета (префикс).
            // Но нужно зарегистрировать для роутинга (обратный трафик).
            // Используем finalize_client с каналом.

            let (tx_router, mut rx_router) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
            registry.finalize_client(&client_info.assigned_ip, tx_router);

            // DATA LOOP
            // Шифрование данных в SSH не обязательно (т.к. SSH шифрует),
            // но для унификации можно включить.
            // Если включить, надо использовать client_info.cipher.
            // Пока сделаем БЕЗ доп. шифрования (прозрачный режим).

            let (mut reader, mut writer) = tokio::io::split(stream);
            let tun_tx_clone = tun_tx.clone();

            let t1 = tokio::spawn(async move {
                loop {
                    match read_next_packet(&mut reader).await {
                        Ok(Some(packet)) => {
                            // Если нужно дешифровать - тут.
                            if tun_tx_clone.send(packet).await.is_err() { break; }
                        }
                        _ => break,
                    }
                }
            });

            let t2 = tokio::spawn(async move {
                while let Some(packet) = rx_router.recv().await {
                    // Если нужно шифровать - тут.
                    let framed = frame_packet(packet);
                    if writer.write_all(&framed).await.is_err() { break; }
                }
            });

            let _ = tokio::join!(t1, t2);

            info!("SSH VPN Session ended for {}", client_info.assigned_ip);
            // registry.remove_client(...) - если надо
            return Ok(());
        }
    }
}

/// Запуск SSH сервера
pub async fn run_ssh_server(
    config: Arc<Config>,
    registry: Arc<ClientRegistry>,
    tun_tx: mpsc::Sender<Bytes>,
    auth_handler: ServerAuthHandler,
) -> Result<()> {


    info!("Starting SSH Transport on {}", config.server.ssh_bind_to);

    let mut sh_config = server::Config::default();
    // Грузим ключ хоста
    let key = russh_keys::load_secret_key(&config.server.ssh_host_key, None)?;
    sh_config.keys.push(key);
    let sh_config = Arc::new(sh_config);

    let socket = tokio::net::TcpListener::bind(config.server.ssh_bind_to.clone()).await?;

    loop {
        let (tcp, addr) = socket.accept().await?;
        let sh_config = sh_config.clone();
        let registry = registry.clone();
        let config = config.clone();
        let tun_tx = tun_tx.clone();
        let auth_handler= auth_handler.clone();
        tokio::spawn(async move {
            let handler = AnetSshHandler {
                remote_addr: addr,
                config,
                registry,
                tun_tx,
                session_tx: None,
                auth_handler,
            };

            let _ = server::run_stream(sh_config, tcp, handler).await;
        });
    }
}