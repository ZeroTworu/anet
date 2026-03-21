use super::{ClientTransport, ConnectionResult};
use crate::config::CoreConfig;
use crate::auth::{AuthHandler, StreamAuthChannel};
use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use log::{info, error, debug};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anet_common::padding_utils::calculate_padding_needed;

const RFB_VER: &[u8; 12] = b"RFB 003.008\n";
const RFB_SEC_TYPES: &[u8; 2] = &[1, 1]; // Security Count = 1, Auth = None
const RFB_SEC_RESULT: &[u8; 4] = &[0, 0, 0, 0];

pub struct VncTransport { config: CoreConfig }

impl VncTransport { pub fn new(c: CoreConfig) -> Self { Self { config: c } } }

#[async_trait]
impl ClientTransport for VncTransport {
    async fn connect(&self) -> Result<ConnectionResult> {
        let addr: SocketAddr = self.config.main.address.parse().context("Invalid server target")?;
        info!("[VNC Transport] Probing fake desktop target: {}", addr);

        let mut stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true).unwrap_or(());

        // Читаем банер сервака (12 байт)
        let mut ver = [0u8; 12]; stream.read_exact(&mut ver).await?;
        info!("-> Read Srv Ban: {:?}", std::str::from_utf8(&ver).unwrap_or(""));

        if &ver != RFB_VER { anyhow::bail!("Target Server returned unknown generic protocol (Not RFB3.8)."); }
        stream.write_all(RFB_VER).await?;
        stream.flush().await?;
        info!("<- Send Cli Ban");

        // 2. Секур Типы
        let mut sc_types = [0u8; 2]; stream.read_exact(&mut sc_types).await?;
        info!("-> Read Sec Types: {:?}", sc_types);

        if &sc_types != RFB_SEC_TYPES { anyhow::bail!("VNC Security handshake rejection.")}
        stream.write_all(&[1]).await?;
        stream.flush().await?;

        // 3. Ответ Секура и Шаред инфо
        let mut sc_rs = [0u8; 4]; stream.read_exact(&mut sc_rs).await?;
        info!("-> Read Auth Result: {:?}", sc_rs);
        if &sc_rs != RFB_SEC_RESULT { anyhow::bail!("VNC Server banned logic.")}

        stream.write_all(&[1]).await?;
        stream.flush().await?;

        // 4. Сервер отдаёт Десктоп-хуйню
        // 4. Сервер отдаёт Десктоп ОДНИМ МАССИВНЫМ БЛОКОМ (28 Bytes)
        let mut rfb_desktop = vec![0u8; 28];
        stream.read_exact(&mut rfb_desktop).await?;

        info!("[VNC Tunnel Ready]. Securing envelope (Entering ASTP Domain)...");

        let raw_stream_mutex = Arc::new(Mutex::new(stream));
        let auth_ch = StreamAuthChannel::new(raw_stream_mutex.clone());

        // ЯДРО СВЯЗИ VPN
        let ath_ctrl = AuthHandler::new(&self.config)?;
        let (auth_pack, key) = ath_ctrl.authenticate(&auth_ch).await?;
        info!("[ASTP over VNC] Encapsulated Layer successful! Bound Local VPN IPv4: {}", auth_pack.ip);

        drop(auth_ch);
        let live_stream = Arc::try_unwrap(raw_stream_mutex).map_err(|_| anyhow::anyhow!("Internal reference block issue"))?.into_inner();
        let (mut tcp_rd, mut tcp_wr) = tokio::io::split(live_stream);

        // Мы возвращаем виртуальный Duplex-Stream ядру через обертки

        let (core_in, route_inner) = tokio::io::duplex(65535 * 10);
        let (mut v_r, mut v_w) = tokio::io::split(route_inner);
        let cipher_tx = Arc::new(anet_common::encryption::Cipher::new(&key));
        let cipher_rx = Arc::new(anet_common::encryption::Cipher::new(&key));
        let st_c = self.config.stealth.clone();
        let np = auth_pack.nonce_prefix.clone().as_slice().try_into().unwrap_or([0,0,0,0]);
        let seq_tk = Arc::new(std::sync::atomic::AtomicU64::new(0));

        let (tx_bridge, rx_bridge) = mpsc::channel(1024);

        // Воркер-адаптер: Читает из виртуального DuplexStream ядра и перекладывает в канал
        tokio::spawn(async move {
            while let Ok(Some(packet)) = read_next_packet(&mut v_r).await {
                if tx_bridge.send(packet).await.is_err() { break; }
            }
        });

        let stealth_clone = st_c.clone();
        let cipher_tx_worker = cipher_tx.clone();
        let seq_worker = seq_tk.clone();
        let np_x = np;

        // Запускаем универсальный крипто-джиттер из anet-common
        tokio::spawn(async move {
            let _ = anet_common::jitter::bridge_crypto_stream_with_jitter(
                rx_bridge,
                tcp_wr,
                stealth_clone,
                cipher_tx_worker,
                seq_worker,
                np_x,
            ).await;
            debug!("[VNC proxy] Inner Jitter&TX channel stopped.");
        });

        // -------------------------------------------------------------
        // ВХОДЯЩИЙ ТРАФИК (RX): receive_crypto_stream -> mpsc -> Duplex
        // -------------------------------------------------------------
        let (tx_in, mut rx_in) = mpsc::channel(1024);
        let cipher_rx_worker = cipher_rx.clone();

        // Запускаем универсальный дешифратор из anet-common
        tokio::spawn(async move {
            let _ = anet_common::jitter::receive_crypto_stream(
                tcp_rd,
                tx_in,
                cipher_rx_worker
            ).await;
            debug!("[VNC proxy] Outer crypto loop terminated");
        });

        // Воркер-адаптер: Читает расшифрованные пакеты из канала и пишет в виртуальный DuplexStream ядра
        tokio::spawn(async move {
            while let Some(packet) = rx_in.recv().await {
                let framed = frame_packet(packet);
                if tokio::io::AsyncWriteExt::write_all(&mut v_w, &framed).await.is_err() {
                    break;
                }
            }
        });

        // Создаем Мост для Коре интерфейса

        let output_stream = Arc::new(Mutex::new(core_in));

        Ok(ConnectionResult {
            auth_response: auth_pack,
            vpn_stream: Box::new(MutexVpnStream(output_stream)),
            endpoint: None,
            connection: None
        })
    }
}

// Универсальная обертка AsyncRead/Write для Дуплексных шлюзов:
struct MutexVpnStream<S>(Arc<Mutex<S>>);

impl<S: tokio::io::AsyncRead + Unpin + Send> tokio::io::AsyncRead for MutexVpnStream<S> {
    fn poll_read(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        let mut guard = futures::ready!(Box::pin(self.0.lock()).as_mut().poll(cx));
        std::pin::Pin::new(&mut *guard).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin + Send> tokio::io::AsyncWrite for MutexVpnStream<S> {
    fn poll_write(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        let mut guard = futures::ready!(Box::pin(self.0.lock()).as_mut().poll(cx));
        std::pin::Pin::new(&mut *guard).poll_write(cx, buf)
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        let mut guard = futures::ready!(Box::pin(self.0.lock()).as_mut().poll(cx));
        std::pin::Pin::new(&mut *guard).poll_flush(cx)
    }

    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        let mut guard = futures::ready!(Box::pin(self.0.lock()).as_mut().poll(cx));
        std::pin::Pin::new(&mut *guard).poll_shutdown(cx)
    }
}

