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

        // ... Дальнейший механизм ИДЕНТИЧЕН 1-В-1 тому, как написан Вами ТрафикКонтроллер (SSH),
        // Мы возвращаем виртуальный Duplex-Stream ядру через обертки

        let (core_in, route_inner) = tokio::io::duplex(65535 * 10);
        let (mut v_r, mut v_w) = tokio::io::split(route_inner);
        let cipher_tx = Arc::new(anet_common::encryption::Cipher::new(&key));
        let cipher_rx = Arc::new(anet_common::encryption::Cipher::new(&key));
        let st_c = self.config.stealth.clone();
        let np = auth_pack.nonce_prefix.clone().as_slice().try_into().unwrap_or([0,0,0,0]);
        let seq_tk = Arc::new(std::sync::atomic::AtomicU64::new(0));

        let worker_tx = cipher_tx.clone(); let np_x = np.clone(); let dls = st_c.clone();

        tokio::spawn(async move {
            let (tr_y, mut r_yr) = mpsc::channel::<Bytes>(1024);
            let ds = tokio::spawn(async move {
                let mut rng = rand::rngs::OsRng;
                while let Ok(Some(bts)) = read_next_packet(&mut v_r).await {
                    let st = tr_y.clone();
                    let dx = if dls.max_jitter_ns > dls.min_jitter_ns { rand::Rng::gen_range(&mut rng, dls.min_jitter_ns..=dls.max_jitter_ns) } else { 0 };
                    tokio::spawn(async move { if dx > 0 { tokio::time::sleep(std::time::Duration::from_nanos(dx)).await; } let _ = st.send(bts).await; });
                }
            });
            while let Some(dpkg) = r_yr.recv().await {
                let q_sq = seq_tk.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let pz = dpkg.len() + 38;
                let pa = calculate_padding_needed(pz, st_c.padding_step); let sa_pa = if pz+(pa as usize) > anet_common::consts::PADDING_MTU {0} else {pa};

                if let Ok(cph) = anet_common::transport::wrap_packet(&worker_tx, &np_x, q_sq, dpkg, sa_pa) {
                    if tcp_wr.write_all(&frame_packet(cph)).await.is_err() { break; }
                }
            }
            ds.abort(); debug!("[VNC Proxier Output Layer Severed]");
        });

        let worker_rx = cipher_rx.clone();
        tokio::spawn(async move {
            while let Ok(Some(net_dt)) = read_next_packet(&mut tcp_rd).await {
                if let Ok(dc_sck) = anet_common::transport::unwrap_packet(&worker_rx, &net_dt) {
                    if v_w.write_all(&frame_packet(dc_sck)).await.is_err() { break; }
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

