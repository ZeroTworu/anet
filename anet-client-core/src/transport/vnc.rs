use super::{ClientTransport, ConnectionResult, MutexVpnStream};
use crate::config::CoreConfig;
use crate::auth::{AuthHandler, AuthChannel};
use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::{BufMut, Bytes};
use log::{info, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use std::time::Duration;
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anet_common::padding_utils::calculate_padding_needed;
use anet_common::consts::{MAX_PACKET_SIZE, CHANNEL_BUFFER_SIZE};

const RFB_VER: &[u8; 12] = b"RFB 003.008\n";
const RFB_SEC_TYPES: &[u8; 2] = &[1, 1]; // Security Count = 1, Auth = None
const RFB_SEC_RESULT: &[u8; 4] = &[0, 0, 0, 0];

struct VncAuthChannel {
    stream: Mutex<TcpStream>,
}

#[async_trait]
impl AuthChannel for VncAuthChannel {
    async fn send(&self, data: Bytes) -> Result<()> {
        let mut stream = self.stream.lock().await;
        let mut framed = bytes::BytesMut::with_capacity(8 + data.len());
        framed.put_u8(6); // ClientCutText
        framed.put_slice(&[0, 0, 0]); // Padding
        framed.put_u32(data.len() as u32);
        framed.put(data);
        stream.write_all(&framed).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn recv(&self, timeout: Duration) -> Result<Bytes> {
        let mut stream = self.stream.lock().await;
        let mut header = [0u8; 8];
        tokio::time::timeout(timeout, stream.read_exact(&mut header)).await??;
        if header[0] != 3 { anyhow::bail!("Invalid VNC Auth msg type from server: {}", header[0]); }

        let len = u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;
        if len > anet_common::consts::MAX_PACKET_SIZE * 2 { anyhow::bail!("VNC Auth packet too large"); }

        let mut payload = vec![0u8; len];
        tokio::time::timeout(timeout, stream.read_exact(&mut payload)).await??;
        Ok(Bytes::from(payload))
    }
}

pub struct VncTransport { config: CoreConfig }
impl VncTransport { pub fn new(c: CoreConfig) -> Self { Self { config: c } } }

#[async_trait]
impl ClientTransport for VncTransport {
    async fn connect(&self) -> Result<ConnectionResult> {
        let addr: SocketAddr = self.config.main.address.parse().context("Invalid server target")?;
        info!("[VNC Transport] Probing fake desktop target: {}", addr);

        let mut stream = TcpStream::connect(addr).await?;
        let _ = stream.set_nodelay(true);

        let mut ver = [0u8; 12]; stream.read_exact(&mut ver).await?;
        info!("-> Read Srv Ban: {:?}", std::str::from_utf8(&ver).unwrap_or(""));
        if &ver != RFB_VER { anyhow::bail!("Target Server returned unknown protocol (Not RFB3.8)."); }
        stream.write_all(RFB_VER).await?;
        stream.flush().await?;

        let mut sc_types = [0u8; 2]; stream.read_exact(&mut sc_types).await?;
        if &sc_types != RFB_SEC_TYPES { anyhow::bail!("VNC Security handshake rejection.")}
        stream.write_all(&[1]).await?;
        stream.flush().await?;

        let mut sc_rs = [0u8; 4]; stream.read_exact(&mut sc_rs).await?;
        if &sc_rs != RFB_SEC_RESULT { anyhow::bail!("VNC Server banned logic.")}
        stream.write_all(&[1]).await?;
        stream.flush().await?;

        let mut rfb_desktop = vec![0u8; 28];
        stream.read_exact(&mut rfb_desktop).await?;

        info!("[VNC Tunnel Ready]. Securing envelope (Entering ASTP Domain)...");

        // ЯДРО СВЯЗИ VPN ЧЕРЕЗ VNC-AUTH-CHANNEL (БЕЗ ARC)
        let auth_ch = VncAuthChannel { stream: Mutex::new(stream) };

        let ath_ctrl = AuthHandler::new(&self.config)?;
        let (auth_pack, key) = ath_ctrl.authenticate(&auth_ch).await?;
        info!("[ASTP over VNC] Encapsulated Layer successful! Bound Local VPN IPv4: {}", auth_pack.ip);

        // Вытаскиваем чистый TCP-сокет обратно из Mutex'а
        let live_stream = auth_ch.stream.into_inner();
        let (mut tcp_reader, mut tcp_writer) = tokio::io::split(live_stream);

        // Мост для Core
        let (client_stream, internal_router) = tokio::io::duplex(MAX_PACKET_SIZE * 10);
        let (mut tunnel_read, mut tunnel_write) = tokio::io::split(internal_router);

        let cipher_tx = Arc::new(anet_common::encryption::Cipher::new(&key));
        let cipher_rx = Arc::new(anet_common::encryption::Cipher::new(&key));
        let sequence_tx = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let nonce_prefix: [u8; 4] = auth_pack.nonce_prefix.clone().as_slice().try_into().unwrap_or([0,0,0,0]);
        let stealth_cfg = self.config.stealth.clone();

        // -------------------------------------------------------------
        // ИСХОДЯЩИЙ ТРАФИК (TX - Пишем серверу, Type = 6)
        // -------------------------------------------------------------
        let (tx_bridge, mut rx_bridge) = mpsc::channel(CHANNEL_BUFFER_SIZE);
        tokio::spawn(async move {
            while let Ok(Some(packet)) = read_next_packet(&mut tunnel_read).await {
                if tx_bridge.send(packet).await.is_err() { break; }
            }
        });

        let p_step = stealth_cfg.padding_step;
        tokio::spawn(async move {
            let (tx_ready, mut rx_ready) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
            let dispatch = tokio::spawn(async move {
                use rand::Rng; let mut r = rand::rngs::OsRng;
                while let Some(ip) = rx_bridge.recv().await {
                    let dly = if stealth_cfg.max_jitter_ns > stealth_cfg.min_jitter_ns { r.gen_range(stealth_cfg.min_jitter_ns..=stealth_cfg.max_jitter_ns) } else { 0 };
                    let st = tx_ready.clone();
                    tokio::spawn(async move {
                        if dly > 0 { tokio::time::sleep(std::time::Duration::from_nanos(dly)).await; }
                        let _ = st.send(ip).await;
                    });
                }
            });

            while let Some(raw) = rx_ready.recv().await {
                let seq = sequence_tx.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let sz = raw.len() + 38;
                let pad = calculate_padding_needed(sz, p_step);
                let sa_pa = if sz+(pad as usize) > anet_common::consts::PADDING_MTU {0} else {pad};

                if let Ok(crypted) = anet_common::transport::wrap_packet(&cipher_tx, &nonce_prefix, seq, raw, sa_pa) {
                    let mut framed = bytes::BytesMut::with_capacity(8 + crypted.len());
                    framed.put_u8(6); // ClientCutText
                    framed.put_slice(&[0, 0, 0]); // Padding
                    framed.put_u32(crypted.len() as u32);
                    framed.put(crypted);

                    if tcp_writer.write_all(&framed).await.is_err() || tcp_writer.flush().await.is_err() { break; }
                }
            }
            dispatch.abort(); warn!("[VNC proxy] Inner TX channel stopped.");
        });

        // -------------------------------------------------------------
        // ВХОДЯЩИЙ ТРАФИК (RX - Читаем от сервера, Type = 3)
        // -------------------------------------------------------------
        let (tx_in, mut rx_in) = mpsc::channel(CHANNEL_BUFFER_SIZE);

        tokio::spawn(async move {
            let mut header = [0u8; 8];
            while let Ok(_) = tcp_reader.read_exact(&mut header).await {
                if header[0] != 3 { warn!("Invalid VNC MSG from Server: {}", header[0]); break; }
                let len = u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;
                if len > anet_common::consts::MAX_PACKET_SIZE * 2 { break; }

                let mut payload = vec![0u8; len];
                if tcp_reader.read_exact(&mut payload).await.is_err() { break; }

                if let Ok(tun_data) = anet_common::transport::unwrap_packet(&cipher_rx, &payload) {
                    if tx_in.send(tun_data).await.is_err() { break; }
                }
            }
            info!("[VNC proxy] Outer RX loop terminated");
        });

        tokio::spawn(async move {
            while let Some(packet) = rx_in.recv().await {
                let framed = frame_packet(packet);
                if tokio::io::AsyncWriteExt::write_all(&mut tunnel_write, &framed).await.is_err() { break; }
            }
        });

        let output_stream = Arc::new(Mutex::new(client_stream));
        Ok(ConnectionResult {
            auth_response: auth_pack,
            vpn_stream: Box::new(MutexVpnStream(output_stream)),
            endpoint: None,
            connection: None
        })
    }
}
