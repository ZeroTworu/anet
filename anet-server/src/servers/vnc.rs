use crate::client_registry::ClientRegistry;
use crate::config::Config;
use crate::auth_handler::ServerAuthHandler;
use anet_common::consts::CHANNEL_BUFFER_SIZE;
use anyhow::Result;
use bytes::Bytes;
use log::{error, info, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

// Сигнатуры VNC RFB 3.8
const RFB_VER: &[u8; 12] = b"RFB 003.008\n";
const RFB_SEC_TYPES: &[u8; 2] = &[1, 1]; // Count: 1, Type: 1 (None)
const RFB_SEC_RESULT: &[u8; 4] = &[0, 0, 0, 0]; // Auth OK
const RFB_SRV_INIT: &[u8; 28] = &[
    0x04, 0x00, 0x03, 0x00, // Screen 1024x768
    0x20, 0x18, 0x00, 0x01, // BPP
    0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x10, 0x08, 0x00, 0x00, 0x00, 0x00, // Pixel format/Pad
    0x00, 0x00, 0x00, 0x04, // Name length
    b'X', b'v', b'n', b'c'  // Desktop Name "Xvnc"
];

async fn emulate_rfb_server_handshake(stream: &mut TcpStream) -> Result<()> {
    stream.write_all(RFB_VER).await?;
    stream.flush().await?;

    let mut buf = [0u8; 12];
    stream.read_exact(&mut buf).await?;
    if &buf != RFB_VER { return Err(anyhow::anyhow!("VNC Banner mismatch")); }

    stream.write_all(RFB_SEC_TYPES).await?;
    stream.flush().await?;
    let mut client_sec_pick = [0u8; 1];
    stream.read_exact(&mut client_sec_pick).await?;

    stream.write_all(RFB_SEC_RESULT).await?;
    stream.flush().await?;
    let mut client_init = [0u8; 1];
    stream.read_exact(&mut client_init).await?;

    stream.write_all(RFB_SRV_INIT).await?;
    stream.flush().await?;

    Ok(())
}

async fn handle_vnc_session(
    mut stream: TcpStream,
    registry: Arc<ClientRegistry>,
    config: Arc<Config>,
    tun_tx: mpsc::Sender<Bytes>,
    remote_addr: SocketAddr,
    auth_handler: ServerAuthHandler,
) -> Result<()> {

    if let Err(e) = emulate_rfb_server_handshake(&mut stream).await {
        error!("[VNC Node] Failed RFB handshake: {}", e);
        return Ok(());
    }
    info!("ASTP[VNC] Transport RFB Phase-I complete: {}", remote_addr);

    // ================= ВАЖНО: ДОБАВЛЕН LOOP =================
    loop {
        // Читаем пакет (ASTP Хендшейк Phase 1 и Phase 3) внутри VNC ClientCutText
        let mut header = [0u8; 8];
        if stream.read_exact(&mut header).await.is_err() { return Ok(()); }
        if header[0] != 6 { return Ok(()); } // Ожидаем ClientCutText

        let len = u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;
        if len > anet_common::consts::MAX_PACKET_SIZE * 2 { return Ok(()); }

        let mut payload = vec![0u8; len];
        if stream.read_exact(&mut payload).await.is_err() { return Ok(()); }

        let (resp, result) = auth_handler.process_handshake_packet(Bytes::from(payload), remote_addr).await?;

        if let Some(r) = resp {
            use bytes::BufMut;
            let mut framed = bytes::BytesMut::with_capacity(8 + r.len());
            framed.put_u8(3); // ServerCutText
            framed.put_slice(&[0, 0, 0]);
            framed.put_u32(r.len() as u32);
            framed.put(r);
            stream.write_all(&framed).await?;
            stream.flush().await?;
        }

        if let Some((client_info, _auth_resp)) = result {
            info!("[VNC ASTP-CORE] Activated routing proxy IP: {}", client_info.assigned_ip);

            let (tx_router, mut rx_router) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
            registry.finalize_client(&client_info.assigned_ip, tx_router);

            let (mut reader, mut writer) = tokio::io::split(stream);

            // ВХОДЯЩИЙ ТРАФИК (RX - читаем от Клиента, Type = 6)
            let tun_tx_clone = tun_tx.clone();
            let cipher_rx = client_info.cipher.clone();
            let t1 = tokio::spawn(async move {
                let mut header = [0u8; 8];
                while let Ok(_) = reader.read_exact(&mut header).await {
                    if header[0] != 6 { warn!("Invalid VNC MSG from Client: {}", header[0]); break; }
                    let len = u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;
                    if len > anet_common::consts::MAX_PACKET_SIZE * 2 { break; }

                    let mut payload = vec![0u8; len];
                    if reader.read_exact(&mut payload).await.is_err() { break; }

                    if let Ok(tun_data) = anet_common::transport::unwrap_packet(&cipher_rx, &payload) {
                        if tun_tx_clone.send(tun_data).await.is_err() { break; }
                    }
                }
            });

            // ИСХОДЯЩИЙ ТРАФИК (TX - пишем Клиенту, Type = 3)
            let stealth_config = config.stealth.clone();
            let cipher_tx = client_info.cipher.clone();
            let sequence_tx = client_info.sequence.clone();
            let nonce_prefix = client_info.nonce_prefix;

            let t2 = tokio::spawn(async move {
                let (tx_ready, mut rx_ready) = mpsc::channel::<Bytes>(1024);
                let dispatch = tokio::spawn(async move {
                    use rand::Rng; let mut r = rand::rngs::OsRng;
                    while let Some(ip) = rx_router.recv().await {
                        if ip.len() < 20 { continue; }
                        let dly = if stealth_config.max_jitter_ns > stealth_config.min_jitter_ns { r.gen_range(stealth_config.min_jitter_ns..=stealth_config.max_jitter_ns) } else { 0 };
                        let st = tx_ready.clone();
                        tokio::spawn(async move {
                            if dly > 0 { tokio::time::sleep(std::time::Duration::from_nanos(dly)).await; }
                            let _ = st.send(ip).await;
                        });
                    }
                });

                let p_step = config.stealth.padding_step;
                while let Some(raw) = rx_ready.recv().await {
                    let seq = sequence_tx.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let sz = raw.len() + 38;
                    let pad = anet_common::padding_utils::calculate_padding_needed(sz, p_step);
                    let sf_p = if sz + (pad as usize) > anet_common::consts::PADDING_MTU { 0 } else { pad };

                    if let Ok(crypted) = anet_common::transport::wrap_packet(&cipher_tx, &nonce_prefix, seq, raw, sf_p) {
                        use bytes::BufMut;
                        let mut framed = bytes::BytesMut::with_capacity(8 + crypted.len());
                        framed.put_u8(3); // ServerCutText
                        framed.put_slice(&[0, 0, 0]);
                        framed.put_u32(crypted.len() as u32);
                        framed.put(crypted);

                        if writer.write_all(&framed).await.is_err() || writer.flush().await.is_err() { break; }
                    }
                }
                dispatch.abort();
            });

            let _ = tokio::join!(t1, t2);

            info!("[VNC Node] Client disconnected and wiped: {}", client_info.assigned_ip);
            registry.remove_client(&client_info);
            return Ok(());
        }
    }
}

pub async fn run_vnc_server(config: Arc<Config>, registry: Arc<ClientRegistry>, tun_tx: mpsc::Sender<Bytes>, auth_handler: ServerAuthHandler) -> Result<()> {
    info!("Initializing Transport Port [VNC RFB 3.8 ASTP] TCP: {}", config.server.vnc_bind_to);
    let socket = TcpListener::bind(&config.server.vnc_bind_to).await?;

    loop {
        let (tcp, addr) = socket.accept().await?;
        let (cfg, reg, t_x, ath) = (config.clone(), registry.clone(), tun_tx.clone(), auth_handler.clone());
        let _ = tcp.set_nodelay(true);

        tokio::spawn(async move {
            if let Err(e) = handle_vnc_session(tcp, reg, cfg, t_x, addr, ath).await {
                info!("VNC Pipeline broke down unexpectedly: {}", e);
            }
        });
    }
}
