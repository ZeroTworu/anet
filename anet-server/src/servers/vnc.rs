/// Created By Gemini
use crate::client_registry::ClientRegistry;
use crate::config::Config;
use crate::auth_handler::ServerAuthHandler;
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anet_common::padding_utils::calculate_padding_needed;
use anet_common::consts::CHANNEL_BUFFER_SIZE;
use anyhow::{Result, Context};
use bytes::Bytes;
use log::{error, info, debug, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

// Фиктивные стадии VNC(RFB 3.8) для пробива сканера
const RFB_VER: &[u8; 12] = b"RFB 003.008\n";
const RFB_SEC_TYPES: &[u8; 2] = &[1, 1]; // Security Types: 1 (Count), Type 1 (None)
const RFB_SEC_RESULT: &[u8; 4] = &[0, 0, 0, 0]; // Auth OK
const RFB_SRV_INIT: &[u8; 28] = &[
    0x04, 0x00, 0x03, 0x00, // Screen 1024x768
    0x20, 0x18, 0x00, 0x01, // BPP
    0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x10, 0x08, 0x00, 0x00, 0x00, 0x00, // Pix Mask/Pad
    0x00, 0x00, 0x00, 0x04, // Str Length
    b'X', b'v', b'n', b'c'  // Desk Name "Xvnc" (Легитимная сигнатура стандартного VNC сервера)
];

async fn emulate_rfb_server_handshake(stream: &mut TcpStream) -> Result<()> {
    // 1
    stream.write_all(RFB_VER).await?;
    let mut buf = [0u8; 12]; stream.read_exact(&mut buf).await?;
    if &buf != RFB_VER { return Err(anyhow::anyhow!("VNC Banner mismatch")); }
    // 2
    stream.write_all(RFB_SEC_TYPES).await?;
    let mut client_sec_pick = [0u8; 1]; stream.read_exact(&mut client_sec_pick).await?;
    // 3
    stream.write_all(RFB_SEC_RESULT).await?;
    let mut client_init = [0u8; 1]; stream.read_exact(&mut client_init).await?;
    // 4.
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
        debug!("[VNC Node] Failed faking RFB handshake: {}", e);
        return Ok(());
    }

    info!("ASTP[VNC] Transport RFB Phase-I complete: {}", remote_addr);

    // Передаем сырой (фэйковый) VNC TCP-соку в дефолтную крипту:
    loop {
        let packet = match read_next_packet(&mut stream).await? {
            Some(p) => p,
            None => return Ok(()),
        };

        let (resp, result) = auth_handler.process_handshake_packet(packet, remote_addr).await?;
        if let Some(r) = resp { stream.write_all(&frame_packet(r)).await?; stream.flush().await?; }

        if let Some((client_info, _auth_resp)) = result {
            info!("[VNC ASTP-CORE] Activated routing proxy IP: {}", client_info.assigned_ip);

            let (tx_router, mut rx_router) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
            registry.finalize_client(&client_info.assigned_ip, tx_router);
            let (mut reader, mut writer) = tokio::io::split(stream);

            let t_tx = tun_tx.clone(); let rc = client_info.clone();

            // ВЕРТИМ RX СТРИМ
            let t1 = tokio::spawn(async move {
                loop {
                    match read_next_packet(&mut reader).await {
                        Ok(Some(enc)) => {
                            if let Ok(ip_data) = anet_common::transport::unwrap_packet(&rc.cipher, &enc) {
                                if t_tx.send(ip_data).await.is_err() { break; }
                            }
                        }
                        _ => break,
                    }
                }
            });


            let stealth_config = config.stealth.clone();
            let tx_client_info = client_info.clone();

            let t2 = tokio::spawn(async move {
                let _ = anet_common::jitter::bridge_crypto_stream_with_jitter(
                    rx_router,
                    writer,
                    stealth_config,
                    tx_client_info.cipher.clone(),
                    tx_client_info.sequence.clone(),
                    tx_client_info.nonce_prefix,
                ).await;
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

        // Разрешаем NO_DELAY на сокете: пакеты игры / VPN не застревают на аппаратной задержке
        if let Err(e) = tcp.set_nodelay(true) { warn!("Failed to config nodelay on TCP/VNC: {}", e); }

        tokio::spawn(async move {
            if let Err(e) = handle_vnc_session(tcp, reg, cfg, t_x, addr, ath).await {
                debug!("VNC Pipeline broke down unexpectedly: {}", e);
            }
        });
    }
}
