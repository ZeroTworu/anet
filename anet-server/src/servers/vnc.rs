use crate::auth_handler::ServerAuthHandler;
use crate::client_registry::{ClientRegistry, ClientTransportInfo};
use crate::config::Config;
use anet_common::consts::{
    ASTP_AUTH_TIMEOUT, CRYPTO_COALESCE_BUDGET_BYTES, MAX_PENDING_JITTER_PACKETS, PADDING_MTU,
    RFB_HANDSHAKE_TIMEOUT,
};
use anet_common::stream_framing::supervise_bidirectional_workers;
use anet_common::vnc::{
    CLIENT_CUT_TEXT, RFB_FRAMEBUFFER_UPDATE_HDR, RFB_SECURITY_OK, RFB_SECURITY_TYPES,
    RFB_SERVER_INIT, RFB_VERSION, SECURITY_TYPE_NONE, SERVER_CUT_TEXT, encode_cut_text,
    read_cut_text, write_cut_text,
};
use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use futures::future::BoxFuture;
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use log::{info, warn};
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

async fn emulate_rfb_server_handshake(stream: &mut TcpStream) -> Result<()> {
    stream.write_all(RFB_VERSION).await?;

    let mut version = [0; 12];
    stream.read_exact(&mut version).await?;
    anyhow::ensure!(&version == RFB_VERSION, "client does not speak RFB 3.8");

    stream.write_all(RFB_SECURITY_TYPES).await?;
    let selected_security = stream.read_u8().await?;
    anyhow::ensure!(
        selected_security == SECURITY_TYPE_NONE,
        "client selected unsupported VNC security type {selected_security}"
    );

    stream.write_all(RFB_SECURITY_OK).await?;
    let shared_desktop = stream.read_u8().await?;
    anyhow::ensure!(shared_desktop <= 1, "invalid VNC ClientInit shared flag");
    stream.write_all(RFB_SERVER_INIT).await?;
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
    stream.set_nodelay(true)?;
    tokio::time::timeout(
        RFB_HANDSHAKE_TIMEOUT,
        emulate_rfb_server_handshake(&mut stream),
    )
        .await
        .context("RFB handshake timed out")??;
    info!("[VNC] RFB handshake complete for {remote_addr}");

    let client_info = tokio::time::timeout(
        ASTP_AUTH_TIMEOUT,
        authenticate(&mut stream, remote_addr, &auth_handler),
    )
        .await
        .context("ASTP authentication timed out")??;
    info!(
        "[VNC] ASTP authenticated for {}; assigned IP {}",
        remote_addr, client_info.assigned_ip
    );

    let (router_tx, router_rx) = mpsc::channel(anet_common::consts::CHANNEL_BUFFER_SIZE);
    registry.finalize_client(&client_info.assigned_ip, router_tx);

    let (reader, writer) = tokio::io::split(stream);
    let mut inbound = tokio::spawn(receive_from_client(
        reader,
        tun_tx,
        client_info.clone(),
        registry.clone(),
    ));
    let mut outbound = tokio::spawn(send_to_client(
        writer,
        router_rx,
        client_info.clone(),
        config.stealth.clone(),
    ));

    let (_finished_worker, result) =
        supervise_bidirectional_workers(inbound, outbound, "VNC").await;
    registry.remove_client(&client_info).await;
    result
}



/// Выполняет аутентификацию ASTP поверх VNC (RFB ClientCutText / ServerCutText).
/// В случае подключения стороннего VNC-клиента или сканера ТСПУ (отправляющего SetPixelFormat,
/// SetEncodings или FramebufferUpdateRequest вместо ClientCutText) отправляет чёрный кадр экрана
/// и штатно завершает сеанс, маскируя сервер под реальный, но не отвечающий VNC десктоп.
async fn authenticate(
    stream: &mut TcpStream,
    remote_addr: SocketAddr,
    auth_handler: &ServerAuthHandler,
) -> Result<Arc<ClientTransportInfo>> {
    loop {
        let read_res = read_cut_text(stream, CLIENT_CUT_TEXT).await;
        let packet = match read_res {
            Ok(Some(p)) => p,
            Ok(None) => anyhow::bail!("client disconnected during ASTP authentication"),
            Err(e) => {
                // Если клиент прислал не ClientCutText (0x06), а другой RFB-запрос
                // (например FramebufferUpdateRequest=3, SetEncodings=2, SetPixelFormat=0):
                // шлем FramebufferUpdate с черным экраном и закрываем соединение.
                log::debug!("[VNC] Non-ASTP RFB message from {remote_addr} ({e}); answering black frame probe defense");
                let _ = send_rfb_probe_black_screen(stream).await;
                anyhow::bail!("non-ASTP RFB probe from {remote_addr} handled and closed");
            }
        };

        let (response, result) = auth_handler
            .process_handshake_packet(packet, remote_addr, "vnc")
            .await?;

        if let Some(response) = response {
            write_cut_text(stream, SERVER_CUT_TEXT, &response).await?;
        }
        if let Some((client_info, _)) = result {
            return Ok(client_info);
        }
    }
}

/// Отправляет черное изображение рабочего стола (1024x768) в формате RFB Raw 32bpp,
/// чтобы любой VNC-сканер (ТСПУ, nmap, RealVNC/TightVNC клиент) зафиксировал легитимный сеанс
/// и не определил туннель ANet.
async fn send_rfb_probe_black_screen(stream: &mut TcpStream) -> Result<()> {
    stream.write_all(RFB_FRAMEBUFFER_UPDATE_HDR).await?;
    // 1024x768 пикселей по 4 байта = 3,145,728 байт нулей (черный экран)
    const CHUNK_SIZE: usize = 64 * 1024;
    const TOTAL_BYTES: usize = 1024 * 768 * 4;
    let black_chunk = [0u8; CHUNK_SIZE];
    let mut written = 0;
    while written < TOTAL_BYTES {
        let to_write = std::cmp::min(CHUNK_SIZE, TOTAL_BYTES - written);
        stream.write_all(&black_chunk[..to_write]).await?;
        written += to_write;
    }
    stream.flush().await?;
    let _ = stream.shutdown().await;
    Ok(())
}

async fn receive_from_client(
    reader: tokio::io::ReadHalf<TcpStream>,
    tun_tx: mpsc::Sender<Bytes>,
    client_info: Arc<ClientTransportInfo>,
    registry: Arc<ClientRegistry>,
) -> Result<()> {
    let mut reader = tokio::io::BufReader::with_capacity(64 * 1024, reader);
    while let Some(encrypted) = read_cut_text(&mut reader, CLIENT_CUT_TEXT).await? {
        let packet =
            anet_common::transport::unwrap_packet_bytes_in_place(&client_info.cipher, encrypted)?;
        let packet_len = packet.len();

        // BACKPRESSURE: Если TUN-очередь переполнена, отбрасываем пакет,
        // чтобы не блокировать TCP-чтение и не создавать Deadlock.
        match tun_tx.try_send(packet) {
            Ok(_) => {
                registry.record_rx(&client_info, packet_len, "vnc");
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("[VNC] TUN queue full, dropping uplink packet from {}", client_info.assigned_ip);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                anyhow::bail!("TUN input queue closed");
            }
        }
    }
    Ok(())
}

async fn send_to_client(
    mut writer: tokio::io::WriteHalf<TcpStream>,
    mut router_rx: mpsc::Receiver<Bytes>,
    client_info: Arc<ClientTransportInfo>,
    stealth: anet_common::config::StealthConfig,
) -> Result<()> {
    let mut rng = StdRng::from_entropy();
    let jitter_enabled = stealth.max_jitter_ns > stealth.min_jitter_ns;
    let mut pending = FuturesUnordered::<BoxFuture<'static, Bytes>>::new();
    let mut input_open = true;

    // БУФЕР КОАЛЕСЦЕНЦИИ
    let mut batch_buf = BytesMut::with_capacity(CRYPTO_COALESCE_BUDGET_BYTES);

    while input_open || !pending.is_empty() {
        let mut packet = if !jitter_enabled {
            match router_rx.recv().await {
                Some(packet) => packet,
                None => break,
            }
        } else if pending.is_empty() {
            match router_rx.recv().await {
                Some(packet) => {
                    schedule_with_jitter(&mut pending, packet, &stealth, &mut rng);
                    continue;
                }
                None => {
                    input_open = false;
                    continue;
                }
            }
        } else if !input_open || pending.len() >= MAX_PENDING_JITTER_PACKETS {
            pending
                .next()
                .await
                .expect("pending jitter queue is not empty")
        } else {
            tokio::select! {
                packet = router_rx.recv() => {
                    match packet {
                        Some(packet) => {
                            schedule_with_jitter(&mut pending, packet, &stealth, &mut rng);
                            continue;
                        }
                        None => {
                            input_open = false;
                            continue;
                        }
                    }
                }
                packet = pending.next() => packet.expect("pending jitter queue is not empty"),
            }
        };

        batch_buf.clear();

        loop {
            if packet.len() >= 20 {
                let sequence = client_info.sequence.fetch_add(1, Ordering::Relaxed);
                let total_len = packet.len() + 38;
                let padding = anet_common::padding_utils::calculate_padding_needed(total_len, stealth.padding_step);
                let safe_padding = if total_len + usize::from(padding) > PADDING_MTU { 0 } else { padding };

                let encrypted = anet_common::transport::wrap_packet(
                    &client_info.cipher,
                    &client_info.nonce_prefix,
                    sequence,
                    packet,
                    safe_padding,
                )?;

                if let Ok(frame) = encode_cut_text(SERVER_CUT_TEXT, &encrypted) {
                    batch_buf.extend_from_slice(&frame);
                }
            }

            if batch_buf.len() >= CRYPTO_COALESCE_BUDGET_BYTES {
                break;
            }

            packet = match router_rx.try_recv() {
                Ok(p) => p,
                Err(_) => break,
            };
        }

        if !batch_buf.is_empty() {
            writer.write_all(&batch_buf).await?;
            // FLUSH УДАЛЕН (сеть отправляет пакеты по мере заполнения окна TCP)
        }
    }
    writer.shutdown().await?;
    Ok(())
}

fn schedule_with_jitter(
    pending: &mut FuturesUnordered<BoxFuture<'static, Bytes>>,
    packet: Bytes,
    stealth: &anet_common::config::StealthConfig,
    rng: &mut StdRng,
) {
    let delay = rng.gen_range(stealth.min_jitter_ns..=stealth.max_jitter_ns);
    pending.push(
        async move {
            if delay > 0 {
                tokio::time::sleep(Duration::from_nanos(delay)).await;
            }
            packet
        }
            .boxed(),
    );
}

pub async fn run_vnc_server(
    config: Arc<Config>,
    registry: Arc<ClientRegistry>,
    tun_tx: mpsc::Sender<Bytes>,
    auth_handler: ServerAuthHandler,
) -> Result<()> {
    info!("[VNC] Listening on {}", config.server.vnc_bind_to);
    let listener = TcpListener::bind(&config.server.vnc_bind_to).await?;

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        let registry = registry.clone();
        let config = config.clone();
        let tun_tx = tun_tx.clone();
        let auth_handler = auth_handler.clone();

        tokio::spawn(async move {
            if let Err(error) =
                handle_vnc_session(stream, registry, config, tun_tx, remote_addr, auth_handler)
                    .await
            {
                warn!("[VNC] Session {remote_addr} stopped: {error:#}");
            }
        });
    }
}
