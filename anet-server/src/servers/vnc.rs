use crate::auth_handler::ServerAuthHandler;
use crate::client_registry::{ClientRegistry, ClientTransportInfo};
use crate::config::Config;
use anet_common::consts::PADDING_MTU;
use anet_common::vnc::{
    CLIENT_CUT_TEXT, RFB_VERSION, SECURITY_TYPE_NONE, SERVER_CUT_TEXT, read_cut_text,
    write_cut_text,
};
use anyhow::{Context, Result};
use bytes::Bytes;
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

const RFB_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const ASTP_AUTH_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PENDING_JITTER_PACKETS: usize = 256;
const RFB_SECURITY_TYPES: &[u8] = &[1, SECURITY_TYPE_NONE];
const RFB_SECURITY_OK: &[u8] = &[0, 0, 0, 0];
const RFB_SERVER_INIT: &[u8] = &[
    0x04, 0x00, 0x03, 0x00, // 1024x768
    0x20, 0x18, 0x00, 0x01, // 32 bpp, depth 24, little-endian, true-colour
    0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x10, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
    b'X', b'v', b'n', b'c',
];

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

    enum FinishedWorker {
        Inbound,
        Outbound,
    }

    let (finished_worker, result) = tokio::select! {
        result = &mut inbound => (FinishedWorker::Inbound, flatten_worker_result("reader", result)),
        result = &mut outbound => (FinishedWorker::Outbound, flatten_worker_result("writer", result)),
    };
    if !matches!(finished_worker, FinishedWorker::Inbound) {
        inbound.abort();
        let _ = inbound.await;
    }
    if !matches!(finished_worker, FinishedWorker::Outbound) {
        outbound.abort();
        let _ = outbound.await;
    }
    registry.remove_client(&client_info);
    result
}

fn flatten_worker_result(
    worker: &'static str,
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> Result<()> {
    result.with_context(|| format!("VNC {worker} task failed"))?
}

async fn authenticate(
    stream: &mut TcpStream,
    remote_addr: SocketAddr,
    auth_handler: &ServerAuthHandler,
) -> Result<Arc<ClientTransportInfo>> {
    loop {
        let packet = read_cut_text(stream, CLIENT_CUT_TEXT)
            .await?
            .context("client disconnected during ASTP authentication")?;
        let (response, result) = auth_handler
            .process_handshake_packet(packet, remote_addr)
            .await?;

        if let Some(response) = response {
            write_cut_text(stream, SERVER_CUT_TEXT, &response).await?;
        }
        if let Some((client_info, _)) = result {
            return Ok(client_info);
        }
    }
}

async fn receive_from_client(
    mut reader: tokio::io::ReadHalf<TcpStream>,
    tun_tx: mpsc::Sender<Bytes>,
    client_info: Arc<ClientTransportInfo>,
    registry: Arc<ClientRegistry>,
) -> Result<()> {
    while let Some(encrypted) = read_cut_text(&mut reader, CLIENT_CUT_TEXT).await? {
        let packet =
            anet_common::transport::unwrap_packet_bytes_in_place(&client_info.cipher, encrypted)?;
        let packet_len = packet.len();
        tun_tx
            .send(packet)
            .await
            .context("TUN input queue closed")?;
        registry.record_rx(&client_info, packet_len);
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

    while input_open || !pending.is_empty() {
        let packet = if !jitter_enabled {
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
        if packet.len() < 20 {
            continue;
        }
        let sequence = client_info.sequence.fetch_add(1, Ordering::Relaxed);
        let total_len = packet.len() + 38;
        let padding =
            anet_common::padding_utils::calculate_padding_needed(total_len, stealth.padding_step);
        let safe_padding = if total_len + usize::from(padding) > PADDING_MTU {
            0
        } else {
            padding
        };
        let encrypted = anet_common::transport::wrap_packet(
            &client_info.cipher,
            &client_info.nonce_prefix,
            sequence,
            packet,
            safe_padding,
        )?;
        write_cut_text(&mut writer, SERVER_CUT_TEXT, &encrypted).await?;
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
