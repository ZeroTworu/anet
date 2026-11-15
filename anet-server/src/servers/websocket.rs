use crate::auth_handler::ServerAuthHandler;
use crate::client_registry::{ClientRegistry, ClientTransportInfo};
use crate::config::Config;
use anet_common::consts::{
    CHANNEL_BUFFER_SIZE, CLIENT_SEQUENCE_START, COALESCE_BUDGET_BYTES,
    WS_MUX_ACK_MAGIC, WS_MUX_BIND_MAGIC, WS_POOL_COALESCE_BUDGET_BYTES,
    WS_REASSEMBLY_GAP_TIMEOUT_MS, WS_REASSEMBLY_QUEUE_MAX_SIZE,
};
use anet_common::reassembly::ReassemblyQueue;
use anet_common::transport::{unwrap_packet, unwrap_packet_with_seq, wrap_packet_slice};
use anyhow::{Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use log::{debug, info, warn};
use rand::Rng;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc, watch};
use tokio_tungstenite::accept_hdr_async_with_config;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

const MAX_WS_MESSAGE_SIZE: usize = 256 * 1024; // Увеличено для коалесценции
const MAX_MUX_SESSION_ID_LEN: usize = 128;

struct WsSessionPool {
    client_info: Arc<ClientTransportInfo>,
    padding_step: u16,
    rx_router: Arc<Mutex<mpsc::Receiver<Bytes>>>,
    uplink_tx: mpsc::Sender<Vec<(u64, Bytes)>>,
    active_sockets: AtomicUsize,
    evicted: AtomicBool,
    shutdown_tx: watch::Sender<bool>,
}

async fn upgrade(
    stream: TcpStream,
    expected_path: String,
    fallback_addr: SocketAddr,
) -> Result<(tokio_tungstenite::WebSocketStream<TcpStream>, SocketAddr)> {
    let real_addr_out = Arc::new(std::sync::Mutex::new(fallback_addr));
    let real_addr_cb = real_addr_out.clone();
    let callback = move |request: &Request,
                         mut response: Response|
                         -> std::result::Result<Response, ErrorResponse> {
        if request.uri().path() != expected_path {
            let mut rejected = ErrorResponse::new(Some("Not Found".to_string()));
            *rejected.status_mut() = StatusCode::NOT_FOUND;
            return Err(rejected);
        }
        let extracted = anet_common::http_help::extract_real_ip(request.headers(), fallback_addr);
        if let Ok(mut guard) = real_addr_cb.lock() {
            *guard = extracted;
        }
        response
            .headers_mut()
            .insert("cache-control", HeaderValue::from_static("no-store"));
        Ok(response)
    };
    let ws_config = WebSocketConfig::default()
        .read_buffer_size(128 * 1024)
        .write_buffer_size(128 * 1024)
        .max_write_buffer_size(512 * 1024)
        .max_message_size(Some(MAX_WS_MESSAGE_SIZE))
        .max_frame_size(Some(MAX_WS_MESSAGE_SIZE));
    let ws_stream = accept_hdr_async_with_config(stream, callback, Some(ws_config)).await?;
    let real_addr = real_addr_out.lock().map(|g| *g).unwrap_or(fallback_addr);
    Ok((ws_stream, real_addr))
}

async fn run_uplink_sink(
    mut uplink_rx: mpsc::Receiver<Vec<(u64, Bytes)>>,
    mut shutdown_rx: watch::Receiver<bool>,
    tun_tx: mpsc::Sender<Bytes>,
    registry: Arc<ClientRegistry>,
    client_info: Arc<ClientTransportInfo>,
) {
    let mut reassembler = ReassemblyQueue::with_config(
        WS_REASSEMBLY_QUEUE_MAX_SIZE,
        CLIENT_SEQUENCE_START,
        Duration::from_millis(WS_REASSEMBLY_GAP_TIMEOUT_MS),
    );

    loop {
        if *shutdown_rx.borrow() {
            break;
        }

        let gap_wait = reassembler.gap_remaining();
        let sleep_fut = async {
            match gap_wait {
                Some(d) => tokio::time::sleep(d).await,
                None => std::future::pending::<()>().await,
            }
        };

        tokio::select! {
            biased;
            res = shutdown_rx.changed() => {
                if res.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            maybe_batch = uplink_rx.recv() => {
                let Some(first_batch) = maybe_batch else {
                    break;
                };
                let mut ready = reassembler.insert_batch(first_batch);
                let mut drained_batches = 0usize;
                while drained_batches < 16 {
                    match uplink_rx.try_recv() {
                        Ok(more) => {
                            ready.extend(reassembler.insert_batch(more));
                            drained_batches += 1;
                        }
                        Err(_) => break,
                    }
                }
                for packet in ready {
                    let packet_len = packet.len();
                    if tun_tx.send(packet).await.is_err() {
                        return;
                    }
                    registry.record_rx(&client_info, packet_len, "ws");
                }
            }
            _ = sleep_fut => {
                for packet in reassembler.flush_expired() {
                    let packet_len = packet.len();
                    if tun_tx.send(packet).await.is_err() {
                        return;
                    }
                    registry.record_rx(&client_info, packet_len, "ws");
                }
            }
        }
    }
}

fn try_bind_mux_socket(
    payload: &[u8],
    ws_pools: &DashMap<String, Arc<WsSessionPool>>,
    registry: &ClientRegistry,
) -> Result<(Arc<WsSessionPool>, Bytes)> {
    anyhow::ensure!(
        payload.len() >= WS_MUX_BIND_MAGIC.len() + 2,
        "Malformed WS_MUX_BIND frame: too short"
    );
    let sid_len = u16::from_be_bytes([payload[8], payload[9]]) as usize;
    anyhow::ensure!(
        sid_len > 0 && sid_len <= MAX_MUX_SESSION_ID_LEN && 10 + sid_len < payload.len(),
        "Malformed WS_MUX_BIND session_id length"
    );
    let session_id = std::str::from_utf8(&payload[10..10 + sid_len])
        .context("Invalid UTF-8 in WS_MUX_BIND session_id")?;
    let proof = &payload[10 + sid_len..];

    anyhow::ensure!(
        registry.get_by_session(session_id).is_some(),
        "Session {} is not active",
        session_id
    );

    let pool = {
        let entry = ws_pools
            .get(session_id)
            .with_context(|| format!("WebSocket pool not found for session {}", session_id))?;
        let pool = entry.value().clone();
        anyhow::ensure!(!*pool.shutdown_tx.borrow(), "WebSocket pool is shutting down");

        let claim = unwrap_packet(&pool.client_info.cipher, proof)
            .context("Failed to decrypt WS_MUX_BIND proof")?;
        let expected_claim = format!("BIND:{session_id}");
        anyhow::ensure!(
            claim.as_ref() == expected_claim.as_bytes(),
            "WS_MUX_BIND claim mismatch"
        );

        // Резервируем слот под read-локом DashMap, исключая гонку с remove_if при закрытии последнего сокета.
        pool.active_sockets.fetch_add(1, Ordering::AcqRel);
        pool
    };

    let ack_seq = pool.client_info.sequence.fetch_add(1, Ordering::Relaxed);
    let ack_proof = wrap_packet_slice(
        &pool.client_info.cipher,
        &pool.client_info.nonce_prefix,
        ack_seq,
        session_id.as_bytes(),
        0,
    )?;
    let mut ack = BytesMut::with_capacity(WS_MUX_ACK_MAGIC.len() + ack_proof.len());
    ack.put_slice(WS_MUX_ACK_MAGIC);
    ack.put_slice(&ack_proof);

    Ok((pool, ack.freeze()))
}

async fn run_pool_socket(
    socket: tokio_tungstenite::WebSocketStream<TcpStream>,
    remote_addr: SocketAddr,
    pool: Arc<WsSessionPool>,
    ws_pools: Arc<DashMap<String, Arc<WsSessionPool>>>,
    registry: Arc<ClientRegistry>,
) -> Result<()> {
    let (mut ws_sink, mut ws_stream) = socket.split();
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Message>(16);
    let (socket_stop_tx, mut socket_stop_rx) = watch::channel(false);

    let reader_pool = pool.clone();
    let reader_registry = registry.clone();
    let mut reader_shutdown_rx = pool.shutdown_tx.subscribe();
    let mut reader_stop_rx = socket_stop_tx.subscribe();
    let reader_stop_tx = socket_stop_tx.clone();

    let reader_task = tokio::spawn(async move {
        let cipher = reader_pool.client_info.cipher.clone();
        loop {
            if *reader_shutdown_rx.borrow() || *reader_stop_rx.borrow() {
                break;
            }
            tokio::select! {
                biased;
                res = reader_shutdown_rx.changed() => {
                    if res.is_err() || *reader_shutdown_rx.borrow() {
                        break;
                    }
                }
                res = reader_stop_rx.changed() => {
                    if res.is_err() || *reader_stop_rx.borrow() {
                        break;
                    }
                }
                incoming = ws_stream.next() => {
                    match incoming {
                        Some(Ok(Message::Binary(data))) => {
                            let mut offset = 0usize;
                            let mut unpacked = Vec::with_capacity(32);
                            while offset + 2 <= data.len() {
                                let len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                                offset += 2;
                                if len == 0 {
                                    continue;
                                }
                                if offset + len > data.len() {
                                    break;
                                }
                                let encrypted_slice = &data[offset..offset + len];
                                offset += len;
                                match unwrap_packet_with_seq(&cipher, encrypted_slice) {
                                    Ok((seq, packet)) => {
                                        unpacked.push((seq, packet));
                                    }
                                    Err(error) => {
                                        debug!("[WebSocket] Dropped invalid message from {remote_addr}: {error}");
                                    }
                                }
                            }
                            if !unpacked.is_empty()
                                && reader_pool.uplink_tx.send(unpacked).await.is_err()
                            {
                                break;
                            }
                        }
                        Some(Ok(Message::Ping(data))) => {
                            reader_registry.touch_client(&reader_pool.client_info);
                            let _ = ctrl_tx.try_send(Message::Pong(data));
                        }
                        Some(Ok(Message::Pong(_))) => {
                            reader_registry.touch_client(&reader_pool.client_info);
                        }
                        Some(Ok(Message::Close(_))) | None => break,
                        Some(Err(_)) => break,
                        _ => {}
                    }
                }
            }
        }
        let _ = reader_stop_tx.send(true);
    });

    let mut pool_shutdown_rx = pool.shutdown_tx.subscribe();
    let cipher = pool.client_info.cipher.clone();
    let nonce_prefix = pool.client_info.nonce_prefix;
    let padding_step = pool.padding_step;
    let mut ping_timer = Box::pin(tokio::time::sleep(random_ping_interval()));
    let mut raw_batch: Vec<Bytes> = Vec::with_capacity(64);
    let mut batch_buf = BytesMut::with_capacity(COALESCE_BUDGET_BYTES + 2048);

    'writer: loop {
        if *pool_shutdown_rx.borrow() || *socket_stop_rx.borrow() {
            break 'writer;
        }
        while let Ok(ctrl_msg) = ctrl_rx.try_recv() {
            if ws_sink.send(ctrl_msg).await.is_err() {
                break 'writer;
            }
        }

        let mut rx_guard = tokio::select! {
            biased;
            res = pool_shutdown_rx.changed() => {
                if res.is_err() || *pool_shutdown_rx.borrow() {
                    break 'writer;
                }
                continue;
            }
            res = socket_stop_rx.changed() => {
                if res.is_err() || *socket_stop_rx.borrow() {
                    break 'writer;
                }
                continue;
            }
            ctrl = ctrl_rx.recv() => {
                match ctrl {
                    Some(msg) => {
                        if ws_sink.send(msg).await.is_err() {
                            break 'writer;
                        }
                    }
                    None => break 'writer,
                }
                continue;
            }
            _ = &mut ping_timer => {
                let ping_payload = rand::rngs::OsRng.r#gen::<u32>().to_be_bytes().to_vec();
                if ws_sink.send(Message::Ping(ping_payload.into())).await.is_err() {
                    break 'writer;
                }
                ping_timer.as_mut().reset(tokio::time::Instant::now() + random_ping_interval());
                continue;
            }
            guard = pool.rx_router.lock() => guard,
        };

        let first_pkt = tokio::select! {
            biased;
            res = pool_shutdown_rx.changed() => {
                if res.is_err() || *pool_shutdown_rx.borrow() {
                    break 'writer;
                }
                continue;
            }
            res = socket_stop_rx.changed() => {
                if res.is_err() || *socket_stop_rx.borrow() {
                    break 'writer;
                }
                continue;
            }
            ctrl = ctrl_rx.recv() => {
                drop(rx_guard);
                match ctrl {
                    Some(msg) => {
                        if ws_sink.send(msg).await.is_err() {
                            break 'writer;
                        }
                    }
                    None => break 'writer,
                }
                continue;
            }
            _ = &mut ping_timer => {
                drop(rx_guard);
                let ping_payload = rand::rngs::OsRng.r#gen::<u32>().to_be_bytes().to_vec();
                if ws_sink.send(Message::Ping(ping_payload.into())).await.is_err() {
                    break 'writer;
                }
                ping_timer.as_mut().reset(tokio::time::Instant::now() + random_ping_interval());
                continue;
            }
            pkt = rx_guard.recv() => pkt,
        };

        let Some(first_raw) = first_pkt else {
            pool.evicted.store(true, Ordering::Release);
            let _ = pool.shutdown_tx.send(true);
            break 'writer;
        };

        let budget = if pool.active_sockets.load(Ordering::Relaxed) > 1 {
            WS_POOL_COALESCE_BUDGET_BYTES
        } else {
            COALESCE_BUDGET_BYTES
        };

        raw_batch.clear();
        let mut est_bytes = 0usize;
        if first_raw.len() >= 20 {
            est_bytes += first_raw.len() + 40;
            raw_batch.push(first_raw);
        }
        while est_bytes < budget {
            match rx_guard.try_recv() {
                Ok(pkt) => {
                    if pkt.len() >= 20 {
                        est_bytes += pkt.len() + 40;
                        raw_batch.push(pkt);
                    }
                }
                Err(_) => break,
            }
        }

        let base_seq = if !raw_batch.is_empty() {
            pool.client_info
                .sequence
                .fetch_add(raw_batch.len() as u64, Ordering::Relaxed)
        } else {
            0
        };
        drop(rx_guard);

        if !raw_batch.is_empty() {
            batch_buf.clear();
            for (idx, raw) in raw_batch.drain(..).enumerate() {
                let seq = base_seq + idx as u64;
                if let Ok(encrypted) = anet_common::transport::wrap_packet_padded(
                    &cipher,
                    &nonce_prefix,
                    seq,
                    raw,
                    padding_step,
                ) {
                    anet_common::stream_framing::frame_packet_into(&mut batch_buf, &encrypted);
                }
            }

            if !batch_buf.is_empty() {
                let out_bytes = batch_buf.split().freeze();
                batch_buf.reserve(budget + 2048);
                if ws_sink.send(Message::Binary(out_bytes)).await.is_err() {
                    break 'writer;
                }
            }
        }
    }

    let _ = socket_stop_tx.send(true);
    let _ = ws_sink.close().await;
    let _ = reader_task.await;

    let prev = pool.active_sockets.fetch_sub(1, Ordering::AcqRel);
    if prev == 1 {
        let removed = ws_pools.remove_if(&pool.client_info.session_id, |_, existing| {
            Arc::ptr_eq(existing, &pool) && existing.active_sockets.load(Ordering::Acquire) == 0
        });
        if removed.is_some() {
            let _ = pool.shutdown_tx.send(true);
            if !pool.evicted.load(Ordering::Acquire) {
                info!("[WebSocket] Client disconnected: {}", pool.client_info.assigned_ip);
                registry.suspend_client(pool.client_info.clone());
            }
        }
    }

    Ok(())
}

async fn handle_session(
    stream: TcpStream,
    remote_addr: SocketAddr,
    registry: Arc<ClientRegistry>,
    config: Arc<Config>,
    tun_tx: mpsc::Sender<Bytes>,
    auth_handler: ServerAuthHandler,
    ws_pools: Arc<DashMap<String, Arc<WsSessionPool>>>,
) -> Result<()> {
    let (mut socket, remote_addr) =
        upgrade(stream, config.server.websocket_path.clone(), remote_addr).await?;
    info!("ASTP[WebSocket] HTTP upgrade complete: {}", remote_addr);

    let mut handshake_phase = 1u8;
    loop {
        let payload = loop {
            match socket.next().await {
                Some(Ok(Message::Binary(data))) => break data,
                Some(Ok(Message::Ping(data))) => socket.send(Message::Pong(data)).await?,
                Some(Ok(Message::Close(_))) | None => return Ok(()),
                Some(Err(error)) => return Err(error.into()),
                _ => {}
            }
        };

        if handshake_phase == 1 && payload.starts_with(WS_MUX_BIND_MAGIC) {
            match try_bind_mux_socket(&payload, &ws_pools, &registry) {
                Ok((pool, ack_frame)) => {
                    if let Err(err) = socket.send(Message::Binary(ack_frame)).await {
                        let prev = pool.active_sockets.fetch_sub(1, Ordering::AcqRel);
                        if prev == 1 {
                            let removed = ws_pools.remove_if(&pool.client_info.session_id, |_, existing| {
                                Arc::ptr_eq(existing, &pool)
                                    && existing.active_sockets.load(Ordering::Acquire) == 0
                            });
                            if removed.is_some() {
                                let _ = pool.shutdown_tx.send(true);
                                if !pool.evicted.load(Ordering::Acquire) {
                                    registry.suspend_client(pool.client_info.clone());
                                }
                            }
                        }
                        return Err(err.into());
                    }
                    info!(
                        "[WebSocket] Attached pooled socket {} to session {} (active: {})",
                        remote_addr,
                        pool.client_info.session_id,
                        pool.active_sockets.load(Ordering::Relaxed)
                    );
                    return run_pool_socket(socket, remote_addr, pool, ws_pools, registry).await;
                }
                Err(err) => {
                    let _ = socket.close(None).await;
                    return Err(err);
                }
            }
        }

        let is_probe = auth_handler.is_probe_packet(&payload);
        let (response, result) = auth_handler
            .process_handshake_packet(payload, remote_addr, "ws")
            .await
            .with_context(|| format!("WebSocket ASTP handshake phase {}", handshake_phase))?;
        if let Some(response) = response {
            socket.send(Message::Binary(response)).await?;
        }
        if is_probe {
            let _ = socket.close(None).await;
            return Ok(());
        }

        if let Some((client_info, _)) = result {
            let assigned_ip = client_info.assigned_ip.clone();
            let session_id = client_info.session_id.clone();
            let (tx_router, rx_router) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
            registry.finalize_client(&assigned_ip, tx_router);

            let (uplink_tx, uplink_rx) = mpsc::channel::<Vec<(u64, Bytes)>>(CHANNEL_BUFFER_SIZE);
            let (shutdown_tx, shutdown_rx) = watch::channel(false);

            let pool = Arc::new(WsSessionPool {
                client_info: client_info.clone(),
                padding_step: config.stealth.padding_step,
                rx_router: Arc::new(Mutex::new(rx_router)),
                uplink_tx,
                active_sockets: AtomicUsize::new(1),
                evicted: AtomicBool::new(false),
                shutdown_tx,
            });

            if let Some((_, old_pool)) = ws_pools.insert(session_id, pool.clone()) {
                old_pool.evicted.store(true, Ordering::Release);
                let _ = old_pool.shutdown_tx.send(true);
            }

            tokio::spawn(run_uplink_sink(
                uplink_rx,
                shutdown_rx,
                tun_tx,
                registry.clone(),
                client_info,
            ));

            return run_pool_socket(socket, remote_addr, pool, ws_pools, registry).await;
        }
        handshake_phase = 3;
    }
}

fn random_ping_interval() -> Duration {
    Duration::from_secs(rand::rngs::OsRng.gen_range(22..=52))
}

pub async fn run_websocket_server(
    config: Arc<Config>,
    registry: Arc<ClientRegistry>,
    tun_tx: mpsc::Sender<Bytes>,
    auth_handler: ServerAuthHandler,
) -> Result<()> {
    info!(
        "Initializing Transport Port [WebSocket ASTP] TCP: {}{}",
        config.server.websocket_bind_to, config.server.websocket_path
    );
    let ws_pools: Arc<DashMap<String, Arc<WsSessionPool>>> = Arc::new(DashMap::new());
    let listener = TcpListener::bind(&config.server.websocket_bind_to).await?;
    loop {
        let (stream, remote_addr) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let (cfg, reg, tx, auth, pools) = (
            config.clone(),
            registry.clone(),
            tun_tx.clone(),
            auth_handler.clone(),
            ws_pools.clone(),
        );
        tokio::spawn(async move {
            if let Err(error) = handle_session(stream, remote_addr, reg, cfg, tx, auth, pools).await {
                warn!("[WebSocket] Session {} stopped: {error:#}", remote_addr);
            }
        });
    }
}
