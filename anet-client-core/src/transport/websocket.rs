use super::{ClientTransport, ConnectionResult};
use crate::auth::{AuthChannel, AuthDenyError, AuthHandler};
use crate::config::{CoreConfig, ServerConfig, WebSocketConfig as ClientWsConfig};
use anet_common::consts::{CLIENT_SEQUENCE_START, WS_MUX_ACK_MAGIC, WS_MUX_BIND_MAGIC};
use anet_common::encryption::Cipher;
use anet_common::handshake_fragmentation::FragmentConfig;
use anet_common::http_help::BrowserProfile;
use anet_common::reassembly::ReassemblyQueue;
use anet_common::stream_framing::{FrameReader, frame_packet_into};
use anet_common::transport::{
    unwrap_packet, unwrap_packet_with_seq, wrap_packet_padded, wrap_packet_slice,
};
use anet_common::transport_trait::VpnStream;
use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use futures::{Sink, SinkExt, StreamExt};
use log::{debug, info, warn};
use rand::Rng;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc, watch};
use tokio::task::AbortHandle;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};
use tokio_tungstenite::{WebSocketStream, client_async_with_config};

type ClientSocket = WebSocketStream<Box<dyn VpnStream>>;

async fn send_ws_with_timeout<S>(
    sink: &mut S,
    msg: Message,
    timeout: Duration,
) -> Result<()>
where
    S: Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    tokio::time::timeout(timeout, sink.send(msg))
        .await
        .context("WebSocket write timed out")?
        .map_err(Into::into)
}

async fn close_ws_with_timeout<S>(sink: &mut S, timeout: Duration)
where
    S: Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let _ = tokio::time::timeout(timeout, sink.close()).await;
}

struct WebSocketAuthChannel {
    socket: Mutex<ClientSocket>,
    write_timeout: Duration,
}

/// Глобальное хранилище Cookie для WebSocket транспорта с разделением по хостам
static WS_COOKIE_JAR: LazyLock<StdMutex<HashMap<String, HashMap<String, String>>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));

#[async_trait]
impl AuthChannel for WebSocketAuthChannel {
    async fn send(&self, data: Bytes, _frag: &FragmentConfig) -> Result<()> {
        let mut socket = self.socket.lock().await;
        send_ws_with_timeout(&mut *socket, Message::Binary(data), self.write_timeout).await?;
        Ok(())
    }

    async fn recv(&self, timeout: Duration) -> Result<Bytes> {
        let write_timeout = self.write_timeout;
        let receive = async {
            let mut socket = self.socket.lock().await;
            loop {
                match socket.next().await {
                    Some(Ok(Message::Binary(data))) => return Ok(data),
                    Some(Ok(Message::Ping(data))) => {
                        send_ws_with_timeout(&mut *socket, Message::Pong(data), write_timeout)
                            .await?;
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        anyhow::bail!("WebSocket closed during authentication")
                    }
                    Some(Err(error)) => return Err(error.into()),
                    _ => {}
                }
            }
        };
        tokio::time::timeout(timeout, receive)
            .await
            .context("WebSocket authentication timeout")?
    }
}

pub struct WebSocketTransport {
    config: CoreConfig,
    server: ServerConfig,
}

impl WebSocketTransport {
    pub fn new(config: CoreConfig, server: ServerConfig) -> Self {
        Self { config, server }
    }
}

struct PoolGeneration {
    gen_id: u64,
    session_id: String,
    cipher: Arc<Cipher>,
    nonce_prefix: [u8; 4],
    tx_sequence: Arc<AtomicU64>,
    active_slots: AtomicUsize,
    cancel_tx: watch::Sender<bool>,
}

impl PoolGeneration {
    fn new(
        gen_id: u64,
        session_id: String,
        key: &[u8; 32],
        nonce_prefix: [u8; 4],
    ) -> Arc<Self> {
        let (cancel_tx, _) = watch::channel(false);
        Arc::new(Self {
            gen_id,
            session_id,
            cipher: Arc::new(Cipher::new(key)),
            nonce_prefix,
            tx_sequence: Arc::new(AtomicU64::new(CLIENT_SEQUENCE_START)),
            active_slots: AtomicUsize::new(0),
            cancel_tx,
        })
    }
}

struct AbortOnDrop(Vec<AbortHandle>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        for handle in &self.0 {
            handle.abort();
        }
    }
}

enum SocketExit {
    Rotated,
    Disconnected,
    GenCancelled,
    TunnelClosed,
}

enum MuxBindError {
    Rejected(anyhow::Error),
    Transport(anyhow::Error),
}

impl MuxBindError {
    fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected(_))
    }
}

impl std::fmt::Display for MuxBindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(e) | Self::Transport(e) => write!(f, "{e:#}"),
        }
    }
}

async fn open_ws_socket(
    server: &ServerConfig,
    profile: &BrowserProfile,
    ws_cfg: &ClientWsConfig,
) -> Result<(ClientSocket, Option<IpAddr>)> {
    let handshake_timeout = ws_cfg.handshake_timeout();
    tokio::time::timeout(handshake_timeout, async {
        let url = server.websocket_url()?;
        let mut request = profile.build_ws_request(&url, None)?;
        let target_host = url.parse::<http::Uri>()?.host().unwrap_or("").to_string();

        // 1. Подставляем сохраненные Cookie для данного хоста
        {
            let jar = WS_COOKIE_JAR.lock().unwrap();
            if let Some(host_cookies) = jar.get(&target_host) {
                if !host_cookies.is_empty() {
                    let cookie_str = host_cookies
                        .iter()
                        .map(|(k, v)| format!("{}={}", k, v))
                        .collect::<Vec<_>>()
                        .join("; ");
                    if let Ok(val) = http::HeaderValue::from_str(&cookie_str) {
                        request.headers_mut().insert(http::header::COOKIE, val);
                    }
                }
            }
        }

        let max_msg_size = ws_cfg.effective_max_message_size();
        let ws_config = WebSocketConfig::default()
            .read_buffer_size(ws_cfg.effective_read_buffer_size())
            .write_buffer_size(ws_cfg.effective_write_buffer_size())
            .max_write_buffer_size(ws_cfg.effective_max_write_buffer_size())
            .max_message_size(Some(max_msg_size))
            .max_frame_size(Some(max_msg_size));

        let endpoint = server.endpoint()?;
        let tcp_stream = TcpStream::connect(&endpoint)
            .await
            .with_context(|| format!("failed to connect to WebSocket endpoint {endpoint}"))?;
        let peer_ip = tcp_stream.peer_addr().ok().map(|sa| sa.ip());
        tcp_stream.set_nodelay(true)?;

        let scheme = server
            .dsn
            .parse::<http::Uri>()?
            .scheme_str()
            .unwrap_or_default()
            .to_ascii_lowercase();

        let stream: Box<dyn VpnStream> = if scheme == "wss" || scheme == "https" {
            info!("[WS] CONNECTING TO: {}, HOST: {}", endpoint, &target_host);
            let tls_stream = profile
                .connect_ws_tls(&target_host, tcp_stream)
                .await
                .context("BoringSSL TLS handshake failed")?;
            Box::new(tls_stream)
        } else {
            Box::new(tcp_stream)
        };

        let (socket, response) = client_async_with_config(request, stream, Some(ws_config)).await?;

        // 2. Перехватываем Set-Cookie из ответа сервера
        {
            let mut jar = WS_COOKIE_JAR.lock().unwrap();
            let host_cookies = jar.entry(target_host).or_default();
            for cookie_header in response.headers().get_all(http::header::SET_COOKIE) {
                if let Ok(cookie_str) = cookie_header.to_str() {
                    if let Some(key_val) = cookie_str.split(';').next() {
                        if let Some((key, val)) = key_val.split_once('=') {
                            host_cookies.insert(key.trim().to_string(), val.trim().to_string());
                        }
                    }
                }
            }
        }

        Ok((socket, peer_ip))
    })
    .await
    .context("WebSocket connect/upgrade timed out")?
}

async fn connect_authenticated(
    config: &CoreConfig,
    server: &ServerConfig,
    profile: &BrowserProfile,
    resume_session_id: Option<String>,
) -> Result<(ClientSocket, anet_common::protocol::AuthResponse, [u8; 32], Option<IpAddr>)> {
    let (socket, peer_ip) = open_ws_socket(server, profile, &config.websocket).await?;
    let channel = WebSocketAuthChannel {
        socket: Mutex::new(socket),
        write_timeout: config.websocket.write_timeout(),
    };
    let auth =
        AuthHandler::new_with_resume(config, server.server_pub_key.as_deref(), resume_session_id)?;
    let (response, key) = auth.authenticate_once(&channel).await?;
    Ok((channel.socket.into_inner(), response, key, peer_ip))
}

async fn connect_pool_member(
    server: &ServerConfig,
    profile: &BrowserProfile,
    ws_cfg: &ClientWsConfig,
    pool_gen: &PoolGeneration,
) -> std::result::Result<ClientSocket, MuxBindError> {
    let timeout_dur = ws_cfg.handshake_timeout();
    let write_timeout = ws_cfg.write_timeout();
    tokio::time::timeout(timeout_dur, async {
        let (mut socket, _) = open_ws_socket(server, profile, ws_cfg)
            .await
            .map_err(MuxBindError::Transport)?;
        let sid_bytes = pool_gen.session_id.as_bytes();
        let claim = format!("BIND:{}", pool_gen.session_id);
        let seq = pool_gen.tx_sequence.fetch_add(1, Ordering::Relaxed);
        let proof = wrap_packet_slice(
            &pool_gen.cipher,
            &pool_gen.nonce_prefix,
            seq,
            claim.as_bytes(),
            0,
        )
        .context("Failed to encrypt WS_MUX_BIND proof")
        .map_err(MuxBindError::Transport)?;

        let mut bind_frame =
            BytesMut::with_capacity(WS_MUX_BIND_MAGIC.len() + 2 + sid_bytes.len() + proof.len());
        bind_frame.put_slice(WS_MUX_BIND_MAGIC);
        bind_frame.put_u16(sid_bytes.len() as u16);
        bind_frame.put_slice(sid_bytes);
        bind_frame.put_slice(&proof);

        send_ws_with_timeout(&mut socket, Message::Binary(bind_frame.freeze()), write_timeout)
            .await
            .map_err(MuxBindError::Transport)?;

        loop {
            match socket.next().await {
                Some(Ok(Message::Binary(ack))) => {
                    if !ack.starts_with(WS_MUX_ACK_MAGIC) {
                        return Err(MuxBindError::Rejected(anyhow::anyhow!(
                            "Unexpected WS_MUX_BIND response magic"
                        )));
                    }
                    let payload = unwrap_packet(&pool_gen.cipher, &ack[WS_MUX_ACK_MAGIC.len()..])
                        .context("Failed to decrypt WS_MUX_ACK proof")
                        .map_err(MuxBindError::Rejected)?;
                    if payload.as_ref() != sid_bytes {
                        return Err(MuxBindError::Rejected(anyhow::anyhow!(
                            "WS_MUX_ACK session_id mismatch"
                        )));
                    }
                    return Ok(socket);
                }
                Some(Ok(Message::Ping(data))) => {
                    send_ws_with_timeout(&mut socket, Message::Pong(data), write_timeout)
                        .await
                        .map_err(MuxBindError::Transport)?;
                }
                Some(Ok(Message::Close(_))) | None => {
                    return Err(MuxBindError::Rejected(anyhow::anyhow!(
                        "WebSocket closed during WS_MUX_BIND"
                    )));
                }
                Some(Err(e)) => return Err(MuxBindError::Transport(e.into())),
                _ => {}
            }
        }
    })
    .await
    .map_err(|_| MuxBindError::Transport(anyhow::anyhow!("WS_MUX_BIND timed out")))?
}

fn session_lifetime(server: &ServerConfig) -> Duration {
    let min = server.websocket_min_session_secs.max(30);
    let max = server.websocket_max_session_secs.max(min);
    Duration::from_secs(rand::rngs::OsRng.gen_range(min..=max))
}

async fn close_browser_session(socket: &mut ClientSocket, ws_cfg: &ClientWsConfig) {
    let close = CloseFrame {
        code: CloseCode::Normal,
        reason: "".into(),
    };
    if send_ws_with_timeout(socket, Message::Close(Some(close)), ws_cfg.write_timeout())
        .await
        .is_err()
    {
        return;
    }

    let _ = tokio::time::timeout(ws_cfg.close_timeout(), async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {}
            }
        }
    })
    .await;
}

fn apply_downlink_batch(
    gid: u64,
    batch: Vec<(u64, Bytes)>,
    current_gen_id: &mut u64,
    reassembler: &mut ReassemblyQueue,
    downlink_buf: &mut BytesMut,
) {
    if gid < *current_gen_id {
        return;
    }
    if gid > *current_gen_id {
        reassembler.reset(0);
        *current_gen_id = gid;
    }
    for pkt in reassembler.insert_batch(batch) {
        frame_packet_into(downlink_buf, &pkt);
    }
}

async fn run_downlink_sink(
    mut tunnel_write: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    mut downlink_rx: mpsc::Receiver<(u64, Vec<(u64, Bytes)>)>,
    mut global_stop_rx: watch::Receiver<bool>,
    ws_cfg: ClientWsConfig,
) {
    let mut reassembler = ReassemblyQueue::with_config(
        ws_cfg.reassembly_queue_max_size.max(1),
        0,
        Duration::from_millis(ws_cfg.reassembly_gap_timeout_ms.max(1)),
    );
    let coalesce_budget = ws_cfg.effective_single_coalesce_budget();
    let mut current_gen_id: u64 = 1;
    let mut downlink_buf = BytesMut::with_capacity(coalesce_budget + 2048);

    loop {
        if *global_stop_rx.borrow() {
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
            res = global_stop_rx.changed() => {
                if res.is_err() || *global_stop_rx.borrow() {
                    break;
                }
            }
            maybe_batch = downlink_rx.recv() => {
                let Some((gen_id, batch)) = maybe_batch else {
                    break;
                };
                downlink_buf.clear();

                apply_downlink_batch(
                    gen_id,
                    batch,
                    &mut current_gen_id,
                    &mut reassembler,
                    &mut downlink_buf,
                );

                let mut extra = 0usize;
                while extra < 16 && downlink_buf.len() < coalesce_budget {
                    match downlink_rx.try_recv() {
                        Ok((gid, b)) => {
                            apply_downlink_batch(
                                gid,
                                b,
                                &mut current_gen_id,
                                &mut reassembler,
                                &mut downlink_buf,
                            );
                            extra += 1;
                        }
                        Err(_) => break,
                    }
                }

                if !downlink_buf.is_empty() && tunnel_write.write_all(&downlink_buf).await.is_err() {
                    break;
                }
            }
            _ = sleep_fut => {
                downlink_buf.clear();
                for pkt in reassembler.flush_expired() {
                    frame_packet_into(&mut downlink_buf, &pkt);
                }
                if !downlink_buf.is_empty() && tunnel_write.write_all(&downlink_buf).await.is_err() {
                    break;
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_client_socket(
    socket: ClientSocket,
    pool_gen: Arc<PoolGeneration>,
    shared_tx_rx: Arc<Mutex<mpsc::Receiver<Bytes>>>,
    downlink_tx: mpsc::Sender<(u64, Vec<(u64, Bytes)>)>,
    mut global_stop_rx: watch::Receiver<bool>,
    ws_cfg: ClientWsConfig,
    padding_step: u16,
    rotation_dur: Duration,
    slot_idx: usize,
) -> SocketExit {
    pool_gen.active_slots.fetch_add(1, Ordering::AcqRel);

    let (mut ws_sink, mut ws_stream) = socket.split();
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Message>(16);
    let (socket_stop_tx, mut socket_stop_rx) = watch::channel(false);

    let reader_gen = pool_gen.clone();
    let mut reader_cancel_rx = pool_gen.cancel_tx.subscribe();
    let mut reader_global_stop_rx = global_stop_rx.clone();
    let mut reader_stop_rx = socket_stop_tx.subscribe();
    let reader_stop_tx = socket_stop_tx.clone();
    let reader_downlink_tx = downlink_tx;

    let reader_task = tokio::spawn(async move {
        let cipher = reader_gen.cipher.clone();
        let gen_id = reader_gen.gen_id;
        loop {
            if *reader_cancel_rx.borrow()
                || *reader_global_stop_rx.borrow()
                || *reader_stop_rx.borrow()
            {
                break;
            }

            tokio::select! {
                biased;
                res = reader_global_stop_rx.changed() => {
                    if res.is_err() || *reader_global_stop_rx.borrow() {
                        break;
                    }
                }
                res = reader_cancel_rx.changed() => {
                    if res.is_err() || *reader_cancel_rx.borrow() {
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
                                    Ok((seq, packet)) => unpacked.push((seq, packet)),
                                    Err(error) => {
                                        debug!("[WebSocket#{}] Dropped invalid inbound packet: {error}", slot_idx);
                                    }
                                }
                            }
                            if !unpacked.is_empty()
                                && reader_downlink_tx.send((gen_id, unpacked)).await.is_err()
                            {
                                break;
                            }
                        }
                        Some(Ok(Message::Ping(data))) => {
                            let _ = ctrl_tx.try_send(Message::Pong(data));
                        }
                        Some(Ok(Message::Pong(_))) => {}
                        Some(Ok(Message::Close(frame))) => {
                            info!("[WebSocket#{}] Server sent Close frame: {:?}", slot_idx, frame);
                            break;
                        }
                        None => {
                            info!("[WebSocket#{}] Connection stream closed (EOF from server).", slot_idx);
                            break;
                        }
                        Some(Err(e)) => {
                            warn!("[WebSocket#{}] Socket error received: {e:#}", slot_idx);
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
        let _ = reader_stop_tx.send(true);
    });

    let write_timeout = ws_cfg.write_timeout();
    let close_timeout = ws_cfg.close_timeout();
    let pool_budget = ws_cfg.effective_pool_coalesce_budget();
    let single_budget = ws_cfg.effective_single_coalesce_budget();
    let mut gen_cancel_rx = pool_gen.cancel_tx.subscribe();
    let mut rotation = Box::pin(tokio::time::sleep(rotation_dur));
    let mut ping_timer = Box::pin(tokio::time::sleep(ws_cfg.random_ping_interval()));
    let mut raw_batch: Vec<Bytes> = Vec::with_capacity(64);
    let mut batch_buf = BytesMut::with_capacity(single_budget + 2048);

    let exit_reason;

    'writer: loop {
        if *global_stop_rx.borrow() {
            exit_reason = SocketExit::TunnelClosed;
            break 'writer;
        }
        if *gen_cancel_rx.borrow() {
            exit_reason = SocketExit::GenCancelled;
            break 'writer;
        }
        if *socket_stop_rx.borrow() {
            exit_reason = SocketExit::Disconnected;
            break 'writer;
        }

        while let Ok(ctrl_msg) = ctrl_rx.try_recv() {
            if send_ws_with_timeout(&mut ws_sink, ctrl_msg, write_timeout)
                .await
                .is_err()
            {
                exit_reason = SocketExit::Disconnected;
                break 'writer;
            }
        }

        let mut rx_guard = tokio::select! {
            biased;
            res = global_stop_rx.changed() => {
                if res.is_err() || *global_stop_rx.borrow() {
                    exit_reason = SocketExit::TunnelClosed;
                    break 'writer;
                }
                continue;
            }
            res = gen_cancel_rx.changed() => {
                if res.is_err() || *gen_cancel_rx.borrow() {
                    exit_reason = SocketExit::GenCancelled;
                    break 'writer;
                }
                continue;
            }
            res = socket_stop_rx.changed() => {
                if res.is_err() || *socket_stop_rx.borrow() {
                    exit_reason = SocketExit::Disconnected;
                    break 'writer;
                }
                continue;
            }
            _ = &mut rotation => {
                exit_reason = SocketExit::Rotated;
                break 'writer;
            }
            ctrl = ctrl_rx.recv() => {
                match ctrl {
                    Some(msg) => {
                        if send_ws_with_timeout(&mut ws_sink, msg, write_timeout)
                            .await
                            .is_err()
                        {
                            exit_reason = SocketExit::Disconnected;
                            break 'writer;
                        }
                    }
                    None => {
                        exit_reason = SocketExit::Disconnected;
                        break 'writer;
                    }
                }
                continue;
            }
            _ = &mut ping_timer => {
                let ping_payload = rand::rngs::OsRng.r#gen::<u32>().to_be_bytes().to_vec();
                if send_ws_with_timeout(&mut ws_sink, Message::Ping(ping_payload.into()), write_timeout)
                    .await
                    .is_err()
                {
                    exit_reason = SocketExit::Disconnected;
                    break 'writer;
                }
                ping_timer.as_mut().reset(tokio::time::Instant::now() + ws_cfg.random_ping_interval());
                continue;
            }
            guard = shared_tx_rx.lock() => guard,
        };

        let first_pkt = tokio::select! {
            biased;
            res = global_stop_rx.changed() => {
                if res.is_err() || *global_stop_rx.borrow() {
                    exit_reason = SocketExit::TunnelClosed;
                    break 'writer;
                }
                continue;
            }
            res = gen_cancel_rx.changed() => {
                if res.is_err() || *gen_cancel_rx.borrow() {
                    exit_reason = SocketExit::GenCancelled;
                    break 'writer;
                }
                continue;
            }
            res = socket_stop_rx.changed() => {
                if res.is_err() || *socket_stop_rx.borrow() {
                    exit_reason = SocketExit::Disconnected;
                    break 'writer;
                }
                continue;
            }
            _ = &mut rotation => {
                drop(rx_guard);
                exit_reason = SocketExit::Rotated;
                break 'writer;
            }
            ctrl = ctrl_rx.recv() => {
                drop(rx_guard);
                match ctrl {
                    Some(msg) => {
                        if send_ws_with_timeout(&mut ws_sink, msg, write_timeout)
                            .await
                            .is_err()
                        {
                            exit_reason = SocketExit::Disconnected;
                            break 'writer;
                        }
                    }
                    None => {
                        exit_reason = SocketExit::Disconnected;
                        break 'writer;
                    }
                }
                continue;
            }
            _ = &mut ping_timer => {
                drop(rx_guard);
                let ping_payload = rand::rngs::OsRng.r#gen::<u32>().to_be_bytes().to_vec();
                if send_ws_with_timeout(&mut ws_sink, Message::Ping(ping_payload.into()), write_timeout)
                    .await
                    .is_err()
                {
                    exit_reason = SocketExit::Disconnected;
                    break 'writer;
                }
                ping_timer.as_mut().reset(tokio::time::Instant::now() + ws_cfg.random_ping_interval());
                continue;
            }
            pkt = rx_guard.recv() => pkt,
        };

        let Some(first_raw) = first_pkt else {
            exit_reason = SocketExit::TunnelClosed;
            break 'writer;
        };

        let budget = if pool_gen.active_slots.load(Ordering::Relaxed) > 1 {
            pool_budget
        } else {
            single_budget
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
            pool_gen
                .tx_sequence
                .fetch_add(raw_batch.len() as u64, Ordering::Relaxed)
        } else {
            0
        };
        drop(rx_guard);

        if !raw_batch.is_empty() {
            batch_buf.clear();
            for (idx, raw) in raw_batch.drain(..).enumerate() {
                let seq = base_seq + idx as u64;
                if let Ok(encrypted) = wrap_packet_padded(
                    &pool_gen.cipher,
                    &pool_gen.nonce_prefix,
                    seq,
                    raw,
                    padding_step,
                ) {
                    frame_packet_into(&mut batch_buf, &encrypted);
                }
            }

            if !batch_buf.is_empty() {
                let out_bytes = batch_buf.split().freeze();
                batch_buf.reserve(budget + 2048);
                if send_ws_with_timeout(&mut ws_sink, Message::Binary(out_bytes), write_timeout)
                    .await
                    .is_err()
                {
                    exit_reason = SocketExit::Disconnected;
                    break 'writer;
                }
            }
        }
    }

    if matches!(exit_reason, SocketExit::Rotated | SocketExit::TunnelClosed) {
        let close = CloseFrame {
            code: CloseCode::Normal,
            reason: "".into(),
        };
        let _ = send_ws_with_timeout(&mut ws_sink, Message::Close(Some(close)), write_timeout).await;
    } else {
        close_ws_with_timeout(&mut ws_sink, close_timeout).await;
    }

    let _ = socket_stop_tx.send(true);
    let _ = reader_task.await;
    pool_gen.active_slots.fetch_sub(1, Ordering::AcqRel);

    exit_reason
}

#[allow(clippy::too_many_arguments)]
async fn run_slot_worker(
    slot_idx: usize,
    pool_size: usize,
    mut initial_socket: Option<ClientSocket>,
    mut gen_rx: watch::Receiver<Arc<PoolGeneration>>,
    gen_tx: Arc<watch::Sender<Arc<PoolGeneration>>>,
    reauth_lock: Arc<Mutex<()>>,
    config: CoreConfig,
    server: ServerConfig,
    browser_profile: BrowserProfile,
    expected_ip: String,
    expected_gateway: String,
    health_pause: Arc<AtomicBool>,
    shared_tx_rx: Arc<Mutex<mpsc::Receiver<Bytes>>>,
    downlink_tx: mpsc::Sender<(u64, Vec<(u64, Bytes)>)>,
    global_stop_tx: watch::Sender<bool>,
) {
    let mut global_stop_rx = global_stop_tx.subscribe();
    let mut is_first_cycle = true;
    let ws_cfg = config.websocket.clone();
    let mut consecutive_bind_failures: u32 = 0;
    let mut consecutive_bind_rejects: u32 = 0;
    let mut last_seen_gen_id: u64 = 0;

    loop {
        if *global_stop_rx.borrow() {
            break;
        }

        let mut cur_gen = gen_rx.borrow_and_update().clone();
        if cur_gen.gen_id != last_seen_gen_id {
            consecutive_bind_failures = 0;
            consecutive_bind_rejects = 0;
            last_seen_gen_id = cur_gen.gen_id;
        }

        let socket = if let Some(sock) = initial_socket.take() {
            sock
        } else if pool_size > 1 && !*cur_gen.cancel_tx.borrow() {
            // 1. Сначала пытаемся присоединиться к уже живущему серверному пулу за 1 RTT (WS_MUX_BIND)
            match connect_pool_member(&server, &browser_profile, &ws_cfg, &cur_gen).await {
                Ok(sock) => {
                    consecutive_bind_failures = 0;
                    consecutive_bind_rejects = 0;
                    info!(
                        "[WS#{}] Bound pooled socket to session {} (gen {})",
                        slot_idx, cur_gen.session_id, cur_gen.gen_id
                    );
                    sock
                }
                Err(bind_err) => {
                    consecutive_bind_failures = consecutive_bind_failures.saturating_add(1);
                    if bind_err.is_rejected() {
                        consecutive_bind_rejects = consecutive_bind_rejects.saturating_add(1);
                    }
                    let reject_limit_hit = ws_cfg.bind_reject_max_retries > 0
                        && consecutive_bind_rejects >= ws_cfg.bind_reject_max_retries;
                    let total_limit_hit = ws_cfg.bind_max_retries > 0
                        && consecutive_bind_failures >= ws_cfg.bind_max_retries;
                    let escalate = reject_limit_hit || total_limit_hit;

                    let active_slots = cur_gen.active_slots.load(Ordering::Acquire);
                    // Если другие слоты пула ещё живы И порог ошибок привязки не исчерпан —
                    // ждём и пробуем WS_MUX_BIND снова, не вытесняя активную сессию на сервере.
                    if !escalate && active_slots > 0 && !*cur_gen.cancel_tx.borrow() {
                        debug!(
                            "[WS#{}] WS_MUX_BIND failed ({}/{} fails, {}/{} rejects) while {} pool slot(s) active: {}",
                            slot_idx,
                            consecutive_bind_failures,
                            ws_cfg.bind_max_retries,
                            consecutive_bind_rejects,
                            ws_cfg.bind_reject_max_retries,
                            active_slots,
                            bind_err
                        );
                        let delay = ws_cfg.random_bind_retry_delay();
                        tokio::select! {
                            biased;
                            _ = global_stop_rx.changed() => break,
                            _ = gen_rx.changed() => continue,
                            _ = tokio::time::sleep(delay) => continue,
                        }
                    }

                    // Все сокеты пула упали (или серверный пул потерян / отклонил bind) — берём reauth_lock
                    let _reauth_guard = tokio::select! {
                        biased;
                        _ = global_stop_rx.changed() => break,
                        g = reauth_lock.lock() => g,
                    };

                    if *global_stop_rx.borrow() {
                        break;
                    }

                    let latest_gen = gen_rx.borrow_and_update().clone();
                    if latest_gen.gen_id != cur_gen.gen_id {
                        // Пока мы ждали лок, другой слот уже восстановил сессию
                        continue;
                    }

                    if escalate && active_slots > 0 {
                        warn!(
                            "[WS#{}] WS_MUX_BIND failed {} time(s) ({} rejected) while {} local slot(s) look active ({}); cancelling stale pool gen {} and performing full ASTP reconnect",
                            slot_idx,
                            consecutive_bind_failures,
                            consecutive_bind_rejects,
                            active_slots,
                            bind_err,
                            cur_gen.gen_id
                        );
                    } else {
                        warn!(
                            "[WS#{}] Pool lost (WS_MUX_BIND: {}); performing ASTP session resume",
                            slot_idx, bind_err
                        );
                    }

                    // Отменяем устаревшее поколение заранее, чтобы полумёртвые слоты вышли
                    // из `run_client_socket` и подключились к новому поколению после реконнекта.
                    let _ = cur_gen.cancel_tx.send(true);
                    health_pause.store(true, Ordering::Release);
                    match reconnect_astp_session(
                        &config,
                        &server,
                        &browser_profile,
                        &expected_ip,
                        &expected_gateway,
                        &cur_gen.session_id,
                        &mut global_stop_rx,
                    )
                    .await
                    {
                        Some((new_sock, new_resp, new_key)) => {
                            let new_nonce: [u8; 4] = match new_resp.nonce_prefix.as_slice().try_into()
                            {
                                Ok(p) => p,
                                Err(_) => {
                                    health_pause.store(false, Ordering::Release);
                                    let _ = global_stop_tx.send(true);
                                    break;
                                }
                            };
                            let next_gen = PoolGeneration::new(
                                cur_gen.gen_id + 1,
                                new_resp.session_id,
                                &new_key,
                                new_nonce,
                            );
                            let _ = gen_tx.send(next_gen.clone());
                            cur_gen = next_gen;
                            consecutive_bind_failures = 0;
                            consecutive_bind_rejects = 0;
                            last_seen_gen_id = cur_gen.gen_id;
                            health_pause.store(false, Ordering::Release);
                            new_sock
                        }
                        None => {
                            health_pause.store(false, Ordering::Release);
                            let _ = global_stop_tx.send(true);
                            break;
                        }
                    }
                }
            }
        } else {
            // pool_size == 1 ИЛИ поколение уже отменено — координируем ASTP resume под reauth_lock
            let _reauth_guard = tokio::select! {
                biased;
                _ = global_stop_rx.changed() => break,
                g = reauth_lock.lock() => g,
            };
            if *global_stop_rx.borrow() {
                break;
            }
            let latest_gen = gen_rx.borrow_and_update().clone();
            if latest_gen.gen_id != cur_gen.gen_id {
                // Другой слот уже перевыпустил поколение, переходим к WS_MUX_BIND
                continue;
            }
            let _ = cur_gen.cancel_tx.send(true);
            health_pause.store(true, Ordering::Release);
            match reconnect_astp_session(
                &config,
                &server,
                &browser_profile,
                &expected_ip,
                &expected_gateway,
                &cur_gen.session_id,
                &mut global_stop_rx,
            )
            .await
            {
                Some((new_sock, new_resp, new_key)) => {
                    let new_nonce: [u8; 4] = match new_resp.nonce_prefix.as_slice().try_into() {
                        Ok(p) => p,
                        Err(_) => {
                            health_pause.store(false, Ordering::Release);
                            let _ = global_stop_tx.send(true);
                            break;
                        }
                    };
                    let next_gen = PoolGeneration::new(
                        cur_gen.gen_id + 1,
                        new_resp.session_id,
                        &new_key,
                        new_nonce,
                    );
                    let _ = gen_tx.send(next_gen.clone());
                    cur_gen = next_gen;
                    consecutive_bind_failures = 0;
                    consecutive_bind_rejects = 0;
                    last_seen_gen_id = cur_gen.gen_id;
                    health_pause.store(false, Ordering::Release);
                    new_sock
                }
                None => {
                    health_pause.store(false, Ordering::Release);
                    let _ = global_stop_tx.send(true);
                    break;
                }
            }
        };

        let base_life = session_lifetime(&server);
        let rotation_dur = if is_first_cycle && pool_size > 1 {
            // Разносим ротацию слотов по времени, чтобы в каждый момент времени
            // переподключался максимум 1 сокет, а остальные держали трафик.
            let step = base_life / (pool_size as u32);
            step.saturating_mul((slot_idx as u32) + 1)
                .max(Duration::from_secs(30))
        } else {
            base_life
        };
        is_first_cycle = false;

        let exit = run_client_socket(
            socket,
            cur_gen.clone(),
            shared_tx_rx.clone(),
            downlink_tx.clone(),
            global_stop_rx.clone(),
            ws_cfg.clone(),
            config.stealth.padding_step,
            rotation_dur,
            slot_idx,
        )
        .await;

        match exit {
            SocketExit::TunnelClosed => {
                let _ = global_stop_tx.send(true);
                break;
            }
            SocketExit::GenCancelled => {
                continue;
            }
            SocketExit::Rotated => {
                info!(
                    "[WS#{}] Browser-like session rotation; reconnecting slot",
                    slot_idx
                );
                let pause_ms = if pool_size > 1 {
                    rand::rngs::OsRng.gen_range(150..=500)
                } else {
                    rand::rngs::OsRng.gen_range(450..=1800)
                };
                tokio::select! {
                    biased;
                    _ = global_stop_rx.changed() => break,
                    _ = tokio::time::sleep(Duration::from_millis(pause_ms)) => {}
                }
            }
            SocketExit::Disconnected => {
                let pause_ms = rand::rngs::OsRng.gen_range(250..=850);
                tokio::select! {
                    biased;
                    _ = global_stop_rx.changed() => break,
                    _ = tokio::time::sleep(Duration::from_millis(pause_ms)) => {}
                }
            }
        }
    }
}

async fn reconnect_astp_session(
    config: &CoreConfig,
    server: &ServerConfig,
    browser_profile: &BrowserProfile,
    expected_ip: &str,
    expected_gateway: &str,
    logical_session_id: &str,
    global_stop_rx: &mut watch::Receiver<bool>,
) -> Option<(ClientSocket, anet_common::protocol::AuthResponse, [u8; 32])> {
    let ws_cfg = &config.websocket;
    let deadline = Instant::now() + ws_cfg.effective_reconnect_timeout(server.timeout_secs);
    let attempt_timeout = ws_cfg.handshake_timeout();
    while Instant::now() < deadline {
        if *global_stop_rx.borrow() {
            return None;
        }
        let attempt = tokio::select! {
            biased;
            _ = global_stop_rx.changed() => return None,
            res = tokio::time::timeout(
                attempt_timeout,
                connect_authenticated(
                    config,
                    server,
                    browser_profile,
                    Some(logical_session_id.to_string()),
                ),
            ) => res,
        };

        match attempt {
            Ok(Ok(mut candidate)) => {
                if candidate.1.ip == expected_ip && candidate.1.gateway == expected_gateway {
                    return Some((candidate.0, candidate.1, candidate.2));
                }
                close_browser_session(&mut candidate.0, ws_cfg).await;
                if ws_cfg.abort_on_ip_change {
                    warn!(
                        "[WebSocket] Reconnected session received a new tunnel address ({} != {} / {} != {}); aborting local reconnect so core reconfigures TUN",
                        candidate.1.ip, expected_ip, candidate.1.gateway, expected_gateway
                    );
                    return None;
                }
                warn!("[WebSocket] Rotated session received a different tunnel address");
            }
            Ok(Err(error)) => {
                if error.downcast_ref::<AuthDenyError>().is_some() {
                    warn!("[WebSocket] Planned reconnect rejected by server: {}", error);
                    return None;
                }
                warn!("[WebSocket] Planned reconnect attempt failed: {}", error);
            }
            Err(_) => warn!("[WebSocket] Planned reconnect attempt timed out"),
        }

        let delay = ws_cfg.random_reconnect_retry_delay();
        tokio::select! {
            biased;
            _ = global_stop_rx.changed() => return None,
            _ = tokio::time::sleep(delay) => {}
        }
    }
    None
}

#[async_trait]
impl ClientTransport for WebSocketTransport {
    async fn connect(&self) -> Result<ConnectionResult> {
        let tls_cfg = self.server.effective_tls_config(&self.config.stealth);
        let browser_profile = BrowserProfile::with_tls_config(tls_cfg);
        let pool_size = self.server.websocket_pool_size();

        let (initial_socket, auth_response, initial_key, remote_ip) =
            connect_authenticated(&self.config, &self.server, &browser_profile, None).await?;
        let initial_nonce: [u8; 4] = auth_response
            .nonce_prefix
            .as_slice()
            .try_into()
            .context("Invalid nonce_prefix length in WebSocket AuthResponse")?;

        let expected_ip = auth_response.ip.clone();
        let expected_gateway = auth_response.gateway.clone();
        let logical_session_id = auth_response.session_id.clone();

        info!(
            "[WS] Connected session {} (IP: {}, pool_size: {})",
            logical_session_id, expected_ip, pool_size
        );

        let health_pause = Arc::new(AtomicBool::new(false));
        let (client_stream, internal_router) = tokio::io::duplex(512 * 1024);
        let (mut tunnel_read, tunnel_write) = tokio::io::split(internal_router);

        let (tx_packet_tx, tx_packet_rx) =
            mpsc::channel::<Bytes>(self.config.websocket.effective_tx_queue_capacity());
        let shared_tx_rx = Arc::new(Mutex::new(tx_packet_rx));
        let (downlink_tx, downlink_rx) = mpsc::channel::<(u64, Vec<(u64, Bytes)>)>(
            self.config.websocket.effective_downlink_queue_capacity(),
        );
        let (global_stop_tx, global_stop_rx) = watch::channel(false);

        let tunnel_reader_stop = global_stop_tx.clone();
        let tunnel_reader_task = tokio::spawn(async move {
            let mut frame_reader = FrameReader::new();
            while let Ok(Some(packet)) = frame_reader.read_next_packet(&mut tunnel_read).await {
                if tx_packet_tx.send(packet).await.is_err() {
                    break;
                }
            }
            let _ = tunnel_reader_stop.send(true);
        });

        let downlink_sink_task = tokio::spawn(run_downlink_sink(
            tunnel_write,
            downlink_rx,
            global_stop_rx.clone(),
            self.config.websocket.clone(),
        ));

        let initial_gen = PoolGeneration::new(
            1,
            logical_session_id,
            &initial_key,
            initial_nonce,
        );
        let (gen_tx_raw, gen_rx_template) = watch::channel(initial_gen);
        let gen_tx = Arc::new(gen_tx_raw);
        let reauth_lock = Arc::new(Mutex::new(()));

        let mut child_handles = Vec::with_capacity(pool_size + 2);
        child_handles.push(tunnel_reader_task.abort_handle());
        child_handles.push(downlink_sink_task.abort_handle());

        let mut slot_join_handles = Vec::with_capacity(pool_size);
        let mut initial_opt = Some(initial_socket);

        for slot_idx in 0..pool_size {
            let handle = tokio::spawn(run_slot_worker(
                slot_idx,
                pool_size,
                initial_opt.take(),
                gen_rx_template.clone(),
                gen_tx.clone(),
                reauth_lock.clone(),
                self.config.clone(),
                self.server.clone(),
                browser_profile.clone(),
                expected_ip.clone(),
                expected_gateway.clone(),
                health_pause.clone(),
                shared_tx_rx.clone(),
                downlink_tx.clone(),
                global_stop_tx.clone(),
            ));
            child_handles.push(handle.abort_handle());
            slot_join_handles.push(handle);
        }

        let shutdown_handles = child_handles.clone();
        let supervisor_stop_tx = global_stop_tx.clone();
        let supervisor_task = tokio::spawn(async move {
            let _abort_guard = AbortOnDrop(child_handles);
            for handle in slot_join_handles {
                let _ = handle.await;
            }
            let _ = supervisor_stop_tx.send(true);
            info!("[WebSocket] Transport supervisor stopped");
        });

        let supervisor_abort = supervisor_task.abort_handle();
        let shutdown_hook: super::ShutdownHook = Box::pin(async move {
            let _ = global_stop_tx.send(true);
            supervisor_abort.abort();
            for handle in shutdown_handles {
                handle.abort();
            }
        });

        Ok(ConnectionResult {
            auth_response,
            vpn_stream: Box::new(client_stream),
            endpoint: None,
            connection: None,
            health_pause: Some(health_pause),
            remote_ip,
            bypass_ips: Vec::new(),
            effective_mode: None,
            shutdown_hook: Some(shutdown_hook),
        })
    }
}
