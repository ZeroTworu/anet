use super::{ClientTransport, ConnectionResult};
use crate::auth::{AuthChannel, AuthDenyError, AuthHandler};
use crate::config::{CoreConfig, ServerConfig};
use anet_common::consts::COALESCE_BUDGET_BYTES;
use anet_common::handshake_fragmentation::FragmentConfig;
use anet_common::http_help::BrowserProfile;
use anet_common::stream_framing::{FrameReader, frame_packet_into};
use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use log::{debug, info, warn};
use rand::Rng;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use anet_common::transport_trait::VpnStream;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex as StdMutex};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};
use tokio_tungstenite::{WebSocketStream, client_async_with_config};

type ClientSocket = WebSocketStream<Box<dyn VpnStream>>;
const MAX_WS_MESSAGE_SIZE: usize = 256 * 1024;

struct WebSocketAuthChannel {
    socket: Mutex<ClientSocket>,
}

/// Глобальное хранилище Cookie для WebSocket транспорта с разделением по хостам
static WS_COOKIE_JAR: LazyLock<StdMutex<HashMap<String, HashMap<String, String>>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));

#[async_trait]
impl AuthChannel for WebSocketAuthChannel {
    async fn send(&self, data: Bytes, _frag: &FragmentConfig) -> Result<()> {
        self.socket.lock().await.send(Message::Binary(data)).await?;
        Ok(())
    }

    async fn recv(&self, timeout: Duration) -> Result<Bytes> {
        let receive = async {
            let mut socket = self.socket.lock().await;
            loop {
                match socket.next().await {
                    Some(Ok(Message::Binary(data))) => return Ok(data),
                    Some(Ok(Message::Ping(data))) => socket.send(Message::Pong(data)).await?,
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

async fn connect_authenticated(
    config: &CoreConfig,
    server: &ServerConfig,
    profile: &BrowserProfile,
    resume_session_id: Option<String>,
) -> Result<(ClientSocket, anet_common::protocol::AuthResponse, [u8; 32], Option<IpAddr>)> {
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

    let ws_config = WebSocketConfig::default()
        .read_buffer_size(128 * 1024)
        .write_buffer_size(128 * 1024)
        .max_write_buffer_size(512 * 1024)
        .max_message_size(Some(MAX_WS_MESSAGE_SIZE))
        .max_frame_size(Some(MAX_WS_MESSAGE_SIZE));

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
        // Нахуя оно ваще тут вычислялось?
        // let sni_host = server.host.as_deref().unwrap_or(&target_host);
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
    let channel = WebSocketAuthChannel {
        socket: Mutex::new(socket),
    };
    let auth =
        AuthHandler::new_with_resume(config, server.server_pub_key.as_deref(), resume_session_id)?;
    let (response, key) = auth.authenticate_once(&channel).await?;
    Ok((channel.socket.into_inner(), response, key, peer_ip))
}

fn session_lifetime(server: &ServerConfig) -> Duration {
    let min = server.websocket_min_session_secs.max(30);
    let max = server.websocket_max_session_secs.max(min);
    Duration::from_secs(rand::rngs::OsRng.gen_range(min..=max))
}

async fn close_browser_session(socket: &mut ClientSocket) {
    let close = CloseFrame {
        code: CloseCode::Normal,
        reason: "".into(),
    };
    if socket.send(Message::Close(Some(close))).await.is_err() {
        return;
    }

    let _ = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {}
            }
        }
    })
        .await;
}

#[async_trait]
impl ClientTransport for WebSocketTransport {
    async fn connect(&self) -> Result<ConnectionResult> {
        let tls_cfg = self.server.effective_tls_config(&self.config.stealth);
        let browser_profile = BrowserProfile::with_tls_config(tls_cfg);
        let (initial_socket, auth_response, initial_key, remote_ip) =
            connect_authenticated(&self.config, &self.server, &browser_profile, None).await?;
        let expected_ip = auth_response.ip.clone();
        let expected_gateway = auth_response.gateway.clone();
        let logical_session_id = auth_response.session_id.clone();
        let initial_response = auth_response.clone();
        let config = self.config.clone();
        let server = self.server.clone();
        let health_pause = Arc::new(AtomicBool::new(false));
        let supervisor_health_pause = health_pause.clone();

        // 512 КБ буфер duplex: гарантирует, что входящий 64 КБ батч WebSocket никогда не заблокирует
        // цикл select! при записи в TUN, но при этом не создаст bufferbloat.
        let (client_stream, internal_router) = tokio::io::duplex(512 * 1024);
        let (mut tunnel_read, mut tunnel_write) = tokio::io::split(internal_router);

        tokio::spawn(async move {
            let mut socket = initial_socket;
            let mut key = initial_key;
            let mut current_response = initial_response;
            let mut frame_reader = FrameReader::new();

            'sessions: loop {
                let cipher = anet_common::encryption::Cipher::new(&key);
                let nonce_prefix: [u8; 4] =
                    match current_response.nonce_prefix.as_slice().try_into() {
                        Ok(prefix) => prefix,
                        Err(_) => break 'sessions,
                    };
                let mut sequence = 0u64;
                let mut rotation = Box::pin(tokio::time::sleep(session_lifetime(&server)));

                let mut batch_buf = BytesMut::with_capacity(COALESCE_BUDGET_BYTES + 2048);
                let mut downlink_buf = BytesMut::with_capacity(COALESCE_BUDGET_BYTES + 2048);

                loop {
                    tokio::select! {
                        pkt_res = frame_reader.read_next_packet(&mut tunnel_read) => {
                            let mut raw = match pkt_res {
                                Ok(Some(pkt)) => pkt,
                                _ => break 'sessions,
                            };
                            batch_buf.clear();

                            loop {
                                if raw.len() >= 20 {
                                    let seq = sequence;
                                    sequence = sequence.wrapping_add(1);
                                    if let Ok(encrypted) = anet_common::transport::wrap_packet_padded(
                                        &cipher,
                                        &nonce_prefix,
                                        seq,
                                        raw,
                                        config.stealth.padding_step,
                                    ) {
                                        frame_packet_into(&mut batch_buf, &encrypted);
                                    }
                                }
                                if batch_buf.len() >= COALESCE_BUDGET_BYTES {
                                    break;
                                }
                                match frame_reader.try_next_packet() {
                                    Ok(Some(packet)) => raw = packet,
                                    Ok(None) => break,
                                    Err(_) => break 'sessions,
                                }
                            }

                            if !batch_buf.is_empty() {
                                let out_bytes = batch_buf.split().freeze();
                                batch_buf.reserve(COALESCE_BUDGET_BYTES);
                                if socket.feed(Message::Binary(out_bytes)).await.is_err() {
                                    break 'sessions;
                                }
                                if socket.flush().await.is_err() {
                                    break 'sessions;
                                }
                            }
                        }
                        incoming = socket.next() => {
                            match incoming {
                                Some(Ok(Message::Binary(data))) => {
                                    downlink_buf.clear();
                                    let mut offset = 0usize;
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
                                        match anet_common::transport::unwrap_packet(&cipher, encrypted_slice) {
                                            Ok(packet) => {
                                                frame_packet_into(&mut downlink_buf, &packet);
                                            }
                                            Err(error) => debug!("[WebSocket] Dropped invalid inbound packet: {error}"),
                                        }
                                    }
                                    if !downlink_buf.is_empty() {
                                        if tunnel_write.write_all(&downlink_buf).await.is_err() {
                                            break 'sessions;
                                        }
                                    }
                                }
                                Some(Ok(Message::Ping(data))) => {
                                    if socket.send(Message::Pong(data)).await.is_err() { break 'sessions; }
                                }
                                Some(Ok(Message::Close(frame))) => {
                                    info!("[WebSocket] Server sent Close frame: {:?}", frame);
                                    break 'sessions;
                                }
                                None => {
                                    info!("[WebSocket] Connection stream closed (EOF from server).");
                                    break 'sessions;
                                }
                                Some(Err(e)) => {
                                    warn!("[WebSocket] Socket error received: {e:#}");
                                    break 'sessions;
                                }
                                _ => {}
                            }
                        }
                        _ = &mut rotation => {
                            supervisor_health_pause.store(true, Ordering::Release);
                            close_browser_session(&mut socket).await;
                            break;
                        }
                    }
                }

                info!("[WebSocket] Browser-like session rotation; reconnecting the same endpoint");
                let navigation_gap_ms = rand::rngs::OsRng.gen_range(450..=1800);
                tokio::time::sleep(Duration::from_millis(navigation_gap_ms)).await;
                let deadline =
                    Instant::now() + Duration::from_secs(server.timeout_secs.max(10) * 3);
                let mut reconnected = None;
                while Instant::now() < deadline {
                    {
                        match tokio::time::timeout(
                            Duration::from_secs(server.timeout_secs),
                            connect_authenticated(
                                &config,
                                &server,
                                &browser_profile,
                                Some(logical_session_id.clone()),
                            ),
                        )
                            .await
                        {
                            Ok(Ok(candidate)) => {
                                if candidate.1.ip == expected_ip
                                    && candidate.1.gateway == expected_gateway
                                {
                                    reconnected = Some((candidate.0, candidate.1, candidate.2));
                                    break;
                                }
                                {
                                    let (mut rejected_socket, _, _, _) = candidate;
                                    close_browser_session(&mut rejected_socket).await;
                                }
                                warn!(
                                    "[WebSocket] Rotated session received a different tunnel address"
                                );
                            }
                            Ok(Err(error)) => {
                                if error.downcast_ref::<AuthDenyError>().is_some() {
                                    warn!(
                                        "[WebSocket] Planned reconnect rejected by server: {}",
                                        error
                                    );
                                    break;
                                }
                                warn!("[WebSocket] Planned reconnect attempt failed: {}", error)
                            }
                            Err(_) => warn!("[WebSocket] Planned reconnect attempt timed out"),
                        }
                    }
                    let delay_ms = rand::rngs::OsRng.gen_range(350..=1400);
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }

                match reconnected {
                    Some((new_socket, new_response, new_key)) => {
                        socket = new_socket;
                        current_response = new_response;
                        key = new_key;
                        supervisor_health_pause.store(false, Ordering::Release);
                    }
                    None => break 'sessions,
                }
            }
            close_browser_session(&mut socket).await;
            info!("[WebSocket] Transport supervisor stopped");
        });

        Ok(ConnectionResult {
            auth_response,
            vpn_stream: Box::new(client_stream),
            endpoint: None,
            connection: None,
            health_pause: Some(health_pause),
            remote_ip, // Передаем IP для добавления в bypass
            bypass_ips: Vec::new(),
            effective_mode: None,
            shutdown_hook: None,
        })
    }
}
