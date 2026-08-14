use super::{ClientTransport, ConnectionResult, MutexVpnStream};
use crate::auth::{AuthChannel, AuthHandler};
use crate::config::{CoreConfig, ServerConfig};
use anet_common::consts::{CHANNEL_BUFFER_SIZE, MAX_PACKET_SIZE};
use anet_common::handshake_fragmentation::FragmentConfig;
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use http::HeaderValue;
use http::header::{ACCEPT_LANGUAGE, CACHE_CONTROL, ORIGIN, PRAGMA, USER_AGENT};
use log::{info, warn};
use rand::{Rng, seq::SliceRandom};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async_with_config};

type ClientSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

const CHROME_USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
];
const FIREFOX_USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:131.0) Gecko/20100101 Firefox/131.0",
];
const CHROME_BRANDS: &[&str] = &[
    "\"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\", \"Google Chrome\";v=\"131\"",
    "\"Chromium\";v=\"130\", \"Not_A Brand\";v=\"24\", \"Google Chrome\";v=\"130\"",
    "\"Chromium\";v=\"129\", \"Not_A Brand\";v=\"24\", \"Google Chrome\";v=\"129\"",
];
const CHROME_PLATFORMS: &[&str] = &["\"Windows\"", "\"Linux\"", "\"macOS\""];
const SAFARI_USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
];
const ACCEPT_LANGUAGES: &[&str] = &[
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
];
const MAX_WS_MESSAGE_SIZE: usize = 64 * 1024;

#[derive(Clone)]
struct BrowserProfile {
    user_agent: &'static str,
    accept_language: &'static str,
    chrome_profile: Option<usize>,
}

impl BrowserProfile {
    fn random() -> Self {
        let mut rng = rand::rngs::OsRng;
        let family = rng.gen_range(0..3);
        let (user_agent, chrome_profile) = match family {
            0 => {
                let index = rng.gen_range(0..CHROME_USER_AGENTS.len());
                (CHROME_USER_AGENTS[index], Some(index))
            }
            1 => (
                FIREFOX_USER_AGENTS
                    .choose(&mut rng)
                    .copied()
                    .unwrap_or(FIREFOX_USER_AGENTS[0]),
                None,
            ),
            _ => (
                SAFARI_USER_AGENTS
                    .choose(&mut rng)
                    .copied()
                    .unwrap_or(SAFARI_USER_AGENTS[0]),
                None,
            ),
        };
        Self {
            user_agent,
            accept_language: ACCEPT_LANGUAGES
                .choose(&mut rng)
                .copied()
                .unwrap_or(ACCEPT_LANGUAGES[0]),
            chrome_profile,
        }
    }
}

struct WebSocketAuthChannel {
    socket: Mutex<ClientSocket>,
}

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

fn browser_request(server: &ServerConfig, profile: &BrowserProfile) -> Result<http::Request<()>> {
    let url = &server.websocket_url;
    let mut request = url.as_str().into_client_request()?;

    request
        .headers_mut()
        .insert(USER_AGENT, HeaderValue::from_str(profile.user_agent)?);
    request.headers_mut().insert(
        ACCEPT_LANGUAGE,
        HeaderValue::from_static(profile.accept_language),
    );
    request
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    request
        .headers_mut()
        .insert(PRAGMA, HeaderValue::from_static("no-cache"));

    let origin_scheme = if url.starts_with("wss://") {
        "https"
    } else {
        "http"
    };
    let authority = request
        .uri()
        .authority()
        .context("WebSocket URL has no authority")?
        .to_string();
    request.headers_mut().insert(
        ORIGIN,
        HeaderValue::from_str(&format!("{}://{}", origin_scheme, authority))?,
    );

    if let Some(index) = profile.chrome_profile {
        request
            .headers_mut()
            .insert("sec-ch-ua", HeaderValue::from_static(CHROME_BRANDS[index]));
        request
            .headers_mut()
            .insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        request.headers_mut().insert(
            "sec-ch-ua-platform",
            HeaderValue::from_static(CHROME_PLATFORMS[index]),
        );
    }
    Ok(request)
}

async fn connect_authenticated(
    config: &CoreConfig,
    server: &ServerConfig,
    profile: &BrowserProfile,
    resume_session_id: Option<String>,
) -> Result<(ClientSocket, anet_common::protocol::AuthResponse, [u8; 32])> {
    let request = browser_request(server, profile)?;
    let ws_config = WebSocketConfig::default()
        .read_buffer_size(16 * 1024)
        .write_buffer_size(16 * 1024)
        .max_write_buffer_size(128 * 1024)
        .max_message_size(Some(MAX_WS_MESSAGE_SIZE))
        .max_frame_size(Some(MAX_WS_MESSAGE_SIZE));
    let (socket, _) = connect_async_with_config(request, Some(ws_config), true).await?;
    let channel = WebSocketAuthChannel {
        socket: Mutex::new(socket),
    };
    let auth =
        AuthHandler::new_with_resume(config, server.server_pub_key.as_deref(), resume_session_id)?;
    let (response, key) = auth.authenticate(&channel).await?;
    Ok((channel.socket.into_inner(), response, key))
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

    // Finish the WebSocket close handshake instead of merely releasing the
    // client handle. Seeing Close/EOF means the peer processed our Close, so
    // its registry cleanup can run before the next ASTP authentication.
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
        let browser_profile = BrowserProfile::random();
        let (initial_socket, auth_response, initial_key) =
            connect_authenticated(&self.config, &self.server, &browser_profile, None).await?;
        let expected_ip = auth_response.ip.clone();
        let expected_gateway = auth_response.gateway.clone();
        let logical_session_id = auth_response.session_id.clone();
        let initial_response = auth_response.clone();
        let config = self.config.clone();
        let server = self.server.clone();
        let health_pause = Arc::new(AtomicBool::new(false));
        let supervisor_health_pause = health_pause.clone();

        let (client_stream, internal_router) = tokio::io::duplex(MAX_PACKET_SIZE * 10);
        let (mut tunnel_read, mut tunnel_write) = tokio::io::split(internal_router);
        let (tunnel_packet_tx, mut tunnel_packet_rx) =
            tokio::sync::mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);

        // read_next_packet() is deliberately isolated from tokio::select!.
        // AsyncRead operations are not generally cancellation-safe: cancelling
        // after a partial length prefix would desynchronise all later frames.
        let tunnel_reader_task = tokio::spawn(async move {
            loop {
                match read_next_packet(&mut tunnel_read).await {
                    Ok(Some(packet)) => {
                        if tunnel_packet_tx.send(packet).await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
        });

        tokio::spawn(async move {
            let mut socket = initial_socket;
            let mut key = initial_key;
            let mut current_response = initial_response;

            'sessions: loop {
                let cipher = anet_common::encryption::Cipher::new(&key);
                let nonce_prefix: [u8; 4] =
                    match current_response.nonce_prefix.as_slice().try_into() {
                        Ok(prefix) => prefix,
                        Err(_) => break 'sessions,
                    };
                let mut sequence = 0u64;
                let mut rotation = Box::pin(tokio::time::sleep(session_lifetime(&server)));

                loop {
                    tokio::select! {
                        packet = tunnel_packet_rx.recv() => {
                            let Some(raw) = packet else { break 'sessions; };
                            let size = raw.len() + 38;
                            let padding = anet_common::padding_utils::calculate_padding_needed(size, config.stealth.padding_step);
                            let padding = if size + padding as usize > anet_common::consts::PADDING_MTU { 0 } else { padding };
                            match anet_common::transport::wrap_packet(&cipher, &nonce_prefix, sequence, raw, padding) {
                                Ok(encrypted) => {
                                    sequence = sequence.wrapping_add(1);
                                    if socket.send(Message::Binary(encrypted)).await.is_err() { break 'sessions; }
                                }
                                Err(_) => break 'sessions,
                            }
                        }
                        incoming = socket.next() => {
                            match incoming {
                                Some(Ok(Message::Binary(data))) => {
                                    if let Ok(packet) = anet_common::transport::unwrap_packet(&cipher, &data) {
                                        let framed = frame_packet(packet);
                                        if tunnel_write.write_all(&framed).await.is_err() { break 'sessions; }
                                    }
                                }
                                Some(Ok(Message::Ping(data))) => {
                                    if socket.send(Message::Pong(data)).await.is_err() { break 'sessions; }
                                }
                                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break 'sessions,
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
                // A real page lifecycle has a short gap between unload and the
                // next navigation. It also lets the server release the old IP
                // and authorization session before a fresh ASTP handshake.
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
                                    reconnected = Some(candidate);
                                    break;
                                }
                                {
                                    let (mut rejected_socket, _, _) = candidate;
                                    close_browser_session(&mut rejected_socket).await;
                                }
                                warn!(
                                    "[WebSocket] Rotated session received a different tunnel address"
                                );
                            }
                            Ok(Err(error)) => {
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
            tunnel_reader_task.abort();
            let _ = tunnel_reader_task.await;
            info!("[WebSocket] Transport supervisor stopped");
        });

        Ok(ConnectionResult {
            auth_response,
            vpn_stream: Box::new(MutexVpnStream(Arc::new(Mutex::new(client_stream)))),
            endpoint: None,
            connection: None,
            health_pause: Some(health_pause),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TransportMode;

    fn server(url: &str) -> ServerConfig {
        ServerConfig {
            name: None,
            address: "example.com:443".to_string(),
            mode: TransportMode::Websocket,
            timeout_secs: 8,
            server_pub_key: None,
            ssh_user: None,
            websocket_url: url.to_string(),
            websocket_min_session_secs: 480,
            websocket_max_session_secs: 1500,
        }
    }

    #[test]
    fn browser_request_has_required_browser_headers() {
        let profile = BrowserProfile::random();
        for _ in 0..20 {
            let request =
                browser_request(&server("ws://example.com:8080/socket"), &profile).unwrap();
            let user_agent = request.headers().get(USER_AGENT).unwrap().to_str().unwrap();
            assert!(
                user_agent.contains("Chrome/")
                    || user_agent.contains("Firefox/")
                    || user_agent.contains("Safari/")
            );
            assert_eq!(
                request.headers().get(ORIGIN).unwrap(),
                "http://example.com:8080"
            );
            assert!(request.headers().contains_key(ACCEPT_LANGUAGE));
        }
    }

    #[test]
    fn browser_profile_is_stable_across_reconnects() {
        let profile = BrowserProfile::random();
        let first = browser_request(&server("wss://example.com/socket"), &profile).unwrap();
        let second = browser_request(&server("wss://example.com/socket"), &profile).unwrap();
        assert_eq!(
            first.headers().get(USER_AGENT),
            second.headers().get(USER_AGENT)
        );
        assert_eq!(
            first.headers().get(ACCEPT_LANGUAGE),
            second.headers().get(ACCEPT_LANGUAGE)
        );
        assert_eq!(
            first.headers().get("sec-ch-ua"),
            second.headers().get("sec-ch-ua")
        );
    }
}
