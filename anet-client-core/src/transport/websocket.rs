use super::{ClientTransport, ConnectionResult};
use crate::auth::{AuthChannel, AuthDenyError, AuthHandler};
use crate::config::{CoreConfig, ServerConfig};
use anet_common::consts::{CHANNEL_BUFFER_SIZE, COALESCE_BUDGET_BYTES, MAX_PACKET_SIZE};
use anet_common::handshake_fragmentation::FragmentConfig;
use anet_common::http_help::BrowserProfile;
use anet_common::stream_framing::{frame_packet, frame_packet_into, read_next_packet};
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
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, client_async_tls_with_config,
};

type ClientSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

const MAX_WS_MESSAGE_SIZE: usize = 128 * 1024;

struct WebSocketAuthChannel {
    socket: Mutex<ClientSocket>,
}

#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
        ]
    }
}

fn wss_connector() -> Result<Connector> {
    let tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    let mut tls = tls;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Connector::Rustls(Arc::new(tls)))
}

fn connector_for(server: &ServerConfig) -> Result<Connector> {
    let scheme = server
        .dsn
        .parse::<http::Uri>()?
        .scheme_str()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if scheme == "wss" {
        wss_connector()
    } else {
        Ok(Connector::Plain)
    }
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

async fn connect_authenticated(
    config: &CoreConfig,
    server: &ServerConfig,
    profile: &BrowserProfile,
    resume_session_id: Option<String>,
) -> Result<(ClientSocket, anet_common::protocol::AuthResponse, [u8; 32], Option<IpAddr>)> {
    let url = server.websocket_url()?;
    let request = profile.build_ws_request(&url, None)?;
    let ws_config = WebSocketConfig::default()
        .read_buffer_size(64 * 1024)
        .write_buffer_size(64 * 1024)
        .max_write_buffer_size(256 * 1024)
        .max_message_size(Some(MAX_WS_MESSAGE_SIZE))
        .max_frame_size(Some(MAX_WS_MESSAGE_SIZE));

    let endpoint = server.endpoint()?;
    let tcp_stream = TcpStream::connect(&endpoint)
        .await
        .with_context(|| format!("failed to connect to WebSocket endpoint {endpoint}"))?;

    // Запоминаем реальный IP, к которому подключились
    let peer_ip = tcp_stream.peer_addr().ok().map(|sa| sa.ip());
    tcp_stream.set_nodelay(true)?;

    let (socket, _) = client_async_tls_with_config(
        request,
        tcp_stream,
        Some(ws_config),
        Some(connector_for(server)?),
    )
        .await?;
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
        let browser_profile = BrowserProfile::random();
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

        let (client_stream, internal_router) = tokio::io::duplex(MAX_PACKET_SIZE * 10);
        let (mut tunnel_read, mut tunnel_write) = tokio::io::split(internal_router);
        let (tunnel_packet_tx, mut tunnel_packet_rx) =
            tokio::sync::mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);

        let tunnel_reader_task = tokio::spawn(async move {
            while let Ok(Some(packet)) = read_next_packet(&mut tunnel_read).await {
                if tunnel_packet_tx.send(packet).await.is_err() {
                    break;
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

                let mut batch_buf = BytesMut::with_capacity(COALESCE_BUDGET_BYTES);

                loop {
                    tokio::select! {
                        packet = tunnel_packet_rx.recv() => {
                            let Some(mut raw) = packet else { break 'sessions; };
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
                                raw = match tunnel_packet_rx.try_recv() {
                                    Ok(packet) => packet,
                                    Err(_) => break,
                                };
                            }

                            if !batch_buf.is_empty() {
                                if socket.feed(Message::Binary(batch_buf.clone().freeze())).await.is_err() {
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
                                    let mut cursor = std::io::Cursor::new(data);
                                    while let Ok(Some(encrypted_packet)) = read_next_packet(&mut cursor).await {
                                        match anet_common::transport::unwrap_packet_bytes(&cipher, encrypted_packet) {
                                            Ok(packet) => {
                                                let framed = frame_packet(packet);
                                                if tunnel_write.write_all(&framed).await.is_err() { break 'sessions; }
                                            }
                                            Err(error) => debug!("[WebSocket] Dropped invalid inbound packet: {error}"),
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
            tunnel_reader_task.abort();
            let _ = tunnel_reader_task.await;
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
