use super::{ClientTransport, ConnectionResult};
use crate::auth::{AuthChannel, AuthHandler};
use crate::config::{CoreConfig, ServerConfig};
use anet_common::consts::MAX_PACKET_SIZE;
use anet_common::encryption::Cipher;
use anet_common::handshake_fragmentation::FragmentConfig;
use anet_common::http_help::BrowserProfile;
use anet_common::wrtc::{
    colibri::{verify_beacon, ColibriMessage, WrtcMessage},
    jingle::parse_jingle_session,
    ktalk::KtalkClient,
    peer::WrtcPeer,
    stealth::generate_random_guest_name,
    xmpp::XmppSession,
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::prelude::*;
use bytes::{Bytes, BytesMut};
use log::{debug, info, warn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;

pub struct WrtcTransport {
    config: CoreConfig,
    server: ServerConfig,
}

impl WrtcTransport {
    pub fn new(config: CoreConfig, server: ServerConfig) -> Self {
        Self { config, server }
    }
}

struct WrtcAuthChannel {
    peer: Arc<Mutex<WrtcPeer>>,
    target_server_id: String,
}

#[async_trait]
impl AuthChannel for WrtcAuthChannel {
    async fn send(&self, data: Bytes, _frag: &FragmentConfig) -> Result<()> {
        let b64 = BASE64_STANDARD.encode(&data);
        let msg = ColibriMessage::astp(self.target_server_id.clone(), b64);
        let peer = self.peer.lock().await;
        peer.send(msg).await?;
        Ok(())
    }

    async fn recv(&self, timeout: Duration) -> Result<Bytes> {
        let receive = async {
            let mut peer = self.peer.lock().await;
            while let Some(msg) = peer.recv().await {
                if let WrtcMessage::Astp { data } = msg.msg_payload {
                    if let Ok(bytes) = BASE64_STANDARD.decode(&data) {
                        return Ok(Bytes::from(bytes));
                    }
                }
            }
            anyhow::bail!("DataChannel closed during authentication")
        };

        tokio::time::timeout(timeout, receive)
            .await
            .context("ASTP authentication timeout over WebRTC DataChannel")?
    }
}

pub struct WrtcStream {
    peer: Arc<Mutex<WrtcPeer>>,
    cipher: Arc<Cipher>,
    target_server_id: String,
    read_buffer: BytesMut,
}

impl WrtcStream {
    pub fn new(peer: WrtcPeer, cipher: Cipher, target_server_id: String) -> Self {
        Self {
            peer: Arc::new(Mutex::new(peer)),
            cipher: Arc::new(cipher),
            target_server_id,
            read_buffer: BytesMut::with_capacity(MAX_PACKET_SIZE * 2),
        }
    }
}

impl AsyncRead for WrtcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Return existing buffered data first
        if !self.read_buffer.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), self.read_buffer.len());
            buf.put_slice(&self.read_buffer.split_to(to_read));
            return Poll::Ready(Ok(()));
        }

        let peer = self.peer.clone();
        let cipher = self.cipher.clone();

        let mut fut = Box::pin(async move {
            let mut p = peer.lock().await;
            while let Some(msg) = p.recv().await {
                if let WrtcMessage::Astp { data } = msg.msg_payload {
                    if let Ok(encrypted_packet) = BASE64_STANDARD.decode(&data) {
                        // Decrypt packet using session cipher
                        if let Ok(plaintext) = cipher.decrypt(&encrypted_packet) {
                            return Some(plaintext);
                        }
                    }
                }
            }
            None
        });

        match fut.as_mut().poll(cx) {
            Poll::Ready(Some(packet)) => {
                let to_read = std::cmp::min(buf.remaining(), packet.len());
                buf.put_slice(&packet[..to_read]);
                if to_read < packet.len() {
                    self.read_buffer.extend_from_slice(&packet[to_read..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WrtcStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let peer = self.peer.clone();
        let target_id = self.target_server_id.clone();
        let encrypted = self.cipher.encrypt(buf);
        let b64 = BASE64_STANDARD.encode(&encrypted);
        let msg = ColibriMessage::astp(target_id, b64);

        let mut fut = Box::pin(async move {
            let p = peer.lock().await;
            p.send(msg).await
        });

        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[async_trait]
impl ClientTransport for WrtcTransport {
    async fn connect(&self) -> Result<ConnectionResult> {
        let (domain, room_name) = self.server.wrtc_room()?;
        let browser_profile = BrowserProfile::random();
        let guest_name = generate_random_guest_name();

        info!(
            "[WRTC] Connecting to Ktalk room '{}' at domain '{}' as '{}'...",
            room_name, domain, guest_name
        );

        // 1. Authorize session in Ktalk REST API with browser stealth headers
        let ktalk = KtalkClient::new(browser_profile.clone());
        let anon_secret = KtalkClient::generate_anonymous_secret();
        let auth_res = ktalk
            .authorize_session(&domain, &room_name, Some(&guest_name), &anon_secret)
            .await
            .context("Failed to authorize Ktalk session")?;
        info!(
            "[WRTC] Ktalk session authorized (token: {}). Resolving conference ID...",
            auth_res.token
        );

        // 2. Resolve room name into conferenceId
        let room_info = ktalk
            .resolve_room(&domain, &room_name, &auth_res.token)
            .await
            .context("Failed to resolve Ktalk room")?;
        info!(
            "[WRTC] Conference ID resolved: {}",
            room_info.conference_id
        );

        // 3. XMPP Signaling: Connect WebSocket, SASL ANONYMOUS, join MUC with dual ping keep-alive
        let ping_secs = self.server.wrtc_ping_interval_secs.unwrap_or(30);
        let mut xmpp = XmppSession::connect(
            &domain,
            &room_info.conference_id,
            &auth_res.token,
            Some(&guest_name),
            &browser_profile,
            ping_secs,
        )
        .await
        .context("Failed to establish XMPP session and join conference MUC")?;
        info!(
            "[WRTC] Successfully joined conference MUC as occupant: {}",
            xmpp.endpoint_id
        );

        // 4. Jicofo allocation & Jingle negotiation with dynamic ICE fallback
        let fallback_ip = self
            .server
            .wrtc_fallback_jvb_ip
            .as_deref()
            .unwrap_or("89.169.16.6");
        let fallback_port = self.server.wrtc_fallback_jvb_port.unwrap_or(10002);

        let _ = xmpp.request_conference_allocation().await;

        let mut parsed_candidates = Vec::new();
        let jingle_timeout = Duration::from_secs(3);
        let jingle_deadline = tokio::time::Instant::now() + jingle_timeout;

        while tokio::time::Instant::now() < jingle_deadline {
            if let Ok(Some(stanza)) = tokio::time::timeout(Duration::from_millis(500), xmpp.recv_stanza()).await {
                if let Some(session) = parse_jingle_session(&stanza, fallback_ip, fallback_port) {
                    debug!("[WRTC] Extracted {} dynamic candidates from Jingle offer", session.transport.candidates.len());
                    parsed_candidates = session.transport.candidates;
                    break;
                }
            }
        }

        // 5. Initialize WebRTC PeerConnection, DataChannel "JVB data channel", and Opus silence keep-alive
        let audio_keepalive_ms = self.server.wrtc_media_keepalive_interval_ms.unwrap_or(20);
        let mut peer = WrtcPeer::create(
            &parsed_candidates,
            fallback_ip,
            fallback_port,
            audio_keepalive_ms,
        )
        .await
        .context("Failed to initialize WebRTC PeerConnection and DataChannel")?;

        // 6. Discovery Phase: Challenge-Response over DataChannel
        let client_nonce = format!("{:016x}", rand::random::<u64>());
        info!(
            "[WRTC] Starting server discovery in room over DataChannel (nonce: {})...",
            client_nonce
        );

        let timeout_secs = if self.server.timeout_secs > 0 {
            self.server.timeout_secs
        } else {
            10
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
        let mut interval = tokio::time::interval(Duration::from_secs(2));

        let server_pub_key = self
            .server
            .server_pub_key
            .as_deref()
            .or_else(|| {
                if !self.config.keys.server_pub_key.is_empty() {
                    Some(self.config.keys.server_pub_key.as_str())
                } else {
                    None
                }
            });

        let mut verified_server_id: Option<String> = None;

        while tokio::time::Instant::now() < deadline {
            tokio::select! {
                _ = interval.tick() => {
                    debug!("[WRTC] Sending anet_discover into DataChannel...");
                    let discover_msg = ColibriMessage::discover(client_nonce.clone());
                    let _ = peer.send(discover_msg).await;
                }
                msg_opt = peer.recv() => {
                    if let Some(msg) = msg_opt {
                        if let WrtcMessage::Beacon { server_id, client_nonce: beacon_nonce, signature } = msg.msg_payload {
                            if beacon_nonce == client_nonce {
                                info!("[WRTC] Received anet_beacon from server: {}", server_id);
                                if let Some(pub_key) = server_pub_key {
                                    match verify_beacon(pub_key, &client_nonce, &server_id, &signature) {
                                        Ok(true) => {
                                            info!("[WRTC] Server beacon signature verified successfully!");
                                            verified_server_id = Some(server_id);
                                            break;
                                        }
                                        Ok(false) => {
                                            warn!("[WRTC] Server beacon signature verification failed");
                                            continue;
                                        }
                                        Err(e) => {
                                            warn!("[WRTC] Error verifying server beacon: {e}");
                                            continue;
                                        }
                                    }
                                } else {
                                    info!("[WRTC] No server_pub_key configured, accepting server: {}", server_id);
                                    verified_server_id = Some(server_id);
                                    break;
                                }
                            }
                        }
                    } else {
                        warn!("[WRTC] DataChannel closed during server discovery");
                        break;
                    }
                }
            }
        }

        let target_server_id = verified_server_id.ok_or_else(|| {
            anyhow::anyhow!(
                "Server discovery in room '{room_name}' timed out after {timeout_secs}s"
            )
        })?;

        info!("[WRTC] Authenticating ASTP session with server {}...", target_server_id);

        let shared_peer = Arc::new(Mutex::new(peer));
        let auth_channel = WrtcAuthChannel {
            peer: shared_peer.clone(),
            target_server_id: target_server_id.clone(),
        };

        let auth_handler = AuthHandler::new(&self.config, self.server.server_pub_key.as_deref())?;
        let (auth_response, cipher) = auth_handler.authenticate(&auth_channel).await?;

        info!(
            "[WRTC] ASTP Authentication succeeded! Assigned VPN IP: {}",
            auth_response.assigned_ip
        );

        let vpn_stream = Box::new(WrtcStream {
            peer: shared_peer,
            cipher: Arc::new(cipher),
            target_server_id,
            read_buffer: BytesMut::with_capacity(MAX_PACKET_SIZE * 2),
        });

        Ok(ConnectionResult {
            auth_response,
            vpn_stream,
            endpoint: None,
            connection: None,
            health_pause: None,
            remote_ip: None,
        })
    }
}
