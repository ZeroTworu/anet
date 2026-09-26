use super::{ClientTransport, ConnectionResult};
use crate::auth::{AuthChannel, AuthHandler};
use crate::config::{CoreConfig, ServerConfig};
use anet_common::consts::{CHANNEL_BUFFER_SIZE, MAX_PACKET_SIZE};
use anet_common::encryption::Cipher;
use anet_common::handshake_fragmentation::FragmentConfig;
use anet_common::http_help::BrowserProfile;
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anet_common::transport::{unwrap_packet_bytes, wrap_packet_padded};
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
use bytes::Bytes;
use log::{debug, info, warn};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
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
    peer: Arc<WrtcPeer>,
    target_server_id: String,
}

#[async_trait]
impl AuthChannel for WrtcAuthChannel {
    async fn send(&self, data: Bytes, _frag: &FragmentConfig) -> Result<()> {
        let b64 = BASE64_STANDARD.encode(&data);
        let msg = ColibriMessage::astp(self.target_server_id.clone(), b64);
        self.peer.send(msg).await?;
        Ok(())
    }

    async fn recv(&self, timeout: Duration) -> Result<Bytes> {
        let receive = async {
            while let Some(msg) = self.peer.recv().await {
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

        // 1. Авторизация гостя через REST API
        let ktalk = KtalkClient::new(browser_profile.clone());
        let anon_secret = KtalkClient::generate_anonymous_secret();
        let auth_res = ktalk
            .authorize_session(&domain, &room_name, Some(&guest_name), &anon_secret)
            .await
            .context("Failed to authorize Ktalk session")?;

        // 2. Получение conferenceId
        let room_info = ktalk
            .resolve_room(&domain, &room_name, &auth_res.token)
            .await
            .context("Failed to resolve Ktalk room")?;

        // 3. XMPP сигналинг через WebSocket
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

        // 4. Jingle negotiation и получение параметров JVB
        let fallback_ip = self
            .server
            .wrtc_fallback_jvb_ip
            .as_deref()
            .unwrap_or("89.169.16.6");
        let fallback_port = self.server.wrtc_fallback_jvb_port.unwrap_or(10002);

        let _ = xmpp.request_conference_allocation().await;

        let timeout_secs = self.server.timeout_secs.max(15);
        let mut parsed_session = None;
        let jingle_deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);

        while tokio::time::Instant::now() < jingle_deadline {
            if let Ok(Some(stanza)) =
                tokio::time::timeout(Duration::from_millis(400), xmpp.recv_stanza()).await
            {
                if let Some(session) = parse_jingle_session(&stanza, fallback_ip, fallback_port) {
                    parsed_session = Some(session);
                    break;
                }
            }
        }

        let Some(session) = parsed_session else {
            anyhow::bail!(
                "Failed to receive Jicofo session-initiate within {timeout_secs}s (no server or bridge session in room)"
            );
        };

        // 5. Создание соединения (Colibri-WS или WebRTC PeerConnection)
        let audio_keepalive_ms = self.server.wrtc_media_keepalive_interval_ms.unwrap_or(20);
        let mut peer = WrtcPeer::create(
            Some(&session),
            &domain,
            fallback_ip,
            fallback_port,
            audio_keepalive_ms,
        )
            .await
            .context("Failed to initialize WebRTC PeerConnection and DataChannel")?;

        info!("[WRTC] WebRTC Peer created. Starting server discovery...");

        // 6. Discovery фаза: опрос участников комнаты
        let client_nonce = format!("{:016x}", rand::random::<u64>());
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

        let mut verified_server_id = None;
        while tokio::time::Instant::now() < deadline {
            tokio::select! {
                _ = interval.tick() => {
                    info!("[WRTC] Sending anet_discover broadcast (nonce: {client_nonce})...");
                    let discover_broadcast = ColibriMessage::discover(None, client_nonce.clone());
                    let _ = peer.send(discover_broadcast).await;

                    let current_occupants = xmpp.get_other_occupants();
                    for occupant in current_occupants {
                        info!("[WRTC] Sending anet_discover to occupant: {occupant}");
                        let unicast_discover = ColibriMessage::discover(Some(occupant), client_nonce.clone());
                        let _ = peer.send(unicast_discover).await;
                    }
                }
                msg_opt = peer.recv() => {
                    if let Some(msg) = msg_opt {
                        if let WrtcMessage::Beacon { server_id, client_nonce: beacon_nonce, signature } = msg.msg_payload {
                            info!("[WRTC] Received beacon from server: {server_id} (nonce match: {})", beacon_nonce == client_nonce);
                            if beacon_nonce == client_nonce {
                                if let Some(pub_key) = server_pub_key {
                                    match verify_beacon(pub_key, &client_nonce, &server_id, &signature) {
                                        Ok(true) => {
                                            info!("[WRTC] Server beacon signature verified successfully! Server ID: {server_id}");
                                            verified_server_id = Some(server_id);
                                            break;
                                        }
                                        Ok(false) => {
                                            warn!("[WRTC] Server beacon signature verification FAILED! Check server_pub_key in client.toml vs server_signing_key in server.toml");
                                        }
                                        Err(e) => {
                                            warn!("[WRTC] Error verifying server beacon: {e:#}");
                                        }
                                    }
                                } else {
                                    info!("[WRTC] No server_pub_key configured, accepting server: {server_id}");
                                    verified_server_id = Some(server_id);
                                    break;
                                }
                            }
                        }
                    } else {
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

        info!("[WRTC] Starting ASTP authentication with server: {target_server_id}");

        // 7. ASTP аутентификация
        let shared_peer = Arc::new(peer);
        let auth_channel = WrtcAuthChannel {
            peer: shared_peer.clone(),
            target_server_id: target_server_id.clone(),
        };

        let auth_handler = AuthHandler::new(&self.config, self.server.server_pub_key.as_deref())?;
        let (auth_response, shared_key) = auth_handler.authenticate(&auth_channel).await?;

        info!(
            "[WRTC] ASTP Authentication succeeded! Assigned VPN IP: {}",
            auth_response.ip
        );

        let cipher = Arc::new(Cipher::new(&shared_key));
        let nonce_prefix: [u8; 4] = auth_response.nonce_prefix.as_slice().try_into()?;
        let sequence = Arc::new(AtomicU64::new(0));

        // 8. Создание дуплексного потока для ядра VPN
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

        // Воркер Uplink: TUN -> WebRTC
        let peer_tx = shared_peer.clone();
        let target_srv_tx = target_server_id.clone();
        let cipher_tx = cipher.clone();
        let sequence_tx = sequence.clone();
        let padding_step = self.config.stealth.padding_step;

        tokio::spawn(async move {
            while let Some(packet) = tunnel_packet_rx.recv().await {
                if packet.len() < 20 {
                    continue;
                }
                let seq = sequence_tx.fetch_add(1, Ordering::Relaxed);
                if let Ok(encrypted) =
                    wrap_packet_padded(&cipher_tx, &nonce_prefix, seq, packet, padding_step)
                {
                    let b64 = BASE64_STANDARD.encode(&encrypted);
                    let msg = ColibriMessage::astp(target_srv_tx.clone(), b64);
                    if peer_tx.send(msg).await.is_err() {
                        break;
                    }
                }
            }
            tunnel_reader_task.abort();
        });

        // Воркер Downlink: WebRTC -> TUN
        let peer_rx = shared_peer.clone();
        let cipher_rx = cipher.clone();

        tokio::spawn(async move {
            loop {
                let msg_opt = peer_rx.recv().await;
                match msg_opt {
                    Some(msg) => {
                        if let WrtcMessage::Astp { data } = msg.msg_payload {
                            if let Ok(raw_encrypted) = BASE64_STANDARD.decode(&data) {
                                if let Ok(packet) = unwrap_packet_bytes(
                                    &cipher_rx,
                                    Bytes::from(raw_encrypted),
                                ) {
                                    let framed = frame_packet(packet);
                                    if tunnel_write.write_all(&framed).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    None => break,
                }
            }
        });

        Ok(ConnectionResult {
            auth_response,
            vpn_stream: Box::new(client_stream),
            endpoint: None,
            connection: None,
            health_pause: None,
            remote_ip: None,
        })
    }
}
