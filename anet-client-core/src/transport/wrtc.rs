use super::{ClientTransport, ConnectionResult};
use crate::config::{CoreConfig, ServerConfig};
use anet_common::wrtc::{
    colibri::{ColibriMessage, ColibriPayload, verify_beacon},
    ktalk::KtalkClient,
    xmpp::XmppSession,
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use log::{debug, info, warn};
use std::time::Duration;

pub struct WrtcTransport {
    config: CoreConfig,
    server: ServerConfig,
}

impl WrtcTransport {
    pub fn new(config: CoreConfig, server: ServerConfig) -> Self {
        Self { config, server }
    }
}

#[async_trait]
impl ClientTransport for WrtcTransport {
    async fn connect(&self) -> Result<ConnectionResult> {
        let (domain, room_name) = self.server.wrtc_room()?;
        info!("[WRTC] Connecting to Ktalk room '{}' at domain '{}'...", room_name, domain);

        // 1. Authorize session in Ktalk REST API
        let ktalk = KtalkClient::new();
        let anon_secret = KtalkClient::generate_anonymous_secret();
        info!("[WRTC] Authorizing anonymous session (secret: {})...", anon_secret);
        let auth_res = ktalk
            .authorize_session(&domain, &room_name, "ANet-Node", &anon_secret)
            .await
            .context("Failed to authorize Ktalk session")?;
        info!(
            "[WRTC] Ktalk session authorized. Token: {} (expires in: {:?}s)",
            auth_res.token,
            auth_res.expires_in
        );

        // 2. Resolve room name into conferenceId
        info!("[WRTC] Resolving conference room ID for '{}'...", room_name);
        let room_info = ktalk
            .resolve_room(&domain, &room_name, &auth_res.token)
            .await
            .context("Failed to resolve Ktalk room")?;
        info!(
            "[WRTC] Conference ID resolved: {} (allowAnonymous: {:?})",
            room_info.conference_id,
            room_info.allow_anonymous
        );

        // 3. XMPP Signaling: Connect WebSocket, SASL ANONYMOUS, join MUC
        info!(
            "[WRTC] Connecting XMPP signaling WebSocket to room {}...",
            room_info.conference_id
        );
        let mut xmpp = XmppSession::connect(
            &domain,
            &room_info.conference_id,
            &auth_res.token,
            "ANet-Node",
        )
        .await
        .context("Failed to establish XMPP session and join conference MUC")?;
        info!(
            "[WRTC] Successfully joined conference MUC as occupant: {}",
            xmpp.endpoint_id
        );

        // 4. Discovery Phase: probe for ANet server
        let client_nonce = format!("{:016x}", rand::random::<u64>());
        info!(
            "[WRTC] Starting server discovery in room. Client nonce: {}",
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

        while tokio::time::Instant::now() < deadline {
            tokio::select! {
                _ = interval.tick() => {
                    info!(
                        "[WRTC] Broadcasting anet_discover (nonce: {}), probing for server presence...",
                        client_nonce
                    );
                    let discover_msg = ColibriMessage::discover(client_nonce.clone());
                    if let Ok(json_str) = serde_json::to_string(&discover_msg) {
                        debug!("[WRTC] Colibri discover payload: {}", json_str);
                        // Forward discovery stanza into MUC channel
                        let broadcast_stanza = format!(
                            r#"<message to="{}@muc.meet.jitsi" type="groupchat"><body>{}</body></message>"#,
                            room_info.conference_id,
                            json_str
                        );
                        let _ = xmpp.send_stanza(broadcast_stanza).await;
                    }
                }
                stanza_opt = xmpp.recv_stanza() => {
                    if let Some(text) = stanza_opt {
                        debug!("[WRTC] Received signaling stanza: {}", text);

                        // Check if this stanza contains an anet_beacon
                        if text.contains("anet_beacon") {
                            if let Some(body_start) = text.find("<body>") {
                                if let Some(body_end) = text[body_start..].find("</body>") {
                                    let json_body = &text[body_start + 6..body_start + body_end];
                                    if let Ok(colibri_msg) = serde_json::from_str::<ColibriMessage>(json_body) {
                                        if let ColibriPayload::Beacon { server_id, client_nonce: beacon_nonce, signature } = colibri_msg.msg_payload {
                                            if beacon_nonce == client_nonce {
                                                info!("[WRTC] Received anet_beacon from server: {}", server_id);

                                                if let Some(pub_key) = server_pub_key {
                                                    match verify_beacon(pub_key, &client_nonce, &server_id, &signature) {
                                                        Ok(true) => {
                                                            info!("[WRTC] Server beacon verified successfully! Server endpoint: {}", server_id);
                                                        }
                                                        Ok(false) => {
                                                            warn!("[WRTC] Beacon signature verification failed for server {}", server_id);
                                                            continue;
                                                        }
                                                        Err(e) => {
                                                            warn!("[WRTC] Error verifying server beacon: {e}");
                                                            continue;
                                                        }
                                                    }
                                                } else {
                                                    info!("[WRTC] No server_pub_key configured to verify signature, accepting server {}", server_id);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        warn!("[WRTC] Signaling connection closed during discovery");
                        break;
                    }
                }
            }
        }

        anyhow::bail!(
            "Server discovery in room '{room_name}' timed out after {timeout_secs}s (no server beacon received)"
        )
    }
}
