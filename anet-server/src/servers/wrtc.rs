use crate::auth_handler::ServerAuthHandler;
use crate::client_registry::{ClientRegistry, ClientTransportInfo};
use crate::config::Config;
use anet_common::consts::{CHANNEL_BUFFER_SIZE, MAX_PACKET_SIZE};
use anet_common::http_help::BrowserProfile;
use anet_common::wrtc::{
    colibri::{sign_beacon, ColibriMessage, WrtcMessage},
    jingle::parse_jingle_session,
    ktalk::KtalkClient,
    peer::WrtcPeer,
    stealth::generate_random_guest_name,
    xmpp::XmppSession,
};
use anyhow::{Context, Result};
use base64::prelude::*;
use bytes::Bytes;
use dashmap::DashMap;
use log::{debug, error, info, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};

pub async fn run_wrtc_server(
    config: Arc<Config>,
    registry: Arc<ClientRegistry>,
    tun_tx: mpsc::Sender<Bytes>,
    auth_handler: ServerAuthHandler,
) -> Result<()> {
    let wrtc_room_url = config
        .server
        .wrtc_room_url
        .as_ref()
        .context("WRTC room URL is not configured")?;

    let parsed_url: http::Uri = wrtc_room_url.parse()?;
    let domain = parsed_url
        .host()
        .context("WRTC room URL has no host")?
        .to_string();
    let room_name = parsed_url.path().trim_start_matches('/').to_string();

    let signing_key_bytes: [u8; 32] = BASE64_STANDARD
        .decode(&config.crypto.server_signing_key)?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid server_signing_key length (expected 32 bytes)"))?;

    info!(
        "[WRTC Server] Starting server worker for Ktalk room '{}' at domain '{}'...",
        room_name, domain
    );

    // Continuous reconnection loop (handles Ktalk 40-minute conference limit)
    loop {
        let browser_profile = BrowserProfile::random();
        let guest_name = generate_random_guest_name();

        info!(
            "[WRTC Server] Authorizing guest session in Ktalk as '{}'...",
            guest_name
        );

        let ktalk = KtalkClient::new(browser_profile.clone());
        let anon_secret = KtalkClient::generate_anonymous_secret();

        let auth_res = match ktalk
            .authorize_session(&domain, &room_name, Some(&guest_name), &anon_secret)
            .await
        {
            Ok(res) => res,
            Err(e) => {
                warn!("[WRTC Server] Ktalk authorization failed: {e}. Retrying in 5s...");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        let room_info = match ktalk.resolve_room(&domain, &room_name, &auth_res.token).await {
            Ok(info) => info,
            Err(e) => {
                warn!("[WRTC Server] Resolving room failed: {e}. Retrying in 5s...");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        info!(
            "[WRTC Server] Resolved conference ID: {}. Connecting XMPP signaling WebSocket...",
            room_info.conference_id
        );

        let ping_secs = config.server.wrtc_ping_interval_secs;
        let mut xmpp = match XmppSession::connect(
            &domain,
            &room_info.conference_id,
            &auth_res.token,
            Some(&guest_name),
            &browser_profile,
            ping_secs,
        )
        .await
        {
            Ok(session) => session,
            Err(e) => {
                warn!("[WRTC Server] XMPP connection failed: {e}. Retrying in 5s...");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        let server_endpoint_id = xmpp.endpoint_id.clone();
        info!(
            "[WRTC Server] Joined room as server occupant: {}",
            server_endpoint_id
        );

        // Jicofo allocation & Jingle negotiation
        let _ = xmpp.request_conference_allocation().await;

        let fallback_ip = &config.server.wrtc_fallback_jvb_ip;
        let fallback_port = config.server.wrtc_fallback_jvb_port;

        let mut parsed_candidates = Vec::new();
        let jingle_deadline = tokio::time::Instant::now() + Duration::from_secs(3);

        while tokio::time::Instant::now() < jingle_deadline {
            if let Ok(Some(stanza)) = tokio::time::timeout(Duration::from_millis(500), xmpp.recv_stanza()).await {
                if let Some(session) = parse_jingle_session(&stanza, fallback_ip, fallback_port) {
                    debug!(
                        "[WRTC Server] Extracted {} dynamic candidates from Jingle offer",
                        session.transport.candidates.len()
                    );
                    parsed_candidates = session.transport.candidates;
                    break;
                }
            }
        }

        let audio_keepalive_ms = config.server.wrtc_media_keepalive_interval_ms;
        let peer = match WrtcPeer::create(
            &parsed_candidates,
            fallback_ip,
            fallback_port,
            audio_keepalive_ms,
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                warn!("[WRTC Server] Failed to initialize WebRTC Peer: {e}. Retrying in 5s...");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        info!("[WRTC Server] WebRTC PeerConnection and DataChannel active. Standing by for clients...");

        let shared_peer = Arc::new(Mutex::new(peer));
        let active_clients: Arc<DashMap<String, Arc<ClientTransportInfo>>> = Arc::new(DashMap::new());

        // Read loop from DataChannel
        let p_clone = shared_peer.clone();
        let reg_clone = registry.clone();
        let auth_clone = auth_handler.clone();
        let tun_clone = tun_tx.clone();
        let clients_map = active_clients.clone();
        let srv_id = server_endpoint_id.clone();

        loop {
            let msg_opt = {
                let mut p = p_clone.lock().await;
                p.recv().await
            };

            let Some(msg) = msg_opt else {
                warn!("[WRTC Server] DataChannel closed (room expired or disconnected). Initiating reconnection...");
                break;
            };

            let from_endpoint = msg.from.clone().unwrap_or_default();
            if from_endpoint.is_empty() || from_endpoint == srv_id {
                continue;
            }

            match msg.msg_payload {
                WrtcMessage::Discover { client_nonce } => {
                    info!(
                        "[WRTC Server] Received anet_discover from client {} (nonce: {}). Answering beacon...",
                        from_endpoint, client_nonce
                    );
                    let signature = sign_beacon(&signing_key_bytes, &client_nonce, &srv_id);
                    let beacon_msg = ColibriMessage::beacon(
                        from_endpoint.clone(),
                        srv_id.clone(),
                        client_nonce,
                        signature,
                    );
                    let p = p_clone.lock().await;
                    let _ = p.send(beacon_msg).await;
                }
                WrtcMessage::Astp { data } => {
                    if let Ok(raw_bytes) = BASE64_STANDARD.decode(&data) {
                        if let Some(client_info) = clients_map.get(&from_endpoint) {
                            // Established session: decrypt and send to TUN
                            if let Ok(plaintext) = client_info.cipher.decrypt(&raw_bytes) {
                                let packet_len = plaintext.len();
                                if let Ok(_) = tun_clone.try_send(Bytes::from(plaintext)) {
                                    reg_clone.record_rx(&client_info, packet_len, "wrtc");
                                }
                            }
                        } else {
                            // Handshake phase
                            let dummy_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
                            match auth_clone
                                .process_handshake_packet(Bytes::from(raw_bytes), dummy_addr, "wrtc")
                                .await
                            {
                                Ok((response, result)) => {
                                    if let Some(resp_bytes) = response {
                                        let b64 = BASE64_STANDARD.encode(&resp_bytes);
                                        let resp_msg = ColibriMessage::astp(from_endpoint.clone(), b64);
                                        let p = p_clone.lock().await;
                                        let _ = p.send(resp_msg).await;
                                    }

                                    if let Some((client_info, _)) = result {
                                        let assigned_ip = client_info.assigned_ip.clone();
                                        info!(
                                            "[WRTC Server] Handshake completed for client {}! Assigned IP: {}",
                                            from_endpoint, assigned_ip
                                        );

                                        let (tx_router, mut rx_router) =
                                            mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
                                        reg_clone.finalize_client(&assigned_ip, tx_router);
                                        clients_map.insert(from_endpoint.clone(), client_info.clone());

                                        // Spawn downlink forwarder task (TUN -> DataChannel)
                                        let target_client_id = from_endpoint.clone();
                                        let client_cipher = client_info.cipher.clone();
                                        let peer_downlink = p_clone.clone();

                                        tokio::spawn(async move {
                                            while let Some(packet) = rx_router.recv().await {
                                                let encrypted = client_cipher.encrypt(&packet);
                                                let b64 = BASE64_STANDARD.encode(&encrypted);
                                                let msg = ColibriMessage::astp(
                                                    target_client_id.clone(),
                                                    b64,
                                                );
                                                let p = peer_downlink.lock().await;
                                                if let Err(e) = p.send(msg).await {
                                                    debug!("[WRTC Downlink] Send error: {e}");
                                                    break;
                                                }
                                            }
                                        });
                                    }
                                }
                                Err(e) => {
                                    warn!("[WRTC Server] Handshake packet processing error: {e}");
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Suspend all active sessions so they can be smoothly resumed upon reconnection
        for entry in active_clients.iter() {
            registry.suspend_client(entry.value().clone());
        }
        active_clients.clear();

        info!("[WRTC Server] Pausing 2s before re-entering conference room...");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
