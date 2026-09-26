use crate::auth_handler::ServerAuthHandler;
use crate::client_registry::{ClientRegistry, ClientTransportInfo};
use crate::config::Config;
use anet_common::consts::CHANNEL_BUFFER_SIZE;
use anet_common::http_help::BrowserProfile;
use anet_common::transport::{unwrap_packet_bytes_in_place, wrap_packet_padded};
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
use ed25519_dalek::SigningKey;
use log::{debug, info, warn};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};

fn endpoint_to_socket_addr(ep: &str) -> SocketAddr {
    let num = u32::from_str_radix(ep, 16).unwrap_or(0);
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::from(num)), 0)
}

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

    let signing_key = SigningKey::from_bytes(&signing_key_bytes);
    let server_pub_key_b64 = BASE64_STANDARD.encode(signing_key.verifying_key().to_bytes());
    info!(
        "[WRTC Server] Server Public Key (must match client.toml server_pub_key): {server_pub_key_b64}"
    );

    info!(
        "[WRTC Server] Starting worker for Ktalk room '{}' at domain '{}'...",
        room_name, domain
    );

    loop {
        let browser_profile = BrowserProfile::random();
        let guest_name = generate_random_guest_name();

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

        let fallback_ip = &config.server.wrtc_fallback_jvb_ip;
        let fallback_port = config.server.wrtc_fallback_jvb_port;

        let mut parsed_session = None;
        let jingle_deadline = tokio::time::Instant::now() + Duration::from_secs(3);

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

        if parsed_session.is_none() {
            info!("[WRTC Server] Using fallback JVB: {fallback_ip}:{fallback_port}");
        }

        let audio_keepalive_ms = config.server.wrtc_media_keepalive_interval_ms;
        let peer = match WrtcPeer::create(
            parsed_session.as_ref(),
            &domain,
            fallback_ip,
            fallback_port,
            audio_keepalive_ms,
        )
            .await
        {
            Ok(p) => p,
            Err(e) => {
                warn!("[WRTC Server] Failed to initialize WebRTC Peer: {e:#}. Retrying in 5s...");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        info!("[WRTC Server] WebRTC connection active. Waiting for clients...");

        let shared_peer = Arc::new(Mutex::new(peer));
        let active_clients: Arc<DashMap<String, Arc<ClientTransportInfo>>> =
            Arc::new(DashMap::new());

        let p_clone = shared_peer.clone();
        let reg_clone = registry.clone();
        let auth_clone = auth_handler.clone();
        let tun_clone = tun_tx.clone();
        let clients_map = active_clients.clone();
        let srv_id = server_endpoint_id.clone();
        let padding_step = config.stealth.padding_step;

        loop {
            let msg_opt = {
                let mut p = p_clone.lock().await;
                p.recv().await
            };

            let Some(msg) = msg_opt else {
                warn!("[WRTC Server] Connection closed (room expired or connection reset).");
                break;
            };

            let from_endpoint = msg.from.clone().unwrap_or_default();
            if from_endpoint.is_empty() || from_endpoint == srv_id {
                continue;
            }

            match msg.msg_payload {
                WrtcMessage::Discover { client_nonce } => {
                    info!(
                        "[WRTC Server] Received anet_discover from client {from_endpoint} (nonce: {client_nonce})! Answering beacon..."
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
                            if let Ok(packet) = unwrap_packet_bytes_in_place(
                                &client_info.cipher,
                                Bytes::from(raw_bytes),
                            ) {
                                let packet_len = packet.len();
                                if let Ok(_) = tun_clone.try_send(packet) {
                                    reg_clone.record_rx(&client_info, packet_len, "wrtc");
                                }
                            }
                        } else {
                            let client_addr = endpoint_to_socket_addr(&from_endpoint);
                            match auth_clone
                                .process_handshake_packet(Bytes::from(raw_bytes), client_addr, "wrtc")
                                .await
                            {
                                Ok((response, result)) => {
                                    if let Some(resp_bytes) = response {
                                        let b64 = BASE64_STANDARD.encode(&resp_bytes);
                                        let resp_msg =
                                            ColibriMessage::astp(from_endpoint.clone(), b64);
                                        let p = p_clone.lock().await;
                                        let _ = p.send(resp_msg).await;
                                    }

                                    if let Some((client_info, _)) = result {
                                        let assigned_ip = client_info.assigned_ip.clone();
                                        info!(
                                            "[WRTC Server] Client {from_endpoint} authenticated! Assigned IP: {assigned_ip}"
                                        );

                                        let (tx_router, mut rx_router) =
                                            mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
                                        reg_clone.finalize_client(&assigned_ip, tx_router);
                                        clients_map
                                            .insert(from_endpoint.clone(), client_info.clone());

                                        let target_client_id = from_endpoint.clone();
                                        let c_info = client_info.clone();
                                        let peer_downlink = p_clone.clone();

                                        tokio::spawn(async move {
                                            while let Some(packet) = rx_router.recv().await {
                                                if packet.len() < 20 {
                                                    continue;
                                                }
                                                let seq = c_info
                                                    .sequence
                                                    .fetch_add(1, Ordering::Relaxed);
                                                if let Ok(encrypted) = wrap_packet_padded(
                                                    &c_info.cipher,
                                                    &c_info.nonce_prefix,
                                                    seq,
                                                    packet,
                                                    padding_step,
                                                ) {
                                                    let b64 = BASE64_STANDARD.encode(&encrypted);
                                                    let msg = ColibriMessage::astp(
                                                        target_client_id.clone(),
                                                        b64,
                                                    );
                                                    let p = peer_downlink.lock().await;
                                                    if p.send(msg).await.is_err() {
                                                        break;
                                                    }
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

        for entry in active_clients.iter() {
            registry.suspend_client(entry.value().clone());
        }
        active_clients.clear();

        info!("[WRTC Server] Pausing 2s before re-entering conference room...");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}