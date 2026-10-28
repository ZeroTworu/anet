use crate::auth_handler::ServerAuthHandler;
use crate::client_registry::{ClientRegistry, ClientTransportInfo};
use crate::config::Config;
use anet_common::consts::{
    MAX_PACKET_SIZE, MAX_VIDEO_BATCH_BYTES, VIDEO_BATCH_MARKER, VP8_ASTP_PREFIX_LEN,
    WRTC_BATCHER_MAX_BYTES, WRTC_BATCHER_MAX_DELAY_MS, WRTC_COLIBRI_CHANNEL_CAPACITY,
    WRTC_DEFAULT_MAX_VIDEO_HEIGHT, WRTC_HANDSHAKE_PROCESS_TIMEOUT_SECS,
    WRTC_ICE_GATHER_POLL_ATTEMPTS, WRTC_MIN_ASTP_VIDEO_FRAME_LEN, WRTC_MIN_IP_PACKET_LEN,
    WRTC_MIN_TUN_MTU, WRTC_P2P_ICE_GATHER_POLL_INTERVAL_MS, WRTC_SDP_RENEGOTIATE_TIMEOUT_SECS,
    WRTC_SERVER_RECONNECT_PAUSE_SECS, WRTC_SERVER_RETRY_DELAY_SECS, WRTC_VIDEO_BATCH_MAX_PACKETS,
    WRTC_WATCHDOG_TICK_SECS,
};
use anet_common::http_help::BrowserProfile;
use anet_common::transport::{
    unwrap_packet_bytes, wrap_packet_padded, wrap_packet_slice, wrap_packet_slice_with_headroom,
};
use anet_common::wrtc::{
    batcher::{unpack_batch, PacketBatcher},
    colibri::{generate_server_endpoint_id, sign_beacon, ColibriMessage, WrtcMessage},
    jingle::{filter_p2p_sdp_relay_only, parse_jingle_session},
    ktalk::KtalkClient,
    peer::{create_p2p_channel, P2pSession, WrtcPeer},
    stealth::generate_random_guest_name,
    xmpp::XmppSession,
};
use anyhow::{Context, Result};
use base64::prelude::*;
use bytes::{BufMut, Bytes, BytesMut};
use dashmap::{DashMap, DashSet};
use ed25519_dalek::SigningKey;
use log::{info, warn};
use rtc::peer_connection::sdp::RTCSessionDescription;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

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
        let browser_profile = BrowserProfile::with_tls_config(config.stealth.to_tls_client_config());
        let guest_name = generate_random_guest_name();

        let ktalk = KtalkClient::new(browser_profile.clone(), &config.wrtc)
        .context("Failed to initialize WRTC Ktalk client on server with BoringSSL TLS")?;
        let anon_secret = KtalkClient::generate_anonymous_secret();

        let auth_res = match ktalk
            .authorize_session(&domain, &room_name, Some(&guest_name), &anon_secret)
            .await
        {
            Ok(res) => res,
            Err(e) => {
                warn!(
                    "[WRTC Server] Ktalk authorization failed: {e}. Retrying in {}s...",
                    WRTC_SERVER_RETRY_DELAY_SECS
                );
                tokio::time::sleep(Duration::from_secs(WRTC_SERVER_RETRY_DELAY_SECS)).await;
                continue;
            }
        };

        let room_info = match ktalk.resolve_room(&domain, &room_name, &auth_res.token).await {
            Ok(info) => info,
            Err(e) => {
                warn!(
                    "[WRTC Server] Resolving room failed: {e}. Retrying in {}s...",
                    WRTC_SERVER_RETRY_DELAY_SECS
                );
                tokio::time::sleep(Duration::from_secs(WRTC_SERVER_RETRY_DELAY_SECS)).await;
                continue;
            }
        };

        let ping_secs = config.server.wrtc_ping_interval_secs;
        let pub_key_bytes = signing_key.verifying_key().to_bytes();
        let deterministic_ep =
            generate_server_endpoint_id(&pub_key_bytes, &room_info.conference_id);
        let mut xmpp = match XmppSession::connect_with_endpoint(
            &domain,
            &room_info.conference_id,
            &auth_res.token,
            Some(&guest_name),
            Some(deterministic_ep),
            &browser_profile,
            ping_secs,
            &config.wrtc,
        )
            .await
        {
            Ok(session) => session,
            Err(e) => {
                warn!(
                    "[WRTC Server] XMPP connection failed: {e}. Retrying in {}s...",
                    WRTC_SERVER_RETRY_DELAY_SECS
                );
                tokio::time::sleep(Duration::from_secs(WRTC_SERVER_RETRY_DELAY_SECS)).await;
                continue;
            }
        };

        let server_endpoint_id = xmpp.endpoint_id.clone();
        info!(
            "[WRTC Server] Joined room as deterministic server occupant: {}",
            server_endpoint_id
        );

        let fallback_ip = &config.server.wrtc_fallback_jvb_ip;
        let fallback_port = config.server.wrtc_fallback_jvb_port;

        let _ = xmpp.request_conference_allocation().await;

        info!("[WRTC Server] Waiting for Jicofo session-initiate (client arrival)...");
        let mut parsed_session = None;
        let idle_rotation_secs = config.wrtc.server_idle_room_rotation_secs.max(60);
        let idle_deadline = tokio::time::Instant::now() + Duration::from_secs(idle_rotation_secs);

        loop {
            match tokio::time::timeout_at(idle_deadline, xmpp.recv_stanza()).await {
                Ok(Some(stanza)) => {
                    if let Some(session) = parse_jingle_session(&stanza, fallback_ip, fallback_port) {
                        parsed_session = Some(session);
                        break;
                    }
                }
                Ok(None) => {
                    warn!(
                        "[WRTC Server] XMPP stream closed while waiting for session-initiate. Reconnecting in {}s...",
                        WRTC_SERVER_RECONNECT_PAUSE_SECS
                    );
                    break;
                }
                Err(_) => {
                    info!(
                        "[WRTC Server] No client joined for {}s; rotating server room session...",
                        idle_rotation_secs
                    );
                    break;
                }
            }
        }

        let Some(session) = parsed_session else {
            xmpp.leave_room().await;
            tokio::time::sleep(Duration::from_secs(WRTC_SERVER_RECONNECT_PAUSE_SECS)).await;
            continue;
        };

        let server_mode = config.server.wrtc_transport_mode();
        let audio_keepalive_ms = config.server.wrtc_media_keepalive_interval_ms;
        let peer = match WrtcPeer::create(
            Some(&session),
            Some(&xmpp),
            fallback_ip,
            fallback_port,
            audio_keepalive_ms,
            server_mode,
            &config.wrtc,
        )
            .await
        {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    "[WRTC Server] Failed to initialize WebRTC Peer: {e:#}. Retrying in {}s...",
                    WRTC_SERVER_RECONNECT_PAUSE_SECS
                );
                xmpp.leave_room().await;
                tokio::time::sleep(Duration::from_secs(WRTC_SERVER_RECONNECT_PAUSE_SECS)).await;
                continue;
            }
        };

        info!(
            "[WRTC Server] WebRTC Peer ICE configuration: {} | Local candidates: {:?}",
            peer.ice_tier_summary, peer.local_candidates_summary
        );
        info!("[WRTC Server] WebRTC connection active. Waiting for clients...");

        let shared_peer = Arc::new(peer);
        let active_clients: Arc<DashMap<String, Arc<ClientTransportInfo>>> =
            Arc::new(DashMap::new());
        let clients_by_tag: Arc<DashMap<u16, Arc<ClientTransportInfo>>> =
            Arc::new(DashMap::new());
        let p2p_clients: Arc<DashMap<String, Arc<P2pSession>>> =
            Arc::new(DashMap::new());
        let client_modes: Arc<DashMap<String, String>> =
            Arc::new(DashMap::new());
        let client_video_endpoints: Arc<DashSet<String>> =
            Arc::new(DashSet::new());
        let client_v2_endpoints: Arc<DashSet<String>> =
            Arc::new(DashSet::new());
        let known_client_video_ssrcs: Arc<DashSet<u32>> =
            Arc::new(DashSet::new());

        let reg_clone = registry.clone();
        let auth_clone = auth_handler.clone();
        let tun_clone = tun_tx.clone();
        let clients_map = active_clients.clone();
        let srv_id = server_endpoint_id.clone();
        let padding_step = config.stealth.padding_step;

        // Воркер Uplink из Fake Video Track (VP8 over DTLS-SRTP / JVB)
        let peer_video_rx = shared_peer.clone();
        let clients_by_tag_rx = clients_by_tag.clone();
        let tun_clone_video = tun_clone.clone();
        let reg_clone_video = reg_clone.clone();

        let client_video_warmed_up: Arc<DashSet<u16>> = Arc::new(DashSet::new());
        let client_video_warmed_rx = client_video_warmed_up.clone();
        let client_last_video_rx_ms: Arc<DashMap<u16, u64>> = Arc::new(DashMap::new());
        let client_last_video_rx_rx = client_last_video_rx_ms.clone();
        let video_uplink_task = tokio::spawn(async move {
            while let Some(first_frame) = peer_video_rx.recv_video_frame().await {
                let mut current_frame = Some(first_frame);
                while let Some(raw_frame) = current_frame.take() {
                    if raw_frame.len() < WRTC_MIN_ASTP_VIDEO_FRAME_LEN {
                        // Слишком короткий для ASTP кадра (2B tag + 12B nonce + 20B IPv4 + 16B MAC)
                        current_frame = peer_video_rx.try_recv_video_frame();
                        continue;
                    }
                    let client_tag = u16::from_be_bytes([raw_frame[0], raw_frame[1]]);
                    let Some(client_info) = clients_by_tag_rx.get(&client_tag) else {
                        current_frame = peer_video_rx.try_recv_video_frame();
                        continue;
                    };

                    let raw_astp = raw_frame.slice(2..);
                    if let Ok(decrypted) = unwrap_packet_bytes(&client_info.cipher, raw_astp) {
                        let now_ms = peer_video_rx.start_instant.elapsed().as_millis() as u64;
                        client_last_video_rx_rx.insert(client_tag, now_ms);
                        if client_video_warmed_rx.insert(client_tag) {
                            peer_video_rx.force_next_keyframe();
                            info!(
                                "[WRTC Server Video IN] First video frame decrypted from client {} (len: {} bytes, tag: 0x{:04X})",
                                client_info.assigned_ip,
                                decrypted.len(),
                                client_tag
                            );
                        }
                        if decrypted.first() == Some(&VIDEO_BATCH_MARKER) {
                            for sub_pkt in unpack_batch(&decrypted[1..]) {
                                let pkt_len = sub_pkt.len();
                                if pkt_len >= WRTC_MIN_IP_PACKET_LEN {
                                    if let Some(reply) =
                                        anet_common::icmp_probe::handle_in_tunnel_icmp_probe(&sub_pkt)
                                    {
                                        let seq = client_info
                                            .sequence
                                            .fetch_add(1, Ordering::Relaxed);
                                        if let Ok(enc_buf) = wrap_packet_slice_with_headroom(
                                            &client_info.cipher,
                                            &client_info.nonce_prefix,
                                            seq,
                                            &reply,
                                            VP8_ASTP_PREFIX_LEN,
                                        ) {
                                            let _ = peer_video_rx
                                                .send_video_frame_preallocated(client_tag, enc_buf)
                                                .await;
                                        }
                                        continue;
                                    }
                                    if tun_clone_video.try_send(sub_pkt).is_ok() {
                                        reg_clone_video.record_rx(client_info.value(), pkt_len, "wrtc_video");
                                    } else {
                                        break;
                                    }
                                }
                            }
                        } else if decrypted.len() >= WRTC_MIN_IP_PACKET_LEN {
                            if let Some(reply) =
                                anet_common::icmp_probe::handle_in_tunnel_icmp_probe(&decrypted)
                            {
                                let seq = client_info
                                    .sequence
                                    .fetch_add(1, Ordering::Relaxed);
                                if let Ok(enc_buf) = wrap_packet_slice_with_headroom(
                                    &client_info.cipher,
                                    &client_info.nonce_prefix,
                                    seq,
                                    &reply,
                                    VP8_ASTP_PREFIX_LEN,
                                ) {
                                    let _ = peer_video_rx
                                        .send_video_frame_preallocated(client_tag, enc_buf)
                                        .await;
                                }
                            } else {
                                let packet_len = decrypted.len();
                                if tun_clone_video.try_send(decrypted).is_ok() {
                                    reg_clone_video.record_rx(client_info.value(), packet_len, "wrtc_video");
                                }
                            }
                        }
                    }
                    current_frame = peer_video_rx.try_recv_video_frame();
                }
            }
        });

        let mut health_watchdog =
            tokio::time::interval(Duration::from_secs(WRTC_WATCHDOG_TICK_SECS));
        health_watchdog.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            let msg_opt = tokio::select! {
                res = shared_peer.recv() => res,
                stanza_opt = xmpp.recv_stanza() => {
                    let Some(stanza) = stanza_opt else {
                        warn!("[WRTC Server] XMPP signaling WebSocket closed. Re-establishing server session...");
                        break;
                    };
                    let mut self_removed = false;
                    for parsed in anet_common::wrtc::xmpp_xml::parse_xmpp_stanzas(&stanza, fallback_ip, fallback_port) {
                        match parsed {
                            anet_common::wrtc::xmpp_xml::InboundXmpp::Jingle(jingle) => {
                                if jingle.action == "session-terminate" {
                                    info!(
                                        "[WRTC Server] Jicofo terminated Jingle session {} (reason: {:?}). Rotating server room session...",
                                        jingle.sid, jingle.reason
                                    );
                                    self_removed = true;
                                } else if jingle.action == "source-add"
                                    || jingle.action == "description-info"
                                    || jingle.action == "session-initiate"
                                {
                                    for v_ssrc in jingle.video_sources {
                                        if known_client_video_ssrcs.contains(&v_ssrc) {
                                            info!("[WRTC Server] Jingle stanza ({}) announced authorized client video SSRC: {v_ssrc}", jingle.action);
                                            let _ = tokio::time::timeout(
                                                Duration::from_secs(WRTC_SDP_RENEGOTIATE_TIMEOUT_SECS),
                                                shared_peer.add_remote_video_ssrc(v_ssrc),
                                            ).await;
                                        } else {
                                            log::debug!("[WRTC Server] Ignoring Jingle ({}) SSRC {v_ssrc} from non-ANET room occupant", jingle.action);
                                        }
                                    }
                                }
                            }
                            anet_common::wrtc::xmpp_xml::InboundXmpp::ExtdiscoServices(fresh_ice) => {
                                shared_peer.rotate_turn_credentials(&fresh_ice).await;
                                let p2p_list: Vec<Arc<P2pSession>> = p2p_clients
                                    .iter()
                                    .map(|e| e.value().clone())
                                    .collect();
                                for p2p in p2p_list {
                                    p2p.rotate_turn_credentials(&fresh_ice).await;
                                }
                            }
                            anet_common::wrtc::xmpp_xml::InboundXmpp::Presence { from, is_unavailable: true, .. } => {
                                if let Some(occupant_id) = from.split('/').nth(1) {
                                    if occupant_id == srv_id {
                                        warn!("[WRTC Server] Server occupant {srv_id} was removed from MUC room. Re-establishing server session...");
                                        self_removed = true;
                                    } else if occupant_id != "focus" {
                                        client_modes.remove(occupant_id);
                                        let removed_video_ep = client_video_endpoints.remove(occupant_id).is_some();
                                        client_v2_endpoints.remove(occupant_id);
                                        if let Some((_, old_p2p)) = p2p_clients.remove(occupant_id) {
                                            old_p2p.close().await;
                                        }
                                        if removed_video_ep {
                                            let video_eps: Vec<String> = client_video_endpoints
                                                .iter()
                                                .map(|e| e.key().clone())
                                                .collect();
                                            let constraints = anet_common::wrtc::colibri::ReceiverVideoConstraints::for_endpoints(
                                                &video_eps,
                                                WRTC_DEFAULT_MAX_VIDEO_HEIGHT,
                                            );
                                            let _ = shared_peer.send_video_constraints(&constraints).await;
                                        }
                                        if let Some((_, dead_client)) = clients_map.remove(occupant_id) {
                                            info!(
                                                "[WRTC Server] Occupant {occupant_id} left MUC room. Removing session {} (IP: {}) immediately.",
                                                dead_client.session_id, dead_client.assigned_ip
                                            );
                                            let old_tag = anet_common::wrtc::colibri::client_tag_from_ip(&dead_client.assigned_ip);
                                            clients_by_tag.remove(&old_tag);
                                            client_video_warmed_up.remove(&old_tag);
                                            reg_clone.remove_client(&dead_client).await;
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    if self_removed {
                        break;
                    }
                    continue;
                }
                _ = shared_peer.failed_notify.notified() => {
                    warn!("[WRTC Server] WebRTC PeerConnection failed/closed by JVB. Re-establishing server session...");
                    break;
                }
                _ = health_watchdog.tick() => {
                    if let Some(reason) = shared_peer.check_dead_reason() {
                        warn!("[WRTC Server] Watchdog detected dead session ({reason}). Re-establishing server session...");
                        break;
                    }
                    continue;
                }
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
                WrtcMessage::Discover { client_nonce, video_ssrc, mode, video_v2 } => {
                    let pref_mode = mode.unwrap_or_else(|| {
                        if video_ssrc.is_some() {
                            "media_video".to_string()
                        } else {
                            "ws".to_string()
                        }
                    });
                    info!(
                        "[WRTC Server] Received anet_discover from client {from_endpoint} (nonce: {client_nonce}, mode: {pref_mode}, video_ssrc: {video_ssrc:?}, video_v2: {video_v2:?})! Answering beacon..."
                    );
                    client_modes.insert(from_endpoint.clone(), pref_mode.clone());
                    if video_v2.unwrap_or(false) {
                        client_v2_endpoints.insert(from_endpoint.clone());
                        shared_peer.set_video_v2(true);
                    }

                    if let Some(c_v_ssrc) = video_ssrc {
                        if matches!(pref_mode.as_str(), "media_video" | "auto") {
                            known_client_video_ssrcs.insert(c_v_ssrc);
                            shared_peer.set_expected_peer_video_ssrc(c_v_ssrc);
                            info!("[WRTC Server] Set expected client video SSRC: {c_v_ssrc} for {from_endpoint}");

                            // Привязываем видео SSRC клиента к выделенному Recvonly трансиверу
                            let _ = tokio::time::timeout(
                                Duration::from_secs(WRTC_SDP_RENEGOTIATE_TIMEOUT_SECS),
                                shared_peer.add_remote_video_ssrc(c_v_ssrc),
                            ).await;

                            client_video_endpoints.insert(from_endpoint.clone());
                            let video_eps: Vec<String> = client_video_endpoints
                                .iter()
                                .map(|e| e.key().clone())
                                .collect();
                            let constraints =
                                anet_common::wrtc::colibri::ReceiverVideoConstraints::for_endpoints(
                                    &video_eps,
                                    WRTC_DEFAULT_MAX_VIDEO_HEIGHT,
                                );
                            let _ = shared_peer.send_video_constraints(&constraints).await;
                        }
                    }
                    shared_peer.force_next_keyframe();
                    let signature = sign_beacon(&signing_key_bytes, &client_nonce, &srv_id);
                    let beacon_msg = ColibriMessage::beacon(
                        from_endpoint.clone(),
                        srv_id.clone(),
                        client_nonce,
                        signature,
                        Some(shared_peer.video_ssrc),
                    );
                    let _ = shared_peer.send(beacon_msg).await;
                }
                WrtcMessage::Ping => {
                    if let Some(client_info) = clients_map.get(&from_endpoint) {
                        // Отвечаем pong только если сессия клиента реально активна в реестре.
                        // Если сессия была выселена таймером неактивности или удалена,
                        // не шлем pong, чтобы клиент своевременно распознал обрыв и выполнил чистый реконнект.
                        if reg_clone.is_session_active(&client_info.session_id) {
                            client_info.last_activity.store(
                                std::time::SystemTime::now()
                                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                                Ordering::Relaxed,
                            );
                            let pong_msg = ColibriMessage::pong(from_endpoint.clone());
                            let _ = shared_peer.send(pong_msg).await;
                        } else {
                            warn!(
                                "[WRTC Server] Ping from {from_endpoint} dropped: session {} already evicted",
                                client_info.session_id
                            );
                        }
                    }
                }
                WrtcMessage::Pong => {
                    // Pongs от клиентов можно игнорировать
                }
                WrtcMessage::Astp { data } => {
                    match BASE64_STANDARD.decode(&data) {
                        Ok(raw_bytes) => {
                            let mut client_found = false;
                            if let Some(client_info) = clients_map.get(&from_endpoint) {
                                if reg_clone.get_by_session(&client_info.session_id).is_some() {
                                    client_found = true;
                                    match unwrap_packet_bytes(
                                        &client_info.cipher,
                                        Bytes::from(raw_bytes.clone()),
                                    ) {
                                        Ok(packet) => {
                                            if packet.first() == Some(&VIDEO_BATCH_MARKER) {
                                                let inner_pkts = unpack_batch(&packet[1..]);
                                                for pkt in inner_pkts {
                                                    if pkt.len() < WRTC_MIN_IP_PACKET_LEN {
                                                        continue;
                                                    }
                                                    if let Some(reply) =
                                                        anet_common::icmp_probe::handle_in_tunnel_icmp_probe(&pkt)
                                                    {
                                                        let seq = client_info
                                                            .sequence
                                                            .fetch_add(1, Ordering::Relaxed);
                                                        if let Ok(enc_reply) = wrap_packet_slice(
                                                            &client_info.cipher,
                                                            &client_info.nonce_prefix,
                                                            seq,
                                                            &reply,
                                                            0,
                                                        ) {
                                                            let b64 = BASE64_STANDARD.encode(&enc_reply);
                                                            let msg = ColibriMessage::astp(
                                                                from_endpoint.clone(),
                                                                b64,
                                                            );
                                                            let _ = shared_peer.send(msg).await;
                                                        }
                                                    } else {
                                                        let packet_len = pkt.len();
                                                        if tun_clone.try_send(pkt).is_ok() {
                                                            reg_clone.record_rx(&client_info, packet_len, "wrtc");
                                                        }
                                                    }
                                                }
                                            } else if let Some(reply) =
                                                anet_common::icmp_probe::handle_in_tunnel_icmp_probe(&packet)
                                            {
                                                let seq = client_info
                                                    .sequence
                                                    .fetch_add(1, Ordering::Relaxed);
                                                if let Ok(enc_reply) = wrap_packet_slice(
                                                    &client_info.cipher,
                                                    &client_info.nonce_prefix,
                                                    seq,
                                                    &reply,
                                                    0,
                                                ) {
                                                    let b64 = BASE64_STANDARD.encode(&enc_reply);
                                                    let msg = ColibriMessage::astp(
                                                        from_endpoint.clone(),
                                                        b64,
                                                    );
                                                    let _ = shared_peer.send(msg).await;
                                                }
                                            } else {
                                                let packet_len = packet.len();
                                                match tun_clone.try_send(packet) {
                                                    Ok(_) => {
                                                        reg_clone.record_rx(&client_info, packet_len, "wrtc");
                                                        log::debug!("[WRTC Server] Injected {} bytes into TUN for {}", packet_len, client_info.assigned_ip);
                                                    }
                                                    Err(e) => {
                                                        warn!("[WRTC Server] TUN queue error for {}: {e}", client_info.assigned_ip);
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!("[WRTC Server] Decrypt packet failed for {from_endpoint}: {e}");
                                            client_found = false;
                                        }
                                    }
                                } else {
                                    drop(client_info);
                                    clients_map.remove(&from_endpoint);
                                }
                            }

                            if !client_found {
                                let client_addr = endpoint_to_socket_addr(&from_endpoint);
                                let hs_res = tokio::time::timeout(
                                    Duration::from_secs(WRTC_HANDSHAKE_PROCESS_TIMEOUT_SECS),
                                    auth_clone.process_handshake_packet(Bytes::from(raw_bytes), client_addr, "wrtc"),
                                )
                                .await;
                                match hs_res {
                                    Ok(Ok((response, result))) => {
                                        // 1. Сначала финализируем и регистрируем клиента, чтобы быть готовыми к приему трафика
                                        if let Some((client_info, _)) = result {
                                            let assigned_ip = client_info.assigned_ip.clone();
                                            info!(
                                                "[WRTC Server] Client {from_endpoint} authenticated! Assigned IP: {assigned_ip}"
                                            );

                                            // 1. Если этот же MUC occupant (from_endpoint) переаутентифицировался, очищаем его старую сессию
                                            if let Some((_, old_ep_client)) = clients_map.remove(&from_endpoint) {
                                                if old_ep_client.session_id != client_info.session_id {
                                                    let old_tag = anet_common::wrtc::colibri::client_tag_from_ip(&old_ep_client.assigned_ip);
                                                    clients_by_tag.remove(&old_tag);
                                                    client_video_warmed_up.remove(&old_tag);
                                                    reg_clone.remove_client(&old_ep_client).await;
                                                }
                                            }

                                            // 2. Очищаем из локальных таблиц WRTC мёртвые сессии этого fingerprint,
                                            // которые уже были удалены из ClientRegistry (например, по таймауту неактивности в Phase 1),
                                            // не затрагивая живые параллельные сессии.
                                            let stale_eps: Vec<(String, Arc<ClientTransportInfo>)> = clients_map
                                                .iter()
                                                .filter(|entry| {
                                                    entry.value().fingerprint == client_info.fingerprint
                                                        && entry.value().session_id != client_info.session_id
                                                        && !reg_clone.is_session_active(&entry.value().session_id)
                                                })
                                                .map(|entry| (entry.key().clone(), entry.value().clone()))
                                                .collect();
                                            for (ep, stale) in stale_eps {
                                                let old_tag = anet_common::wrtc::colibri::client_tag_from_ip(&stale.assigned_ip);
                                                clients_by_tag.remove(&old_tag);
                                                client_video_warmed_up.remove(&old_tag);
                                                clients_map.remove(&ep);
                                                if let Some((_, old_p2p)) = p2p_clients.remove(&ep) {
                                                    old_p2p.close().await;
                                                }
                                            }

                                            let client_tag = anet_common::wrtc::colibri::client_tag_from_ip(&assigned_ip);
                                            client_video_warmed_up.remove(&client_tag);
                                            clients_by_tag.insert(client_tag, client_info.clone());
                                            shared_peer.force_next_keyframe();

                                            let (tx_router, mut rx_router) =
                                                mpsc::channel::<Bytes>(WRTC_COLIBRI_CHANNEL_CAPACITY);
                                            reg_clone.finalize_client(&assigned_ip, tx_router);
                                            clients_map
                                                .insert(from_endpoint.clone(), client_info.clone());

                                            let target_client_id = from_endpoint.clone();
                                            let c_info = client_info.clone();
                                            let peer_downlink = shared_peer.clone();
                                            let p2p_clients_dl = p2p_clients.clone();
                                            let srv_mode = server_mode;
                                            let client_modes_dl = client_modes.clone();
                                            let client_video_ep_dl = client_video_endpoints.clone();
                                            let client_v2_ep_dl = client_v2_endpoints.clone();
                                            let client_video_warmed_dl = client_video_warmed_up.clone();
                                            let server_tun_mtu = config
                                                .network
                                                .mtu
                                                .saturating_sub(config.wrtc.video_mtu_overhead)
                                                .max(WRTC_MIN_TUN_MTU as u16)
                                                as usize;
                                            let max_video_batch_bytes = server_tun_mtu
                                                .saturating_sub(30)
                                                .min(MAX_VIDEO_BATCH_BYTES);

                                            tokio::spawn(async move {
                                                const VIDEO_WARMUP_PAYLOAD: [u8; 16] = [
                                                    VIDEO_BATCH_MARKER,
                                                    0xFF,
                                                    0xFF,
                                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                ];
                                                let mut batcher = PacketBatcher::new(
                                                    WRTC_BATCHER_MAX_BYTES,
                                                    WRTC_BATCHER_MAX_DELAY_MS,
                                                );
                                                let mut batch_interval = tokio::time::interval(
                                                    Duration::from_millis(WRTC_BATCHER_MAX_DELAY_MS),
                                                );
                                                batch_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                                                let mut warmup_probe_interval = tokio::time::interval(
                                                    Duration::from_secs(2),
                                                );
                                                warmup_probe_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                                                let mut batch_buf = BytesMut::with_capacity(MAX_PACKET_SIZE);
                                                let mut pending_packet: Option<Bytes> = None;

                                                if (srv_mode == anet_common::wrtc::colibri::WrtcMode::MediaVideo
                                                    || srv_mode == anet_common::wrtc::colibri::WrtcMode::Auto)
                                                    && client_video_ep_dl.contains(&target_client_id)
                                                    && client_v2_ep_dl.contains(&target_client_id)
                                                {
                                                    peer_downlink.force_next_keyframe();
                                                    for _ in 0..3 {
                                                        let seq = c_info.sequence.fetch_add(1, Ordering::Relaxed);
                                                        if let Ok(enc_buf) = wrap_packet_slice_with_headroom(
                                                            &c_info.cipher,
                                                            &c_info.nonce_prefix,
                                                            seq,
                                                            &VIDEO_WARMUP_PAYLOAD,
                                                            VP8_ASTP_PREFIX_LEN,
                                                        ) {
                                                            let _ = peer_downlink
                                                                .send_video_frame_preallocated(client_tag, enc_buf)
                                                                .await;
                                                        }
                                                    }
                                                }

                                                loop {
                                                    tokio::select! {
                                                        biased;
                                                        packet_opt = rx_router.recv() => {
                                                            let Some(mut packet) = packet_opt else { break; };

                                                            loop {
                                                                if packet.len() >= WRTC_MIN_IP_PACKET_LEN {
                                                                    let client_pref_mode = client_modes_dl
                                                                        .get(&target_client_id)
                                                                        .map(|m| m.clone())
                                                                        .unwrap_or_else(|| "auto".to_string());
                                                                    let has_video = client_video_ep_dl.contains(&target_client_id);
                                                                    let is_v2 = client_v2_ep_dl.contains(&target_client_id);
                                                                    let video_warmed_up = client_video_warmed_dl.contains(&client_tag);

                                                                    let p2p_session = if client_pref_mode == "p2p_direct" {
                                                                        p2p_clients_dl
                                                                            .get(&target_client_id)
                                                                            .and_then(|entry| {
                                                                                if entry.is_ready() {
                                                                                    Some(entry.value().clone())
                                                                                } else {
                                                                                    None
                                                                                }
                                                                            })
                                                                    } else {
                                                                        None
                                                                    };
                                                                    let p2p_active = p2p_session.is_some();

                                                                    let client_uses_video = !p2p_active
                                                                        && (srv_mode == anet_common::wrtc::colibri::WrtcMode::MediaVideo
                                                                            || srv_mode == anet_common::wrtc::colibri::WrtcMode::Auto)
                                                                        && matches!(client_pref_mode.as_str(), "media_video" | "auto")
                                                                        && has_video;

                                                                    if client_uses_video && is_v2 && packet.len() <= server_tun_mtu {
                                                                        if video_warmed_up && packet.len() + 3 < max_video_batch_bytes {
                                                                            batch_buf.clear();
                                                                            batch_buf.put_u8(VIDEO_BATCH_MARKER);
                                                                            batch_buf.put_u16(packet.len() as u16);
                                                                            batch_buf.extend_from_slice(&packet);
                                                                            let mut count = 1usize;

                                                                            while count < WRTC_VIDEO_BATCH_MAX_PACKETS {
                                                                                let next_p = if let Some(p) = pending_packet.take() {
                                                                                    p
                                                                                } else if let Ok(p) = rx_router.try_recv() {
                                                                                    p
                                                                                } else {
                                                                                    break;
                                                                                };
                                                                                if next_p.len() < WRTC_MIN_IP_PACKET_LEN {
                                                                                    continue;
                                                                                };
                                                                                if batch_buf.len() + 2 + next_p.len() <= max_video_batch_bytes {
                                                                                    batch_buf.put_u16(next_p.len() as u16);
                                                                                    batch_buf.extend_from_slice(&next_p);
                                                                                    count += 1;
                                                                                } else {
                                                                                    pending_packet = Some(next_p);
                                                                                    break;
                                                                                }
                                                                            }

                                                                            let seq = c_info.sequence.fetch_add(1, Ordering::Relaxed);
                                                                            let payload_slice = if count == 1 {
                                                                                &batch_buf[3..]
                                                                            } else {
                                                                                &batch_buf[..]
                                                                            };
                                                                            if let Ok(enc_buf) = wrap_packet_slice_with_headroom(
                                                                                &c_info.cipher,
                                                                                &c_info.nonce_prefix,
                                                                                seq,
                                                                                payload_slice,
                                                                                VP8_ASTP_PREFIX_LEN,
                                                                            ) {
                                                                                let _ = peer_downlink
                                                                                    .send_video_frame_preallocated(client_tag, enc_buf)
                                                                                    .await;
                                                                            }
                                                                        } else {
                                                                            // Одиночный пакет без stealth-паддинга в едином преаллоцированном буфере VP8+ASTP
                                                                            let seq = c_info.sequence.fetch_add(1, Ordering::Relaxed);
                                                                            if let Ok(enc_buf) = wrap_packet_slice_with_headroom(
                                                                                &c_info.cipher,
                                                                                &c_info.nonce_prefix,
                                                                                seq,
                                                                                &packet,
                                                                                VP8_ASTP_PREFIX_LEN,
                                                                            ) {
                                                                                if let Ok(frozen) = peer_downlink
                                                                                    .send_video_frame_preallocated(client_tag, enc_buf)
                                                                                    .await
                                                                                {
                                                                                    if !video_warmed_up {
                                                                                        // До прогрева видео дублируем ASTP-срез в WS батчер без копирования
                                                                                        batcher.push(frozen.slice(VP8_ASTP_PREFIX_LEN..));
                                                                                        if batcher.should_flush() {
                                                                                            if let Some(batch_data) = batcher.flush() {
                                                                                                let b64 = BASE64_STANDARD.encode(&batch_data);
                                                                                                let msg = ColibriMessage::astp_batch(
                                                                                                    target_client_id.clone(),
                                                                                                    b64,
                                                                                                );
                                                                                                if peer_downlink.send(msg).await.is_err() {
                                                                                                    break;
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    } else {
                                                                        if p2p_active && packet.len() + 3 < max_video_batch_bytes {
                                                                            batch_buf.clear();
                                                                            batch_buf.put_u8(VIDEO_BATCH_MARKER);
                                                                            batch_buf.put_u16(packet.len() as u16);
                                                                            batch_buf.extend_from_slice(&packet);
                                                                            let mut count = 1usize;

                                                                            while count < WRTC_VIDEO_BATCH_MAX_PACKETS {
                                                                                let next_p = if let Some(p) = pending_packet.take() {
                                                                                    p
                                                                                } else if let Ok(p) = rx_router.try_recv() {
                                                                                    p
                                                                                } else {
                                                                                    break;
                                                                                };
                                                                                if next_p.len() < WRTC_MIN_IP_PACKET_LEN {
                                                                                    continue;
                                                                                }
                                                                                if batch_buf.len() + 2 + next_p.len() <= max_video_batch_bytes {
                                                                                    batch_buf.put_u16(next_p.len() as u16);
                                                                                    batch_buf.extend_from_slice(&next_p);
                                                                                    count += 1;
                                                                                } else {
                                                                                    pending_packet = Some(next_p);
                                                                                    break;
                                                                                }
                                                                            }

                                                                            let seq = c_info.sequence.fetch_add(1, Ordering::Relaxed);
                                                                            let payload_slice = if count == 1 {
                                                                                &batch_buf[3..]
                                                                            } else {
                                                                                &batch_buf[..]
                                                                            };
                                                                            if let Ok(enc_bytes) = wrap_packet_slice(
                                                                                &c_info.cipher,
                                                                                &c_info.nonce_prefix,
                                                                                seq,
                                                                                payload_slice,
                                                                                0,
                                                                            ) {
                                                                                let mut sent_p2p = false;
                                                                                if let Some(ref p2p_entry) = p2p_session {
                                                                                    if p2p_entry.send_packet(&enc_bytes).await.is_ok() {
                                                                                        sent_p2p = true;
                                                                                    }
                                                                                }
                                                                                if !sent_p2p {
                                                                                    batcher.push(enc_bytes);
                                                                                    if batcher.should_flush() {
                                                                                        if let Some(batch_data) = batcher.flush() {
                                                                                            let b64 = BASE64_STANDARD.encode(&batch_data);
                                                                                            let msg = ColibriMessage::astp_batch(
                                                                                                target_client_id.clone(),
                                                                                                b64,
                                                                                            );
                                                                                            if peer_downlink.send(msg).await.is_err() {
                                                                                                break;
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        } else {
                                                                            let pkt_len = packet.len();
                                                                            let seq = c_info
                                                                                .sequence
                                                                                .fetch_add(1, Ordering::Relaxed);
                                                                            let effective_pad = if p2p_active || client_uses_video { 0 } else { padding_step };
                                                                            if let Ok(encrypted) = wrap_packet_padded(
                                                                                &c_info.cipher,
                                                                                &c_info.nonce_prefix,
                                                                                seq,
                                                                                packet,
                                                                                effective_pad,
                                                                            ) {
                                                                                let enc_bytes = Bytes::from(encrypted);
                                                                                let mut sent = false;

                                                                                // 1. Приоритет №1: Прямой P2P DataChannel с клиентом (для p2p_direct и auto)
                                                                                if let Some(ref p2p_entry) = p2p_session {
                                                                                    if pkt_len <= server_tun_mtu && p2p_entry.send_packet(&enc_bytes).await.is_ok() {
                                                                                        sent = true;
                                                                                    }
                                                                                }

                                                                                // 2. Приоритет №2: Режим MediaVideo (Fake Video Track over DTLS-SRTP / JVB), только если пакет помещается в PMTU
                                                                                if !sent && client_uses_video && pkt_len <= server_tun_mtu {
                                                                                    if peer_downlink.send_video_frame_tagged(client_tag, &enc_bytes).await.is_ok() {
                                                                                        // До подтверждения приема видео от клиента дублируем в WS
                                                                                        if video_warmed_up {
                                                                                            sent = true;
                                                                                        }
                                                                                    } else {
                                                                                        warn!("[WRTC Server Video OUT] send error to {target_client_id}, fallback to WS");
                                                                                    }
                                                                                }

                                                                                // 3. Если P2P и Video не сработали (или пакет > server_tun_mtu / клиент в WS режиме), шлем через батчер (Colibri-WS)
                                                                                if !sent {
                                                                                    batcher.push(enc_bytes);
                                                                                    if batcher.should_flush() {
                                                                                        if let Some(batch_data) = batcher.flush() {
                                                                                            let b64 = BASE64_STANDARD.encode(&batch_data);
                                                                                            let msg = ColibriMessage::astp_batch(
                                                                                                target_client_id.clone(),
                                                                                                b64,
                                                                                            );
                                                                                            if peer_downlink.send(msg).await.is_err() {
                                                                                                break;
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }

                                                                if let Some(next_p) = pending_packet.take() {
                                                                    packet = next_p;
                                                                } else if let Ok(next_p) = rx_router.try_recv() {
                                                                    packet = next_p;
                                                                } else {
                                                                    break;
                                                                }
                                                            }

                                                            // Немедленно отправляем накопленный батч по окончании текущего бурста из rx_router,
                                                            // не дожидаясь срабатывания 3-миллисекундного таймера batch_interval!
                                                            if !batcher.is_empty() {
                                                                if let Some(batch_data) = batcher.flush() {
                                                                    let b64 = BASE64_STANDARD.encode(&batch_data);
                                                                    let msg = ColibriMessage::astp_batch(
                                                                        target_client_id.clone(),
                                                                        b64,
                                                                    );
                                                                    if peer_downlink.send(msg).await.is_err() {
                                                                        break;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        _ = batch_interval.tick(), if !batcher.is_empty() => {
                                                            if let Some(batch_data) = batcher.flush() {
                                                                let b64 = BASE64_STANDARD.encode(&batch_data);
                                                                let msg = ColibriMessage::astp_batch(
                                                                    target_client_id.clone(),
                                                                    b64,
                                                                );
                                                                if peer_downlink.send(msg).await.is_err() {
                                                                    break;
                                                                }
                                                            }
                                                        }
                                                        _ = warmup_probe_interval.tick() => {
                                                            let client_pref_mode = client_modes_dl
                                                                .get(&target_client_id)
                                                                .map(|m| m.clone())
                                                                .unwrap_or_else(|| "auto".to_string());
                                                            let has_video = client_video_ep_dl.contains(&target_client_id);
                                                            let is_v2 = client_v2_ep_dl.contains(&target_client_id);
                                                            if (srv_mode == anet_common::wrtc::colibri::WrtcMode::MediaVideo
                                                                || srv_mode == anet_common::wrtc::colibri::WrtcMode::Auto)
                                                                && matches!(client_pref_mode.as_str(), "media_video" | "auto")
                                                                && has_video
                                                                && is_v2
                                                            {
                                                                let seq = c_info.sequence.fetch_add(1, Ordering::Relaxed);
                                                                if let Ok(enc_buf) = wrap_packet_slice_with_headroom(
                                                                    &c_info.cipher,
                                                                    &c_info.nonce_prefix,
                                                                    seq,
                                                                    &VIDEO_WARMUP_PAYLOAD,
                                                                    VP8_ASTP_PREFIX_LEN,
                                                                ) {
                                                                    let _ = peer_downlink
                                                                        .send_video_frame_preallocated(client_tag, enc_buf)
                                                                        .await;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            });
                                        }

                                        // 2. Затем отправляем финальный ответ хэндшейка клиенту
                                        if let Some(resp_bytes) = response {
                                            let b64 = BASE64_STANDARD.encode(&resp_bytes);
                                            let resp_msg =
                                                ColibriMessage::astp(from_endpoint.clone(), b64);
                                            let _ = shared_peer.send(resp_msg).await;
                                        }
                                    }
                                    Ok(Err(e)) => {
                                        // При опережающих пакетах трафика от TUN не забиваем лог warn-штормом
                                        log::debug!("[WRTC Server] Handshake packet processing error from {from_endpoint}: {e}");
                                    }
                                    Err(_) => {
                                        warn!("[WRTC Server] Handshake processing timed out after 10s for {from_endpoint}");
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("[WRTC Server] Base64 decode error from {from_endpoint}: {e}");
                        }
                    }
                }
                WrtcMessage::AstpBatch { data } => {
                    match BASE64_STANDARD.decode(&data) {
                        Ok(raw_bytes) => {
                            let packets = unpack_batch(&raw_bytes);
                            if let Some(client_info) = clients_map.get(&from_endpoint) {
                                if reg_clone.get_by_session(&client_info.session_id).is_some() {
                                    let c_tag = anet_common::wrtc::colibri::client_tag_from_ip(
                                        &client_info.assigned_ip,
                                    );
                                    let now_ms =
                                        shared_peer.start_instant.elapsed().as_millis() as u64;
                                    let video_active = client_last_video_rx_ms
                                        .get(&c_tag)
                                        .map(|ts| now_ms.saturating_sub(*ts) <= 4000)
                                        .unwrap_or(false);
                                    if !video_active {
                                        client_video_warmed_up.remove(&c_tag);
                                        for enc_pkt in packets {
                                            match unwrap_packet_bytes(
                                                &client_info.cipher,
                                                enc_pkt,
                                            ) {
                                                Ok(packet) => {
                                                    if packet.first() == Some(&VIDEO_BATCH_MARKER) {
                                                        let inner_pkts = unpack_batch(&packet[1..]);
                                                        for pkt in inner_pkts {
                                                            if pkt.len() < WRTC_MIN_IP_PACKET_LEN {
                                                                continue;
                                                            }
                                                            if let Some(reply) =
                                                                anet_common::icmp_probe::handle_in_tunnel_icmp_probe(&pkt)
                                                            {
                                                                let seq = client_info
                                                                    .sequence
                                                                    .fetch_add(1, Ordering::Relaxed);
                                                                if let Ok(enc_reply) = wrap_packet_slice(
                                                                    &client_info.cipher,
                                                                    &client_info.nonce_prefix,
                                                                    seq,
                                                                    &reply,
                                                                    0,
                                                                ) {
                                                                    let b64 = BASE64_STANDARD.encode(&enc_reply);
                                                                    let msg = ColibriMessage::astp(
                                                                        from_endpoint.clone(),
                                                                        b64,
                                                                    );
                                                                    let _ = shared_peer.send(msg).await;
                                                                }
                                                                continue;
                                                            }
                                                            let packet_len = pkt.len();
                                                            if let Err(e) = tun_clone.try_send(pkt) {
                                                                warn!("[WRTC Server] TUN queue error for {}: {e}", client_info.assigned_ip);
                                                                break;
                                                            } else {
                                                                reg_clone.record_rx(&client_info, packet_len, "wrtc");
                                                            }
                                                        }
                                                        continue;
                                                    }
                                                    if let Some(reply) =
                                                        anet_common::icmp_probe::handle_in_tunnel_icmp_probe(&packet)
                                                    {
                                                        let seq = client_info
                                                            .sequence
                                                            .fetch_add(1, Ordering::Relaxed);
                                                        if let Ok(enc_reply) = wrap_packet_slice(
                                                            &client_info.cipher,
                                                            &client_info.nonce_prefix,
                                                            seq,
                                                            &reply,
                                                            0,
                                                        ) {
                                                            let b64 = BASE64_STANDARD.encode(&enc_reply);
                                                            let msg = ColibriMessage::astp(
                                                                from_endpoint.clone(),
                                                                b64,
                                                            );
                                                            let _ = shared_peer.send(msg).await;
                                                        }
                                                        continue;
                                                    }
                                                    let packet_len = packet.len();
                                                    match tun_clone.try_send(packet) {
                                                        Ok(_) => {
                                                            reg_clone.record_rx(&client_info, packet_len, "wrtc");
                                                        }
                                                        Err(e) => {
                                                            warn!("[WRTC Server] TUN queue error for {}: {e}", client_info.assigned_ip);
                                                            break;
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    warn!("[WRTC Server] Decrypt batch packet failed for {from_endpoint}: {e}");
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("[WRTC Server] Base64 batch decode error from {from_endpoint}: {e}");
                        }
                    }
                }
                WrtcMessage::P2pOffer { sdp, .. } => {
                    info!("[P2P Direct] Received ice-offer from client {from_endpoint}! Setting up Relay-Only P2P DataChannel...");
                    let p2p_map_c = p2p_clients.clone();
                    let peer_c = shared_peer.clone();
                    let tun_tx_c = tun_clone.clone();
                    let clients_map_c = clients_map.clone();
                    let reg_c = reg_clone.clone();
                    let client_ep = from_endpoint.clone();
                    let ice_servers = xmpp.get_ice_servers();
                    let wrtc_cfg_p2p = config.wrtc.clone();

                    tokio::spawn(async move {
                        match create_p2p_channel(&ice_servers, &wrtc_cfg_p2p, &peer_c.bind_addr).await {
                            Ok(p2p) => {
                                let p2p_arc = Arc::new(p2p);
                                let relay_offer_sdp = filter_p2p_sdp_relay_only(&sdp);
                                match RTCSessionDescription::offer(relay_offer_sdp) {
                                    Ok(offer_desc) => {
                                        if let Err(e) = p2p_arc.pc.set_remote_description(offer_desc).await {
                                            warn!("[P2P Direct] Server set_remote_description error: {e}");
                                            return;
                                        }
                                        match p2p_arc.pc.create_answer(None).await {
                                            Ok(answer) => {
                                                if let Err(e) = p2p_arc.pc.set_local_description(answer.clone()).await {
                                                    warn!("[P2P Direct] Server set_local_description error: {e}");
                                                    return;
                                                }

                                                let mut answer_sdp = answer.sdp.clone();
                                                for _ in 0..WRTC_ICE_GATHER_POLL_ATTEMPTS {
                                                    if let Some(desc) = p2p_arc.pc.local_description().await {
                                                        if desc.sdp.contains("a=candidate:") {
                                                            answer_sdp = desc.sdp;
                                                            if answer_sdp.contains("typ relay") {
                                                                break;
                                                            }
                                                        }
                                                    }
                                                    tokio::time::sleep(Duration::from_millis(
                                                        WRTC_P2P_ICE_GATHER_POLL_INTERVAL_MS,
                                                    ))
                                                    .await;
                                                }
                                                if answer_sdp.is_empty() {
                                                    if let Some(desc) = p2p_arc.pc.local_description().await {
                                                        answer_sdp = desc.sdp;
                                                    }
                                                }
                                                let relay_answer_sdp = filter_p2p_sdp_relay_only(&answer_sdp);

                                                let answer_msg = ColibriMessage::p2p_answer(client_ep.clone(), relay_answer_sdp, vec![]);
                                                if let Err(e) = peer_c.send(answer_msg).await {
                                                    warn!("[P2P Direct] Failed to send ice-answer: {e}");
                                                    return;
                                                }
                                                info!("[P2P Direct] Sent Relay-Only ice-answer to client {client_ep}");

                                                if let Some(prev_p2p) =
                                                    p2p_map_c.insert(client_ep.clone(), p2p_arc.clone())
                                                {
                                                    prev_p2p.close().await;
                                                }

                                                // Воркер чтения пакетов из прямого DataChannel клиента в TUN
                                                let p2p_read = p2p_arc.clone();
                                                let client_id_read = client_ep.clone();
                                                tokio::spawn(async move {
                                                    while let Some(first_bytes) = p2p_read.recv_packet().await {
                                                        let mut current_raw = Some(first_bytes);
                                                        while let Some(raw_bytes) = current_raw.take() {
                                                            if let Some(c_info) = clients_map_c.get(&client_id_read) {
                                                                if reg_c.get_by_session(&c_info.session_id).is_some() {
                                                                    match unwrap_packet_bytes(&c_info.cipher, raw_bytes) {
                                                                        Ok(decrypted) => {
                                                                            if decrypted.first() == Some(&VIDEO_BATCH_MARKER) {
                                                                                let packets = unpack_batch(&decrypted[1..]);
                                                                                for pkt in packets {
                                                                                    if pkt.len() >= WRTC_MIN_IP_PACKET_LEN {
                                                                                        if let Some(reply) =
                                                                                            anet_common::icmp_probe::handle_in_tunnel_icmp_probe(&pkt)
                                                                                        {
                                                                                            let seq = c_info
                                                                                                .sequence
                                                                                                .fetch_add(1, Ordering::Relaxed);
                                                                                            if let Ok(enc_reply) = wrap_packet_slice(
                                                                                                &c_info.cipher,
                                                                                                &c_info.nonce_prefix,
                                                                                                seq,
                                                                                                &reply,
                                                                                                0,
                                                                                            ) {
                                                                                                let _ = p2p_read.send_packet(&enc_reply).await;
                                                                                            }
                                                                                            continue;
                                                                                        }
                                                                                        let pkt_len = pkt.len();
                                                                                        if tun_tx_c.try_send(pkt).is_ok() {
                                                                                            reg_c.record_rx(&c_info, pkt_len, "wrtc");
                                                                                        }
                                                                                    }
                                                                                }
                                                                            } else if decrypted.len() >= WRTC_MIN_IP_PACKET_LEN {
                                                                                if let Some(reply) =
                                                                                    anet_common::icmp_probe::handle_in_tunnel_icmp_probe(&decrypted)
                                                                                {
                                                                                    let seq = c_info
                                                                                        .sequence
                                                                                        .fetch_add(1, Ordering::Relaxed);
                                                                                    if let Ok(enc_reply) = wrap_packet_slice(
                                                                                        &c_info.cipher,
                                                                                        &c_info.nonce_prefix,
                                                                                        seq,
                                                                                        &reply,
                                                                                        0,
                                                                                    ) {
                                                                                        let _ = p2p_read.send_packet(&enc_reply).await;
                                                                                    }
                                                                                } else {
                                                                                    let packet_len = decrypted.len();
                                                                                    if tun_tx_c.try_send(decrypted).is_ok() {
                                                                                        reg_c.record_rx(&c_info, packet_len, "wrtc");
                                                                                        log::trace!("[P2P Direct IN] {} bytes from {}", packet_len, c_info.assigned_ip);
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                        Err(e) => {
                                                                            log::debug!("[P2P Direct] Decrypt error from {client_id_read}: {e}");
                                                                        }
                                                                    }
                                                            } else {
                                                                drop(c_info);
                                                                clients_map_c.remove(&client_id_read);
                                                                if let Some((_, dead_p2p)) = p2p_map_c.remove(&client_id_read) {
                                                                    dead_p2p.close().await;
                                                                }
                                                                break;
                                                            }
                                                        } else {
                                                            if let Some((_, dead_p2p)) = p2p_map_c.remove(&client_id_read) {
                                                                dead_p2p.close().await;
                                                            }
                                                            break;
                                                        }
                                                        current_raw = p2p_read.try_recv_packet();
                                                    }
                                                }
                                                log::info!("[P2P Direct] Receiver loop stopped for {client_id_read}");
                                            });
                                        }
                                        Err(e) => {
                                            warn!("[P2P Direct] Server create_answer error: {e}");
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("[P2P Direct] Invalid remote offer SDP from {client_ep}: {e}");
                                }
                            }
                        }
                        Err(e) => {
                            warn!("[P2P Direct] Failed to create server P2P channel: {e:#}");
                        }
                    }
                });
            }
            _ => {}
        }
    }

    video_uplink_task.abort();
    let stale_p2ps: Vec<Arc<P2pSession>> = p2p_clients.iter().map(|e| e.value().clone()).collect();
    for p2p in stale_p2ps {
        p2p.close().await;
    }
    p2p_clients.clear();
    xmpp.leave_room().await;
    let _ = shared_peer.close().await;

    for entry in active_clients.iter() {
        registry.suspend_client(entry.value().clone());
    }
    active_clients.clear();
    clients_by_tag.clear();
    client_video_warmed_up.clear();
    client_modes.clear();
    client_video_endpoints.clear();
    client_v2_endpoints.clear();
    known_client_video_ssrcs.clear();

        info!(
            "[WRTC Server] Pausing {}s before re-entering conference room...",
            WRTC_SERVER_RECONNECT_PAUSE_SECS
        );
        tokio::time::sleep(Duration::from_secs(WRTC_SERVER_RECONNECT_PAUSE_SECS)).await;
    }
}
