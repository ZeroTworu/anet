use crate::auth_handler::ServerAuthHandler;
use crate::client_registry::{ClientRegistry, ClientTransportInfo};
use crate::config::Config;
use anet_common::http_help::BrowserProfile;
use anet_common::transport::{
    unwrap_packet_bytes, wrap_packet_padded, wrap_packet_slice_with_headroom,
};
use anet_common::wrtc::{
    batcher::{unpack_batch, PacketBatcher},
    colibri::{
        sign_beacon, ColibriMessage, WrtcMessage, MAX_VIDEO_BATCH_BYTES, VIDEO_BATCH_MARKER,
        VP8_ASTP_PREFIX_LEN,
    },
    jingle::parse_jingle_session,
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

        let _ = xmpp.request_conference_allocation().await;

        info!("[WRTC Server] Waiting for Jicofo session-initiate (client arrival)...");
        let mut parsed_session = None;
        let idle_deadline = tokio::time::Instant::now() + Duration::from_secs(1800);

        loop {
            match tokio::time::timeout_at(idle_deadline, xmpp.recv_stanza()).await {
                Ok(Some(stanza)) => {
                    if let Some(session) = parse_jingle_session(&stanza, fallback_ip, fallback_port) {
                        parsed_session = Some(session);
                        break;
                    }
                }
                Ok(None) => {
                    warn!("[WRTC Server] XMPP stream closed while waiting for session-initiate. Reconnecting in 2s...");
                    break;
                }
                Err(_) => {
                    info!("[WRTC Server] No client joined for 30m; rotating server room session...");
                    break;
                }
            }
        }

        let Some(session) = parsed_session else {
            xmpp.leave_room().await;
            tokio::time::sleep(Duration::from_secs(2)).await;
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
        )
            .await
        {
            Ok(p) => p,
            Err(e) => {
                warn!("[WRTC Server] Failed to initialize WebRTC Peer: {e:#}. Retrying in 3s...");
                xmpp.leave_room().await;
                tokio::time::sleep(Duration::from_secs(3)).await;
                continue;
            }
        };

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
        let video_uplink_task = tokio::spawn(async move {
            while let Some(first_frame) = peer_video_rx.recv_video_frame().await {
                let mut current_frame = Some(first_frame);
                while let Some(raw_frame) = current_frame.take() {
                    if raw_frame.len() < 50 {
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
                                if tun_clone_video.try_send(sub_pkt).is_ok() {
                                    reg_clone_video.record_rx(client_info.value(), pkt_len, "wrtc_video");
                                } else {
                                    break;
                                }
                            }
                        } else {
                            let packet_len = decrypted.len();
                            if tun_clone_video.try_send(decrypted).is_ok() {
                                reg_clone_video.record_rx(client_info.value(), packet_len, "wrtc_video");
                            }
                        }
                    }
                    current_frame = peer_video_rx.try_recv_video_frame();
                }
            }
        });

        let mut health_watchdog = tokio::time::interval(Duration::from_secs(2));
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
                                if jingle.action == "source-add"
                                    || jingle.action == "description-info"
                                    || jingle.action == "session-initiate"
                                {
                                    for v_ssrc in jingle.video_sources {
                                        info!("[WRTC Server] Jingle stanza ({}) announced remote video SSRC: {v_ssrc}", jingle.action);
                                        let _ = tokio::time::timeout(
                                            Duration::from_secs(5),
                                            shared_peer.add_remote_video_ssrc(v_ssrc),
                                        ).await;
                                    }
                                }
                            }
                            anet_common::wrtc::xmpp_xml::InboundXmpp::Presence { from, is_unavailable: true, .. } => {
                                if let Some(occupant_id) = from.split('/').nth(1) {
                                    if occupant_id == srv_id {
                                        warn!("[WRTC Server] Server occupant {srv_id} was removed from MUC room. Re-establishing server session...");
                                        self_removed = true;
                                    } else if occupant_id != "focus" {
                                        client_modes.remove(occupant_id);
                                        client_video_endpoints.remove(occupant_id);
                                        client_v2_endpoints.remove(occupant_id);
                                        p2p_clients.remove(occupant_id);
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
                        if pref_mode != "ws" {
                            shared_peer.set_expected_peer_video_ssrc(c_v_ssrc);
                            info!("[WRTC Server] Set expected client video SSRC: {c_v_ssrc} for {from_endpoint}");

                            // Привязываем видео SSRC клиента к выделенному Recvonly трансиверу
                            let _ = tokio::time::timeout(
                                Duration::from_secs(5),
                                shared_peer.add_remote_video_ssrc(c_v_ssrc),
                            ).await;

                            client_video_endpoints.insert(from_endpoint.clone());
                            let constraints = anet_common::wrtc::colibri::ReceiverVideoConstraints::new_all(2160);
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
                                    Duration::from_secs(10),
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
                                            }

                                            let client_tag = anet_common::wrtc::colibri::client_tag_from_ip(&assigned_ip);
                                            client_video_warmed_up.remove(&client_tag);
                                            clients_by_tag.insert(client_tag, client_info.clone());
                                            shared_peer.force_next_keyframe();

                                            let (tx_router, mut rx_router) =
                                                mpsc::channel::<Bytes>(16384);
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

                                            tokio::spawn(async move {
                                                let mut batcher = PacketBatcher::new(16384, 2);
                                                let mut batch_interval = tokio::time::interval(Duration::from_millis(2));
                                                batch_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                                                let mut batch_buf = BytesMut::with_capacity(2048);
                                                let mut pending_packet: Option<Bytes> = None;

                                                loop {
                                                    tokio::select! {
                                                        biased;
                                                        packet_opt = rx_router.recv() => {
                                                            let Some(mut packet) = packet_opt else { break; };

                                                            loop {
                                                                if packet.len() >= 20 {
                                                                    let client_pref_mode = client_modes_dl
                                                                        .get(&target_client_id)
                                                                        .map(|m| m.clone())
                                                                        .unwrap_or_else(|| "auto".to_string());
                                                                    let has_video = client_video_ep_dl.contains(&target_client_id);
                                                                    let is_v2 = client_v2_ep_dl.contains(&target_client_id);
                                                                    let video_warmed_up = client_video_warmed_dl.contains(&client_tag);

                                                                    let client_uses_video = (srv_mode == anet_common::wrtc::colibri::WrtcMode::MediaVideo
                                                                        || srv_mode == anet_common::wrtc::colibri::WrtcMode::Auto)
                                                                        && client_pref_mode != "ws"
                                                                        && has_video;

                                                                    if client_uses_video && is_v2 {
                                                                        if video_warmed_up && packet.len() + 3 < MAX_VIDEO_BATCH_BYTES {
                                                                            batch_buf.clear();
                                                                            batch_buf.put_u8(VIDEO_BATCH_MARKER);
                                                                            batch_buf.put_u16(packet.len() as u16);
                                                                            batch_buf.extend_from_slice(&packet);
                                                                            let mut count = 1usize;

                                                                            while count < 16 {
                                                                                let next_p = if let Some(p) = pending_packet.take() {
                                                                                    p
                                                                                } else if let Ok(p) = rx_router.try_recv() {
                                                                                    p
                                                                                } else {
                                                                                    break;
                                                                                };
                                                                                if next_p.len() < 20 {
                                                                                    continue;
                                                                                }
                                                                                if batch_buf.len() + 2 + next_p.len() <= MAX_VIDEO_BATCH_BYTES {
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
                                                                            let enc_bytes = Bytes::from(encrypted);
                                                                            let mut sent = false;

                                                                            // 1. Проверяем режим MediaVideo (Fake Video Track over DTLS-SRTP / JVB)
                                                                            if client_uses_video {
                                                                                if peer_downlink.send_video_frame_tagged(client_tag, &enc_bytes).await.is_ok() {
                                                                                    // До подтверждения приема видео от клиента дублируем в WS
                                                                                    if video_warmed_up {
                                                                                        sent = true;
                                                                                    }
                                                                                } else {
                                                                                    warn!("[WRTC Server Video OUT] send error to {target_client_id}, fallback to WS/P2P");
                                                                                }
                                                                            }

                                                                            // 2. Проверяем P2P DataChannel с клиентом
                                                                            if !sent {
                                                                                if let Some(p2p_entry) = p2p_clients_dl.get(&target_client_id) {
                                                                                    if p2p_entry.is_open.load(Ordering::SeqCst) {
                                                                                        if p2p_entry.send_packet(&enc_bytes).await.is_ok() {
                                                                                            sent = true;
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }

                                                                            // 3. Если Video и P2P не сработали (или клиент в WS режиме), шлем через батчер (Colibri-WS)
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

                                                                if let Some(next_p) = pending_packet.take() {
                                                                    packet = next_p;
                                                                } else if let Ok(next_p) = rx_router.try_recv() {
                                                                    packet = next_p;
                                                                } else {
                                                                    break;
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
                                    for enc_pkt in packets {
                                        match unwrap_packet_bytes(
                                            &client_info.cipher,
                                            enc_pkt,
                                        ) {
                                            Ok(packet) => {
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
                        Err(e) => {
                            warn!("[WRTC Server] Base64 batch decode error from {from_endpoint}: {e}");
                        }
                    }
                }
                WrtcMessage::P2pOffer { sdp, .. } => {
                    info!("[P2P Direct] Received anet_p2p_offer from client {from_endpoint}! Setting up P2P DataChannel...");
                    let p2p_map_c = p2p_clients.clone();
                    let peer_c = shared_peer.clone();
                    let tun_tx_c = tun_clone.clone();
                    let clients_map_c = clients_map.clone();
                    let reg_c = reg_clone.clone();
                    let client_ep = from_endpoint.clone();
                    let stun_servers = xmpp.get_stun_servers();

                    tokio::spawn(async move {
                        match create_p2p_channel(&stun_servers).await {
                            Ok(p2p) => {
                                let p2p_arc = Arc::new(p2p);
                                match RTCSessionDescription::offer(sdp) {
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
                                                for _ in 0..50 {
                                                    if let Some(desc) = p2p_arc.pc.local_description().await {
                                                        if desc.sdp.contains("a=candidate:") {
                                                            answer_sdp = desc.sdp;
                                                            if answer_sdp.contains("typ srflx") {
                                                                break;
                                                            }
                                                        }
                                                    }
                                                    tokio::time::sleep(Duration::from_millis(50)).await;
                                                }
                                                if answer_sdp.is_empty() {
                                                    if let Some(desc) = p2p_arc.pc.local_description().await {
                                                        answer_sdp = desc.sdp;
                                                    }
                                                }

                                                let answer_msg = ColibriMessage::p2p_answer(client_ep.clone(), answer_sdp, vec![]);
                                                if let Err(e) = peer_c.send(answer_msg).await {
                                                    warn!("[P2P Direct] Failed to send anet_p2p_answer: {e}");
                                                    return;
                                                }
                                                info!("[P2P Direct] Sent anet_p2p_answer to client {client_ep}");

                                                p2p_map_c.insert(client_ep.clone(), p2p_arc.clone());

                                                // Воркер чтения пакетов из прямого DataChannel клиента в TUN
                                                let p2p_read = p2p_arc.clone();
                                                let client_id_read = client_ep.clone();
                                                tokio::spawn(async move {
                                                    while let Some(raw_bytes) = p2p_read.recv_packet().await {
                                                        if let Some(c_info) = clients_map_c.get(&client_id_read) {
                                                            if reg_c.get_by_session(&c_info.session_id).is_some() {
                                                                match unwrap_packet_bytes(&c_info.cipher, raw_bytes) {
                                                                    Ok(packet) => {
                                                                        let packet_len = packet.len();
                                                                        if tun_tx_c.try_send(packet).is_ok() {
                                                                            reg_c.record_rx(&c_info, packet_len, "wrtc");
                                                                            log::trace!("[P2P Direct IN] {} bytes from {}", packet_len, c_info.assigned_ip);
                                                                        }
                                                                    }
                                                                    Err(e) => {
                                                                        log::debug!("[P2P Direct] Decrypt error from {client_id_read}: {e}");
                                                                    }
                                                                }
                                                            }
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
        xmpp.leave_room().await;
        let _ = shared_peer.close().await;

        for entry in active_clients.iter() {
            registry.suspend_client(entry.value().clone());
        }
        active_clients.clear();
        clients_by_tag.clear();
        client_video_warmed_up.clear();
        p2p_clients.clear();
        client_modes.clear();
        client_video_endpoints.clear();
        client_v2_endpoints.clear();

        info!("[WRTC Server] Pausing 2s before re-entering conference room...");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
