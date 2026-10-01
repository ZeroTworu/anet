use crate::auth_handler::ServerAuthHandler;
use crate::client_registry::{ClientRegistry, ClientTransportInfo};
use crate::config::Config;
use anet_common::consts::CHANNEL_BUFFER_SIZE;
use anet_common::http_help::BrowserProfile;
use anet_common::transport::{unwrap_packet_bytes, wrap_packet_padded};
use anet_common::wrtc::{
    batcher::{unpack_batch, PacketBatcher},
    colibri::{sign_beacon, ColibriMessage, WrtcMessage},
    jingle::parse_jingle_session,
    ktalk::KtalkClient,
    peer::{create_p2p_channel, P2pSession, WrtcPeer},
    stealth::generate_random_guest_name,
    xmpp::XmppSession,
};
use anyhow::{Context, Result};
use base64::prelude::*;
use bytes::Bytes;
use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use log::{info, warn};
use rtc::peer_connection::sdp::RTCSessionDescription;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
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

        while let Some(stanza) = xmpp.recv_stanza().await {
            if let Some(session) = parse_jingle_session(&stanza, fallback_ip, fallback_port) {
                parsed_session = Some(session);
                break;
            }
        }

        let Some(session) = parsed_session else {
            warn!("[WRTC Server] XMPP stream closed while waiting for session-initiate. Reconnecting in 3s...");
            tokio::time::sleep(Duration::from_secs(3)).await;
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
                warn!("[WRTC Server] Failed to initialize WebRTC Peer: {e:#}. Retrying in 5s...");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        info!("[WRTC Server] WebRTC connection active. Waiting for clients...");

        let shared_peer = Arc::new(peer);
        let active_clients: Arc<DashMap<String, Arc<ClientTransportInfo>>> =
            Arc::new(DashMap::new());
        let p2p_clients: Arc<DashMap<String, Arc<P2pSession>>> =
            Arc::new(DashMap::new());

        let reg_clone = registry.clone();
        let auth_clone = auth_handler.clone();
        let tun_clone = tun_tx.clone();
        let clients_map = active_clients.clone();
        let srv_id = server_endpoint_id.clone();
        let padding_step = config.stealth.padding_step;

        // Воркер Downlink из Fake Video Track (VP8 over DTLS-SRTP / JVB)
        let peer_video_rx = shared_peer.clone();
        let clients_map_video = clients_map.clone();
        let tun_clone_video = tun_clone.clone();
        let reg_clone_video = reg_clone.clone();

        let first_server_rx = Arc::new(AtomicBool::new(true));
        tokio::spawn(async move {
            while let Some(raw_astp) = peer_video_rx.recv_video_frame().await {
                for entry in clients_map_video.iter() {
                    let client_info = entry.value();
                    if let Ok(packet) = unwrap_packet_bytes(&client_info.cipher, raw_astp.clone()) {
                        let packet_len = packet.len();
                        if first_server_rx.swap(false, Ordering::Relaxed) {
                            info!(
                                "[WRTC Server Video IN] First video frame decrypted from client {} (len: {} bytes)",
                                client_info.assigned_ip, packet_len
                            );
                        }
                        if tun_clone_video.try_send(packet).is_ok() {
                            reg_clone_video.record_rx(client_info, packet_len, "wrtc_video");
                        }
                        break;
                    }
                }
            }
        });

        loop {
            let msg_opt = tokio::select! {
                res = shared_peer.recv() => res,
                _ = shared_peer.failed_notify.notified() => {
                    warn!("[WRTC Server] WebRTC PeerConnection failed/closed by JVB. Re-establishing server session in 3s...");
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    break;
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
                WrtcMessage::Discover { client_nonce, video_ssrc } => {
                    info!(
                        "[WRTC Server] Received anet_discover from client {from_endpoint} (nonce: {client_nonce}, client_video_ssrc: {video_ssrc:?})! Answering beacon..."
                    );
                    if let Some(c_v_ssrc) = video_ssrc {
                        shared_peer.set_expected_peer_video_ssrc(c_v_ssrc);
                        info!("[WRTC Server] Set expected client video SSRC: {c_v_ssrc}");
                        let constraints = anet_common::wrtc::colibri::ReceiverVideoConstraints::for_endpoint(&from_endpoint, 720);
                        let _ = shared_peer.send_video_constraints(&constraints).await;
                    }
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
                        client_info.last_activity.store(
                            std::time::SystemTime::now()
                                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                            Ordering::Relaxed,
                        );
                        let pong_msg = ColibriMessage::pong(from_endpoint.clone());
                        let _ = shared_peer.send(pong_msg).await;
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
                                match auth_clone
                                    .process_handshake_packet(Bytes::from(raw_bytes), client_addr, "wrtc")
                                    .await
                                {
                                    Ok((response, result)) => {
                                        // 1. Сначала финализируем и регистрируем клиента, чтобы быть готовыми к приему трафика
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
                                            let peer_downlink = shared_peer.clone();
                                            let p2p_clients_dl = p2p_clients.clone();
                                            let srv_mode = server_mode;

                                            tokio::spawn(async move {
                                                let mut batcher = PacketBatcher::new(16384, 2);
                                                let mut batch_interval = tokio::time::interval(Duration::from_millis(2));
                                                loop {
                                                    tokio::select! {
                                                        packet_opt = rx_router.recv() => {
                                                            let Some(packet) = packet_opt else { break; };
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
                                                                let enc_bytes = Bytes::from(encrypted);
                                                                let mut sent_p2p = false;

                                                                // 1. Проверяем режим MediaVideo (Fake Video Track over DTLS-SRTP / JVB)
                                                                if srv_mode == anet_common::wrtc::colibri::WrtcMode::MediaVideo {
                                                                    if let Err(e) = peer_downlink.send_video_frame(&enc_bytes).await {
                                                                        warn!("[WRTC Server Video OUT] send error: {e}");
                                                                    }
                                                                    continue;
                                                                }

                                                                // 2. Проверяем P2P DataChannel с клиентом
                                                                if let Some(p2p_entry) = p2p_clients_dl.get(&target_client_id) {
                                                                    if p2p_entry.is_open.load(Ordering::SeqCst) {
                                                                        if p2p_entry.send_packet(&enc_bytes).await.is_ok() {
                                                                            sent_p2p = true;
                                                                        }
                                                                    }
                                                                }

                                                                // 2. Если P2P еще не открыт или недоступен, шлем через батчер (Colibri-WS)
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
                                                        }
                                                        _ = batch_interval.tick() => {
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
                                    Err(e) => {
                                        // При опережающих пакетах трафика от TUN не забиваем лог warn-штормом
                                        log::debug!("[WRTC Server] Handshake packet processing error from {from_endpoint}: {e}");
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

        for entry in active_clients.iter() {
            registry.suspend_client(entry.value().clone());
        }
        active_clients.clear();
        p2p_clients.clear();

        info!("[WRTC Server] Pausing 2s before re-entering conference room...");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
