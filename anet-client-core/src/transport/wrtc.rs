use super::{ClientTransport, ConnectionResult};
use crate::auth::{AuthChannel, AuthHandler};
use crate::config::{CoreConfig, ServerConfig};
use anet_common::encryption::Cipher;
use anet_common::handshake_fragmentation::FragmentConfig;
use anet_common::http_help::BrowserProfile;
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anet_common::transport::{unwrap_packet_bytes, wrap_packet_padded};
use anet_common::wrtc::{
    batcher::{unpack_batch, PacketBatcher},
    colibri::{verify_beacon, ColibriMessage, WrtcMessage},
    jingle::parse_jingle_session,
    ktalk::KtalkClient,
    peer::{create_p2p_channel, P2pSession, WrtcPeer},
    stealth::generate_random_guest_name,
    xmpp::XmppSession,
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::prelude::*;
use bytes::Bytes;
use log::{info, warn};
use rtc::peer_connection::sdp::RTCSessionDescription;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

fn current_timestamp_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

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

        let ktalk = KtalkClient::new(browser_profile.clone());
        let anon_secret = KtalkClient::generate_anonymous_secret();
        let auth_res = ktalk
            .authorize_session(&domain, &room_name, Some(&guest_name), &anon_secret)
            .await
            .context("Failed to authorize Ktalk session")?;

        let room_info = ktalk
            .resolve_room(&domain, &room_name, &auth_res.token)
            .await
            .context("Failed to resolve Ktalk room")?;

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

        let mut bypass_ips: Vec<std::net::IpAddr> = Vec::new();

        if let Some(ref ws_url) = session.transport.colibri_ws_url {
            if let Ok(uri) = ws_url.parse::<http::Uri>() {
                if let Some(host) = uri.host() {
                    let port = uri.port_u16().unwrap_or(443);
                    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                        if !ip.is_loopback() {
                            bypass_ips.push(ip);
                        }
                    } else if let Ok(resolved) = tokio::net::lookup_host((host, port)).await {
                        for addr in resolved {
                            if !addr.ip().is_loopback() {
                                bypass_ips.push(addr.ip());
                            }
                        }
                    }
                }
            }
        }

        for candidate in &session.transport.candidates {
            if let Ok(ip) = candidate.ip.parse::<std::net::IpAddr>() {
                if !ip.is_loopback() {
                    bypass_ips.push(ip);
                }
            }
        }

        if let Ok(ip) = fallback_ip.parse::<std::net::IpAddr>() {
            if !ip.is_loopback() {
                bypass_ips.push(ip);
            }
        }

        for stun_url in xmpp.get_stun_servers() {
            let clean = stun_url
                .trim_start_matches("stun:")
                .trim_start_matches("turn:")
                .trim_start_matches("turns:");
            let (host, port) = if let Some((h, p)) = clean.split_once(':') {
                (h, p.parse::<u16>().unwrap_or(3478))
            } else {
                (clean, 3478)
            };
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                if !ip.is_loopback() {
                    bypass_ips.push(ip);
                }
            } else if let Ok(resolved) = tokio::net::lookup_host((host, port)).await {
                for addr in resolved {
                    if !addr.ip().is_loopback() {
                        bypass_ips.push(addr.ip());
                    }
                }
            }
        }

        bypass_ips.sort_unstable();
        bypass_ips.dedup();
        info!("[WRTC] Discovered media bypass IPs: {:?}", bypass_ips);

        let wrtc_mode = self.server.wrtc_transport_mode();
        info!("[WRTC] Selected WebRTC transport mode: {:?}", wrtc_mode);

        let audio_keepalive_ms = self.server.wrtc_media_keepalive_interval_ms.unwrap_or(20);
        let peer = WrtcPeer::create(
            Some(&session),
            Some(&xmpp),
            fallback_ip,
            fallback_port,
            audio_keepalive_ms,
            wrtc_mode,
        )
            .await
            .context("Failed to initialize WebRTC PeerConnection and DataChannel")?;

        info!("[WRTC] WebRTC Peer created. Starting server discovery...");

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
                    info!("[WRTC] Sending anet_discover broadcast (nonce: {client_nonce}, video_ssrc: {})...", peer.video_ssrc);
                    let discover_broadcast = ColibriMessage::discover(None, client_nonce.clone(), Some(peer.video_ssrc));
                    let _ = peer.send(discover_broadcast).await;

                    let current_occupants = xmpp.get_other_occupants();
                    for occupant in current_occupants {
                        info!("[WRTC] Sending anet_discover to occupant: {occupant}");
                        let unicast_discover = ColibriMessage::discover(Some(occupant), client_nonce.clone(), Some(peer.video_ssrc));
                        let _ = peer.send(unicast_discover).await;
                    }
                }
                msg_opt = peer.recv() => {
                    if let Some(msg) = msg_opt {
                        if let WrtcMessage::Beacon { server_id, client_nonce: beacon_nonce, signature, video_ssrc } = msg.msg_payload {
                            info!("[WRTC] Received beacon from server: {server_id} (nonce match: {}, server_video_ssrc: {video_ssrc:?})", beacon_nonce == client_nonce);
                            if beacon_nonce == client_nonce {
                                if let Some(v_ssrc) = video_ssrc {
                                    peer.set_expected_peer_video_ssrc(v_ssrc);
                                    info!("[WRTC Client] Set expected server video SSRC: {v_ssrc}");

                                    // ИНЖЕКТИРУЕМ SSRC СЕРВЕРА В REMOTE_DESCRIPTION
                                    peer.add_remote_video_ssrc(v_ssrc).await;

                                    let constraints = anet_common::wrtc::colibri::ReceiverVideoConstraints::for_endpoint(&server_id, 2160);
                                    let _ = peer.send_video_constraints(&constraints).await;
                                }
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

        let shared_peer = Arc::new(peer);
        let auth_channel = WrtcAuthChannel {
            peer: shared_peer.clone(),
            target_server_id: target_server_id.clone(),
        };

        let auth_handler = AuthHandler::new(&self.config, self.server.server_pub_key.as_deref())?;
        let (mut auth_response, shared_key) = auth_handler.authenticate(&auth_channel).await?;

        if wrtc_mode == anet_common::wrtc::colibri::WrtcMode::MediaVideo || auth_response.mtu > 1280 {
            info!(
                "[WRTC] Setting safe TUN MTU {} (clamped from {}) for WebRTC DTLS-SRTP packetization",
                1280, auth_response.mtu
            );
            auth_response.mtu = 1280;
        }

        info!(
            "[WRTC] ASTP Authentication succeeded! Assigned VPN IP: {}",
            auth_response.ip
        );

        let cipher = Arc::new(Cipher::new(&shared_key));
        let nonce_prefix: [u8; 4] = auth_response.nonce_prefix.as_slice().try_into()?;
        let sequence = Arc::new(AtomicU64::new(0));

        let p2p_session_opt: Arc<Mutex<Option<Arc<P2pSession>>>> = Arc::new(Mutex::new(None));
        if wrtc_mode == anet_common::wrtc::colibri::WrtcMode::P2pDirect
            || wrtc_mode == anet_common::wrtc::colibri::WrtcMode::Auto
        {
            info!("[P2P Direct] Initiating direct WebRTC P2P DataChannel with server {target_server_id}...");
            let p2p_store = p2p_session_opt.clone();
            let peer_sig = shared_peer.clone();
            let target_srv = target_server_id.clone();
            let stun_servers = xmpp.get_stun_servers();

            tokio::spawn(async move {
                match create_p2p_channel(&stun_servers).await {
                    Ok(p2p) => {
                        let p2p_arc = Arc::new(p2p);
                        *p2p_store.lock().await = Some(p2p_arc.clone());

                        match p2p_arc.pc.create_offer(None).await {
                            Ok(offer) => {
                                if let Err(e) = p2p_arc.pc.set_local_description(offer.clone()).await {
                                    warn!("[P2P Direct] set_local_description error: {e}");
                                    return;
                                }
                                let mut final_sdp = offer.sdp.clone();
                                for _ in 0..50 {
                                    if let Some(desc) = p2p_arc.pc.local_description().await {
                                        if desc.sdp.contains("a=candidate:") {
                                            final_sdp = desc.sdp;
                                            if final_sdp.contains("typ srflx") {
                                                break;
                                            }
                                        }
                                    }
                                    tokio::time::sleep(Duration::from_millis(50)).await;
                                }
                                if final_sdp.is_empty() {
                                    if let Some(desc) = p2p_arc.pc.local_description().await {
                                        final_sdp = desc.sdp;
                                    }
                                }

                                let offer_msg = ColibriMessage::p2p_offer(target_srv.clone(), final_sdp, vec![]);
                                if let Err(e) = peer_sig.send(offer_msg).await {
                                    warn!("[P2P Direct] Failed to send anet_p2p_offer: {e}");
                                } else {
                                    info!("[P2P Direct] Sent anet_p2p_offer to server {target_srv}");
                                }
                            }
                            Err(e) => {
                                warn!("[P2P Direct] create_offer error: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        warn!("[P2P Direct] Failed to create P2P channel: {e:#}");
                    }
                }
            });
        }

        let (client_stream, internal_router) = tokio::io::duplex(2 * 1024 * 1024);
        let (mut tunnel_read, mut tunnel_write) = tokio::io::split(internal_router);
        let (tunnel_packet_tx, mut tunnel_packet_rx) =
            tokio::sync::mpsc::channel::<Bytes>(16384);

        let tunnel_reader_task = tokio::spawn(async move {
            while let Ok(Some(packet)) = read_next_packet(&mut tunnel_read).await {
                if tunnel_packet_tx.send(packet).await.is_err() {
                    break;
                }
            }
        });

        let (tun_inject_tx, mut tun_inject_rx) =
            tokio::sync::mpsc::channel::<Bytes>(16384);

        tokio::spawn(async move {
            while let Some(packet) = tun_inject_rx.recv().await {
                let framed = frame_packet(packet);
                if let Err(e) = tunnel_write.write_all(&framed).await {
                    warn!("[WRTC Client] tunnel_write error: {e}");
                    break;
                }
            }
        });

        let peer_tx = shared_peer.clone();
        let target_srv_tx = target_server_id.clone();
        let cipher_tx = cipher.clone();
        let sequence_tx = sequence.clone();
        let padding_step = self.config.stealth.padding_step;
        let p2p_uplink = p2p_session_opt.clone();

        let mut ping_interval = tokio::time::interval(Duration::from_secs(15));
        let mut batch_interval = tokio::time::interval(Duration::from_millis(2));
        let last_pong = Arc::new(AtomicU64::new(current_timestamp_secs()));
        let last_pong_tx = last_pong.clone();
        let mut batcher = PacketBatcher::new(16384, 2);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    packet_opt = tunnel_packet_rx.recv() => {
                        let Some(packet) = packet_opt else { break; };
                        if packet.len() < 20 {
                            continue;
                        }
                        let seq = sequence_tx.fetch_add(1, Ordering::Relaxed);
                        match wrap_packet_padded(&cipher_tx, &nonce_prefix, seq, packet, padding_step) {
                            Ok(encrypted) => {
                                let enc_bytes = Bytes::from(encrypted);
                                let mut sent_p2p = false;

                                if wrtc_mode == anet_common::wrtc::colibri::WrtcMode::MediaVideo {
                                    if let Err(e) = peer_tx.send_video_frame(&enc_bytes).await {
                                        warn!("[WRTC Media Video OUT] send error: {e}");
                                    }
                                    continue;
                                }

                                let p2p_opt = {
                                    let guard = p2p_uplink.lock().await;
                                    guard.clone()
                                };
                                if let Some(p2p) = p2p_opt {
                                    if p2p.is_open.load(Ordering::SeqCst) {
                                        if p2p.send_packet(&enc_bytes).await.is_ok() {
                                            log::trace!("[P2P Direct OUT]");
                                            sent_p2p = true;
                                        }
                                    }
                                }

                                if !sent_p2p {
                                    batcher.push(enc_bytes);
                                    if batcher.should_flush() {
                                        if let Some(batch_data) = batcher.flush() {
                                            let b64 = BASE64_STANDARD.encode(&batch_data);
                                            let msg = ColibriMessage::astp_batch(target_srv_tx.clone(), b64);
                                            if let Err(e) = peer_tx.send(msg).await {
                                                warn!("[WRTC Client] Peer send batch error: {e}");
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("[WRTC Client] wrap_packet_padded error: {e}");
                            }
                        }
                    }
                    _ = batch_interval.tick() => {
                        if !batcher.is_empty() {
                            if let Some(batch_data) = batcher.flush() {
                                let b64 = BASE64_STANDARD.encode(&batch_data);
                                let msg = ColibriMessage::astp_batch(target_srv_tx.clone(), b64);
                                if let Err(e) = peer_tx.send(msg).await {
                                    warn!("[WRTC Client] Peer flush batch send error: {e}");
                                    break;
                                }
                            }
                        }
                    }
                    _ = ping_interval.tick() => {
                        let now = current_timestamp_secs();
                        if now.saturating_sub(last_pong_tx.load(Ordering::Relaxed)) > 45 {
                            warn!("[WRTC Client] Ping timeout (no pong from server for 45s). Reconnecting...");
                            break;
                        }
                        let ping_msg = ColibriMessage::ping(target_srv_tx.clone());
                        if let Err(e) = peer_tx.send(ping_msg).await {
                            warn!("[WRTC Client] Peer ping error: {e}");
                            break;
                        }
                    }
                }
            }
            tunnel_reader_task.abort();
        });

        let peer_rx = shared_peer.clone();
        let cipher_rx = cipher.clone();
        let tun_inject_ws = tun_inject_tx.clone();
        let p2p_sig = p2p_session_opt.clone();

        tokio::spawn(async move {
            loop {
                let msg_opt = peer_rx.recv().await;
                match msg_opt {
                    Some(msg) => {
                        match msg.msg_payload {
                            WrtcMessage::P2pAnswer { sdp, .. } => {
                                info!("[P2P Direct] Received anet_p2p_answer from server! Applying remote SDP...");
                                let p2p_opt = {
                                    let guard = p2p_sig.lock().await;
                                    guard.clone()
                                };
                                if let Some(p2p) = p2p_opt {
                                    if let Ok(answer_desc) = RTCSessionDescription::answer(sdp) {
                                        if let Err(e) = p2p.pc.set_remote_description(answer_desc).await {
                                            warn!("[P2P Direct] set_remote_description error: {e}");
                                        } else {
                                            info!("[P2P Direct] Applied remote answer successfully. Awaiting DataChannel open...");
                                        }
                                    }
                                }
                            }
                            WrtcMessage::Astp { data } => {
                                match BASE64_STANDARD.decode(&data) {
                                    Ok(raw_encrypted) => {
                                        match unwrap_packet_bytes(
                                            &cipher_rx,
                                            Bytes::from(raw_encrypted),
                                        ) {
                                            Ok(packet) => {
                                                let _ = tun_inject_ws.send(packet).await;
                                            }
                                            Err(e) => {
                                                warn!("[WRTC Client] Decrypt packet error: {e}");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("[WRTC Client] Base64 decode error: {e}");
                                    }
                                }
                            }
                            WrtcMessage::AstpBatch { data } => {
                                match BASE64_STANDARD.decode(&data) {
                                    Ok(raw_batch) => {
                                        let packets = unpack_batch(&raw_batch);
                                        for enc_pkt in packets {
                                            match unwrap_packet_bytes(&cipher_rx, enc_pkt) {
                                                Ok(packet) => {
                                                    let _ = tun_inject_ws.send(packet).await;
                                                }
                                                Err(e) => {
                                                    warn!("[WRTC Client] Decrypt batch packet error: {e}");
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("[WRTC Client] Base64 batch decode error: {e}");
                                    }
                                }
                            }
                            WrtcMessage::Pong => {
                                last_pong.store(current_timestamp_secs(), Ordering::Relaxed);
                            }
                            _ => {}
                        }
                    }
                    None => break,
                }
            }
        });

        let p2p_rx_task = p2p_session_opt.clone();
        let cipher_p2p = cipher.clone();
        let tun_inject_p2p = tun_inject_tx.clone();

        tokio::spawn(async move {
            loop {
                let p2p_opt = {
                    let guard = p2p_rx_task.lock().await;
                    guard.clone()
                };

                if let Some(p2p) = p2p_opt {
                    if p2p.is_open.load(Ordering::SeqCst) {
                        while let Some(raw_bytes) = p2p.recv_packet().await {
                            match unwrap_packet_bytes(&cipher_p2p, raw_bytes) {
                                Ok(packet) => {
                                    log::trace!("[P2P Direct IN] Decrypted packet ({} bytes)", packet.len());
                                    let _ = tun_inject_p2p.send(packet).await;
                                }
                                Err(e) => {
                                    warn!("[P2P Direct] Decrypt packet error: {e}");
                                }
                            }
                        }
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        let peer_video_rx = shared_peer.clone();
        let cipher_video = cipher.clone();
        let tun_inject_video = tun_inject_tx.clone();

        let first_client_rx = Arc::new(AtomicBool::new(true));
        if wrtc_mode == anet_common::wrtc::colibri::WrtcMode::MediaVideo {
            let first_rx_clone = first_client_rx.clone();
            let peer_reassert = shared_peer.clone();
            let srv_id_reassert = target_server_id.clone();
            tokio::spawn(async move {
                for _ in 0..10 {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    if !first_rx_clone.load(Ordering::Relaxed) {
                        break;
                    }
                    let constraints = anet_common::wrtc::colibri::ReceiverVideoConstraints::for_endpoint(&srv_id_reassert, 2160);
                    let _ = peer_reassert.send_video_constraints(&constraints).await;
                    log::debug!("[WRTC Client] Periodic re-assertion of ReceiverVideoConstraints for {}", srv_id_reassert);
                }
            });
        }
        tokio::spawn(async move {
            while let Some(raw_astp) = peer_video_rx.recv_video_frame().await {
                let raw_len = raw_astp.len();
                match unwrap_packet_bytes(&cipher_video, raw_astp) {
                    Ok(packet) => {
                        if first_client_rx.swap(false, Ordering::Relaxed) {
                            info!(
                                "[WRTC Client Video IN] First video frame decrypted from server (len: {} bytes)",
                                packet.len()
                            );
                        }
                        log::trace!("[WRTC Media Video IN] Decrypted packet ({} bytes)", packet.len());
                        let _ = tun_inject_video.send(packet).await;
                    }
                    Err(e) => {
                        warn!("[WRTC Media Video IN] Decrypt packet error: {e} (raw_astp len: {raw_len})");
                    }
                }
            }
        });

        let p2p_open = {
            let guard = p2p_session_opt.lock().await;
            guard.as_ref().map(|p| p.is_open.load(Ordering::SeqCst)).unwrap_or(false)
        };
        let effective_mode = Some(shared_peer.effective_mode(p2p_open).to_string());
        info!("[WRTC] Active transport mode: {:?}", effective_mode.as_deref().unwrap_or("UNKNOWN"));

        let remote_ip = bypass_ips.first().copied();
        Ok(ConnectionResult {
            auth_response,
            vpn_stream: Box::new(client_stream),
            endpoint: None,
            connection: None,
            health_pause: None,
            remote_ip,
            bypass_ips,
            effective_mode,
        })
    }
}
