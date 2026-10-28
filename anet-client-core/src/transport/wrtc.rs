use super::{ClientTransport, ConnectionResult};
use crate::auth::{AuthChannel, AuthHandler};
use crate::config::{CoreConfig, ServerConfig};
use anet_common::consts::{
    COALESCE_BUDGET_BYTES, MAX_VIDEO_BATCH_BYTES, VIDEO_BATCH_MARKER, VP8_ASTP_PREFIX_LEN,
    WRTC_BATCHER_MAX_BYTES, WRTC_BATCHER_MAX_DELAY_MS, WRTC_CLIENT_CONSTRAINTS_REASSERT_COUNT,
    WRTC_CLIENT_CONSTRAINTS_REASSERT_INTERVAL_SECS, WRTC_DEFAULT_FALLBACK_JVB_IP,
    WRTC_DEFAULT_FALLBACK_JVB_PORT, WRTC_DEFAULT_MAX_VIDEO_HEIGHT,
    WRTC_DISCOVER_BROADCAST_INTERVAL_SECS, WRTC_DUPLEX_BUFFER_SIZE, WRTC_ICE_GATHER_POLL_ATTEMPTS,
    WRTC_MIN_ASTP_VIDEO_FRAME_LEN, WRTC_MIN_IP_PACKET_LEN, WRTC_MIN_TUN_MTU,
    WRTC_P2P_ICE_GATHER_POLL_INTERVAL_MS, WRTC_UPLINK_BURST_MAX_PACKETS,
    WRTC_VIDEO_CHANNEL_CAPACITY, WRTC_WATCHDOG_TICK_SECS,
};
use anet_common::encryption::Cipher;
use anet_common::handshake_fragmentation::FragmentConfig;
use anet_common::http_help::BrowserProfile;
use anet_common::stream_framing::{FrameReader, frame_packet_into};
use anet_common::transport::{
    unwrap_packet_bytes, wrap_packet_padded, wrap_packet_slice, wrap_packet_slice_with_headroom,
};
use anet_common::wrtc::{
    batcher::{unpack_batch, PacketBatcher},
    colibri::{
        compute_server_endpoint_suffix_from_b64, verify_beacon, ColibriMessage, WrtcMessage,
    },
    jingle::{filter_p2p_sdp_relay_only, parse_jingle_session},
    ktalk::KtalkClient,
    peer::{create_p2p_channel, P2pSession, WrtcPeer},
    stealth::generate_random_guest_name,
    xmpp::XmppSession,
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::prelude::*;
use bytes::{BufMut, Bytes, BytesMut};
use log::{info, warn};
use rtc::peer_connection::sdp::RTCSessionDescription;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use crate::events::{status, warn};

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
        let tls_cfg = self.server.effective_tls_config(&self.config.stealth);
        anet_common::boring_tls::set_default_tls_config(tls_cfg.clone());
        let browser_profile = BrowserProfile::with_tls_config(tls_cfg);
        let guest_name = generate_random_guest_name();

        info!(
            "[WRTC] Connecting to Ktalk room '{}' at domain '{}' as '{}'...",
            room_name, domain, guest_name
        );

        let ktalk = KtalkClient::new(browser_profile.clone(), &self.config.wrtc)
            .context("Failed to initialize WRTC Ktalk client with BoringSSL TLS")?;
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
            &self.config.wrtc,
        )
            .await
            .context("Failed to establish XMPP session and join conference MUC")?;

        let fallback_ip = self
            .server
            .wrtc_fallback_jvb_ip
            .as_deref()
            .unwrap_or(WRTC_DEFAULT_FALLBACK_JVB_IP);
        let fallback_port = self
            .server
            .wrtc_fallback_jvb_port
            .unwrap_or(WRTC_DEFAULT_FALLBACK_JVB_PORT);

        let _ = xmpp.request_conference_allocation().await;

        let timeout_secs = self.server.timeout_secs.max(15);
        let mut parsed_session = None;
        let jingle_deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);

        while tokio::time::Instant::now() < jingle_deadline {
            match tokio::time::timeout(Duration::from_millis(400), xmpp.recv_stanza()).await {
                Ok(Some(stanza)) => {
                    if let Some(session) = parse_jingle_session(&stanza, fallback_ip, fallback_port) {
                        parsed_session = Some(session);
                        break;
                    }
                }
                Ok(None) => {
                    xmpp.leave_room().await;
                    anyhow::bail!("XMPP WebSocket closed while waiting for Jicofo session-initiate");
                }
                Err(_) => {}
            }
        }

        let Some(session) = parsed_session else {
            xmpp.leave_room().await;
            anyhow::bail!(
                "Failed to receive Jicofo session-initiate within {timeout_secs}s (no server or bridge session in room)"
            );
        };

        let mut bypass_ips: Vec<std::net::IpAddr> = Vec::new();

        if let Some(ip) = xmpp.remote_ip {
            if !ip.is_loopback() {
                bypass_ips.push(ip);
            }
        }
        if let Ok(ip) = domain.parse::<std::net::IpAddr>() {
            if !ip.is_loopback() {
                bypass_ips.push(ip);
            }
        } else if let Ok(resolved) = tokio::net::lookup_host((domain.as_str(), 443)).await {
            for addr in resolved {
                if !addr.ip().is_loopback() {
                    bypass_ips.push(addr.ip());
                }
            }
        }

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

        let mut extdisco_bypass_log: Vec<String> = Vec::new();
        for ice in xmpp.get_ice_servers() {
            let mut host_ips = Vec::new();
            if let Ok(ip) = ice.host.parse::<std::net::IpAddr>() {
                if !ip.is_loopback() {
                    bypass_ips.push(ip);
                    host_ips.push(ip);
                }
            } else if let Ok(resolved) = tokio::net::lookup_host((ice.host.as_str(), ice.port)).await {
                for addr in resolved {
                    if !addr.ip().is_loopback() {
                        bypass_ips.push(addr.ip());
                        host_ips.push(addr.ip());
                    }
                }
            }
            let proto_tag = ice
                .urls
                .first()
                .map(|u| u.as_str())
                .unwrap_or(ice.host.as_str());
            extdisco_bypass_log.push(format!("{proto_tag} -> {host_ips:?}"));
        }

        info!(
            "[WRTC] Resolved extdisco STUN/TURN/TURNS hosts for TUN bypass: {:?}",
            extdisco_bypass_log
        );
        status(format!(
            "[WRTC] Resolved extdisco STUN/TURN/TURNS bypass: {:?}",
            extdisco_bypass_log
        ));

        bypass_ips.sort_unstable();
        bypass_ips.dedup();
        info!("[WRTC] Discovered media bypass IPs: {:?}", bypass_ips);
        status(format!("[WRTC] Discovered media bypass IPs: {:?}", bypass_ips));

        let wrtc_mode = self.server.wrtc_transport_mode();
        info!("[WRTC] Selected WebRTC transport mode: {:?}", wrtc_mode);
        status(format!("[WRTC] Selected transport mode: {:?}", wrtc_mode));

        let audio_keepalive_ms = self.server.wrtc_media_keepalive_interval_ms.unwrap_or(20);
        let peer = match WrtcPeer::create(
            Some(&session),
            Some(&xmpp),
            fallback_ip,
            fallback_port,
            audio_keepalive_ms,
            wrtc_mode,
            &self.config.wrtc,
        )
            .await
        {
            Ok(p) => p,
            Err(e) => {
                xmpp.leave_room().await;
                return Err(e).context("Failed to initialize WebRTC PeerConnection and DataChannel");
            }
        };

        info!(
            "[WRTC] WebRTC Peer ICE configuration: {} | Local candidates: {:?}",
            peer.ice_tier_summary, peer.local_candidates_summary
        );
        status(format!(
            "[WRTC] ICE config: {} | Local candidates: {:?}",
            peer.ice_tier_summary, peer.local_candidates_summary
        ));

        info!("[WRTC] WebRTC Peer created. Starting server discovery...");
        status("[WRTC] WebRTC Peer created. Starting server discovery...");

        let client_nonce = format!("{:016x}", rand::random::<u64>());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
        let mut interval = tokio::time::interval(Duration::from_secs(
            WRTC_DISCOVER_BROADCAST_INTERVAL_SECS,
        ));

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

        let expected_srv_suffix = server_pub_key
            .and_then(|pk| compute_server_endpoint_suffix_from_b64(pk, &room_info.conference_id));

        let mut verified_server_id = None;
        while tokio::time::Instant::now() < deadline {
            tokio::select! {
                _ = interval.tick() => {
                    let (c_video_ssrc, c_mode_str) = match wrtc_mode {
                        anet_common::wrtc::colibri::WrtcMode::Ws => (None, "ws"),
                        anet_common::wrtc::colibri::WrtcMode::MediaVideo => (Some(peer.video_ssrc), "media_video"),
                        anet_common::wrtc::colibri::WrtcMode::P2pDirect => (None, "p2p_direct"),
                        anet_common::wrtc::colibri::WrtcMode::JvbDatachannel => (None, "jvb_datachannel"),
                        anet_common::wrtc::colibri::WrtcMode::Auto => (Some(peer.video_ssrc), "auto"),
                    };

                    let current_occupants = xmpp.get_other_occupants();
                    let target_occupants: Vec<String> = match expected_srv_suffix {
                        Some(ref suffix) => current_occupants
                            .into_iter()
                            .filter(|occ| occ.ends_with(suffix.as_str()))
                            .collect(),
                        None => current_occupants,
                    };
                    for occupant in target_occupants {
                        info!("[WRTC] Sending unicast e2ee-ping to server occupant: {occupant} (nonce: {client_nonce}, mode: {c_mode_str}, video_ssrc: {c_video_ssrc:?})");
                        status(format!("[WRTC] Sending unicast e2ee-ping to occupant: {occupant}"));
                        let unicast_discover = ColibriMessage::discover(
                            Some(occupant),
                            client_nonce.clone(),
                            c_video_ssrc,
                            Some(c_mode_str.to_string()),
                        );
                        let _ = peer.send(unicast_discover).await;
                    }
                }
                msg_opt = peer.recv() => {
                    if let Some(msg) = msg_opt {
                        if let WrtcMessage::Beacon { server_id, client_nonce: beacon_nonce, signature, video_ssrc, video_v2 } = msg.msg_payload {
                            info!("[WRTC] Received beacon from server: {server_id} (nonce match: {}, server_video_ssrc: {video_ssrc:?}, video_v2: {video_v2:?})", beacon_nonce == client_nonce);
                            status(format!("[WRTC] Received beacon from server: {server_id} (nonce match: {}, server_video_ssrc: {video_ssrc:?}, video_v2: {video_v2:?})", beacon_nonce == client_nonce));
                            if beacon_nonce == client_nonce {
                                if video_v2.unwrap_or(false) {
                                    peer.set_video_v2(true);
                                }
                                if wrtc_mode == anet_common::wrtc::colibri::WrtcMode::MediaVideo
                                    || wrtc_mode == anet_common::wrtc::colibri::WrtcMode::Auto
                                {
                                    if let Some(v_ssrc) = video_ssrc {
                                        peer.set_expected_peer_video_ssrc(v_ssrc);
                                        info!("[WRTC Client] Set expected server video SSRC: {v_ssrc}");
                                        status(format!("[WRTC Client] Set expected server video SSRC: {v_ssrc}"));

                                        // ИНЖЕКТИРУЕМ SSRC СЕРВЕРА В REMOTE_DESCRIPTION
                                        peer.add_remote_video_ssrc(v_ssrc).await;

                                        let constraints = anet_common::wrtc::colibri::ReceiverVideoConstraints::for_endpoint(
                                            &server_id,
                                            WRTC_DEFAULT_MAX_VIDEO_HEIGHT,
                                        );
                                        let _ = peer.send_video_constraints(&constraints).await;
                                    }
                                }
                                if let Some(pub_key) = server_pub_key {
                                    match verify_beacon(pub_key, &client_nonce, &server_id, &signature) {
                                        Ok(true) => {
                                            info!("[WRTC] Server beacon signature verified successfully! Server ID: {server_id}");
                                            status(format!("[WRTC] Server beacon signature verified successfully! Server ID: {server_id}"));
                                            verified_server_id = Some(server_id);
                                            break;
                                        }
                                        Ok(false) => {
                                            warn!("[WRTC] Server beacon signature verification FAILED! Check server_pub_key in client.toml vs server_signing_key in server.toml");
                                            warn("[WRTC] Server beacon signature verification FAILED! Check server_pub_key in client.toml vs server_signing_key in server.toml");
                                        }
                                        Err(e) => {
                                            warn!("[WRTC] Error verifying server beacon: {e:#}");
                                            warn(format!("[WRTC] Error verifying server beacon: {e:#}"));
                                        }
                                    }
                                } else {
                                    info!("[WRTC] No server_pub_key configured, accepting server: {server_id}");
                                    status(format!("[WRTC] No server_pub_key configured, accepting server: {server_id}"));
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

        let Some(target_server_id) = verified_server_id else {
            xmpp.leave_room().await;
            let _ = peer.close().await;
            anyhow::bail!(
                "Server discovery in room '{room_name}' timed out after {timeout_secs}s"
            );
        };

        info!("[WRTC] Starting ASTP authentication with server: {target_server_id}");
        status(format!("[WRTC] Starting ASTP authentication with server: {target_server_id}"));

        let shared_peer = Arc::new(peer);
        let auth_channel = WrtcAuthChannel {
            peer: shared_peer.clone(),
            target_server_id: target_server_id.clone(),
        };

        let auth_handler = match AuthHandler::new(&self.config, self.server.server_pub_key.as_deref()) {
            Ok(h) => h,
            Err(e) => {
                xmpp.leave_room().await;
                let _ = shared_peer.close().await;
                return Err(e);
            }
        };
        let (mut auth_response, shared_key) = match auth_handler.authenticate(&auth_channel).await {
            Ok(res) => res,
            Err(e) => {
                xmpp.leave_room().await;
                let _ = shared_peer.close().await;
                return Err(e);
            }
        };

        if wrtc_mode == anet_common::wrtc::colibri::WrtcMode::MediaVideo
            || wrtc_mode == anet_common::wrtc::colibri::WrtcMode::P2pDirect
            || wrtc_mode == anet_common::wrtc::colibri::WrtcMode::Auto
        {
            let server_mtu = auth_response.mtu;
            let video_overhead = i32::from(self.config.wrtc.video_mtu_overhead);
            let adjusted_mtu = server_mtu
                .saturating_sub(video_overhead)
                .max(WRTC_MIN_TUN_MTU);
            info!(
                "[WRTC] Adjusted TUN MTU to {} (server MTU {} - {}B WebRTC RTP/SCTP overhead)",
                adjusted_mtu,
                server_mtu,
                self.config.wrtc.video_mtu_overhead
            );
            auth_response.mtu = adjusted_mtu;
        }
        let max_video_batch_bytes = (auth_response.mtu as usize)
            .saturating_sub(30)
            .min(MAX_VIDEO_BATCH_BYTES);

        info!(
            "[WRTC] ASTP Authentication succeeded! Assigned VPN IP: {}",
            auth_response.ip
        );
        status(format!("[WRTC] ASTP Authentication succeeded! Assigned VPN IP: {}", auth_response.ip));
        let my_client_tag = anet_common::wrtc::colibri::client_tag_from_ip(&auth_response.ip);
        info!(
            "[WRTC] Fake Video Track client tag: 0x{:04X} (derived from IP {})",
            my_client_tag, auth_response.ip
        );

        let cipher = Arc::new(Cipher::new(&shared_key));
        let nonce_prefix: [u8; 4] = auth_response.nonce_prefix.as_slice().try_into()?;
        let sequence = Arc::new(AtomicU64::new(0));

        let p2p_session_opt: Arc<Mutex<Option<Arc<P2pSession>>>> = Arc::new(Mutex::new(None));
        let p2p_negotiating = Arc::new(AtomicBool::new(false));
        let p2p_xmpp_rot = p2p_session_opt.clone();
        let xmpp_arc = Arc::new(Mutex::new(xmpp));
        let xmpp_bg = Arc::clone(&xmpp_arc);
        let peer_xmpp = Arc::clone(&shared_peer);
        let target_srv_xmpp = target_server_id.clone();
        let fb_ip_owned = fallback_ip.to_string();
        let domain_xmpp = domain.clone();
        let room_name_xmpp = room_name.clone();
        let conf_id_xmpp = room_info.conference_id.clone();
        let profile_xmpp = browser_profile.clone();
        let wrtc_cfg_xmpp = self.config.wrtc.clone();
        let xmpp_jingle_task = tokio::spawn(async move {
            loop {
                if peer_xmpp.is_failed.load(Ordering::SeqCst) {
                    return;
                }
                let recv_res = {
                    let mut guard = xmpp_bg.lock().await;
                    tokio::time::timeout(Duration::from_millis(250), guard.recv_stanza()).await
                };
                match recv_res {
                    Ok(Some(stanza)) => {
                        for parsed in anet_common::wrtc::xmpp_xml::parse_xmpp_stanzas(
                            &stanza,
                            &fb_ip_owned,
                            fallback_port,
                        ) {
                            match parsed {
                                anet_common::wrtc::xmpp_xml::InboundXmpp::Jingle(jingle) => {
                                    if jingle.action == "session-terminate" {
                                        warn!(
                                            "[WRTC Client] Jicofo sent session-terminate (sid: {}, reason: {:?}). Triggering reconnect...",
                                            jingle.sid, jingle.reason
                                        );
                                        warn(format!(
                                            "[WRTC Client] Jingle session terminated ({:?}). Reconnecting...",
                                            jingle.reason
                                        ));
                                        peer_xmpp.failed_notify.notify_waiters();
                                        peer_xmpp.failed_notify.notify_one();
                                        return;
                                    } else if jingle.action == "source-add"
                                        || jingle.action == "description-info"
                                        || jingle.action == "session-initiate"
                                    {
                                        let expected_srv_ssrc = peer_xmpp
                                            .expected_peer_video_ssrc
                                            .load(Ordering::Relaxed);
                                        for v_ssrc in jingle.video_sources {
                                            // На клиенте привязываем только видео-SSRC сервера, игнорируя SSRC других клиентов в комнате
                                            if expected_srv_ssrc == 0 || v_ssrc == expected_srv_ssrc
                                            {
                                                peer_xmpp.add_remote_video_ssrc(v_ssrc).await;
                                            }
                                        }
                                    }
                                }
                                anet_common::wrtc::xmpp_xml::InboundXmpp::ExtdiscoServices(
                                    fresh_ice,
                                ) => {
                                    peer_xmpp.rotate_turn_credentials(&fresh_ice).await;
                                    if let Some(p2p) = p2p_xmpp_rot.lock().await.clone() {
                                        p2p.rotate_turn_credentials(&fresh_ice).await;
                                    }
                                }
                                anet_common::wrtc::xmpp_xml::InboundXmpp::Presence {
                                    from,
                                    is_unavailable: true,
                                    ..
                                } => {
                                    if let Some(occupant_id) = from.split('/').nth(1) {
                                        if occupant_id == target_srv_xmpp {
                                            warn!(
                                                "[WRTC Client] Server occupant {target_srv_xmpp} left the MUC room. Triggering immediate reconnect..."
                                            );
                                            warn(format!(
                                                "[WRTC Client] Server {target_srv_xmpp} left room. Reconnecting..."
                                            ));
                                            peer_xmpp.failed_notify.notify_waiters();
                                            peer_xmpp.failed_notify.notify_one();
                                            return;
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Ok(None) => {
                        // Если медиа-туннель (VP8 RTP / Colibri-WS / P2P) уже мёртв — немедленно реконнектим.
                        if peer_xmpp.check_dead_reason().is_some() {
                            warn!(
                                "[WRTC Client] XMPP signaling closed and media peer is dead. Triggering reconnect..."
                            );
                            peer_xmpp.failed_notify.notify_waiters();
                            peer_xmpp.failed_notify.notify_one();
                            return;
                        }

                        // Медиа-туннель ЖИВ! Не убиваем рабочий видео-канал из-за часового таймаута nginx на XMPP WS.
                        // Переподключаем сигнальный XMPP в фоне, чтобы продолжать мониторить присутствие сервера и ротировать TURN-креды.
                        info!(
                            "[WRTC Client] XMPP signaling WebSocket closed while media tunnel is healthy. Reconnecting XMPP in background without dropping VPN..."
                        );
                        let mut reconnected = false;
                        for attempt in 1..=3 {
                            if peer_xmpp.check_dead_reason().is_some() {
                                break;
                            }
                            let Ok(ktalk_bg) = KtalkClient::new(profile_xmpp.clone(), &wrtc_cfg_xmpp) else {
                                log::warn!("[WRTC/XMPP] Failed to initialize background Ktalk client");
                                continue;
                            };
                            let secret_bg = KtalkClient::generate_anonymous_secret();
                            let guest_bg = generate_random_guest_name();
                            if let Ok(auth_bg) = ktalk_bg
                                .authorize_session(
                                    &domain_xmpp,
                                    &room_name_xmpp,
                                    Some(&guest_bg),
                                    &secret_bg,
                                )
                                .await
                            {
                                if let Ok(new_xmpp) = XmppSession::connect(
                                    &domain_xmpp,
                                    &conf_id_xmpp,
                                    &auth_bg.token,
                                    Some(&guest_bg),
                                    &profile_xmpp,
                                    ping_secs,
                                    &wrtc_cfg_xmpp,
                                )
                                .await
                                {
                                    let fresh_ice = new_xmpp.get_ice_servers();
                                    peer_xmpp.rotate_turn_credentials(&fresh_ice).await;
                                    if let Some(p2p) = p2p_xmpp_rot.lock().await.clone() {
                                        p2p.rotate_turn_credentials(&fresh_ice).await;
                                    }
                                    let occupants = new_xmpp.get_other_occupants();
                                    if !occupants.iter().any(|o| o == &target_srv_xmpp) {
                                        warn!(
                                            "[WRTC Client] Server occupant {target_srv_xmpp} is no longer in MUC room after XMPP reconnect. Triggering tunnel reconnect..."
                                        );
                                        new_xmpp.leave_room().await;
                                        peer_xmpp.failed_notify.notify_waiters();
                                        peer_xmpp.failed_notify.notify_one();
                                        return;
                                    }
                                    info!(
                                        "[WRTC Client] Background XMPP signaling reconnected (attempt {attempt}); server {target_srv_xmpp} is present, media tunnel preserved!"
                                    );
                                    let mut guard = xmpp_bg.lock().await;
                                    *guard = new_xmpp;
                                    reconnected = true;
                                    break;
                                }
                            }
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }

                        if !reconnected {
                            // Если фоновый XMPP не поднялся, оставляем живой медиа-туннель работать под контролем
                            // внутритуннельного anet_ping/anet_pong и peer_xmpp.check_dead_reason().
                            info!(
                                "[WRTC Client] Background XMPP reconnect deferred; keeping active media tunnel alive under data-plane watchdog."
                            );
                            return;
                        }
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        });

        let spawn_p2p_handshake = {
            let p2p_store = p2p_session_opt.clone();
            let p2p_neg_flag = p2p_negotiating.clone();
            let peer_sig = shared_peer.clone();
            let target_srv = target_server_id.clone();
            let wrtc_cfg_p2p = self.config.wrtc.clone();
            let xmpp_for_p2p = xmpp_arc.clone();

            move |reason_label: &'static str| {
                if p2p_neg_flag
                    .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                    .is_err()
                {
                    return;
                }
                let p2p_store = p2p_store.clone();
                let p2p_neg_flag = p2p_neg_flag.clone();
                let peer_sig = peer_sig.clone();
                let target_srv = target_srv.clone();
                let wrtc_cfg_p2p = wrtc_cfg_p2p.clone();
                let xmpp_for_p2p = xmpp_for_p2p.clone();

                tokio::spawn(async move {
                    info!(
                        "[P2P Direct] {reason_label}: initiating Relay-Only WebRTC P2P DataChannel with server {target_srv}..."
                    );
                    status(format!(
                        "[P2P Direct] {reason_label}: initiating Relay-Only P2P with {target_srv}..."
                    ));
                    let fresh_ice = {
                        let guard = xmpp_for_p2p.lock().await;
                        guard.get_ice_servers()
                    };
                    match create_p2p_channel(&fresh_ice, &wrtc_cfg_p2p, &peer_sig.bind_addr).await {
                        Ok(p2p) => {
                            let p2p_arc = Arc::new(p2p);
                            let old_p2p = {
                                let mut guard = p2p_store.lock().await;
                                guard.replace(p2p_arc.clone())
                            };
                            if let Some(prev) = old_p2p {
                                prev.close().await;
                            }

                            match p2p_arc.pc.create_offer(None).await {
                                Ok(offer) => {
                                    if let Err(e) =
                                        p2p_arc.pc.set_local_description(offer.clone()).await
                                    {
                                        warn!("[P2P Direct] set_local_description error: {e}");
                                        warn(format!(
                                            "[P2P Direct] set_local_description error: {e}"
                                        ));
                                        p2p_neg_flag.store(false, Ordering::SeqCst);
                                        return;
                                    }
                                    let mut final_sdp = offer.sdp.clone();
                                    for _ in 0..WRTC_ICE_GATHER_POLL_ATTEMPTS {
                                        if let Some(desc) = p2p_arc.pc.local_description().await {
                                            if desc.sdp.contains("a=candidate:") {
                                                final_sdp = desc.sdp;
                                                if final_sdp.contains("typ relay") {
                                                    break;
                                                }
                                            }
                                        }
                                        tokio::time::sleep(Duration::from_millis(
                                            WRTC_P2P_ICE_GATHER_POLL_INTERVAL_MS,
                                        ))
                                        .await;
                                    }
                                    if final_sdp.is_empty() {
                                        if let Some(desc) = p2p_arc.pc.local_description().await {
                                            final_sdp = desc.sdp;
                                        }
                                    }
                                    let relay_only_sdp = filter_p2p_sdp_relay_only(&final_sdp);

                                    let offer_msg = ColibriMessage::p2p_offer(
                                        target_srv.clone(),
                                        relay_only_sdp,
                                        vec![],
                                    );
                                    if let Err(e) = peer_sig.send(offer_msg).await {
                                        warn!("[P2P Direct] Failed to send ice-offer: {e}");
                                        warn(format!("[P2P Direct] Send failed: {e}"));
                                    } else {
                                        info!("[P2P Direct] Sent Relay-Only ice-offer to server {target_srv}");
                                        status(format!(
                                            "[P2P Direct] Sent Relay-Only ice-offer to server {target_srv}"
                                        ));
                                    }
                                }
                                Err(e) => {
                                    warn!("[P2P Direct] create_offer error: {e}");
                                    warn(format!("[P2P Direct] Create offer error: {e}"));
                                }
                            }
                        }
                        Err(e) => {
                            warn!("[P2P Direct] Failed to create P2P channel: {e:#}");
                        }
                    }
                    p2p_neg_flag.store(false, Ordering::SeqCst);
                });
            }
        };

        if wrtc_mode == anet_common::wrtc::colibri::WrtcMode::P2pDirect {
            spawn_p2p_handshake("Initial connect");
        }

        let (client_stream, internal_router) = tokio::io::duplex(WRTC_DUPLEX_BUFFER_SIZE);
        let (mut tunnel_read, mut tunnel_write) = tokio::io::split(internal_router);

        let (tun_inject_tx, mut tun_inject_rx) =
            tokio::sync::mpsc::channel::<Bytes>(WRTC_VIDEO_CHANNEL_CAPACITY);

        let tunnel_writer_task = tokio::spawn(async move {
            let mut write_buf = BytesMut::with_capacity(COALESCE_BUDGET_BYTES);
            while let Some(packet) = tun_inject_rx.recv().await {
                write_buf.clear();
                frame_packet_into(&mut write_buf, &packet);
                while write_buf.len() < COALESCE_BUDGET_BYTES {
                    match tun_inject_rx.try_recv() {
                        Ok(next_pkt) => frame_packet_into(&mut write_buf, &next_pkt),
                        Err(_) => break,
                    }
                }
                if let Err(e) = tunnel_write.write_all(&write_buf).await {
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
        let first_client_rx = Arc::new(AtomicBool::new(true));
        let first_client_rx_tx = first_client_rx.clone();
        let last_video_rx_secs = Arc::new(AtomicU64::new(0));
        let last_video_rx_tx = last_video_rx_secs.clone();

        let tunnel_ping_interval_secs = self.config.wrtc.tunnel_ping_interval_secs.max(1);
        let tunnel_ping_timeout_secs = self.config.wrtc.tunnel_ping_timeout_secs.max(5);
        let mut ping_interval =
            tokio::time::interval(Duration::from_secs(tunnel_ping_interval_secs));
        let mut watchdog_interval =
            tokio::time::interval(Duration::from_secs(WRTC_WATCHDOG_TICK_SECS));
        watchdog_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut batch_interval =
            tokio::time::interval(Duration::from_millis(WRTC_BATCHER_MAX_DELAY_MS));
        let last_pong = Arc::new(AtomicU64::new(current_timestamp_secs()));
        let last_pong_tx = last_pong.clone();
        let mut batcher = PacketBatcher::new(WRTC_BATCHER_MAX_BYTES, WRTC_BATCHER_MAX_DELAY_MS);

        tokio::spawn(async move {
            const VIDEO_WARMUP_PAYLOAD: [u8; 16] = [
                VIDEO_BATCH_MARKER,
                0xFF,
                0xFF,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            let mut frame_reader = FrameReader::new();
            let mut pending_packet: Option<Bytes> = None;
            let mut video_batch_buf = BytesMut::with_capacity(max_video_batch_bytes + 64);
            let mut cached_p2p: Option<Arc<P2pSession>> = None;

            if (wrtc_mode == anet_common::wrtc::colibri::WrtcMode::MediaVideo
                || wrtc_mode == anet_common::wrtc::colibri::WrtcMode::Auto)
                && peer_tx.is_video_v2()
            {
                peer_tx.force_next_keyframe();
                for _ in 0..3 {
                    let seq = sequence_tx.fetch_add(1, Ordering::Relaxed);
                    if let Ok(enc_buf) = wrap_packet_slice_with_headroom(
                        &cipher_tx,
                        &nonce_prefix,
                        seq,
                        &VIDEO_WARMUP_PAYLOAD,
                        VP8_ASTP_PREFIX_LEN,
                    ) {
                        let _ = peer_tx
                            .send_video_frame_preallocated(my_client_tag, enc_buf)
                            .await;
                    }
                }
            }

            loop {
                tokio::select! {
                    biased;
                    packet_opt = async {
                        if let Some(p) = pending_packet.take() {
                            Some(p)
                        } else {
                            frame_reader.read_next_packet(&mut tunnel_read).await.ok().flatten()
                        }
                    } => {
                        let Some(mut packet) = packet_opt else { break; };

                        if wrtc_mode == anet_common::wrtc::colibri::WrtcMode::P2pDirect {
                            let need_refresh = cached_p2p
                                .as_ref()
                                .map(|p| !p.is_ready())
                                .unwrap_or(true);
                            if need_refresh {
                                cached_p2p = p2p_uplink.lock().await.clone();
                            }
                        }
                        let p2p_active = cached_p2p
                            .as_ref()
                            .map(|p| p.is_ready())
                            .unwrap_or(false);
                        let use_video = !p2p_active
                            && (wrtc_mode == anet_common::wrtc::colibri::WrtcMode::MediaVideo
                                || wrtc_mode == anet_common::wrtc::colibri::WrtcMode::Auto);

                        for _burst_idx in 0..WRTC_UPLINK_BURST_MAX_PACKETS {
                            if packet.len() >= WRTC_MIN_IP_PACKET_LEN {
                                // Zero-delay micro-batching мелких пакетов (TCP ACK, DNS) в единый VP8 RTP кадр
                                let mut batch_capable = p2p_active;
                                if use_video {
                                    let is_v2 = peer_tx.is_video_v2();
                                    let last_v_rx = last_video_rx_tx.load(Ordering::Relaxed);
                                    let video_warmed_up = !first_client_rx_tx.load(Ordering::Relaxed)
                                        && peer_tx.is_connected.load(Ordering::Relaxed)
                                        && (last_v_rx > 0
                                            && current_timestamp_secs().saturating_sub(last_v_rx) <= 5);
                                    batch_capable = is_v2 && video_warmed_up;
                                }
                                let mut batched_payload = false;

                                if batch_capable && (packet.len() + 3 < max_video_batch_bytes) {
                                    while let Ok(Some(next_pkt)) = frame_reader.try_next_packet() {
                                        if next_pkt.len() < WRTC_MIN_IP_PACKET_LEN {
                                            continue;
                                        }
                                        let current_len = if batched_payload {
                                            video_batch_buf.len()
                                        } else {
                                            1 + 2 + packet.len()
                                        };
                                        if current_len + 2 + next_pkt.len() <= max_video_batch_bytes {
                                            if !batched_payload {
                                                video_batch_buf.clear();
                                                video_batch_buf.put_u8(VIDEO_BATCH_MARKER);
                                                video_batch_buf.put_u16(packet.len() as u16);
                                                video_batch_buf.put_slice(&packet);
                                                batched_payload = true;
                                            }
                                            video_batch_buf.put_u16(next_pkt.len() as u16);
                                            video_batch_buf.put_slice(&next_pkt);
                                        } else {
                                            pending_packet = Some(next_pkt);
                                            break;
                                        }
                                    }
                                }

                                let seq = sequence_tx.fetch_add(1, Ordering::Relaxed);

                                if use_video {
                                    let last_v_rx = last_video_rx_tx.load(Ordering::Relaxed);
                                    let video_warmed_up = !first_client_rx_tx.load(Ordering::Relaxed)
                                        && peer_tx.is_connected.load(Ordering::Relaxed)
                                        && (last_v_rx > 0
                                            && current_timestamp_secs().saturating_sub(last_v_rx) <= 5);
                                    let payload_slice: &[u8] = if batched_payload {
                                        &video_batch_buf
                                    } else {
                                        &packet
                                    };
                                    match wrap_packet_slice_with_headroom(
                                        &cipher_tx,
                                        &nonce_prefix,
                                        seq,
                                        payload_slice,
                                        VP8_ASTP_PREFIX_LEN,
                                    ) {
                                        Ok(enc_buf) => {
                                            match peer_tx
                                                .send_video_frame_preallocated(my_client_tag, enc_buf)
                                                .await
                                            {
                                                Ok(frozen) => {
                                                    // До получения первого входящего видеокадра от сервера дублируем ASTP-срез
                                                    // в WS-батчер без копирования, чтобы не терять первые пакеты во время прогрева SFU.
                                                    if !video_warmed_up {
                                                        batcher.push(frozen.slice(VP8_ASTP_PREFIX_LEN..));
                                                        if batcher.should_flush() {
                                                            if let Some(batch_data) = batcher.flush() {
                                                                let b64 = BASE64_STANDARD.encode(&batch_data);
                                                                let msg = ColibriMessage::astp_batch(
                                                                    target_srv_tx.clone(),
                                                                    b64,
                                                                );
                                                                if let Err(e) = peer_tx.send(msg).await {
                                                                    warn!("[WRTC Client] Peer send batch error: {e}");
                                                                    return;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    warn!("[WRTC Media Video OUT] send error: {e}");
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!("[WRTC Client] wrap_packet error: {e}");
                                            warn(format!("[WRTC Client] wrap_packet error: {e}"));
                                        }
                                    }
                                } else {
                                    let enc_res = if p2p_active {
                                        let payload_slice: &[u8] = if batched_payload {
                                            &video_batch_buf
                                        } else {
                                            &packet
                                        };
                                        wrap_packet_slice(&cipher_tx, &nonce_prefix, seq, payload_slice, 0)
                                    } else {
                                        wrap_packet_padded(&cipher_tx, &nonce_prefix, seq, packet, padding_step)
                                    };

                                    match enc_res {
                                        Ok(enc_bytes) => {
                                            let mut sent_p2p = false;
                                            if let Some(ref p2p) = cached_p2p {
                                                if p2p_active {
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
                                                        let msg = ColibriMessage::astp_batch(
                                                            target_srv_tx.clone(),
                                                            b64,
                                                        );
                                                        if let Err(e) = peer_tx.send(msg).await {
                                                            warn!("[WRTC Client] Peer send batch error: {e}");
                                                            return;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!("[WRTC Client] wrap_packet error: {e}");
                                            warn(format!("[WRTC Client] wrap_packet error: {e}"));
                                        }
                                    }
                                }
                            }

                            if let Some(next_p) = pending_packet.take() {
                                packet = next_p;
                            } else if let Ok(Some(next_p)) = frame_reader.try_next_packet() {
                                packet = next_p;
                            } else {
                                break;
                            }
                        }

                        // Сбрасываем накопленный в этом бурсте батч сразу после осушения буфера,
                        // не дожидаясь 3-миллисекундного таймера batch_interval!
                        if !batcher.is_empty() && pending_packet.is_none() {
                            if let Some(batch_data) = batcher.flush() {
                                let b64 = BASE64_STANDARD.encode(&batch_data);
                                let msg = ColibriMessage::astp_batch(
                                    target_srv_tx.clone(),
                                    b64,
                                );
                                if let Err(e) = peer_tx.send(msg).await {
                                    warn!("[WRTC Client] Peer send batch error: {e}");
                                    return;
                                }
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
                                    warn(format!("[WRTC Client] Peer send batch error: {e}"));
                                    break;
                                }
                            }
                        }
                    }
                    _ = ping_interval.tick() => {
                        let now = current_timestamp_secs();
                        if now.saturating_sub(last_pong_tx.load(Ordering::Relaxed)) > tunnel_ping_timeout_secs {
                            warn!(
                                "[WRTC Client] Ping timeout (no pong from server for {}s). Reconnecting...",
                                tunnel_ping_timeout_secs
                            );
                            warn(format!(
                                "[WRTC Client] Ping timeout (no pong from server for {}s). Reconnecting...",
                                tunnel_ping_timeout_secs
                            ));
                            break;
                        }
                        let ping_msg = ColibriMessage::ping(target_srv_tx.clone());
                        if let Err(e) = peer_tx.send(ping_msg).await {
                            warn!("[WRTC Client] Peer ping error: {e}");
                            warn(format!("[WRTC Client] Peer ping error: {e}"));
                            break;
                        }
                    }
                    _ = watchdog_interval.tick() => {
                        if let Some(reason) = peer_tx.check_dead_reason() {
                            warn!("[WRTC Client] Watchdog detected dead WebRTC session ({reason}). Reconnecting...");
                            warn(format!("[WRTC Client] Watchdog detected dead session ({reason}). Reconnecting..."));
                            break;
                        }
                        if wrtc_mode == anet_common::wrtc::colibri::WrtcMode::P2pDirect {
                            let need_reneg = {
                                let guard = p2p_uplink.lock().await;
                                match guard.as_ref() {
                                    Some(p2p) => p2p.should_renegotiate(6_000, 15_000),
                                    None => true,
                                }
                            };
                            if need_reneg {
                                cached_p2p = None;
                                spawn_p2p_handshake("Watchdog P2P auto-recovery");
                            }
                        }
                        if (wrtc_mode == anet_common::wrtc::colibri::WrtcMode::MediaVideo
                            || wrtc_mode == anet_common::wrtc::colibri::WrtcMode::Auto)
                            && peer_tx.is_video_v2()
                            && peer_tx.is_connected.load(Ordering::Relaxed)
                        {
                            let seq = sequence_tx.fetch_add(1, Ordering::Relaxed);
                            if let Ok(enc_buf) = wrap_packet_slice_with_headroom(
                                &cipher_tx,
                                &nonce_prefix,
                                seq,
                                &VIDEO_WARMUP_PAYLOAD,
                                VP8_ASTP_PREFIX_LEN,
                            ) {
                                let _ = peer_tx
                                    .send_video_frame_preallocated(my_client_tag, enc_buf)
                                    .await;
                            }
                        }
                    }
                    _ = peer_tx.failed_notify.notified() => {
                        warn!("[WRTC Client] WebRTC session or server signaling closed. Reconnecting...");
                        warn("[WRTC Client] WebRTC session or server signaling closed. Reconnecting...");
                        break;
                    }
                }
            }
            tunnel_writer_task.abort();
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
                                info!("[P2P Direct] Received ice-answer from server! Applying remote Relay-Only SDP...");
                                status("[P2P Direct] Received ice-answer from server! Applying remote SDP...");
                                let p2p_opt = {
                                    let guard = p2p_sig.lock().await;
                                    guard.clone()
                                };
                                if let Some(p2p) = p2p_opt {
                                    let relay_sdp = filter_p2p_sdp_relay_only(&sdp);
                                    if let Ok(answer_desc) = RTCSessionDescription::answer(relay_sdp) {
                                        if let Err(e) = p2p.pc.set_remote_description(answer_desc).await {
                                            warn!("[P2P Direct] set_remote_description error: {e}");
                                        } else {
                                            info!("[P2P Direct] Applied remote answer successfully. Awaiting DataChannel open...");
                                            status("[P2P Direct] Applied remote answer successfully. Awaiting DataChannel open...");
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
                                            Ok(decrypted) => {
                                                if decrypted.first() == Some(&VIDEO_BATCH_MARKER) {
                                                    let packets = unpack_batch(&decrypted[1..]);
                                                    for pkt in packets {
                                                        if pkt.len() >= WRTC_MIN_IP_PACKET_LEN {
                                                            let _ = tun_inject_ws.send(pkt).await;
                                                        }
                                                    }
                                                } else if decrypted.len() >= WRTC_MIN_IP_PACKET_LEN {
                                                    let _ = tun_inject_ws.send(decrypted).await;
                                                }
                                            }
                                            Err(e) => {
                                                warn!("[WRTC Client] Decrypt packet error: {e}");
                                                warn(format!("[WRTC Client] Decrypt packet error: {e}"));
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("[WRTC Client] Base64 decode error: {e}");
                                        warn(format!("[WRTC Client] wrap_packet error: {e}"));
                                    }
                                }
                            }
                            WrtcMessage::AstpBatch { data } => {
                                match BASE64_STANDARD.decode(&data) {
                                    Ok(raw_batch) => {
                                        let packets = unpack_batch(&raw_batch);
                                        for enc_pkt in packets {
                                            match unwrap_packet_bytes(&cipher_rx, enc_pkt) {
                                                Ok(decrypted) => {
                                                    if decrypted.first() == Some(&VIDEO_BATCH_MARKER) {
                                                        let inner_pkts = unpack_batch(&decrypted[1..]);
                                                        for pkt in inner_pkts {
                                                            if pkt.len() >= WRTC_MIN_IP_PACKET_LEN {
                                                                let _ = tun_inject_ws.send(pkt).await;
                                                            }
                                                        }
                                                    } else if decrypted.len() >= WRTC_MIN_IP_PACKET_LEN {
                                                        let _ = tun_inject_ws.send(decrypted).await;
                                                    }
                                                }
                                                Err(e) => {
                                                    warn!("[WRTC Client] Decrypt batch packet error: {e}");
                                                    warn(format!("[WRTC Client] Decrypt batch packet: {e}"));
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("[WRTC Client] Base64 batch decode error: {e}");
                                        warn(format!("[WRTC Client] Decrypt batch error: {e}"));
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
                        while let Some(first_bytes) = p2p.recv_packet().await {
                            let mut current_raw = Some(first_bytes);
                            while let Some(raw_bytes) = current_raw.take() {
                                match unwrap_packet_bytes(&cipher_p2p, raw_bytes) {
                                    Ok(decrypted) => {
                                        if decrypted.first() == Some(&VIDEO_BATCH_MARKER) {
                                            let packets = unpack_batch(&decrypted[1..]);
                                            for pkt in packets {
                                                if pkt.len() >= WRTC_MIN_IP_PACKET_LEN {
                                                    if tun_inject_p2p.send(pkt).await.is_err() {
                                                        return;
                                                    }
                                                }
                                            }
                                        } else if decrypted.len() >= WRTC_MIN_IP_PACKET_LEN {
                                            log::trace!("[P2P Direct IN] Decrypted packet ({} bytes)", decrypted.len());
                                            if tun_inject_p2p.send(decrypted).await.is_err() {
                                                return;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("[P2P Direct] Decrypt packet error: {e}");
                                        warn(format!("[P2P Direct] Decrypt packet error: {e}"));
                                    }
                                }
                                current_raw = p2p.try_recv_packet();
                            }
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        let peer_video_rx = shared_peer.clone();
        let cipher_video = cipher.clone();
        let tun_inject_video = tun_inject_tx.clone();

        if wrtc_mode == anet_common::wrtc::colibri::WrtcMode::MediaVideo
            || wrtc_mode == anet_common::wrtc::colibri::WrtcMode::Auto {
            let first_rx_clone = first_client_rx.clone();
            let peer_reassert = shared_peer.clone();
            let srv_ep_reassert = target_server_id.clone();
            tokio::spawn(async move {
                for _ in 0..WRTC_CLIENT_CONSTRAINTS_REASSERT_COUNT {
                    tokio::time::sleep(Duration::from_secs(
                        WRTC_CLIENT_CONSTRAINTS_REASSERT_INTERVAL_SECS,
                    ))
                    .await;
                    if !first_rx_clone.load(Ordering::Relaxed) {
                        break;
                    }
                    let constraints = anet_common::wrtc::colibri::ReceiverVideoConstraints::for_endpoint(
                        &srv_ep_reassert,
                        WRTC_DEFAULT_MAX_VIDEO_HEIGHT,
                    );
                    let _ = peer_reassert.send_video_constraints(&constraints).await;
                    log::debug!("[WRTC Client] Periodic re-assertion of ReceiverVideoConstraints for server endpoint {srv_ep_reassert}");
                }
            });
        }
        tokio::spawn(async move {
            'outer: while let Some(mut raw_frame) = peer_video_rx.recv_video_frame().await {
                loop {
                    if raw_frame.len() >= WRTC_MIN_ASTP_VIDEO_FRAME_LEN {
                        let tag = u16::from_be_bytes([raw_frame[0], raw_frame[1]]);
                        if tag == my_client_tag {
                            let raw_astp = raw_frame.slice(2..);
                            let raw_len = raw_astp.len();
                            match unwrap_packet_bytes(&cipher_video, raw_astp) {
                                Ok(decrypted) => {
                                    last_video_rx_secs.store(current_timestamp_secs(), Ordering::Relaxed);
                                    if first_client_rx.swap(false, Ordering::Relaxed) {
                                        info!(
                                            "[WRTC Client Video IN] First video frame decrypted from server (len: {} bytes, tag: 0x{:04X})",
                                            decrypted.len(), tag
                                        );
                                        status(format!("[WRTC Client Video IN] First video frame decrypted from server (len: {} bytes, tag: 0x{:04X})", decrypted.len(), tag));
                                    }
                                    if decrypted.first() == Some(&VIDEO_BATCH_MARKER) {
                                        let packets = unpack_batch(&decrypted[1..]);
                                        for pkt in packets {
                                            if pkt.len() >= WRTC_MIN_IP_PACKET_LEN {
                                                if tun_inject_video.send(pkt).await.is_err() {
                                                    break 'outer;
                                                }
                                            }
                                        }
                                    } else if decrypted.len() >= WRTC_MIN_IP_PACKET_LEN {
                                        log::trace!("[WRTC Media Video IN] Decrypted packet ({} bytes)", decrypted.len());
                                        if tun_inject_video.send(decrypted).await.is_err() {
                                            break 'outer;
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("[WRTC Media Video IN] Decrypt packet error: {e} (raw_astp len: {raw_len})");
                                    warn(format!("[WRTC Media Video IN] Decrypt packet error: {e} (raw_astp len: {raw_len})"));
                                }
                            }
                        }
                    }
                    match peer_video_rx.try_recv_video_frame() {
                        Some(next) => raw_frame = next,
                        None => break,
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
        status(format!("[WRTC] Effective mode: {:?}", effective_mode.as_deref().unwrap_or("UNKNOWN")));

        if let Some(ws_ip) = shared_peer.colibri_ws_ip() {
            if !ws_ip.is_loopback() && !bypass_ips.contains(&ws_ip) {
                bypass_ips.push(ws_ip);
            }
        }
        let remote_ip = bypass_ips.first().copied();
        let xmpp_shutdown = Arc::clone(&xmpp_arc);
        let peer_shutdown = Arc::clone(&shared_peer);
        let p2p_shutdown = Arc::clone(&p2p_session_opt);
        let shutdown_hook: super::ShutdownHook = Box::pin(async move {
            xmpp_jingle_task.abort();
            if let Some(p2p) = p2p_shutdown.lock().await.take() {
                p2p.close().await;
            }
            xmpp_shutdown.lock().await.leave_room().await;
            let _ = peer_shutdown.close().await;
        });

        Ok(ConnectionResult {
            auth_response,
            vpn_stream: Box::new(client_stream),
            endpoint: None,
            connection: None,
            health_pause: None,
            remote_ip,
            bypass_ips,
            effective_mode,
            shutdown_hook: Some(shutdown_hook),
        })
    }
}
