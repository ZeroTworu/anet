use crate::config::WrtcConfig;
use crate::consts::WRTC_XMPP_CHANNEL_CAPACITY;
use crate::http_help::BrowserProfile;
use crate::wrtc::stealth::generate_random_guest_name;
use crate::wrtc::xmpp_xml::{
    escape_xml_attr, parse_xmpp_stanzas, InboundXmpp, XmppBuilder, XmppIceServer,
};
use futures::{SinkExt, StreamExt};
use rand::Rng;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;

pub struct XmppSession {
    pub endpoint_id: String,
    pub conference_id: String,
    pub jid: String,
    pub client_name: String,
    pub profile: BrowserProfile,
    pub origin: String,
    pub remote_ip: Option<std::net::IpAddr>,
    pub occupants: Arc<Mutex<HashSet<String>>>,
    pub discovered_ice_servers: Arc<Mutex<Vec<XmppIceServer>>>,
    active_jingle: Arc<Mutex<Option<(String, String, u32, u32)>>>,
    write_tx: mpsc::Sender<String>,
    read_rx: mpsc::Receiver<String>,
    io_handle: tokio::task::JoinHandle<()>,
}

use crate::transport_trait::VpnStream;

impl XmppSession {
    pub fn generate_endpoint_id() -> String {
        let mut rng = rand::thread_rng();
        let val: u32 = rng.r#gen();
        format!("{val:08x}")
    }

    pub fn get_other_occupants(&self) -> Vec<String> {
        let occ = self.occupants.lock().unwrap();
        occ.iter().cloned().collect()
    }

    pub fn get_ice_servers(&self) -> Vec<XmppIceServer> {
        let servers = self.discovered_ice_servers.lock().unwrap();
        if !servers.is_empty() {
            servers.clone()
        } else {
            vec![
                XmppIceServer {
                    urls: vec!["stun:stun1.ktalk.host:34788".to_string()],
                    username: String::new(),
                    credential: String::new(),
                    host: "stun1.ktalk.host".to_string(),
                    port: 34788,
                    is_turn: false,
                    is_tcp_or_tls: false,
                },
                XmppIceServer {
                    urls: vec!["stun:stun3.ktalk.host:34788".to_string()],
                    username: String::new(),
                    credential: String::new(),
                    host: "stun3.ktalk.host".to_string(),
                    port: 34788,
                    is_turn: false,
                    is_tcp_or_tls: false,
                },
            ]
        }
    }

    pub fn get_stun_servers(&self) -> Vec<String> {
        self.get_ice_servers()
            .into_iter()
            .flat_map(|s| s.urls)
            .collect()
    }

    pub async fn connect(
        domain: &str,
        conference_id: &str,
        session_token: &str,
        client_name_opt: Option<&str>,
        profile: &BrowserProfile,
        ping_interval_secs: u64,
        wrtc_cfg: &WrtcConfig,
    ) -> anyhow::Result<Self> {
        Self::connect_with_endpoint(
            domain,
            conference_id,
            session_token,
            client_name_opt,
            None,
            profile,
            ping_interval_secs,
            wrtc_cfg,
        )
        .await
    }

    pub async fn connect_with_endpoint(
        domain: &str,
        conference_id: &str,
        session_token: &str,
        client_name_opt: Option<&str>,
        custom_endpoint_id: Option<String>,
        profile: &BrowserProfile,
        ping_interval_secs: u64,
        wrtc_cfg: &WrtcConfig,
    ) -> anyhow::Result<Self> {
        let ws_url = format!(
            "wss://{domain}/jitsi/xmpp-websocket?room={conference_id}&sessionToken={session_token}"
        );
        let origin = format!("https://{domain}");
        log::info!("[XMPP] Connecting to signaling WebSocket: {ws_url}");

        let mut request = profile.build_ws_request(&ws_url, Some(&origin))?;
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_static("xmpp"),
        );

        let handshake_timeout_secs = wrtc_cfg.xmpp_handshake_timeout_secs.max(1);
        let tcp_stream = tokio::time::timeout(
            Duration::from_secs(handshake_timeout_secs),
            tokio::net::TcpStream::connect((domain, 443)),
        )
        .await
        .map_err(|_| anyhow::anyhow!("XMPP TCP connect to {domain}:443 timed out"))??;
        let remote_ip = tcp_stream.peer_addr().ok().map(|a| a.ip());
        let _ = tcp_stream.set_nodelay(true);
        let sock_ref = socket2::SockRef::from(&tcp_stream);
        let ka = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(10))
            .with_interval(Duration::from_secs(5));
        let _ = sock_ref.set_tcp_keepalive(&ka);

        let tls_stream = tokio::time::timeout(
            Duration::from_secs(handshake_timeout_secs),
            profile.connect_ws_tls(domain, tcp_stream),
        )
        .await
        .map_err(|_| anyhow::anyhow!("XMPP BoringSSL TLS handshake with {domain} timed out"))??;

        let stream: Box<dyn VpnStream> = Box::new(tls_stream);
        let (mut ws_stream, response) = tokio::time::timeout(
            Duration::from_secs(handshake_timeout_secs),
            tokio_tungstenite::client_async_with_config(request, stream, None),
        )
        .await
        .map_err(|_| anyhow::anyhow!("XMPP WebSocket handshake timed out"))?
        .map_err(|e| anyhow::anyhow!("XMPP WebSocket handshake failed: {e}"))?;
        log::info!(
            "[XMPP] WebSocket connected (HTTP status: {:?}, remote_ip: {:?})",
            response.status(),
            remote_ip
        );

        let open_xml = XmppBuilder::open();
        log::info!("[XMPP OUT]: {open_xml}");
        ws_stream.send(Message::text(open_xml)).await?;

        let mut authed = false;
        let mut bind_sent = false;
        let mut bound = false;
        let mut jid = String::new();
        let endpoint_id = custom_endpoint_id
            .filter(|ep| !ep.is_empty())
            .unwrap_or_else(Self::generate_endpoint_id);
        let occupants = Arc::new(Mutex::new(HashSet::new()));
        let discovered_ice_servers = Arc::new(Mutex::new(Vec::new()));

        let effective_client_name = match client_name_opt {
            Some(name) if !name.is_empty() && name != "ANet-Node" => name.to_string(),
            _ => generate_random_guest_name(),
        };

        let timeout = Duration::from_secs(handshake_timeout_secs);
        let occ_track = occupants.clone();
        let discovered_ice_hs = discovered_ice_servers.clone();
        let my_ep = endpoint_id.clone();
        let conf_muc = format!("{conference_id}@muc.meet.jitsi/");

        let handshake_fut = async {
            let mut joined = false;
            while let Some(msg_res) = ws_stream.next().await {
                let msg = msg_res?;
                if let Message::Text(text) = msg {
                    log::info!("[XMPP IN]: {text}");
                    let stanzas = parse_xmpp_stanzas(text.as_str(), "0.0.0.0", 0);
                    for parsed in stanzas {
                        match parsed {
                            InboundXmpp::Presence {
                                from,
                                is_unavailable,
                                is_self_110,
                            } => {
                                if let Some(occupant) = from.strip_prefix(&conf_muc) {
                                    if occupant != my_ep && occupant != "focus" {
                                        if is_unavailable {
                                            occ_track.lock().unwrap().remove(occupant);
                                        } else {
                                            occ_track.lock().unwrap().insert(occupant.to_string());
                                            log::info!("[XMPP] Detected occupant in room: {occupant}");
                                        }
                                    }
                                }
                                if is_self_110 {
                                    log::info!(
                                        "[XMPP] Successfully joined MUC room {conference_id} as occupant {endpoint_id}"
                                    );
                                    joined = true;
                                    break;
                                }
                            }
                            InboundXmpp::ExtdiscoServices(ice_servers) => {
                                let urls: Vec<String> = ice_servers
                                    .iter()
                                    .flat_map(|s| s.urls.clone())
                                    .collect();
                                log::info!(
                                    "[XMPP] Discovered Ktalk ICE services (STUN/TURN/TURNS): {:?}",
                                    urls
                                );
                                *discovered_ice_hs.lock().unwrap() = ice_servers;
                            }
                            InboundXmpp::SaslMechanisms if !authed => {
                                log::info!("[XMPP] SASL mechanisms received, sending ANONYMOUS auth");
                                ws_stream
                                    .send(Message::text(XmppBuilder::auth_anonymous()))
                                    .await?;
                            }
                            InboundXmpp::SaslSuccess => {
                                log::info!("[XMPP] SASL auth success, resetting stream");
                                authed = true;
                                ws_stream.send(Message::text(XmppBuilder::open())).await?;
                            }
                            InboundXmpp::Features { has_bind }
                                if authed && has_bind && !bind_sent =>
                            {
                                bind_sent = true;
                                log::info!("[XMPP] Binding resource...");
                                ws_stream
                                    .send(Message::text(XmppBuilder::bind_resource("_bind_auth_2")))
                                    .await?;
                            }
                            InboundXmpp::BindResult {
                                id,
                                jid: bound_jid,
                            } if authed && id == "_bind_auth_2" && !bound => {
                                bound = true;
                                jid = bound_jid;
                                log::info!("[XMPP] Bound JID: {jid}");

                                // Запрашиваем STUN/TURN/TURNS-серверы Контура по XEP-0215 extdisco сразу после бинда,
                                // чтобы ответ гарантированно пришёл параллельно с входом в комнату MUC до session-initiate.
                                let extdisco_req = XmppBuilder::extdisco_services("extdisco_1");
                                log::info!("[XMPP OUT]: {extdisco_req}");
                                ws_stream.feed(Message::text(extdisco_req)).await?;

                                log::info!(
                                    "[XMPP] Entering MUC room {conference_id} with occupant {endpoint_id} (name: {effective_client_name})..."
                                );
                                let presence = XmppBuilder::muc_presence(
                                    conference_id,
                                    &endpoint_id,
                                    &effective_client_name,
                                );
                                ws_stream.feed(Message::text(presence)).await?;
                                ws_stream.flush().await?;
                            }
                            InboundXmpp::SaslFailure(err) => {
                                anyhow::bail!("XMPP SASL authentication failed: {err}");
                            }
                            _ => {}
                        }
                    }
                    if joined {
                        break;
                    }
                }
            }
            if !joined {
                anyhow::bail!("XMPP stream closed before MUC room join completed");
            }
            Ok::<(), anyhow::Error>(())
        };

        tokio::time::timeout(timeout, handshake_fut)
            .await
            .map_err(|_| {
                anyhow::anyhow!("XMPP MUC handshake timed out after {}s", handshake_timeout_secs)
            })??;

        let (write_tx, mut write_rx) = mpsc::channel::<String>(WRTC_XMPP_CHANNEL_CAPACITY);
        let (read_tx, read_rx) = mpsc::channel::<String>(WRTC_XMPP_CHANNEL_CAPACITY);

        let ping_secs = if ping_interval_secs > 0 {
            ping_interval_secs.clamp(3, 25)
        } else {
            15
        };
        let read_timeout_dur = Duration::from_secs(ping_secs * 2 + handshake_timeout_secs);
        let write_timeout_dur = Duration::from_secs(wrtc_cfg.ws_write_timeout_secs.max(1));

        let occ_track_bg = occupants.clone();
        let discovered_ice_bg = discovered_ice_servers.clone();

        // Единая задача I/O без ws_stream.split() (BiLock):
        // В tokio_boring::SslStream<TcpStream> чтение и запись делят один SSL state machine,
        // а конкурентный опрос SplitSink + SplitStream из двух разных tokio::spawn при коллизии
        // входящего Pong и второго ws_sink.send() затирает waker чтения.
        let io_handle = tokio::spawn(async move {
            let mut ping_interval = tokio::time::interval_at(
                tokio::time::Instant::now() + Duration::from_secs(ping_secs),
                Duration::from_secs(ping_secs),
            );
            ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut extdisco_interval = tokio::time::interval_at(
                tokio::time::Instant::now() + Duration::from_secs(600),
                Duration::from_secs(600),
            );
            extdisco_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            let mut last_inbound_at = tokio::time::Instant::now();

            loop {
                tokio::select! {
                    _ = tokio::time::sleep_until(last_inbound_at + read_timeout_dur) => {
                        log::warn!(
                            "[XMPP] WebSocket read timed out after {:?} without incoming frames (half-open connection)",
                            read_timeout_dur
                        );
                        break;
                    }
                    msg_opt = ws_stream.next() => {
                        let Some(msg_res) = msg_opt else {
                            log::warn!("[XMPP] WebSocket stream ended (EOF)");
                            break;
                        };
                        if msg_res.is_ok() {
                            last_inbound_at = tokio::time::Instant::now();
                        }
                        match msg_res {
                            Ok(Message::Text(text)) => {
                                let stanzas = parse_xmpp_stanzas(text.as_str(), "0.0.0.0", 0);
                                let mut ack_replies: Vec<String> = Vec::new();
                                for parsed in stanzas {
                                    match parsed {
                                        InboundXmpp::Presence {
                                            from,
                                            is_unavailable,
                                            ..
                                        } => {
                                            if let Some(occupant) = from.strip_prefix(&conf_muc) {
                                                if occupant != my_ep && occupant != "focus" {
                                                    if is_unavailable {
                                                        occ_track_bg.lock().unwrap().remove(occupant);
                                                    } else {
                                                        occ_track_bg
                                                            .lock()
                                                            .unwrap()
                                                            .insert(occupant.to_string());
                                                    }
                                                }
                                            }
                                        }
                                        InboundXmpp::DiscoInfo { id, from, node } => {
                                            let disco_reply =
                                                XmppBuilder::disco_info_result(&from, &id, node.as_deref());
                                            log::info!("[XMPP OUT]: {disco_reply}");
                                            ack_replies.push(disco_reply);
                                        }
                                        InboundXmpp::Ping { id, from } => {
                                            let pong = XmppBuilder::iq_result(&from, &id);
                                            log::info!("[XMPP OUT]: {pong}");
                                            ack_replies.push(pong);
                                        }
                                        InboundXmpp::Jingle(ref sess) => {
                                            if let Some(ref iq_id) = sess.iq_id {
                                                let ack = XmppBuilder::iq_result(&sess.from, iq_id);
                                                log::info!("[XMPP OUT]: {ack}");
                                                ack_replies.push(ack);
                                            }
                                        }
                                        InboundXmpp::ExtdiscoServices(ice_servers) => {
                                            let urls: Vec<String> = ice_servers
                                                .iter()
                                                .flat_map(|s| s.urls.clone())
                                                .collect();
                                            log::info!(
                                                "[XMPP] Discovered Ktalk ICE services (STUN/TURN/TURNS): {:?}",
                                                urls
                                            );
                                            let mut guard = discovered_ice_bg.lock().unwrap();
                                            *guard = ice_servers;
                                        }
                                        _ => {}
                                    }
                                }

                                if !ack_replies.is_empty() {
                                    let send_acks = async {
                                        for reply in ack_replies {
                                            ws_stream.feed(Message::text(reply)).await?;
                                        }
                                        ws_stream.flush().await
                                    };
                                    if tokio::time::timeout(write_timeout_dur, send_acks)
                                        .await
                                        .map_or(true, |r| r.is_err())
                                    {
                                        log::warn!("[XMPP] Failed or timed out flushing IQ ACK replies");
                                        break;
                                    }
                                }

                                let _ = read_tx.try_send(text.to_string());
                            }
                            Ok(Message::Ping(data)) => {
                                if tokio::time::timeout(write_timeout_dur, ws_stream.send(Message::Pong(data)))
                                    .await
                                    .map_or(true, |r| r.is_err())
                                {
                                    log::warn!("[XMPP] Failed or timed out sending WebSocket Pong");
                                    break;
                                }
                            }
                            Ok(Message::Close(frame)) => {
                                log::warn!("[XMPP] WebSocket closed by server: {frame:?}");
                                break;
                            }
                            Err(e) => {
                                log::warn!("[XMPP] WebSocket read error: {e}");
                                break;
                            }
                            _ => {}
                        }
                    }
                    stanza_opt = write_rx.recv() => {
                        let Some(first_stanza) = stanza_opt else {
                            break;
                        };
                        let mut batch = Vec::with_capacity(8);
                        let mut should_close = false;
                        if first_stanza == "__CLOSE__" {
                            should_close = true;
                        } else {
                            batch.push(first_stanza);
                        }
                        while batch.len() < 8 && !should_close {
                            match write_rx.try_recv() {
                                Ok(next_stanza) => {
                                    if next_stanza == "__CLOSE__" {
                                        should_close = true;
                                    } else {
                                        batch.push(next_stanza);
                                    }
                                }
                                Err(_) => break,
                            }
                        }

                        if !batch.is_empty() {
                            let send_batch = async {
                                for stanza in batch {
                                    ws_stream.feed(Message::text(stanza)).await?;
                                }
                                ws_stream.flush().await
                            };
                            match tokio::time::timeout(write_timeout_dur, send_batch).await {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => {
                                    log::warn!("[XMPP] Error sending stanza over WebSocket: {e}");
                                    break;
                                }
                                Err(_) => {
                                    log::warn!("[XMPP] Timeout sending stanza over WebSocket");
                                    break;
                                }
                            }
                        }

                        if should_close {
                            let _ = tokio::time::timeout(Duration::from_millis(500), ws_stream.flush()).await;
                            let _ = tokio::time::timeout(Duration::from_millis(500), ws_stream.close(None)).await;
                            break;
                        }
                    }
                    _ = ping_interval.tick() => {
                        // Коалесцируем WebSocket Ping и XMPP IQ ping в один TLS-запрос через feed() + flush()
                        let ping_iq = XmppBuilder::ping("meet.jitsi", &format!("ping_{:08x}", rand::random::<u32>()));
                        let send_keepalive = async {
                            ws_stream
                                .feed(Message::Ping(bytes::Bytes::from_static(&[0x01, 0x02])))
                                .await?;
                            ws_stream.feed(Message::text(ping_iq)).await?;
                            ws_stream.flush().await
                        };
                        if tokio::time::timeout(write_timeout_dur, send_keepalive)
                            .await
                            .map_or(true, |r| r.is_err())
                        {
                            log::warn!("[XMPP] Failed or timed out sending coalesced WebSocket + XMPP keepalive ping");
                            break;
                        }
                    }
                    _ = extdisco_interval.tick() => {
                        // Периодическое обновление динамических TURN/TURNS credentials по XEP-0215
                        let extdisco_iq = XmppBuilder::extdisco_services(&format!("extdisco_{:08x}", rand::random::<u32>()));
                        let _ = tokio::time::timeout(write_timeout_dur, ws_stream.send(Message::text(extdisco_iq))).await;
                    }
                }
            }
            log::warn!("[XMPP] I/O loop exited");
        });

        Ok(Self {
            endpoint_id,
            conference_id: conference_id.to_string(),
            jid,
            client_name: effective_client_name,
            profile: profile.clone(),
            origin,
            remote_ip,
            occupants,
            discovered_ice_servers,
            active_jingle: Arc::new(Mutex::new(None)),
            write_tx,
            read_rx,
            io_handle,
        })
    }

    pub async fn accept_session(
        &self,
        sid: &str,
        focus_jid: &str,
        ssrc: u32,
        video_ssrc: u32,
        video_payload_type: u8,
        ufrag: &str,
        pwd: &str,
        fingerprint: &str,
        fingerprint_hash: &str,
        candidates: &[String],
        has_data_channel: bool,
        has_video: bool,
    ) -> anyhow::Result<()> {
        let req_id = format!("accept_{:08x}", rand::random::<u32>());
        let cname = crate::wrtc::stealth::generate_random_uuid_v4();
        let msid = crate::wrtc::stealth::generate_random_uuid_v4();

        let mut candidate_xml = String::new();
        for (i, c_line) in candidates.iter().enumerate() {
            let parts: Vec<&str> = c_line.split_whitespace().collect();
            if parts.len() >= 8 && parts[6] == "typ" {
                let foundation = escape_xml_attr(parts[0]);
                let component = parts[1];
                if component != "1" {
                    continue;
                }
                let protocol = escape_xml_attr(&parts[2].to_lowercase());
                let priority = parts[3];
                let ip = escape_xml_attr(parts[4]);
                let port = parts[5];
                let c_type = escape_xml_attr(parts[7]);
                if ip == "0.0.0.0" || ip == "127.0.0.1" || ip.starts_with("127.") || ip.starts_with("172.112.") {
                    continue;
                }
                let mut rel_attr = String::new();
                let mut idx = 8;
                while idx + 1 < parts.len() {
                    if parts[idx] == "raddr" {
                        let raddr = escape_xml_attr(parts[idx + 1]);
                        rel_attr.push_str(&format!(r#" rel-addr="{raddr}""#));
                        idx += 2;
                    } else if parts[idx] == "rport" {
                        let rport = escape_xml_attr(parts[idx + 1]);
                        rel_attr.push_str(&format!(r#" rel-port="{rport}""#));
                        idx += 2;
                    } else {
                        idx += 1;
                    }
                }
                candidate_xml.push_str(&format!(
                    r#"<candidate component="1" foundation="{foundation}" generation="0" id="c_{i}" ip="{ip}" port="{port}" priority="{priority}" protocol="{protocol}" type="{c_type}"{rel_attr} network="0"/>"#
                ));
            }
        }

        if candidate_xml.is_empty() {
            log::warn!("[XMPP] No valid ICE candidates gathered for session-accept");
        }

        let stanza = XmppBuilder::jingle_session_accept(
            focus_jid,
            &req_id,
            &self.jid,
            sid,
            ssrc,
            video_ssrc,
            video_payload_type,
            &cname,
            &msid,
            ufrag,
            pwd,
            fingerprint_hash,
            fingerprint,
            &candidate_xml,
            has_data_channel,
            has_video,
        );

        let effective_video_ssrc = if has_video { video_ssrc } else { 0 };
        if let Ok(mut guard) = self.active_jingle.lock() {
            *guard = Some((
                sid.to_string(),
                focus_jid.to_string(),
                ssrc,
                effective_video_ssrc,
            ));
        }
        log::info!("[XMPP] Sending Jingle session-accept (sid: {sid}) to Jicofo ({focus_jid})...");
        self.send_stanza(stanza).await
    }

    pub async fn announce_source(
        &self,
        sid: &str,
        focus_jid: &str,
        ssrc: u32,
    ) -> anyhow::Result<()> {
        let req_id = format!("src_add_{:08x}", rand::random::<u32>());
        let cname = crate::wrtc::stealth::generate_random_uuid_v4();
        let msid = crate::wrtc::stealth::generate_random_uuid_v4();

        let stanza = XmppBuilder::jingle_source_add(
            focus_jid,
            &req_id,
            sid,
            ssrc,
            &cname,
            &msid,
        );
        log::info!("[XMPP] Announcing audio SSRC {ssrc} to Jicofo ({focus_jid})...");
        self.send_stanza(stanza).await
    }

    pub async fn request_conference_allocation(&self) -> anyhow::Result<()> {
        let iq_id = format!("conf_alloc_{}", self.endpoint_id);
        let stanza = XmppBuilder::conference_allocation(
            &self.conference_id,
            &self.endpoint_id,
            &iq_id,
        );
        log::info!(
            "[XMPP] Requesting conference focus allocation for {} (machine-uid: {})...",
            self.conference_id,
            self.endpoint_id
        );
        self.send_stanza(stanza).await
    }

    pub async fn send_stanza(&self, stanza: String) -> anyhow::Result<()> {
        log::info!("[XMPP OUT]: {stanza}");
        self.write_tx
            .send(stanza)
            .await
            .map_err(|_| anyhow::anyhow!("XMPP write channel closed"))
    }

    pub async fn recv_stanza(&mut self) -> Option<String> {
        let s = self.read_rx.recv().await;
        if let Some(ref text) = s {
            log::info!("[XMPP IN]: {text}");
        }
        s
    }

    pub async fn leave_room(&self) {
        if let Ok(mut guard) = self.active_jingle.lock() {
            if let Some((sid, focus_jid, ssrc, video_ssrc)) = guard.take() {
                if ssrc != 0 || video_ssrc != 0 {
                    let rm_id = format!("src_rm_{:08x}", rand::random::<u32>());
                    let rm_stanza = XmppBuilder::jingle_source_remove(
                        &focus_jid,
                        &rm_id,
                        &self.jid,
                        &sid,
                        ssrc,
                        video_ssrc,
                    );
                    log::info!(
                        "[XMPP] Sending Jingle source-remove (sid: {sid}, audio_ssrc: {ssrc}, video_ssrc: {video_ssrc}) to Jicofo ({focus_jid})..."
                    );
                    let _ = self.write_tx.try_send(rm_stanza);
                }
                let req_id = format!("term_{:08x}", rand::random::<u32>());
                let term_stanza = XmppBuilder::jingle_session_terminate(
                    &focus_jid,
                    &req_id,
                    &self.jid,
                    &sid,
                );
                log::info!(
                    "[XMPP] Sending Jingle session-terminate (sid: {sid}) to Jicofo ({focus_jid})..."
                );
                let _ = self.write_tx.try_send(term_stanza);
            }
        }
        let leave_stanza = XmppBuilder::muc_leave(&self.conference_id, &self.endpoint_id);
        log::info!(
            "[XMPP] Leaving MUC room {} as occupant {}: {}",
            self.conference_id,
            self.endpoint_id,
            leave_stanza
        );
        let _ = self.write_tx.try_send(leave_stanza);
        // Даём Prosody 120 мс на доставку IQ source-remove, session-terminate и presence unavailable в Jicofo
        // до отправки <close/> и закрытия WebSocket-соединения.
        tokio::time::sleep(Duration::from_millis(120)).await;
        let _ = self.write_tx.try_send(XmppBuilder::close().to_string());
        let _ = self.write_tx.try_send("__CLOSE__".to_string());
        for _ in 0..25 {
            if self.io_handle.is_finished() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.io_handle.abort();
    }
}

impl Drop for XmppSession {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.active_jingle.lock() {
            if let Some((sid, focus_jid, ssrc, video_ssrc)) = guard.take() {
                if ssrc != 0 || video_ssrc != 0 {
                    let rm_id = format!("src_rm_{:08x}", rand::random::<u32>());
                    let rm_stanza = XmppBuilder::jingle_source_remove(
                        &focus_jid,
                        &rm_id,
                        &self.jid,
                        &sid,
                        ssrc,
                        video_ssrc,
                    );
                    let _ = self.write_tx.try_send(rm_stanza);
                }
                let req_id = format!("term_{:08x}", rand::random::<u32>());
                let term_stanza = XmppBuilder::jingle_session_terminate(
                    &focus_jid,
                    &req_id,
                    &self.jid,
                    &sid,
                );
                let _ = self.write_tx.try_send(term_stanza);
            }
        }
        let leave_stanza = XmppBuilder::muc_leave(&self.conference_id, &self.endpoint_id);
        let _ = self.write_tx.try_send(leave_stanza);
        let _ = self.write_tx.try_send(XmppBuilder::close().to_string());
        let _ = self.write_tx.try_send("__CLOSE__".to_string());
        let io_abort = self.io_handle.abort_handle();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                tokio::time::sleep(Duration::from_millis(350)).await;
                io_abort.abort();
            });
        } else {
            io_abort.abort();
        }
    }
}

