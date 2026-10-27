use crate::config::WrtcConfig;
use crate::consts::{WRTC_XMPP_CHANNEL_CAPACITY, WRTC_XMPP_RAW_WS_CHANNEL_CAPACITY};
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
    write_tx: mpsc::Sender<String>,
    read_rx: mpsc::Receiver<String>,
    writer_handle: tokio::task::JoinHandle<()>,
    reader_handle: tokio::task::JoinHandle<()>,
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

        let tls_stream = tokio::time::timeout(
            Duration::from_secs(handshake_timeout_secs),
            profile.connect_ws_tls(domain, tcp_stream),
        )
        .await
        .map_err(|_| anyhow::anyhow!("XMPP BoringSSL TLS handshake with {domain} timed out"))??;

        let stream: Box<dyn VpnStream> = Box::new(tls_stream);
        let (ws_stream, response) = tokio::time::timeout(
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

        let (mut ws_sink, mut ws_stream) = ws_stream.split();

        let open_xml = XmppBuilder::open();
        log::info!("[XMPP OUT]: {open_xml}");
        ws_sink.send(Message::text(open_xml)).await?;

        let mut authed = false;
        let mut bind_sent = false;
        let mut bound = false;
        let mut jid = String::new();
        let endpoint_id = Self::generate_endpoint_id();
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
                                ws_sink
                                    .send(Message::text(XmppBuilder::auth_anonymous()))
                                    .await?;
                            }
                            InboundXmpp::SaslSuccess => {
                                log::info!("[XMPP] SASL auth success, resetting stream");
                                authed = true;
                                ws_sink.send(Message::text(XmppBuilder::open())).await?;
                            }
                            InboundXmpp::Features { has_bind }
                                if authed && has_bind && !bind_sent =>
                            {
                                bind_sent = true;
                                log::info!("[XMPP] Binding resource...");
                                ws_sink
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
                                ws_sink.send(Message::text(extdisco_req)).await?;

                                log::info!(
                                    "[XMPP] Entering MUC room {conference_id} with occupant {endpoint_id} (name: {effective_client_name})..."
                                );
                                let presence = XmppBuilder::muc_presence(
                                    conference_id,
                                    &endpoint_id,
                                    &effective_client_name,
                                );
                                ws_sink.send(Message::text(presence)).await?;
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
        let (raw_ws_tx, mut raw_ws_rx) = mpsc::channel::<Message>(WRTC_XMPP_RAW_WS_CHANNEL_CAPACITY);

        let ping_secs = if ping_interval_secs > 0 {
            ping_interval_secs.clamp(5, 25)
        } else {
            20
        };
        let read_timeout_dur = Duration::from_secs(ping_secs * 2 + handshake_timeout_secs);
        let write_timeout_dur = Duration::from_secs(wrtc_cfg.ws_write_timeout_secs.max(1));

        let writer_handle = tokio::spawn(async move {
            let mut ping_interval = tokio::time::interval(Duration::from_secs(ping_secs));
            loop {
                tokio::select! {
                    stanza_opt = write_rx.recv() => {
                        match stanza_opt {
                            Some(stanza) => {
                                if stanza == "__CLOSE__" {
                                    let _ = tokio::time::timeout(Duration::from_secs(2), ws_sink.close()).await;
                                    break;
                                }
                                match tokio::time::timeout(write_timeout_dur, ws_sink.send(Message::text(stanza))).await {
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
                            None => break,
                        }
                    }
                    raw_opt = raw_ws_rx.recv() => {
                        if let Some(msg) = raw_opt {
                            if tokio::time::timeout(write_timeout_dur, ws_sink.send(msg)).await.map_or(true, |r| r.is_err()) {
                                log::warn!("[XMPP] Failed or timed out sending raw WS control frame");
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                    _ = ping_interval.tick() => {
                        // 1. WebSocket keepalive
                        if tokio::time::timeout(
                            write_timeout_dur,
                            ws_sink.send(Message::Ping(bytes::Bytes::from_static(&[0x01, 0x02]))),
                        )
                        .await
                        .map_or(true, |r| r.is_err())
                        {
                            log::warn!("[XMPP] Failed or timed out sending WebSocket keepalive ping");
                            break;
                        }
                        // 2. XMPP keepalive (предотвращает выселение Prosody по 120s c2s_timeout)
                        let ping_iq = XmppBuilder::ping("meet.jitsi", &format!("ping_{:08x}", rand::random::<u32>()));
                        if tokio::time::timeout(write_timeout_dur, ws_sink.send(Message::text(ping_iq)))
                            .await
                            .map_or(true, |r| r.is_err())
                        {
                            log::warn!("[XMPP] Failed or timed out sending XMPP IQ ping");
                            break;
                        }
                    }
                }
            }
            log::warn!("[XMPP] Writer loop exited");
        });

        let write_tx_ack = write_tx.clone();
        let occ_track_bg = occupants.clone();
        let discovered_ice_bg = discovered_ice_servers.clone();
        let raw_ws_tx_clone = raw_ws_tx.clone();

        let reader_handle = tokio::spawn(async move {
            loop {
                let msg_opt = match tokio::time::timeout(read_timeout_dur, ws_stream.next()).await {
                    Ok(opt) => opt,
                    Err(_) => {
                        log::warn!(
                            "[XMPP] WebSocket read timed out after {:?} without incoming frames (half-open connection)",
                            read_timeout_dur
                        );
                        break;
                    }
                };
                let Some(msg_res) = msg_opt else {
                    break;
                };
                match msg_res {
                    Ok(Message::Text(text)) => {
                        let stanzas = parse_xmpp_stanzas(text.as_str(), "0.0.0.0", 0);
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
                                    let _ = write_tx_ack.try_send(disco_reply);
                                }
                                InboundXmpp::Ping { id, from } => {
                                    let pong = XmppBuilder::iq_result(&from, &id);
                                    log::info!("[XMPP OUT]: {pong}");
                                    let _ = write_tx_ack.try_send(pong);
                                }
                                InboundXmpp::Jingle(ref sess) => {
                                    if let Some(ref iq_id) = sess.iq_id {
                                        let ack = XmppBuilder::iq_result(&sess.from, iq_id);
                                        log::info!("[XMPP OUT]: {ack}");
                                        let _ = write_tx_ack.try_send(ack);
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

                        let _ = read_tx.try_send(text.to_string());
                    }
                    Ok(Message::Ping(data)) => {
                        let _ = raw_ws_tx_clone.try_send(Message::Pong(data));
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
            log::warn!("[XMPP] Reader loop exited (WebSocket stream ended)");
            let _ = write_tx_ack.try_send("__CLOSE__".to_string());
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
            write_tx,
            read_rx,
            writer_handle,
            reader_handle,
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
        let cname = format!("cname_{:08x}", rand::random::<u32>());
        let msid = format!("msid_{:08x}", rand::random::<u32>());

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
        let cname = format!("cname_{:08x}", rand::random::<u32>());
        let msid = format!("msid_{:08x}", rand::random::<u32>());

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
        let leave_stanza = XmppBuilder::muc_leave(&self.conference_id, &self.endpoint_id);
        log::info!(
            "[XMPP] Leaving MUC room {} as occupant {}: {}",
            self.conference_id,
            self.endpoint_id,
            leave_stanza
        );
        let _ = self.write_tx.try_send(leave_stanza);
        let _ = self.write_tx.try_send(XmppBuilder::close().to_string());
        let _ = self.write_tx.try_send("__CLOSE__".to_string());
        tokio::time::sleep(Duration::from_millis(60)).await;
        self.reader_handle.abort();
        self.writer_handle.abort();
    }
}

impl Drop for XmppSession {
    fn drop(&mut self) {
        let leave_stanza = XmppBuilder::muc_leave(&self.conference_id, &self.endpoint_id);
        let _ = self.write_tx.try_send(leave_stanza);
        let _ = self.write_tx.try_send(XmppBuilder::close().to_string());
        let _ = self.write_tx.try_send("__CLOSE__".to_string());
        self.reader_handle.abort();
        let writer_abort = self.writer_handle.abort_handle();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            writer_abort.abort();
        });
    }
}

