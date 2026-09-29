use crate::http_help::BrowserProfile;
use crate::wrtc::stealth::{apply_ws_browser_headers, generate_random_guest_name};
use crate::wrtc::xmpp_xml::{escape_xml_attr, parse_xmpp_stanzas, InboundXmpp, XmppBuilder};
use futures::{SinkExt, StreamExt};
use rand::Rng;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;

pub struct XmppSession {
    pub endpoint_id: String,
    pub conference_id: String,
    pub jid: String,
    pub client_name: String,
    pub occupants: Arc<Mutex<HashSet<String>>>,
    write_tx: mpsc::Sender<String>,
    read_rx: mpsc::Receiver<String>,
}

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

    pub async fn connect(
        domain: &str,
        conference_id: &str,
        session_token: &str,
        client_name_opt: Option<&str>,
        profile: &BrowserProfile,
        ping_interval_secs: u64,
    ) -> anyhow::Result<Self> {
        let ws_url = format!(
            "wss://{domain}/jitsi/xmpp-websocket?room={conference_id}&sessionToken={session_token}"
        );
        let origin = format!("https://{domain}");
        log::info!("[XMPP] Connecting to signaling WebSocket: {ws_url}");

        let mut request = ws_url.as_str().into_client_request()?;
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_static("xmpp"),
        );

        apply_ws_browser_headers(&mut request, profile, &origin)?;

        let (ws_stream, response) = tokio_tungstenite::connect_async(request).await?;
        log::info!("[XMPP] WebSocket connected (HTTP status: {:?})", response.status());

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

        let effective_client_name = match client_name_opt {
            Some(name) if !name.is_empty() && name != "ANet-Node" => name.to_string(),
            _ => generate_random_guest_name(),
        };

        let timeout = Duration::from_secs(15);
        let occ_track = occupants.clone();
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
            Ok::<(), anyhow::Error>(())
        };

        tokio::time::timeout(timeout, handshake_fut)
            .await
            .map_err(|_| anyhow::anyhow!("XMPP MUC handshake timed out after 15s"))??;

        let (write_tx, mut write_rx) = mpsc::channel::<String>(128);
        let (read_tx, read_rx) = mpsc::channel::<String>(128);
        let (raw_ws_tx, mut raw_ws_rx) = mpsc::channel::<Message>(32);

        let ping_secs = if ping_interval_secs > 0 { ping_interval_secs } else { 20 };

        tokio::spawn(async move {
            let mut ping_interval = tokio::time::interval(Duration::from_secs(ping_secs));
            loop {
                tokio::select! {
                    stanza_opt = write_rx.recv() => {
                        match stanza_opt {
                            Some(stanza) => {
                                if let Err(e) = ws_sink.send(Message::text(stanza)).await {
                                    log::error!("[XMPP] Error sending stanza over WebSocket: {e}");
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                    raw_opt = raw_ws_rx.recv() => {
                        if let Some(msg) = raw_opt {
                            if ws_sink.send(msg).await.is_err() { break; }
                        } else { break; }
                    }
                    _ = ping_interval.tick() => {
                        // 1. WebSocket keepalive
                        if ws_sink.send(Message::Ping(bytes::Bytes::from_static(&[0x01, 0x02]))).await.is_err() {
                            break;
                        }
                        // 2. XMPP keepalive (предотвращает выселение Prosody по 120s c2s_timeout)
                        let ping_iq = XmppBuilder::ping("meet.jitsi", &format!("ping_{:08x}", rand::random::<u32>()));
                        if ws_sink.send(Message::text(ping_iq)).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let write_tx_ack = write_tx.clone();
        let occ_track_bg = occupants.clone();
        let raw_ws_tx_clone = raw_ws_tx.clone();

        tokio::spawn(async move {
            while let Some(msg_res) = ws_stream.next().await {
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
                                InboundXmpp::DiscoInfo { id, from } => {
                                    let disco_reply = XmppBuilder::disco_info_result(&from, &id);
                                    let _ = write_tx_ack.send(disco_reply).await;
                                }
                                InboundXmpp::Ping { id, from } => {
                                    let pong = XmppBuilder::iq_result(&from, &id);
                                    let _ = write_tx_ack.send(pong).await;
                                }
                                InboundXmpp::Jingle(ref sess) => {
                                    if let Some(ref iq_id) = sess.iq_id {
                                        let ack = XmppBuilder::iq_result(&sess.from, iq_id);
                                        let _ = write_tx_ack.send(ack).await;
                                    }
                                }
                                _ => {}
                            }
                        }

                        let _ = read_tx.try_send(text.to_string());
                    }
                    Ok(Message::Ping(data)) => {
                        let _ = raw_ws_tx_clone.send(Message::Pong(data)).await;
                    }
                    Ok(Message::Close(_)) | Err(_) => {
                        break;
                    }
                    _ => {}
                }
            }
        });

        Ok(Self {
            endpoint_id,
            conference_id: conference_id.to_string(),
            jid,
            client_name: effective_client_name,
            occupants,
            write_tx,
            read_rx,
        })
    }

    pub async fn accept_session(
        &self,
        sid: &str,
        focus_jid: &str,
        ssrc: u32,
        ufrag: &str,
        pwd: &str,
        fingerprint: &str,
        fingerprint_hash: &str,
        candidates: &[String],
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
                if ip == "0.0.0.0" {
                    continue;
                }
                candidate_xml.push_str(&format!(
                    r#"<candidate component="1" foundation="{foundation}" generation="0" id="c_{i}" ip="{ip}" port="{port}" priority="{priority}" protocol="{protocol}" type="{c_type}" network="0"/>"#
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
            &cname,
            &msid,
            ufrag,
            pwd,
            fingerprint_hash,
            fingerprint,
            &candidate_xml,
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
}
