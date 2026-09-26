use crate::http_help::BrowserProfile;
use crate::wrtc::stealth::{apply_ws_browser_headers, generate_random_guest_name};
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

fn extract_attr(text: &str, attr_name: &str) -> Option<String> {
    let pattern_double = format!("{attr_name}=\"");
    if let Some(pos) = text.find(&pattern_double) {
        let start = pos + pattern_double.len();
        let end = text[start..].find('"')? + start;
        return Some(text[start..end].to_string());
    }
    let pattern_single = format!("{attr_name}='");
    if let Some(pos) = text.find(&pattern_single) {
        let start = pos + pattern_single.len();
        let end = text[start..].find('\'')? + start;
        return Some(text[start..end].to_string());
    }
    None
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

        let open_xml = r#"<open to="meet.jitsi" version="1.0" xmlns="urn:ietf:params:xml:ns:xmpp-framing"/>"#;
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
            while let Some(msg_res) = ws_stream.next().await {
                let msg = msg_res?;
                if let Message::Text(text) = msg {
                    let text_str = text.as_str();

                    // Трекинг участников из presence
                    if text_str.contains("<presence") {
                        if let Some(from) = extract_attr(text_str, "from") {
                            if let Some(occupant) = from.strip_prefix(&conf_muc) {
                                if occupant != my_ep && occupant != "focus" {
                                    if text_str.contains("type=\"unavailable\"") {
                                        occ_track.lock().unwrap().remove(occupant);
                                    } else {
                                        occ_track.lock().unwrap().insert(occupant.to_string());
                                        log::info!("[XMPP] Detected occupant in room: {occupant}");
                                    }
                                }
                            }
                        }
                    }

                    if text_str.contains(r#"<mechanisms"#) && !authed {
                        log::info!("[XMPP] SASL mechanisms received, sending ANONYMOUS auth");
                        let auth_xml = r#"<auth mechanism="ANONYMOUS" xmlns="urn:ietf:params:xml:ns:xmpp-sasl"/>"#;
                        ws_sink.send(Message::text(auth_xml)).await?;
                    } else if text_str.contains(r#"<success"#) && text_str.contains(r#"urn:ietf:params:xml:ns:xmpp-sasl"#) {
                        log::info!("[XMPP] SASL auth success, resetting stream");
                        authed = true;
                        let open_reset = r#"<open to="meet.jitsi" version="1.0" xmlns="urn:ietf:params:xml:ns:xmpp-framing"/>"#;
                        ws_sink.send(Message::text(open_reset)).await?;
                    }

                    if authed && text_str.contains("<features") && text_str.contains(r#"<bind xmlns="urn:ietf:params:xml:ns:xmpp-bind"#) && !bind_sent {
                        bind_sent = true;
                        log::info!("[XMPP] Binding resource...");
                        let bind_xml = r#"<iq type="set" id="_bind_auth_2"><bind xmlns="urn:ietf:params:xml:ns:xmpp-bind"/></iq>"#;
                        ws_sink.send(Message::text(bind_xml)).await?;
                    }

                    if authed && text_str.contains(r#"id="_bind_auth_2""#) && text_str.contains(r#"<jid>"#) && !bound {
                        bound = true;
                        if let Some(start) = text_str.find("<jid>") {
                            if let Some(end) = text_str.find("</jid>") {
                                jid = text_str[start + 5..end].to_string();
                                log::info!("[XMPP] Bound JID: {jid}");
                            }
                        }

                        log::info!(
                            "[XMPP] Entering MUC room {conference_id} with occupant {endpoint_id} (name: {effective_client_name})..."
                        );
                        let presence = format!(
                            r#"<presence to="{conference_id}@muc.meet.jitsi/{endpoint_id}"><x xmlns="http://jabber.org/protocol/muc"/><nick xmlns="http://jabber.org/protocol/nick">{effective_client_name}</nick><c xmlns="http://jabber.org/protocol/caps" hash="sha-1" node="https://jitsi.org/jitsi-meet" ver="7Y4Yx3m5c03c5188efb8b2ebda41e8c072e912da"/><jitsi_participant_id>{endpoint_id}</jitsi_participant_id></presence>"#
                        );
                        ws_sink.send(Message::text(presence)).await?;
                    }

                    if text_str.contains(r#"<presence"#) && (text_str.contains(r#"code="110""#) || text_str.contains(r#"code='110'"#)) {
                        log::info!(
                            "[XMPP] Successfully joined MUC room {conference_id} as occupant {endpoint_id}"
                        );
                        break;
                    }

                    if text_str.contains(r#"<failure xmlns="urn:ietf:params:xml:ns:xmpp-sasl"#) {
                        anyhow::bail!("XMPP SASL authentication failed: {text_str}");
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

        let ping_secs = if ping_interval_secs > 0 { ping_interval_secs } else { 30 };

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
                    _ = ping_interval.tick() => {
                        if ws_sink.send(Message::Ping(bytes::Bytes::from_static(&[0x01, 0x02]))).await.is_err() {
                            break;
                        }
                        if ws_sink.send(Message::text(" ")).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let write_tx_ack = write_tx.clone();
        let occ_track_bg = occupants.clone();
        tokio::spawn(async move {
            while let Some(msg_res) = ws_stream.next().await {
                match msg_res {
                    Ok(Message::Text(text)) => {
                        let text_str = text.as_str();

                        // Трекинг участников в фоне
                        if text_str.contains("<presence") {
                            if let Some(from) = extract_attr(text_str, "from") {
                                if let Some(occupant) = from.strip_prefix(&conf_muc) {
                                    if occupant != my_ep && occupant != "focus" {
                                        if text_str.contains("type=\"unavailable\"") {
                                            occ_track_bg.lock().unwrap().remove(occupant);
                                        } else {
                                            occ_track_bg.lock().unwrap().insert(occupant.to_string());
                                        }
                                    }
                                }
                            }
                        }

                        if text_str.contains("disco#info") && (text_str.contains("type=\"get\"") || text_str.contains("type='get'")) {
                            if let (Some(iq_id), Some(from_jid)) = (extract_attr(text_str, "id"), extract_attr(text_str, "from")) {
                                let disco_reply = format!(
                                    r#"<iq type="result" to="{from_jid}" id="{iq_id}"><query xmlns="http://jabber.org/protocol/disco#info"><identity category="client" type="web" name="jitsi-meet"/><feature var="urn:xmpp:jingle:1"/><feature var="urn:xmpp:jingle:apps:rtp:1"/><feature var="urn:xmpp:jingle:apps:rtp:audio"/><feature var="urn:xmpp:jingle:apps:rtp:video"/><feature var="urn:xmpp:jingle:apps:dtls:0"/><feature var="urn:xmpp:jingle:transports:ice-udp:1"/><feature var="http://jitsi.org/protocols/colibri"/><feature var="urn:ietf:rfc:5761"/><feature var="urn:ietf:rfc:5888"/><feature var="http://jabber.org/protocol/caps"/></query></iq>"#
                                );
                                let _ = write_tx_ack.send(disco_reply).await;
                            }
                        }

                        if text_str.contains("urn:xmpp:jingle:1") && (text_str.contains("type=\"set\"") || text_str.contains("type='set'")) {
                            if let (Some(iq_id), Some(from_jid)) = (extract_attr(text_str, "id"), extract_attr(text_str, "from")) {
                                let ack = format!(r#"<iq type="result" to="{from_jid}" id="{iq_id}"/>"#);
                                let _ = write_tx_ack.send(ack).await;
                            }
                        }

                        if read_tx.send(text.to_string()).await.is_err() {
                            break;
                        }
                    }
                    Ok(Message::Ping(_)) => {}
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

    pub async fn request_conference_allocation(&self) -> anyhow::Result<()> {
        let conf_room = format!("{}@muc.meet.jitsi", self.conference_id);
        let iq_id = format!("conf_alloc_{}", self.endpoint_id);
        let stanza = format!(
            r#"<iq to="focus.meet.jitsi" type="set" id="{iq_id}"><conference xmlns="http://jitsi.org/protocol/focus" room="{conf_room}" machine-uid="{}"/></iq>"#,
            self.endpoint_id
        );
        log::info!(
            "[XMPP] Requesting conference focus allocation for {conf_room} (machine-uid: {})...",
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
