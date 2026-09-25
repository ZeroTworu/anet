use crate::http_help::BrowserProfile;
use crate::wrtc::stealth::{apply_ws_browser_headers, generate_random_guest_name};
use futures::{SinkExt, StreamExt};
use rand::Rng;
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
    write_tx: mpsc::Sender<String>,
    read_rx: mpsc::Receiver<String>,
}

impl XmppSession {
    pub fn generate_endpoint_id() -> String {
        let mut rng = rand::thread_rng();
        let val: u32 = rng.r#gen();
        format!("{val:08x}")
    }

    /// Connect to Ktalk Jitsi XMPP WebSocket, perform SASL ANONYMOUS, join MUC room,
    /// with browser stealth headers, natural guest name, and dual keep-alive ping.
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
        log::debug!("[XMPP] WebSocket handshake response: {:?}", response.status());

        let (mut ws_sink, mut ws_stream) = ws_stream.split();

        // 1. Initial framing open
        log::debug!("[XMPP] Sending initial framing open");
        ws_sink
            .send(Message::text(
                r#"<open to="meet.jitsi" version="1.0" xmlns="urn:ietf:params:xml:ns:xmpp-framing"/>"#,
            ))
            .await?;

        // 2. Wait for features with SASL mechanism ANONYMOUS
        let mut authed = false;
        let mut bound = false;
        let mut jid = String::new();
        let endpoint_id = Self::generate_endpoint_id();

        let effective_client_name = match client_name_opt {
            Some(name) if !name.is_empty() && name != "ANet-Node" => name.to_string(),
            _ => generate_random_guest_name(),
        };

        let timeout = Duration::from_secs(15);
        let handshake_fut = async {
            while let Some(msg_res) = ws_stream.next().await {
                let msg = msg_res?;
                if let Message::Text(text) = msg {
                    let text_str = text.as_str();
                    log::trace!("[XMPP HANDSHAKE]: {text_str}");

                    if text_str.contains(r#"<open"#) {
                        log::debug!("[XMPP] Stream opened, waiting for SASL mechanisms");
                    } else if text_str.contains(r#"<mechanisms"#) && !authed {
                        log::debug!("[XMPP] Requesting SASL ANONYMOUS auth");
                        ws_sink
                            .send(Message::text(
                                r#"<auth mechanism="ANONYMOUS" xmlns="urn:ietf:params:xml:ns:xmpp-sasl"/>"#,
                            ))
                            .await?;
                    } else if text_str.contains(r#"<success xmlns="urn:ietf:params:xml:ns:xmpp-sasl"#) {
                        log::debug!("[XMPP] SASL auth success, resetting stream");
                        authed = true;
                        ws_sink
                            .send(Message::text(
                                r#"<open to="meet.jitsi" version="1.0" xmlns="urn:ietf:params:xml:ns:xmpp-framing"/>"#,
                            ))
                            .await?;
                    } else if authed && text_str.contains(r#"<bind xmlns="urn:ietf:params:xml:ns:xmpp-bind"#) && !bound {
                        log::debug!("[XMPP] Binding resource");
                        ws_sink
                            .send(Message::text(
                                r#"<iq type="set" id="_bind_auth_2"><bind xmlns="urn:ietf:params:xml:ns:xmpp-bind"/></iq>"#,
                            ))
                            .await?;
                    } else if authed && text_str.contains(r#"id="_bind_auth_2""#) && text_str.contains(r#"<jid>"#) {
                        bound = true;
                        if let Some(start) = text_str.find("<jid>") {
                            if let Some(end) = text_str.find("</jid>") {
                                jid = text_str[start + 5..end].to_string();
                                log::info!("[XMPP] Bound JID: {jid}");
                            }
                        }

                        // 3. Send MUC presence to enter the conference room
                        log::info!(
                            "[XMPP] Entering MUC room {conference_id} with occupant {endpoint_id} (name: {effective_client_name})..."
                        );
                        let presence = format!(
                            r#"<presence to="{conference_id}@muc.meet.jitsi/{endpoint_id}"><x xmlns="http://jabber.org/protocol/muc"/><nick xmlns="http://jabber.org/protocol/nick">{effective_client_name}</nick></presence>"#
                        );
                        ws_sink.send(Message::text(presence)).await?;
                    } else if text_str.contains(r#"<presence"#) && text_str.contains(r#"status code="110""#) {
                        log::info!(
                            "[XMPP] Joined MUC room {conference_id} as occupant {endpoint_id}"
                        );
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

        let ping_secs = if ping_interval_secs > 0 { ping_interval_secs } else { 30 };

        // Background write loop with dual ping (whitespace + WS ping)
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
                        // 1. WebSocket protocol ping
                        if let Err(e) = ws_sink.send(Message::Ping(vec![0x01, 0x02])).await {
                            log::debug!("[XMPP] WS ping send error: {e}");
                            break;
                        }
                        // 2. XMPP whitespace ping
                        if let Err(e) = ws_sink.send(Message::text(" ")).await {
                            log::debug!("[XMPP] XMPP whitespace ping send error: {e}");
                            break;
                        }
                    }
                }
            }
        });

        // Background read loop
        tokio::spawn(async move {
            while let Some(msg_res) = ws_stream.next().await {
                match msg_res {
                    Ok(Message::Text(text)) => {
                        log::trace!("[XMPP INCOMING]: {text}");
                        if read_tx.send(text.to_string()).await.is_err() {
                            break;
                        }
                    }
                    Ok(Message::Ping(p)) => {
                        log::trace!("[XMPP] Received Ping ({} bytes)", p.len());
                    }
                    Ok(Message::Close(c)) => {
                        log::info!("[XMPP] Signaling WebSocket closed: {c:?}");
                        break;
                    }
                    Err(e) => {
                        log::warn!("[XMPP] WebSocket read error: {e}");
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
            write_tx,
            read_rx,
        })
    }

    /// Request Jicofo bridge conference allocation IQ.
    pub async fn request_conference_allocation(&self) -> anyhow::Result<()> {
        let iq = format!(
            r#"<iq type="set" to="focus@auth.meet.jitsi" id="conf_req_1"><conference xmlns="http://jitsi.org/protocol/focus" room="{}@muc.meet.jitsi"/></iq>"#,
            self.conference_id
        );
        self.send_stanza(iq).await
    }

    /// Send an XMPP stanza.
    pub async fn send_stanza(&self, stanza: String) -> anyhow::Result<()> {
        self.write_tx
            .send(stanza)
            .await
            .map_err(|_| anyhow::anyhow!("XMPP write channel closed"))
    }

    /// Receive the next XMPP stanza.
    pub async fn recv_stanza(&mut self) -> Option<String> {
        self.read_rx.recv().await
    }
}
