use crate::config::WrtcConfig;
use crate::consts::WRTC_XMPP_CHANNEL_CAPACITY;
use crate::http_help::BrowserProfile;
use crate::transport_trait::VpnStream;
use crate::wrtc::providers::ktalk::KonturTalkProvider;
use crate::wrtc::providers::{ProviderKind, RoomBootstrapInfo, WrtcProviderRegistry};
use crate::wrtc::stealth::generate_random_guest_name;
use crate::wrtc::xmpp_xml::{parse_xmpp_stanzas, InboundXmpp, XmppBuilder, XmppIceServer};
use futures::{SinkExt, StreamExt};
use rand::Rng;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

/// Внутренняя типизированная команда исходящей очереди XMPP I/O (без строковых сентинелов).
#[derive(Debug, Clone)]
enum XmppOutboundCmd {
    Stanza(String),
    Close,
}

/// Легковесный отправитель управляющих JSON-сообщений (`<json-message/>`) через XMPP MUC,
/// используемый `WrtcPeer` как резервный канал сигнализации при отсутствии Colibri-WS / SCTP.
#[derive(Clone)]
pub struct XmppJsonSender {
    conference_id: String,
    write_tx: mpsc::Sender<XmppOutboundCmd>,
}

impl XmppJsonSender {
    pub fn try_send_json(&self, to_occupant: Option<&str>, json_payload: &str) -> bool {
        let stanza = XmppBuilder::muc_json_message(&self.conference_id, to_occupant, json_payload);
        log::debug!("[XMPP OUT JSON]: {stanza}");
        self.write_tx
            .try_send(XmppOutboundCmd::Stanza(stanza))
            .is_ok()
    }
}

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
    colibri_sink: Arc<Mutex<Option<mpsc::Sender<crate::wrtc::colibri::ColibriMessage>>>>,
    default_ice_servers: Vec<XmppIceServer>,
    active_jingle: Arc<Mutex<Option<(String, String, u32, u32)>>>,
    write_tx: mpsc::Sender<XmppOutboundCmd>,
    read_rx: mpsc::Receiver<String>,
    io_handle: tokio::task::JoinHandle<()>,
}

/// Устанавливает TCP + BoringSSL TLS + WebSocket соединение к одному из URL сигналинга XMPP
/// с поддержкой быстрого перебора эфемерных исходных TCP-портов (Fast Ephemeral Port Hopping)
/// для обхода L4 ECMP / LAG фильтрации.
async fn open_xmpp_ws_stream(
    domain: &str,
    ws_urls: &[String],
    origin: &str,
    profile: &BrowserProfile,
    wrtc_cfg: &WrtcConfig,
) -> anyhow::Result<(WebSocketStream<Box<dyn VpnStream>>, Option<std::net::IpAddr>, String)> {
    let handshake_timeout_secs = wrtc_cfg.xmpp_handshake_timeout_secs.max(1);
    let hop_attempts = wrtc_cfg.tcp_port_hop_attempts.clamp(1, 16);
    let hop_timeout = Duration::from_millis(wrtc_cfg.tcp_port_hop_timeout_ms.clamp(300, 10_000));

    let mut last_err = None;
    for ws_url in ws_urls {
        for attempt in 1..=hop_attempts {
            let connect_timeout = if attempt == hop_attempts {
                Duration::from_secs(handshake_timeout_secs)
            } else {
                hop_timeout
            };

            let tcp_res = tokio::time::timeout(
                connect_timeout,
                tokio::net::TcpStream::connect((domain, 443)),
            )
            .await;

            let tcp_stream = match tcp_res {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    log::debug!(
                        "[XMPP] TCP connect attempt {}/{} to {}:443 failed: {}",
                        attempt,
                        hop_attempts,
                        domain,
                        e
                    );
                    last_err = Some(anyhow::anyhow!("XMPP TCP connect to {domain}:443 failed: {e}"));
                    continue;
                }
                Err(_) => {
                    log::debug!(
                        "[XMPP] TCP connect attempt {}/{} to {}:443 timed out after {:?} (hopping source port)",
                        attempt,
                        hop_attempts,
                        domain,
                        connect_timeout
                    );
                    last_err = Some(anyhow::anyhow!("XMPP TCP connect to {domain}:443 timed out"));
                    continue;
                }
            };

            let remote_ip = tcp_stream.peer_addr().ok().map(|a| a.ip());
            let local_port = tcp_stream.local_addr().ok().map(|a| a.port()).unwrap_or(0);
            let _ = tcp_stream.set_nodelay(true);
            let sock_ref = socket2::SockRef::from(&tcp_stream);
            let ka = socket2::TcpKeepalive::new()
                .with_time(Duration::from_secs(10))
                .with_interval(Duration::from_secs(5));
            let _ = sock_ref.set_tcp_keepalive(&ka);

            let tls_res = tokio::time::timeout(
                Duration::from_secs(handshake_timeout_secs),
                profile.connect_ws_tls(domain, tcp_stream),
            )
            .await;

            let tls_stream = match tls_res {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    last_err = Some(anyhow::anyhow!(
                        "XMPP BoringSSL TLS handshake with {domain} failed: {e}"
                    ));
                    continue;
                }
                Err(_) => {
                    last_err = Some(anyhow::anyhow!(
                        "XMPP BoringSSL TLS handshake with {domain} timed out"
                    ));
                    continue;
                }
            };

            let mut request = profile.build_ws_request(ws_url, Some(origin))?;
            request.headers_mut().insert(
                "Sec-WebSocket-Protocol",
                HeaderValue::from_static("xmpp"),
            );

            let stream: Box<dyn VpnStream> = Box::new(tls_stream);
            match tokio::time::timeout(
                Duration::from_secs(handshake_timeout_secs),
                tokio_tungstenite::client_async_with_config(request, stream, None),
            )
            .await
            {
                Ok(Ok((ws_stream, response))) => {
                    log::info!(
                        "[XMPP] WebSocket connected to {} (HTTP status: {:?}, remote_ip: {:?}, src_port: {}, attempt: {}/{})",
                        ws_url,
                        response.status(),
                        remote_ip,
                        local_port,
                        attempt,
                        hop_attempts
                    );
                    return Ok((ws_stream, remote_ip, ws_url.clone()));
                }
                Ok(Err(e)) => {
                    log::debug!(
                        "[XMPP] WebSocket upgrade to {} failed: {} (trying next candidate URL)",
                        ws_url,
                        e
                    );
                    last_err = Some(anyhow::anyhow!(
                        "XMPP WebSocket handshake with {ws_url} failed: {e}"
                    ));
                    break;
                }
                Err(_) => {
                    last_err = Some(anyhow::anyhow!(
                        "XMPP WebSocket handshake with {ws_url} timed out"
                    ));
                    break;
                }
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("XMPP WebSocket connection failed")))
}

/// Выполняет прозрачное переподключение и возобновление потока по XEP-0198 (`<resume xmlns="urn:xmpp:sm:3" .../>`)
/// внутри фоновой задачи `io_handle` без сброса MUC-комнаты и медиа-сессии.
async fn try_resume_xmpp_stream(
    domain: &str,
    ws_url: &str,
    origin: &str,
    profile: &BrowserProfile,
    wrtc_cfg: &WrtcConfig,
    previd: &str,
    inbound_h: u32,
) -> anyhow::Result<WebSocketStream<Box<dyn VpnStream>>> {
    let urls = vec![ws_url.to_string()];
    let (mut ws_stream, _remote_ip, _) =
        open_xmpp_ws_stream(domain, &urls, origin, profile, wrtc_cfg).await?;

    let handshake_timeout = Duration::from_secs(wrtc_cfg.xmpp_handshake_timeout_secs.max(5));
    let resume_fut = async {
        ws_stream.send(Message::text(XmppBuilder::open())).await?;
        let mut authed = false;
        let mut resume_sent = false;

        while let Some(msg_res) = ws_stream.next().await {
            let msg = msg_res?;
            if let Message::Text(text) = msg {
                log::info!("[XMPP RESUME IN]: {text}");
                let stanzas = parse_xmpp_stanzas(text.as_str(), "0.0.0.0", 0);
                for parsed in stanzas {
                    match parsed {
                        InboundXmpp::SaslMechanisms if !authed => {
                            ws_stream
                                .send(Message::text(XmppBuilder::auth_anonymous()))
                                .await?;
                        }
                        InboundXmpp::SaslSuccess => {
                            authed = true;
                            ws_stream.send(Message::text(XmppBuilder::open())).await?;
                        }
                        InboundXmpp::Features { .. } if authed && !resume_sent => {
                            resume_sent = true;
                            let resume_xml = XmppBuilder::sm_resume(previd, inbound_h);
                            log::info!("[XMPP RESUME OUT]: {resume_xml}");
                            ws_stream.send(Message::text(resume_xml)).await?;
                        }
                        InboundXmpp::SmResumed { previd: pid, h } => {
                            log::info!(
                                "[XMPP] XEP-0198 stream successfully resumed in-place (previd={pid}, server_h={h}, client_h={inbound_h})"
                            );
                            let ack_xml = XmppBuilder::sm_ack(inbound_h);
                            ws_stream.send(Message::text(ack_xml)).await?;
                            return Ok(());
                        }
                        InboundXmpp::SmFailed | InboundXmpp::SaslFailure(_) => {
                            anyhow::bail!("XEP-0198 stream resume rejected by server");
                        }
                        _ => {}
                    }
                }
            }
        }
        anyhow::bail!("WebSocket closed before XEP-0198 <resumed/>")
    };

    tokio::time::timeout(handshake_timeout, resume_fut)
        .await
        .map_err(|_| anyhow::anyhow!("XEP-0198 stream resume timed out"))??;

    Ok(ws_stream)
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

    pub fn get_ice_servers(&self) -> Vec<XmppIceServer> {
        let servers = self.discovered_ice_servers.lock().unwrap();
        if !servers.is_empty() {
            servers.clone()
        } else {
            self.default_ice_servers.clone()
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
        let clean_domain = WrtcProviderRegistry::normalize_domain(domain);
        let is_ktalk = KonturTalkProvider::is_ktalk_domain(&clean_domain);
        let ws_urls = if is_ktalk {
            vec![
                format!(
                    "wss://{clean_domain}/jitsi/xmpp-websocket?room={conference_id}&sessionToken={session_token}"
                ),
                format!(
                    "wss://{clean_domain}/xmpp-websocket?room={conference_id}&token={session_token}& Lists=true"
                ),
            ]
        } else {
            vec![
                format!("wss://{clean_domain}/xmpp-websocket?room={conference_id}"),
                format!(
                    "wss://{clean_domain}/{conference_id}/xmpp-websocket?room={conference_id}"
                ),
                format!("wss://{clean_domain}/xmpp-websocket"),
            ]
        };

        let bootstrap = RoomBootstrapInfo {
            provider_kind: if is_ktalk {
                ProviderKind::KonturTalk
            } else {
                ProviderKind::StandardJitsi
            },
            domain: clean_domain,
            room_name: conference_id.to_string(),
            conference_id: conference_id.to_string(),
            session_token: session_token.to_string(),
            ws_urls,
            pre_allocate_before_muc: !is_ktalk,
            default_ice_servers: Vec::new(),
        };

        Self::connect_from_bootstrap(
            &bootstrap,
            client_name_opt,
            custom_endpoint_id,
            profile,
            ping_interval_secs,
            wrtc_cfg,
        )
        .await
    }

    /// Подключается к XMPP WebSocket на основе подготовленного `RoomBootstrapInfo`.
    pub async fn connect_from_bootstrap(
        bootstrap: &RoomBootstrapInfo,
        client_name_opt: Option<&str>,
        custom_endpoint_id: Option<String>,
        profile: &BrowserProfile,
        ping_interval_secs: u64,
        wrtc_cfg: &WrtcConfig,
    ) -> anyhow::Result<Self> {
        let domain = bootstrap.domain.as_str();
        let conference_id = bootstrap.conference_id.as_str();
        let origin = format!("https://{domain}");

        // Для Контур.Толк сохраняем приоритетным проверенный URL `/jitsi/xmpp-websocket?...&sessionToken=...`
        let mut candidate_urls = Vec::with_capacity(bootstrap.ws_urls.len() + 1);
        if bootstrap.provider_kind == ProviderKind::KonturTalk && !bootstrap.session_token.is_empty()
        {
            let primary_ktalk_url = format!(
                "wss://{domain}/jitsi/xmpp-websocket?room={conference_id}&sessionToken={}",
                bootstrap.session_token
            );
            candidate_urls.push(primary_ktalk_url);
        }
        for u in &bootstrap.ws_urls {
            if !candidate_urls.contains(u) {
                candidate_urls.push(u.clone());
            }
        }

        log::info!(
            "[XMPP] Connecting to signaling WebSocket on {} (candidates: {})",
            domain,
            candidate_urls.len()
        );

        let handshake_timeout_secs = wrtc_cfg.xmpp_handshake_timeout_secs.max(1);
        let (mut ws_stream, remote_ip, connected_ws_url) =
            open_xmpp_ws_stream(domain, &candidate_urls, &origin, profile, wrtc_cfg).await?;

        let open_xml = XmppBuilder::open();
        log::info!("[XMPP OUT]: {open_xml}");
        ws_stream.send(Message::text(open_xml)).await?;

        let mut authed = false;
        let mut bind_sent = false;
        let mut bound = false;
        let mut server_supports_sm = false;
        let mut sm_enabled = false;
        let mut sm_resume_id: Option<String> = None;
        let mut inbound_h: u32 = 0;

        let mut jid = String::new();
        let endpoint_id = custom_endpoint_id
            .filter(|ep| !ep.is_empty())
            .unwrap_or_else(Self::generate_endpoint_id);
        let occupants = Arc::new(Mutex::new(HashSet::new()));
        let discovered_ice_servers = Arc::new(Mutex::new(Vec::new()));
        let colibri_sink: Arc<Mutex<Option<mpsc::Sender<crate::wrtc::colibri::ColibriMessage>>>> =
            Arc::new(Mutex::new(None));

        let effective_client_name = match client_name_opt {
            Some(name) if !name.is_empty() && name != "ANet-Node" => name.to_string(),
            _ => generate_random_guest_name(),
        };

        let timeout = Duration::from_secs(handshake_timeout_secs);
        let occ_track = occupants.clone();
        let discovered_ice_hs = discovered_ice_servers.clone();
        let my_ep = endpoint_id.clone();
        let conf_muc = format!("{conference_id}@muc.meet.jitsi/");
        let pre_allocate_before_muc = bootstrap.pre_allocate_before_muc;
        let is_ktalk = bootstrap.provider_kind == ProviderKind::KonturTalk;

        let handshake_fut = async {
            let mut joined = false;
            let mut disco_answered = false;
            let mut waiting_pre_alloc = false;
            let mut presence_sent = false;
            let mut focus_in_room = false;
            let alloc_id = format!("conf_pre_{endpoint_id}");
            let mut pending_jingle_frames: Vec<String> = Vec::new();

            while let Some(msg_res) = ws_stream.next().await {
                let msg = msg_res?;
                if let Message::Text(text) = msg {
                    log::info!("[XMPP IN]: {text}");
                    let stanzas = parse_xmpp_stanzas(text.as_str(), "0.0.0.0", 0);
                    let mut frame_has_jingle = false;
                    for parsed in stanzas {
                        if sm_enabled && parsed.is_counted_stanza() {
                            inbound_h = inbound_h.wrapping_add(1);
                        }
                        match parsed {
                            InboundXmpp::SmEnabled { id, resume } => {
                                sm_enabled = true;
                                inbound_h = 0;
                                if resume {
                                    sm_resume_id = id.clone();
                                }
                                log::info!(
                                    "[XMPP] XEP-0198 Stream Management enabled (resume={}, id={:?})",
                                    resume,
                                    sm_resume_id
                                );
                            }
                            InboundXmpp::SmRequest => {
                                let ack = XmppBuilder::sm_ack(inbound_h);
                                ws_stream.send(Message::text(ack)).await?;
                            }
                            InboundXmpp::DiscoInfo { id, from, node } => {
                                disco_answered = true;
                                let disco_reply = XmppBuilder::disco_info_result_ext(
                                    &from,
                                    &id,
                                    node.as_deref(),
                                    is_ktalk,
                                );
                                log::info!("[XMPP OUT]: {disco_reply}");
                                ws_stream.send(Message::text(disco_reply)).await?;
                            }
                            InboundXmpp::Ping { id, from } => {
                                let pong = XmppBuilder::iq_result(&from, &id);
                                log::info!("[XMPP OUT]: {pong}");
                                ws_stream.send(Message::text(pong)).await?;
                            }
                            InboundXmpp::Jingle(ref sess) => {
                                if let Some(ref iq_id) = sess.iq_id {
                                    let ack = XmppBuilder::iq_result(&sess.from, iq_id);
                                    log::info!("[XMPP OUT]: {ack}");
                                    ws_stream.send(Message::text(ack)).await?;
                                }
                                frame_has_jingle = true;
                            }
                            InboundXmpp::JingleAck { ref id, .. }
                                if waiting_pre_alloc && !presence_sent && id == &alloc_id =>
                            {
                                waiting_pre_alloc = false;
                                presence_sent = true;
                                log::info!(
                                    "[XMPP] Conference focus ready; entering MUC room {conference_id} with occupant {endpoint_id} (name: {effective_client_name})..."
                                );
                                let presence = XmppBuilder::muc_presence_ext(
                                    conference_id,
                                    &endpoint_id,
                                    &effective_client_name,
                                    is_ktalk,
                                );
                                log::info!("[XMPP OUT]: {presence}");
                                ws_stream.send(Message::text(presence)).await?;
                            }
                            InboundXmpp::Presence {
                                from,
                                is_unavailable,
                                is_self_110,
                            } => {
                                if let Some(occupant) = from.strip_prefix(&conf_muc) {
                                    if occupant == "focus" {
                                        focus_in_room = !is_unavailable;
                                    } else if occupant != my_ep {
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
                                    if pre_allocate_before_muc && !focus_in_room {
                                        let post_alloc_id = format!("conf_post_{endpoint_id}");
                                        let post_alloc_iq = XmppBuilder::conference_allocation(
                                            conference_id,
                                            &endpoint_id,
                                            &post_alloc_id,
                                        );
                                        log::info!(
                                            "[XMPP] Focus not yet in room {conference_id} after MUC join; sending post-join conference allocation..."
                                        );
                                        log::info!("[XMPP OUT]: {post_alloc_iq}");
                                        ws_stream.send(Message::text(post_alloc_iq)).await?;
                                    }
                                    joined = true;
                                }
                            }
                            InboundXmpp::ExtdiscoServices(ice_servers) => {
                                let urls: Vec<String> = ice_servers
                                    .iter()
                                    .flat_map(|s| s.urls.clone())
                                    .collect();
                                log::info!(
                                    "[XMPP] Discovered ICE services (STUN/TURN/TURNS): {:?}",
                                    urls
                                );
                                *discovered_ice_hs.lock().unwrap() = ice_servers;
                            }
                            InboundXmpp::SaslMechanisms if !authed => {
                                log::info!("[XMPP] SASL mechanisms received, sending ANONYMOUS auth");
                                let auth_xml = XmppBuilder::auth_anonymous();
                                log::info!("[XMPP OUT]: {auth_xml}");
                                ws_stream.send(Message::text(auth_xml)).await?;
                            }
                            InboundXmpp::SaslSuccess => {
                                log::info!("[XMPP] SASL auth success, resetting stream");
                                authed = true;
                                let open_xml = XmppBuilder::open();
                                log::info!("[XMPP OUT]: {open_xml}");
                                ws_stream.send(Message::text(open_xml)).await?;
                            }
                            InboundXmpp::Features { has_bind, has_sm }
                                if authed && has_bind && !bind_sent =>
                            {
                                bind_sent = true;
                                server_supports_sm = has_sm;
                                log::info!(
                                    "[XMPP] Binding resource (server_supports_sm={})...",
                                    server_supports_sm
                                );
                                let bind_xml = XmppBuilder::bind_resource("_bind_auth_2");
                                log::info!("[XMPP OUT]: {bind_xml}");
                                ws_stream.send(Message::text(bind_xml)).await?;
                            }
                            InboundXmpp::BindResult {
                                id,
                                jid: bound_jid,
                            } if authed && id == "_bind_auth_2" && !bound => {
                                bound = true;
                                jid = bound_jid;
                                log::info!("[XMPP] Bound JID: {jid}");

                                if server_supports_sm {
                                    let sm_req = XmppBuilder::sm_enable();
                                    log::info!("[XMPP OUT]: {sm_req}");
                                    ws_stream.feed(Message::text(sm_req)).await?;
                                }

                                let extdisco_req = XmppBuilder::extdisco_services("extdisco_1");
                                log::info!("[XMPP OUT]: {extdisco_req}");
                                ws_stream.feed(Message::text(extdisco_req)).await?;

                                if pre_allocate_before_muc {
                                    waiting_pre_alloc = true;
                                    let alloc_iq = XmppBuilder::conference_allocation(
                                        conference_id,
                                        &endpoint_id,
                                        &alloc_id,
                                    );
                                    log::info!(
                                        "[XMPP] Pre-allocating conference room {conference_id} via Jicofo before MUC join..."
                                    );
                                    log::info!("[XMPP OUT]: {alloc_iq}");
                                    ws_stream.feed(Message::text(alloc_iq)).await?;
                                    ws_stream.flush().await?;
                                } else {
                                    presence_sent = true;
                                    log::info!(
                                        "[XMPP] Entering MUC room {conference_id} with occupant {endpoint_id} (name: {effective_client_name})..."
                                    );
                                    let presence = XmppBuilder::muc_presence_ext(
                                        conference_id,
                                        &endpoint_id,
                                        &effective_client_name,
                                        is_ktalk,
                                    );
                                    log::info!("[XMPP OUT]: {presence}");
                                    ws_stream.feed(Message::text(presence)).await?;
                                    ws_stream.flush().await?;
                                }
                            }
                            InboundXmpp::SaslFailure(err) => {
                                anyhow::bail!("XMPP SASL authentication failed: {err}");
                            }
                            _ => {}
                        }
                    }
                    if frame_has_jingle {
                        pending_jingle_frames.push(text.to_string());
                    }
                    if joined {
                        if !disco_answered && pending_jingle_frames.is_empty() && !is_ktalk {
                            // Даём Jicofo до 250 мс прислать disco#info после входа в комнату,
                            // чтобы ответ ушёл до того, как второй участник инициирует аллокацию моста.
                            let post_join_deadline =
                                tokio::time::Instant::now() + Duration::from_millis(250);
                            while let Ok(Some(Ok(Message::Text(extra_txt)))) =
                                tokio::time::timeout_at(post_join_deadline, ws_stream.next()).await
                            {
                                log::info!("[XMPP IN (post-join)]: {extra_txt}");
                                let extra_stanzas =
                                    parse_xmpp_stanzas(extra_txt.as_str(), "0.0.0.0", 0);
                                let mut extra_has_jingle = false;
                                for p in extra_stanzas {
                                    if sm_enabled && p.is_counted_stanza() {
                                        inbound_h = inbound_h.wrapping_add(1);
                                    }
                                    match p {
                                        InboundXmpp::DiscoInfo { id, from, node } => {
                                            disco_answered = true;
                                            let disco_reply = XmppBuilder::disco_info_result_ext(
                                                &from,
                                                &id,
                                                node.as_deref(),
                                                is_ktalk,
                                            );
                                            log::info!("[XMPP OUT]: {disco_reply}");
                                            ws_stream.send(Message::text(disco_reply)).await?;
                                        }
                                        InboundXmpp::Ping { id, from } => {
                                            let pong = XmppBuilder::iq_result(&from, &id);
                                            ws_stream.send(Message::text(pong)).await?;
                                        }
                                        InboundXmpp::SmRequest => {
                                            let ack = XmppBuilder::sm_ack(inbound_h);
                                            ws_stream.send(Message::text(ack)).await?;
                                        }
                                        InboundXmpp::Jingle(ref sess) => {
                                            if let Some(ref iq_id) = sess.iq_id {
                                                let ack = XmppBuilder::iq_result(&sess.from, iq_id);
                                                ws_stream.send(Message::text(ack)).await?;
                                            }
                                            extra_has_jingle = true;
                                        }
                                        InboundXmpp::Presence {
                                            from,
                                            is_unavailable,
                                            ..
                                        } => {
                                            if let Some(occupant) = from.strip_prefix(&conf_muc) {
                                                if occupant != my_ep && occupant != "focus" {
                                                    if is_unavailable {
                                                        occ_track.lock().unwrap().remove(occupant);
                                                    } else {
                                                        occ_track
                                                            .lock()
                                                            .unwrap()
                                                            .insert(occupant.to_string());
                                                    }
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                if extra_has_jingle {
                                    pending_jingle_frames.push(extra_txt.to_string());
                                }
                                if disco_answered || !pending_jingle_frames.is_empty() {
                                    break;
                                }
                            }
                        }
                        break;
                    }
                }
            }
            if !joined {
                anyhow::bail!("XMPP stream closed before MUC room join completed");
            }
            Ok::<Vec<String>, anyhow::Error>(pending_jingle_frames)
        };

        let pending_jingle_frames = tokio::time::timeout(timeout, handshake_fut)
            .await
            .map_err(|_| {
                anyhow::anyhow!("XMPP MUC handshake timed out after {}s", handshake_timeout_secs)
            })??;

        let (write_tx, mut write_rx) = mpsc::channel::<XmppOutboundCmd>(WRTC_XMPP_CHANNEL_CAPACITY);
        let (read_tx, read_rx) = mpsc::channel::<String>(WRTC_XMPP_CHANNEL_CAPACITY);
        for frame in pending_jingle_frames {
            let _ = read_tx.try_send(frame);
        }

        let ping_secs = if ping_interval_secs > 0 {
            ping_interval_secs.clamp(3, 25)
        } else {
            15
        };
        let read_timeout_dur = Duration::from_secs(ping_secs * 2 + handshake_timeout_secs);
        let write_timeout_dur = Duration::from_secs(wrtc_cfg.ws_write_timeout_secs.max(1));

        let occ_track_bg = occupants.clone();
        let discovered_ice_bg = discovered_ice_servers.clone();
        let colibri_sink_bg = colibri_sink.clone();
        let domain_owned = domain.to_string();
        let origin_owned = origin.clone();
        let profile_bg = profile.clone();
        let wrtc_cfg_bg = wrtc_cfg.clone();

        // Единая задача I/O без ws_stream.split() (BiLock):
        // Поддерживает XEP-0198 Stream Management и прозрачное переподключение при зависании TCP поверх WARP.
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
                let mut stream_broken = false;

                tokio::select! {
                    _ = tokio::time::sleep_until(last_inbound_at + read_timeout_dur) => {
                        log::warn!(
                            "[XMPP] WebSocket read timed out after {:?} without incoming frames (half-open connection)",
                            read_timeout_dur
                        );
                        stream_broken = true;
                    }
                    msg_opt = ws_stream.next() => {
                        match msg_opt {
                            None => {
                                log::warn!("[XMPP] WebSocket stream ended (EOF)");
                                stream_broken = true;
                            }
                            Some(msg_res) => {
                                if msg_res.is_ok() {
                                    last_inbound_at = tokio::time::Instant::now();
                                }
                                match msg_res {
                            Ok(Message::Text(text)) => {
                                let stanzas = parse_xmpp_stanzas(text.as_str(), "0.0.0.0", 0);
                                let mut ack_replies: Vec<String> = Vec::new();
                                for parsed in stanzas {
                                    if sm_enabled && parsed.is_counted_stanza() {
                                        inbound_h = inbound_h.wrapping_add(1);
                                    }
                                    match parsed {
                                        InboundXmpp::SmEnabled { id, resume } => {
                                            sm_enabled = true;
                                            inbound_h = 0;
                                            if resume {
                                                sm_resume_id = id.clone();
                                            }
                                            log::info!(
                                                "[XMPP] XEP-0198 Stream Management enabled in I/O loop (resume={}, id={:?})",
                                                resume,
                                                sm_resume_id
                                            );
                                        }
                                        InboundXmpp::SmRequest => {
                                            ack_replies.push(XmppBuilder::sm_ack(inbound_h));
                                        }
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
                                            let disco_reply = XmppBuilder::disco_info_result_ext(
                                                &from,
                                                &id,
                                                node.as_deref(),
                                                is_ktalk,
                                            );
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
                                                "[XMPP] Discovered ICE services (STUN/TURN/TURNS): {:?}",
                                                urls
                                            );
                                            let mut guard = discovered_ice_bg.lock().unwrap();
                                            *guard = ice_servers;
                                        }
                                        InboundXmpp::EndpointMessage(c_msg) => {
                                            if c_msg.from.as_deref() != Some(my_ep.as_str()) {
                                                let for_me = match c_msg.to.as_deref() {
                                                    None | Some("") => true,
                                                    Some(target) => target == my_ep,
                                                };
                                                if for_me {
                                                    if let Ok(guard) = colibri_sink_bg.lock() {
                                                        if let Some(ref tx) = *guard {
                                                            let _ = tx.try_send(c_msg);
                                                        }
                                                    }
                                                }
                                            }
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
                                        log::warn!("[XMPP] Failed or timed out flushing IQ/SM ACK replies");
                                        stream_broken = true;
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
                                    stream_broken = true;
                                }
                            }
                            Ok(Message::Close(frame)) => {
                                log::warn!("[XMPP] WebSocket closed by server: {frame:?}");
                                stream_broken = true;
                            }
                            Err(e) => {
                                log::warn!("[XMPP] WebSocket read error: {e}");
                                stream_broken = true;
                            }
                            _ => {}
                                }
                            }
                        }
                    }
                    cmd_opt = write_rx.recv() => {
                        let Some(first_cmd) = cmd_opt else {
                            break;
                        };
                        let mut batch = Vec::with_capacity(8);
                        let mut should_close = false;
                        match first_cmd {
                            XmppOutboundCmd::Stanza(s) => batch.push(s),
                            XmppOutboundCmd::Close => should_close = true,
                        }
                        while batch.len() < 8 && !should_close {
                            match write_rx.try_recv() {
                                Ok(XmppOutboundCmd::Stanza(s)) => batch.push(s),
                                Ok(XmppOutboundCmd::Close) => should_close = true,
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
                                    stream_broken = true;
                                }
                                Err(_) => {
                                    log::warn!("[XMPP] Timeout sending stanza over WebSocket");
                                    stream_broken = true;
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
                        // Коалесцируем WebSocket Ping, XMPP IQ ping и XEP-0198 <a/> в один TLS-запрос через feed() + flush()
                        let ping_iq = XmppBuilder::ping("meet.jitsi", &format!("ping_{:08x}", rand::random::<u32>()));
                        let sm_ack_opt = if sm_enabled {
                            Some(XmppBuilder::sm_ack(inbound_h))
                        } else {
                            None
                        };
                        let send_keepalive = async {
                            ws_stream
                                .feed(Message::Ping(bytes::Bytes::from_static(&[0x01, 0x02])))
                                .await?;
                            ws_stream.feed(Message::text(ping_iq)).await?;
                            if let Some(ack_xml) = sm_ack_opt {
                                ws_stream.feed(Message::text(ack_xml)).await?;
                            }
                            ws_stream.flush().await
                        };
                        if tokio::time::timeout(write_timeout_dur, send_keepalive)
                            .await
                            .map_or(true, |r| r.is_err())
                        {
                            log::warn!("[XMPP] Failed or timed out sending coalesced WebSocket + XMPP keepalive ping");
                            stream_broken = true;
                        }
                    }
                    _ = extdisco_interval.tick() => {
                        let extdisco_iq = XmppBuilder::extdisco_services(&format!("extdisco_{:08x}", rand::random::<u32>()));
                        let _ = tokio::time::timeout(write_timeout_dur, ws_stream.send(Message::text(extdisco_iq))).await;
                    }
                }

                if stream_broken {
                    if let Some(ref previd) = sm_resume_id {
                        log::info!(
                            "[XMPP] Attempting in-place XEP-0198 stream resumption (previd={}, h={})...",
                            previd,
                            inbound_h
                        );
                        match try_resume_xmpp_stream(
                            &domain_owned,
                            &connected_ws_url,
                            &origin_owned,
                            &profile_bg,
                            &wrtc_cfg_bg,
                            previd,
                            inbound_h,
                        )
                        .await
                        {
                            Ok(new_ws) => {
                                ws_stream = new_ws;
                                last_inbound_at = tokio::time::Instant::now();
                                continue;
                            }
                            Err(e) => {
                                log::warn!("[XMPP] XEP-0198 stream resumption failed: {e}");
                                break;
                            }
                        }
                    } else {
                        break;
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
            colibri_sink,
            default_ice_servers: bootstrap.default_ice_servers.clone(),
            active_jingle: Arc::new(Mutex::new(None)),
            write_tx,
            read_rx,
            io_handle,
        })
    }

    pub fn set_colibri_sink(&self, tx: mpsc::Sender<crate::wrtc::colibri::ColibriMessage>) {
        if let Ok(mut guard) = self.colibri_sink.lock() {
            *guard = Some(tx);
        }
    }

    pub fn muc_json_sender(&self) -> XmppJsonSender {
        XmppJsonSender {
            conference_id: self.conference_id.clone(),
            write_tx: self.write_tx.clone(),
        }
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
        let mut seen_candidates = HashSet::new();
        for (i, c_line) in candidates.iter().enumerate() {
            let parts: Vec<&str> = c_line.split_whitespace().collect();
            if parts.len() >= 8 && parts[6] == "typ" {
                let foundation = parts[0];
                let component = parts[1];
                if component != "1" {
                    continue;
                }
                let protocol = parts[2].to_lowercase();
                let priority = parts[3];
                let ip = parts[4];
                let port = parts[5];
                let c_type = parts[7];
                if ip == "0.0.0.0"
                    || ip == "127.0.0.1"
                    || ip.starts_with("127.")
                    || ip.starts_with("172.112.")
                {
                    continue;
                }
                let dedup_key = format!("{ip}:{port}:{protocol}:{c_type}");
                if !seen_candidates.insert(dedup_key) {
                    continue;
                }

                let mut rel_addr_opt: Option<&str> = None;
                let mut rel_port_opt: Option<&str> = None;
                let mut idx = 8;
                while idx + 1 < parts.len() {
                    if parts[idx] == "raddr" {
                        rel_addr_opt = Some(parts[idx + 1]);
                        idx += 2;
                    } else if parts[idx] == "rport" {
                        rel_port_opt = Some(parts[idx + 1]);
                        idx += 2;
                    } else {
                        idx += 1;
                    }
                }

                let cid = format!("c_{i}");
                candidate_xml.push_str(&XmppBuilder::jingle_candidate(
                    component,
                    foundation,
                    &cid,
                    ip,
                    port,
                    priority,
                    &protocol,
                    c_type,
                    rel_addr_opt,
                    rel_port_opt,
                ));
            }
        }

        if candidate_xml.is_empty() {
            log::warn!("[XMPP] No valid ICE candidates gathered for session-accept");
        }

        let stanza = XmppBuilder::jingle_session_accept_with_endpoint(
            focus_jid,
            &req_id,
            &self.jid,
            &self.endpoint_id,
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
            .send(XmppOutboundCmd::Stanza(stanza))
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
                    let _ = self.write_tx.try_send(XmppOutboundCmd::Stanza(rm_stanza));
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
                let _ = self.write_tx.try_send(XmppOutboundCmd::Stanza(term_stanza));
            }
        }
        let leave_stanza = XmppBuilder::muc_leave(&self.conference_id, &self.endpoint_id);
        log::info!(
            "[XMPP] Leaving MUC room {} as occupant {}: {}",
            self.conference_id,
            self.endpoint_id,
            leave_stanza
        );
        let _ = self.write_tx.try_send(XmppOutboundCmd::Stanza(leave_stanza));
        tokio::time::sleep(Duration::from_millis(120)).await;
        let _ = self
            .write_tx
            .try_send(XmppOutboundCmd::Stanza(XmppBuilder::close().to_string()));
        let _ = self.write_tx.try_send(XmppOutboundCmd::Close);
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
                    let _ = self.write_tx.try_send(XmppOutboundCmd::Stanza(rm_stanza));
                }
                let req_id = format!("term_{:08x}", rand::random::<u32>());
                let term_stanza = XmppBuilder::jingle_session_terminate(
                    &focus_jid,
                    &req_id,
                    &self.jid,
                    &sid,
                );
                let _ = self.write_tx.try_send(XmppOutboundCmd::Stanza(term_stanza));
            }
        }
        let leave_stanza = XmppBuilder::muc_leave(&self.conference_id, &self.endpoint_id);
        let _ = self.write_tx.try_send(XmppOutboundCmd::Stanza(leave_stanza));
        let _ = self
            .write_tx
            .try_send(XmppOutboundCmd::Stanza(XmppBuilder::close().to_string()));
        let _ = self.write_tx.try_send(XmppOutboundCmd::Close);
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

