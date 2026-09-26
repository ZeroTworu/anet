use crate::wrtc::colibri::ColibriMessage;
use crate::wrtc::jingle::{JingleCandidate, JingleSession, JingleTransportInfo};
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use webrtc::data_channel::{DataChannel, DataChannelEvent, RTCDataChannelInit};
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler,
    RTCConfigurationBuilder, RTCIceCandidateInit, RTCPeerConnectionState,
    RTCSessionDescription,
};

#[derive(Clone)]
struct PeerEvents;

#[async_trait::async_trait]
impl PeerConnectionEventHandler for PeerEvents {
    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        log::info!("[WRTC] PeerConnection state: {state:?}");
    }
}

pub struct WrtcPeer {
    pub peer_connection: Option<Arc<dyn PeerConnection>>,
    pub data_channel: Option<Arc<dyn DataChannel>>,
    pub outgoing_tx: mpsc::Sender<ColibriMessage>,
    pub incoming_rx: Mutex<mpsc::Receiver<ColibriMessage>>,
}

impl WrtcPeer {
    pub async fn create(
        session_opt: Option<&JingleSession>,
        domain: &str,
        fallback_ip: &str,
        fallback_port: u16,
        _audio_keepalive_ms: u64,
    ) -> anyhow::Result<Self> {
        let (incoming_tx, incoming_rx) = mpsc::channel::<ColibriMessage>(512);
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<ColibriMessage>(512);

        // 1. Приоритетный путь: прямое подключение к JVB Colibri-WS
        if let Some(session) = session_opt {
            if let Some(ref ws_url) = session.transport.colibri_ws_url {
                log::info!("[WRTC] Connecting to JVB Colibri-WS: {ws_url}");

                let mut request = ws_url.as_str().into_client_request()?;
                request.headers_mut().insert(
                    "Origin",
                    HeaderValue::from_str(&format!("https://{domain}"))?,
                );
                request.headers_mut().insert(
                    "User-Agent",
                    HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
                );

                match tokio_tungstenite::connect_async(request).await {
                    Ok((ws_stream, response)) => {
                        log::info!(
                            "[WRTC] Connected to JVB Colibri-WS (HTTP status: {:?})",
                            response.status()
                        );
                        let (mut ws_sink, mut ws_stream) = ws_stream.split();

                        // Воркер отправки сообщений в JVB WebSocket + keepalive ping
                        tokio::spawn(async move {
                            let mut ping_interval =
                                tokio::time::interval(std::time::Duration::from_secs(10));
                            loop {
                                tokio::select! {
                                    msg_opt = outgoing_rx.recv() => {
                                        match msg_opt {
                                            Some(msg) => {
                                                if let Ok(json_str) = serde_json::to_string(&msg) {
                                                    match msg.msg_payload {
                                                        crate::wrtc::colibri::WrtcMessage::Astp { .. } => {
                                                            log::trace!("[JVB WS OUT ASTP]");
                                                        }
                                                        _ => {
                                                            log::info!("[JVB WS OUT]: {json_str}");
                                                        }
                                                    }
                                                    if let Err(e) = ws_sink
                                                        .send(tokio_tungstenite::tungstenite::Message::text(json_str))
                                                        .await
                                                    {
                                                        log::warn!("[WRTC] JVB WS send error: {e}");
                                                        break;
                                                    }
                                                }
                                            }
                                            None => break,
                                        }
                                    }
                                    _ = ping_interval.tick() => {
                                        if ws_sink
                                            .send(tokio_tungstenite::tungstenite::Message::Ping(bytes::Bytes::from_static(&[0x09])))
                                            .await
                                            .is_err()
                                        {
                                            break;
                                        }
                                    }
                                }
                            }
                        });

                        // Воркер вычитывания входящих сообщений от JVB WebSocket
                        let in_tx = incoming_tx.clone();
                        tokio::spawn(async move {
                            while let Some(msg_res) = ws_stream.next().await {
                                match msg_res {
                                    Ok(tokio_tungstenite::tungstenite::Message::Text(text)) => {
                                        match serde_json::from_str::<ColibriMessage>(text.as_str()) {
                                            Ok(c_msg) => {
                                                match c_msg.msg_payload {
                                                    crate::wrtc::colibri::WrtcMessage::Astp { .. } => {
                                                        log::trace!("[JVB WS IN ASTP]");
                                                    }
                                                    _ => {
                                                        log::info!("[JVB WS IN]: {text}");
                                                    }
                                                }
                                                let _ = in_tx.send(c_msg).await;
                                            }
                                            Err(e) => {
                                                log::info!("[JVB WS IN non-colibri]: {text}");
                                                log::debug!("[WRTC] Non-ColibriMessage payload: {e}");
                                            }
                                        }
                                    }
                                    Ok(tokio_tungstenite::tungstenite::Message::Binary(bin)) => {
                                        if let Ok(c_msg) = serde_json::from_slice::<ColibriMessage>(&bin) {
                                            let _ = in_tx.send(c_msg).await;
                                        }
                                    }
                                    Ok(tokio_tungstenite::tungstenite::Message::Close(_)) | Err(_) => {
                                        log::info!("[WRTC] JVB Colibri-WS closed");
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                        });

                        return Ok(Self {
                            peer_connection: None,
                            data_channel: None,
                            outgoing_tx,
                            incoming_rx: Mutex::new(incoming_rx),
                        });
                    }
                    Err(e) => {
                        log::warn!("[WRTC] Colibri-WS connection failed: {e}. Falling back to WebRTC PeerConnection...");
                    }
                }
            }
        }

        // 2. Резервный путь: WebRTC PeerConnection
        let config = RTCConfigurationBuilder::new()
            .with_ice_servers(vec![])
            .build();

        let peer_connection: Arc<dyn PeerConnection> = Arc::new(
            PeerConnectionBuilder::new()
                .with_configuration(config)
                .with_handler(Arc::new(PeerEvents))
                .with_udp_addrs(vec!["0.0.0.0:0".to_string()])
                .build()
                .await
                .map_err(|e| anyhow::anyhow!("PeerConnectionBuilder failed: {e:#}"))?,
        );

        let dc_init = RTCDataChannelInit {
            ordered: false,
            max_packet_life_time: None,
            max_retransmits: Some(0),
            protocol: "http://jitsi.org/protocols/colibri".to_string(),
            negotiated: None,
        };

        let data_channel: Arc<dyn DataChannel> = peer_connection
            .create_data_channel("JVB data channel", Some(dc_init))
            .await
            .map_err(|e| anyhow::anyhow!("create_data_channel failed: {e:#}"))?;

        let default_session = JingleSession {
            iq_id: None,
            sid: "fallback".to_string(),
            from: String::new(),
            action: "session-initiate".to_string(),
            transport: JingleTransportInfo {
                ufrag: "jvb_ufrag".to_string(),
                pwd: "jvb_pwd_secret".to_string(),
                fingerprint: None,
                fingerprint_hash: None,
                fingerprint_setup: Some("actpass".to_string()),
                candidates: vec![JingleCandidate {
                    ip: fallback_ip.to_string(),
                    port: fallback_port,
                    protocol: "udp".to_string(),
                    candidate_type: "host".to_string(),
                    priority: 2130706431,
                    foundation: "1".to_string(),
                    component: 1,
                }],
                colibri_ws_url: None,
            },
        };

        let session = session_opt.unwrap_or(&default_session);
        let sdp_str = session.to_sdp(fallback_ip, fallback_port);

        if let Ok(remote_desc) = RTCSessionDescription::offer(sdp_str) {
            let _ = peer_connection.set_remote_description(remote_desc).await;
            if let Ok(answer) = peer_connection.create_answer(None).await {
                let _ = peer_connection.set_local_description(answer).await;
            }
        }

        for c in &session.transport.candidates {
            let candidate_sdp = format!(
                "candidate:{} {} {} {} {} {} typ {}",
                c.foundation, c.component, c.protocol, c.priority, c.ip, c.port, c.candidate_type
            );
            let init = RTCIceCandidateInit {
                candidate: candidate_sdp,
                url: None,
                ..Default::default()
            };
            let _ = peer_connection.add_ice_candidate(init).await;
        }

        let dc_out = Arc::clone(&data_channel);
        tokio::spawn(async move {
            while let Some(msg) = outgoing_rx.recv().await {
                if let Ok(json_str) = serde_json::to_string(&msg) {
                    for _ in 0..10 {
                        match dc_out.send_text(&json_str).await {
                            Ok(_) => break,
                            Err(_) => {
                                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                            }
                        }
                    }
                }
            }
        });

        let dc_in = Arc::clone(&data_channel);
        tokio::spawn(async move {
            while let Some(event) = dc_in.poll().await {
                match event {
                    DataChannelEvent::OnMessage(msg) => {
                        if let Ok(colibri_msg) = serde_json::from_slice::<ColibriMessage>(&msg.data) {
                            let _ = incoming_tx.send(colibri_msg).await;
                        } else if let Ok(text) = std::str::from_utf8(&msg.data) {
                            if let Ok(colibri_msg) = serde_json::from_str::<ColibriMessage>(text) {
                                let _ = incoming_tx.send(colibri_msg).await;
                            }
                        }
                    }
                    DataChannelEvent::OnClose => {
                        break;
                    }
                    _ => {}
                }
            }
        });

        Ok(Self {
            peer_connection: Some(peer_connection),
            data_channel: Some(data_channel),
            outgoing_tx,
            incoming_rx: Mutex::new(incoming_rx),
        })
    }

    pub async fn send(&self, msg: ColibriMessage) -> anyhow::Result<()> {
        self.outgoing_tx
            .send(msg)
            .await
            .map_err(|_| anyhow::anyhow!("DataChannel write channel closed"))
    }

    pub async fn recv(&self) -> Option<ColibriMessage> {
        let mut rx = self.incoming_rx.lock().await;
        rx.recv().await
    }
}
