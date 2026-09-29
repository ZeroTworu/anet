use crate::wrtc::colibri::ColibriMessage;
use crate::wrtc::jingle::JingleSession;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use rtc::interceptor::Registry;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{MediaEngine, MIME_TYPE_OPUS};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::rtp::{Header as RtpHeader, Packet as RtpPacket};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use std::sync::atomic::{AtomicU16, AtomicU32};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use webrtc::media_stream::track_local::static_rtp::TrackLocalStaticRTP;
use webrtc::media_stream::track_local::TrackLocal;
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCIceCandidateInit,
    RTCPeerConnectionState,
};
use webrtc::runtime::TokioRuntime;

pub const WRTC_SERVER_SSRC: u32 = 0x53525631; // 1397962289 ("SRV1")
pub const WRTC_CLIENT_SSRC: u32 = 0x434c4931; // 1129072945 ("CLI1")

struct PeerEvents {
    connected_tx: mpsc::Sender<()>,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for PeerEvents {
    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        log::info!("[WRTC Media] WebRTC PeerConnection state: {state:?}");
        if state == RTCPeerConnectionState::Connected {
            let _ = self.connected_tx.try_send(());
        }
    }
}

pub struct WrtcPeer {
    pub peer_connection: Option<Arc<dyn PeerConnection>>,
    pub audio_track: Option<Arc<TrackLocalStaticRTP>>,
    pub ssrc: u32,
    pub outgoing_tx: mpsc::Sender<ColibriMessage>,
    pub incoming_rx: Mutex<mpsc::Receiver<ColibriMessage>>,
}

impl WrtcPeer {
    pub async fn create(
        session_opt: Option<&JingleSession>,
        xmpp_opt: Option<&crate::wrtc::xmpp::XmppSession>,
        domain: &str,
        fallback_ip: &str,
        fallback_port: u16,
        audio_keepalive_ms: u64,
        is_server: bool,
    ) -> anyhow::Result<Self> {
        let (incoming_tx, incoming_rx) = mpsc::channel::<ColibriMessage>(1024);
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<ColibriMessage>(1024);
        let (connected_tx, mut connected_rx) = mpsc::channel::<()>(1);

        let (local_ssrc, remote_ssrc) = if is_server {
            (WRTC_SERVER_SSRC, WRTC_CLIENT_SSRC)
        } else {
            (WRTC_CLIENT_SSRC, WRTC_SERVER_SSRC)
        };

        // 1. ПРИОРИТЕТНЫЙ И ЕДИНСТВЕННЫЙ ТРАНСПОРТ ДАННЫХ: Colibri-WS
        if let Some(session) = session_opt {
            if let Some(ref ws_url) = session.transport.colibri_ws_url {
                log::info!("[WRTC] Connecting to JVB Colibri-WS for data transport: {ws_url}");

                let mut request = ws_url.as_str().into_client_request()?;
                request.headers_mut().insert(
                    "Origin",
                    HeaderValue::from_str(&format!("https://{domain}"))?,
                );
                request.headers_mut().insert(
                    "User-Agent",
                    HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
                );

                let (ws_stream, response) = tokio_tungstenite::connect_async(request)
                    .await
                    .map_err(|e| anyhow::anyhow!("Colibri-WS connection failed: {e}"))?;

                log::info!(
                    "[WRTC] Connected to JVB Colibri-WS (HTTP status: {:?})",
                    response.status()
                );
                let (mut ws_sink, mut ws_stream) = ws_stream.split();
                let (ws_raw_tx, mut ws_raw_rx) = mpsc::channel::<tokio_tungstenite::tungstenite::Message>(64);

                // Воркер отправки данных в JVB WebSocket
                let raw_tx_ping = ws_raw_tx.clone();
                tokio::spawn(async move {
                    let mut ping_interval = tokio::time::interval(Duration::from_secs(10));
                    loop {
                        tokio::select! {
                            raw_opt = ws_raw_rx.recv() => {
                                match raw_opt {
                                    Some(raw) => {
                                        if let Err(e) = ws_sink.send(raw).await {
                                            log::warn!("[WRTC] JVB WS raw send error: {e}");
                                            break;
                                        }
                                    }
                                    None => break,
                                }
                            }
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

                // Воркер вычитывания входящих данных из JVB WebSocket
                let in_tx = incoming_tx.clone();
                let raw_tx_pong = ws_raw_tx.clone();
                tokio::spawn(async move {
                    while let Some(msg_res) = ws_stream.next().await {
                        match msg_res {
                            Ok(tokio_tungstenite::tungstenite::Message::Text(text)) => {
                                if let Ok(c_msg) = serde_json::from_str::<ColibriMessage>(&text) {
                                    let _ = in_tx.send(c_msg).await;
                                } else {
                                    log::debug!("[JVB WS UNHANDLED TEXT]: {text}");
                                }
                            }
                            Ok(tokio_tungstenite::tungstenite::Message::Binary(bin)) => {
                                if let Ok(c_msg) = serde_json::from_slice::<ColibriMessage>(&bin) {
                                    let _ = in_tx.send(c_msg).await;
                                }
                            }
                            Ok(tokio_tungstenite::tungstenite::Message::Ping(data)) => {
                                let _ = raw_tx_pong
                                    .send(tokio_tungstenite::tungstenite::Message::Pong(data))
                                    .await;
                            }
                            Ok(tokio_tungstenite::tungstenite::Message::Close(frame)) => {
                                log::warn!("[WRTC] JVB Colibri-WS closed by server: {:?}", frame);
                                break;
                            }
                            Err(e) => {
                                log::warn!("[WRTC] JVB Colibri-WS error: {e}");
                                break;
                            }
                            _ => {}
                        }
                    }
                });
            }
        }

        // 2. МИНИМАЛЬНЫЙ ФОНОВЫЙ WebRTC: ICE/DTLS хендшейк + keepalive тишины для JVB
        let mut peer_connection_opt = None;
        let mut audio_track_opt = None;

        if let (Some(session), Some(xmpp)) = (session_opt, xmpp_opt) {
            log::info!("[WRTC Media] Initializing background WebRTC session for JVB keepalive...");

            let mut media_engine = MediaEngine::default();
            let audio_codec = RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_OPUS.to_owned(),
                    clock_rate: 48000,
                    channels: 2,
                    sdp_fmtp_line: "".to_owned(),
                    rtcp_feedback: vec![],
                },
                payload_type: 111,
                ..Default::default()
            };
            media_engine.register_codec(audio_codec.clone(), RtpCodecKind::Audio)?;
            let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;

            // Позволяем webrtc-rs биндиться ко всем интерфейсам и самостоятельно собирать кандидатов.
            let bind_addr = "0.0.0.0:0".to_string();

            let config = RTCConfigurationBuilder::new()
                .with_ice_servers(vec![])
                .build();

            let setting_engine = SettingEngineBuilder::new()
                .with_answering_dtls_role(RTCDtlsRole::Client)
                .build();

            let handler = Arc::new(PeerEvents { connected_tx });

            let pc_res = PeerConnectionBuilder::new()
                .with_configuration(config)
                .with_setting_engine(setting_engine)
                .with_media_engine(media_engine)
                .with_interceptor_registry(registry)
                .with_handler(handler)
                .with_runtime(Arc::new(TokioRuntime))
                .with_udp_addrs(vec![bind_addr])
                .build()
                .await;

            if let Ok(pc_impl) = pc_res {
                let pc: Arc<dyn PeerConnection> = Arc::new(pc_impl);
                let track = MediaStreamTrack::new(
                    format!("webrtc-rs-stream-id-{}", RtpCodecKind::Audio),
                    format!("webrtc-rs-track-id-{}", RtpCodecKind::Audio),
                    format!("webrtc-rs-track-label-{}", RtpCodecKind::Audio),
                    RtpCodecKind::Audio,
                    vec![RTCRtpEncodingParameters {
                        rtp_coding_parameters: RTCRtpCodingParameters {
                            ssrc: Some(local_ssrc),
                            ..Default::default()
                        },
                        codec: audio_codec.rtp_codec.clone(),
                        ..Default::default()
                    }],
                );
                let audio_track = Arc::new(TrackLocalStaticRTP::new(track));
                let _ = pc
                    .add_track(Arc::clone(&audio_track) as Arc<dyn TrackLocal>)
                    .await;

                let sdp_str = session.to_sdp(fallback_ip, fallback_port, remote_ssrc);
                if let Ok(offer) = RTCSessionDescription::offer(sdp_str) {
                    if pc.set_remote_description(offer).await.is_ok() {
                        if let Ok(answer) = pc.create_answer(None).await {
                            let _ = pc.set_local_description(answer.clone()).await;

                            for c in &session.transport.candidates {
                                if c.ip == "127.0.0.1" || c.ip.starts_with("127.") || c.ip == "0.0.0.0" {
                                    continue;
                                }
                                let candidate_sdp = format!(
                                    "candidate:{} {} {} {} {} {} typ {}",
                                    c.foundation,
                                    c.component,
                                    c.protocol.to_lowercase(),
                                    c.priority,
                                    c.ip,
                                    c.port,
                                    c.candidate_type
                                );
                                let init = RTCIceCandidateInit {
                                    candidate: candidate_sdp,
                                    sdp_mid: Some("audio".to_string()),
                                    sdp_mline_index: Some(0),
                                    username_fragment: Some(session.transport.ufrag.clone()),
                                    url: None,
                                };
                                let _ = pc.add_ice_candidate(init).await;
                            }

                            let mut final_sdp = answer.sdp.clone();
                            for _ in 0..25 {
                                if let Some(desc) = pc.local_description().await {
                                    if desc.sdp.contains("a=candidate:") {
                                        final_sdp = desc.sdp;
                                        break;
                                    }
                                }
                                tokio::time::sleep(Duration::from_millis(20)).await;
                            }

                            let local_params = crate::wrtc::jingle::parse_sdp_answer(&final_sdp);

                            log::info!(
                                "[WRTC Media] Generated local SDP Answer: ufrag={}, pwd={}, fp={}, candidates count={}",
                                local_params.ufrag,
                                local_params.pwd,
                                local_params.fingerprint,
                                local_params.candidates.len()
                            );

                            let _ = xmpp
                                .accept_session(
                                    &session.sid,
                                    &session.from,
                                    local_ssrc,
                                    &local_params.ufrag,
                                    &local_params.pwd,
                                    &local_params.fingerprint,
                                    &local_params.fingerprint_hash,
                                    &local_params.candidates,
                                )
                                .await;
                        }
                    }
                }

                let track_keepalive = Arc::clone(&audio_track);
                let seq_c = Arc::new(AtomicU16::new(0));
                let ts_c = Arc::new(AtomicU32::new(0));
                let interval_ms = if audio_keepalive_ms > 0 && audio_keepalive_ms <= 100 {
                    audio_keepalive_ms as u64
                } else {
                    20
                };
                let samples_per_packet = (48000 * interval_ms / 1000) as u32;

                tokio::spawn(async move {
                    if tokio::time::timeout(Duration::from_secs(30), connected_rx.recv()).await.is_ok() {
                        log::info!(
                            "[WRTC Media] WebRTC ICE/DTLS connected, starting Opus silence keepalive (interval: {}ms, samples: {})",
                            interval_ms, samples_per_packet
                        );
                        let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));
                        let silence_payload = Bytes::from_static(&[0xf8, 0xff, 0xfe]);
                        loop {
                            interval.tick().await;
                            let seq = seq_c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let ts = ts_c.fetch_add(samples_per_packet, std::sync::atomic::Ordering::Relaxed);
                            let rtp_packet = RtpPacket {
                                header: RtpHeader {
                                    version: 2,
                                    padding: false,
                                    extension: false,
                                    marker: false,
                                    payload_type: 111,
                                    sequence_number: seq,
                                    timestamp: ts,
                                    ssrc: local_ssrc,
                                    csrc: vec![],
                                    extension_profile: 0,
                                    extensions: vec![],
                                    extensions_padding: 0,
                                },
                                payload: silence_payload.clone(),
                            };
                            if track_keepalive.write_rtp(rtp_packet).await.is_err() {
                                break;
                            }
                        }
                    } else {
                        log::warn!("[WRTC Media] WebRTC connection did not reach Connected in 30s (continuing with WS)");
                    }
                });

                peer_connection_opt = Some(pc);
                audio_track_opt = Some(audio_track);
            }
        }

        Ok(Self {
            peer_connection: peer_connection_opt,
            audio_track: audio_track_opt,
            ssrc: local_ssrc,
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

    pub async fn close(&self) -> anyhow::Result<()> {
        if let Some(ref pc) = self.peer_connection {
            let _ = pc.close().await;
        }
        Ok(())
    }
}
