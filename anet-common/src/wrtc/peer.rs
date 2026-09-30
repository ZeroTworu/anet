use crate::wrtc::colibri::ColibriMessage;
use crate::wrtc::jingle::JingleSession;
use bytes::Bytes;
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
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use webrtc::data_channel::{DataChannel, RTCDataChannelInit};
use webrtc::media_stream::track_local::static_rtp::TrackLocalStaticRTP;
use webrtc::media_stream::track_local::TrackLocal;
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler,
    RTCPeerConnectionState,
};
use webrtc::runtime::TokioRuntime;

fn generate_random_ssrc() -> u32 {
    (rand::random::<u32>() & 0x7FFFFFFF) | 0x1000
}

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
    pub data_channel: Option<Arc<dyn DataChannel>>,
    pub audio_track: Option<Arc<TrackLocalStaticRTP>>,
    pub ssrc: u32,
    pub outgoing_tx: mpsc::Sender<ColibriMessage>,
    pub incoming_rx: Mutex<mpsc::Receiver<ColibriMessage>>,
}

impl WrtcPeer {
    pub async fn create(
        session_opt: Option<&JingleSession>,
        xmpp_opt: Option<&crate::wrtc::xmpp::XmppSession>,
        _domain: &str,
        fallback_ip: &str,
        fallback_port: u16,
        audio_keepalive_ms: u64,
    ) -> anyhow::Result<Self> {
        let (incoming_tx, incoming_rx) = mpsc::channel::<ColibriMessage>(1024);
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<ColibriMessage>(1024);
        let (connected_tx, mut connected_rx) = mpsc::channel::<()>(1);

        let local_ssrc = generate_random_ssrc();
        let remote_ssrc = 0;

        let mut peer_connection_opt = None;
        let mut data_channel_opt = None;
        let mut audio_track_opt = None;

        if let (Some(session), Some(xmpp)) = (session_opt, xmpp_opt) {
            log::info!("[WRTC Media] Initializing WebRTC PeerConnection and DataChannel...");

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

                // 1. Добавляем Opus-аудиотрек для удержания сессии в JVB
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

                // 2. Создаем WebRTC DataChannel для прямой передачи пакетов по UDP/SCTP
                let dc_init = RTCDataChannelInit {
                    ordered: false,
                    max_packet_life_time: None,
                    max_retransmits: Some(0),
                    protocol: "http://jitsi.org/protocols/colibri".to_string(),
                    negotiated: None,
                };
                let data_channel: Arc<dyn DataChannel> = pc
                    .create_data_channel("JVB data channel", Some(dc_init))
                    .await
                    .map_err(|e| anyhow::anyhow!("create_data_channel failed: {e:#}"))?;

                let dc_is_open = Arc::new(AtomicBool::new(false));
                let dc_is_open_on_open = dc_is_open.clone();
                let dc_open_notify = Arc::new(tokio::sync::Notify::new());
                let dc_open_notify_on_open = dc_open_notify.clone();

                data_channel.on_open(Box::new(move || {
                    log::info!("[WRTC DataChannel] 'JVB data channel' state is now OPEN!");
                    dc_is_open_on_open.store(true, Ordering::SeqCst);
                    dc_open_notify_on_open.notify_waiters();
                    Box::pin(async move {})
                }));

                let dc_is_open_on_close = dc_is_open.clone();
                data_channel.on_close(Box::new(move || {
                    log::info!("[WRTC DataChannel] 'JVB data channel' closed.");
                    dc_is_open_on_close.store(false, Ordering::SeqCst);
                    Box::pin(async move {})
                }));

                data_channel.on_error(Box::new(move |err| {
                    log::warn!("[WRTC DataChannel] Error: {err}");
                    Box::pin(async move {})
                }));

                let in_tx = incoming_tx.clone();
                data_channel.on_message(Box::new(move |msg| {
                    let tx = in_tx.clone();
                    Box::pin(async move {
                        if let Ok(colibri_msg) = serde_json::from_slice::<ColibriMessage>(&msg.data) {
                            let _ = tx.send(colibri_msg).await;
                        } else if let Ok(text) = std::str::from_utf8(&msg.data) {
                            if let Ok(colibri_msg) = serde_json::from_str::<ColibriMessage>(text) {
                                let _ = tx.send(colibri_msg).await;
                            }
                        }
                    })
                }));

                // 3. Применяем Jingle Offer от Jicofo/JVB и создаем локальный Answer
                let sdp_str = session.to_sdp(fallback_ip, fallback_port, remote_ssrc);
                if let Ok(offer) = RTCSessionDescription::offer(sdp_str) {
                    if pc.set_remote_description(offer).await.is_ok() {
                        if let Ok(answer) = pc.create_answer(None).await {
                            let _ = pc.set_local_description(answer.clone()).await;

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

                // 4. Воркер отправки данных в DataChannel
                let dc_out = Arc::clone(&data_channel);
                let dc_is_open_out = dc_is_open.clone();
                let dc_open_notify_out = dc_open_notify.clone();

                tokio::spawn(async move {
                    if !dc_is_open_out.load(Ordering::SeqCst) {
                        let _ = tokio::time::timeout(Duration::from_secs(30), dc_open_notify_out.notified()).await;
                    }
                    log::info!(
                        "[WRTC DataChannel] Outgoing sender loop active (is_open={})",
                        dc_is_open_out.load(Ordering::SeqCst)
                    );

                    while let Some(msg) = outgoing_rx.recv().await {
                        let Ok(json_str) = serde_json::to_string(&msg) else { continue; };
                        match msg.msg_payload {
                            crate::wrtc::colibri::WrtcMessage::Astp { .. } => {
                                log::trace!("[JVB DC OUT ASTP]");
                            }
                            _ => {
                                log::info!("[JVB DC OUT]: {json_str}");
                            }
                        }

                        // Отправка с ретраями при временном backpressure; никогда не делаем break из цикла!
                        for attempt in 0..5 {
                            if !dc_is_open_out.load(Ordering::SeqCst) {
                                let _ = tokio::time::timeout(Duration::from_millis(500), dc_open_notify_out.notified()).await;
                            }
                            match dc_out.send_text(&json_str).await {
                                Ok(_) => break,
                                Err(e) => {
                                    if attempt == 4 {
                                        log::warn!("[WRTC DataChannel] Failed to send message after 5 attempts: {e}");
                                    } else {
                                        tokio::time::sleep(Duration::from_millis(20)).await;
                                    }
                                }
                            }
                        }
                    }
                });

                // 5. Фоновый keepalive аудио-тишины
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
                            let seq = seq_c.fetch_add(1, Ordering::Relaxed);
                            let ts = ts_c.fetch_add(samples_per_packet, Ordering::Relaxed);
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
                        log::warn!("[WRTC Media] WebRTC connection did not reach Connected in 30s");
                    }
                });

                peer_connection_opt = Some(pc);
                data_channel_opt = Some(data_channel);
                audio_track_opt = Some(audio_track);
            }
        }

        Ok(Self {
            peer_connection: peer_connection_opt,
            data_channel: data_channel_opt,
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
            .map_err(|_| anyhow::anyhow!("WebRTC DataChannel write channel closed"))
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

impl Drop for WrtcPeer {
    fn drop(&mut self) {
        if let Some(pc) = self.peer_connection.take() {
            tokio::spawn(async move {
                let _ = pc.close().await;
            });
        }
    }
}
