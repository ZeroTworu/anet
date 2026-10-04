use crate::wrtc::colibri::{
    ColibriMessage, ReceiverVideoConstraints, WrtcMessage, WrtcMode, VP8_KEYFRAME_HEADER,
};
use crate::wrtc::jingle::JingleSession;
use bytes::{BufMut, Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use rtc::interceptor::Registry;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{MediaEngine, MIME_TYPE_OPUS, MIME_TYPE_VP8};
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
use webrtc::data_channel::{DataChannel, DataChannelEvent, RTCDataChannelInit};
use webrtc::media_stream::track_local::static_rtp::TrackLocalStaticRTP;
use webrtc::media_stream::track_local::TrackLocal;
use webrtc::media_stream::track_remote::{TrackRemote, TrackRemoteEvent};
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler,
    RTCPeerConnectionState,
};
use webrtc::runtime::TokioRuntime;

fn generate_random_ssrc() -> u32 {
    (rand::random::<u32>() & 0x7FFFFFFF) | 0x1000
}

/// Корректный парсинг и отсечение VP8 Payload Descriptor (RFC 7741).
pub fn strip_vp8_payload_descriptor(payload: Bytes) -> Option<Bytes> {
    if payload.is_empty() {
        return None;
    }
    let mut offset = 1;
    let b0 = payload[0];
    let has_x = (b0 & 0x80) != 0;
    if has_x {
        if payload.len() <= offset {
            return None;
        }
        let b1 = payload[offset];
        offset += 1;
        let has_i = (b1 & 0x80) != 0;
        let has_l = (b1 & 0x40) != 0;
        let has_t = (b1 & 0x20) != 0;
        let has_k = (b1 & 0x10) != 0;
        if has_i {
            if payload.len() <= offset {
                return None;
            }
            let pic_id_b0 = payload[offset];
            offset += 1;
            if (pic_id_b0 & 0x80) != 0 {
                if payload.len() <= offset {
                    return None;
                }
                offset += 1;
            }
        }
        if has_l {
            if payload.len() <= offset {
                return None;
            }
            offset += 1;
        }
        if has_t || has_k {
            if payload.len() <= offset {
                return None;
            }
            offset += 1;
        }
    }
    if payload.len() < offset {
        return None;
    }
    Some(payload.slice(offset..))
}

struct PeerEvents {
    connected_tx: mpsc::Sender<()>,
    is_connected: Arc<AtomicBool>,
    failed_notify: Arc<tokio::sync::Notify>,
    dc_is_open: Arc<AtomicBool>,
    dc_open_notify: Arc<tokio::sync::Notify>,
    incoming_tx: mpsc::Sender<ColibriMessage>,
    remote_dc: Arc<Mutex<Option<Arc<dyn DataChannel>>>>,
    video_incoming_tx: mpsc::Sender<Bytes>,
    expected_peer_video_ssrc: Arc<AtomicU32>,
    first_video_rx: Arc<AtomicBool>,
    local_video_ssrc: u32,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for PeerEvents {
    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        log::info!("[WRTC Media] WebRTC PeerConnection state: {state:?}");
        if state == RTCPeerConnectionState::Connected {
            self.is_connected.store(true, Ordering::SeqCst);
            let _ = self.connected_tx.try_send(());
        } else if state == RTCPeerConnectionState::Disconnected
            || state == RTCPeerConnectionState::Failed
            || state == RTCPeerConnectionState::Closed
        {
            self.is_connected.store(false, Ordering::SeqCst);
            if state == RTCPeerConnectionState::Failed || state == RTCPeerConnectionState::Closed {
                self.failed_notify.notify_waiters();
            }
        }
    }

    async fn on_track(&self, track: Arc<dyn TrackRemote>) {
        let kind = track.kind().await;
        log::info!("[WRTC Media] Inbound remote track: kind={kind:?}");
        if kind == RtpCodecKind::Video {
            let in_tx = self.video_incoming_tx.clone();
            let expected_ssrc = self.expected_peer_video_ssrc.clone();
            let first_rx = self.first_video_rx.clone();
            let local_v_ssrc = self.local_video_ssrc;
            tokio::spawn(async move {
                while let Some(event) = track.poll().await {
                    match event {
                        TrackRemoteEvent::OnRtpPacket(pkt) => {
                            // 1. Никогда не принимаем свои собственные отражённые кадры (петля / broadcast storm в JVB)
                            if pkt.header.ssrc == local_v_ssrc {
                                continue;
                            }

                            // 2. Отсекаем RTP-паддинг (RFC 3550 Section 5.1), если SFU/JVB выставил флаг padding
                            let mut raw_payload = pkt.payload;
                            if pkt.header.padding && !raw_payload.is_empty() {
                                let pad_len = raw_payload[raw_payload.len() - 1] as usize;
                                if pad_len > 0 && pad_len <= raw_payload.len() {
                                    raw_payload = raw_payload.slice(..raw_payload.len() - pad_len);
                                }
                            }

                            // 3. Отсекаем дескриптор VP8 (RFC 7741)
                            if let Some(mut data) = strip_vp8_payload_descriptor(raw_payload) {
                                if !data.starts_with(&VP8_KEYFRAME_HEADER) {
                                    continue;
                                }

                                // 4. Динамический маппинг SSRC: JVB переписывает SSRC при форвардинге
                                let exp = expected_ssrc.load(Ordering::Relaxed);
                                if exp != 0 && pkt.header.ssrc != exp {
                                    log::debug!(
                                        "[WRTC Media Video IN] SSRC mapped from {} to actual SFU SSRC {}",
                                        exp, pkt.header.ssrc
                                    );
                                    expected_ssrc.store(pkt.header.ssrc, Ordering::Relaxed);
                                } else if exp == 0 {
                                    expected_ssrc.store(pkt.header.ssrc, Ordering::Relaxed);
                                }

                                data = data.slice(VP8_KEYFRAME_HEADER.len()..);
                                if data.is_empty() {
                                    // Keepalive-кадр без ASTP-пейлоуда
                                    continue;
                                }

                                if first_rx.swap(false, Ordering::Relaxed) {
                                    log::info!(
                                        "[WRTC Media Video IN] First video frame received (SSRC: {}, len: {} bytes)",
                                        pkt.header.ssrc, data.len()
                                    );
                                }
                                let _ = in_tx.send(data).await;
                            }
                        }
                        TrackRemoteEvent::OnEnded => {
                            log::info!("[WRTC Media] Remote video track ended");
                            break;
                        }
                        _ => {}
                    }
                }
            });
        } else if kind == RtpCodecKind::Audio {
            tokio::spawn(async move {
                while let Some(event) = track.poll().await {
                    if matches!(event, TrackRemoteEvent::OnEnded) {
                        break;
                    }
                }
            });
        }
    }

    async fn on_data_channel(&self, data_channel: Arc<dyn DataChannel>) {
        let label = data_channel.label().await.unwrap_or_default();
        let proto = data_channel.protocol().await.unwrap_or_default();
        log::info!(
            "[WRTC DataChannel] Inbound DataChannel negotiated by JVB/peer: label='{label}', protocol='{proto}'"
        );
        *self.remote_dc.lock().await = Some(Arc::clone(&data_channel));
        self.dc_is_open.store(true, Ordering::SeqCst);
        self.dc_open_notify.notify_waiters();

        let in_tx = self.incoming_tx.clone();
        let dc_is_open_c = self.dc_is_open.clone();
        let dc_poll = Arc::clone(&data_channel);

        tokio::spawn(async move {
            while let Some(event) = dc_poll.poll().await {
                match event {
                    DataChannelEvent::OnOpen => {
                        log::info!("[WRTC DataChannel] Inbound DataChannel state is OPEN!");
                        dc_is_open_c.store(true, Ordering::SeqCst);
                    }
                    DataChannelEvent::OnClose => {
                        log::info!("[WRTC DataChannel] Inbound DataChannel closed.");
                        dc_is_open_c.store(false, Ordering::SeqCst);
                        break;
                    }
                    DataChannelEvent::OnMessage(msg) => {
                        if let Ok(c_msg) = serde_json::from_slice::<ColibriMessage>(&msg.data) {
                            let _ = in_tx.send(c_msg).await;
                        } else if let Ok(text) = std::str::from_utf8(&msg.data) {
                            if let Ok(c_msg) = serde_json::from_str::<ColibriMessage>(text) {
                                let _ = in_tx.send(c_msg).await;
                            }
                        }
                    }
                    _ => {}
                }
            }
        });
    }
}

struct P2pEvents {
    is_open: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for P2pEvents {
    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        log::info!("[P2P Direct] WebRTC PeerConnection state: {state:?}");
        if state == RTCPeerConnectionState::Failed || state == RTCPeerConnectionState::Closed {
            self.is_open.store(false, Ordering::SeqCst);
        }
    }
}

pub struct P2pSession {
    pub pc: Arc<dyn PeerConnection>,
    pub dc: Arc<dyn DataChannel>,
    pub is_open: Arc<AtomicBool>,
    pub open_notify: Arc<tokio::sync::Notify>,
    pub incoming_rx: Mutex<mpsc::Receiver<Bytes>>,
}

impl P2pSession {
    pub async fn send_packet(&self, data: &Bytes) -> anyhow::Result<()> {
        if !self.is_open.load(Ordering::SeqCst) {
            anyhow::bail!("P2P DataChannel is not open");
        }
        self.dc
            .send(BytesMut::from(data.as_ref()))
            .await
            .map_err(|e| anyhow::anyhow!("P2P DataChannel send error: {e}"))?;
        Ok(())
    }

    pub async fn recv_packet(&self) -> Option<Bytes> {
        let mut rx = self.incoming_rx.lock().await;
        rx.recv().await
    }
}

pub async fn create_p2p_channel(stun_servers: &[String]) -> anyhow::Result<P2pSession> {
    let mut media_engine = MediaEngine::default();
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;

    use rtc::peer_connection::configuration::RTCIceServer;
    let mut ice_servers = Vec::new();
    for s in stun_servers {
        ice_servers.push(RTCIceServer {
            urls: vec![s.clone()],
            username: String::new(),
            credential: String::new(),
        });
    }
    if ice_servers.is_empty() {
        ice_servers.push(RTCIceServer {
            urls: vec![
                "stun:stun.l.google.com:19302".to_string(),
                "stun:stun1.l.google.com:19302".to_string(),
            ],
            username: String::new(),
            credential: String::new(),
        });
    }

    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(ice_servers)
        .build();

    let setting_engine = SettingEngineBuilder::new()
        .with_ice_timeouts(
            Some(Duration::from_secs(10)),
            Some(Duration::from_secs(25)),
            Some(Duration::from_millis(2000)),
        )
        .with_sctp_max_receive_buffer_size(2 * 1024 * 1024)
        .with_sctp_mtu(1280)
        .with_receive_mtu(1500)
        .build();

    let is_open = Arc::new(AtomicBool::new(false));
    let open_notify = Arc::new(tokio::sync::Notify::new());

    let handler = Arc::new(P2pEvents {
        is_open: is_open.clone(),
    });

    let pc_res = PeerConnectionBuilder::new()
        .with_configuration(config)
        .with_setting_engine(setting_engine)
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .with_handler(handler)
        .with_runtime(Arc::new(TokioRuntime))
        .with_udp_addrs(vec!["0.0.0.0:0".to_string()])
        .with_dedicated_reactor_pool_size(1)
        .build()
        .await?;

    let pc: Arc<dyn PeerConnection> = Arc::new(pc_res);

    let dc_init = RTCDataChannelInit {
        ordered: false,
        max_packet_life_time: None,
        max_retransmits: Some(0),
        protocol: "anet-tunnel-v1".to_string(),
        negotiated: Some(0),
    };

    let dc: Arc<dyn DataChannel> = pc.create_data_channel("anet-data", Some(dc_init)).await?;

    let (incoming_tx, incoming_rx) = mpsc::channel::<Bytes>(1024);
    let in_tx = incoming_tx.clone();

    let is_open_c = is_open.clone();
    let notify_c = open_notify.clone();
    let dc_poll = Arc::clone(&dc);

    tokio::spawn(async move {
        while let Some(event) = dc_poll.poll().await {
            match event {
                DataChannelEvent::OnOpen => {
                    log::info!("[P2P Direct] established: DataChannel 'anet-data' is now OPEN!");
                    is_open_c.store(true, Ordering::SeqCst);
                    notify_c.notify_waiters();
                }
                DataChannelEvent::OnClose => {
                    log::info!("[P2P Direct] DataChannel closed");
                    is_open_c.store(false, Ordering::SeqCst);
                    break;
                }
                DataChannelEvent::OnMessage(msg) => {
                    let _ = in_tx.send(msg.data.into()).await;
                }
                _ => {}
            }
        }
    });

    Ok(P2pSession {
        pc,
        dc,
        is_open,
        open_notify,
        incoming_rx: Mutex::new(incoming_rx),
    })
}

pub struct WrtcPeer {
    pub peer_connection: Option<Arc<dyn PeerConnection>>,
    pub data_channel: Option<Arc<dyn DataChannel>>,
    pub audio_track: Option<Arc<TrackLocalStaticRTP>>,
    pub video_track: Option<Arc<TrackLocalStaticRTP>>,
    pub ssrc: u32,
    pub video_ssrc: u32,
    pub video_payload_type: u8,
    pub video_seq: Arc<AtomicU16>,
    pub video_ts: Arc<AtomicU32>,
    pub expected_peer_video_ssrc: Arc<AtomicU32>,
    pub outgoing_tx: mpsc::Sender<ColibriMessage>,
    pub raw_outgoing_tx: mpsc::Sender<String>,
    pub incoming_rx: Mutex<mpsc::Receiver<ColibriMessage>>,
    pub video_incoming_rx: Mutex<mpsc::Receiver<Bytes>>,
    pub mode: WrtcMode,
    pub dc_is_open: Arc<AtomicBool>,
    pub has_ws: Arc<AtomicBool>,
    pub is_connected: Arc<AtomicBool>,
    pub failed_notify: Arc<tokio::sync::Notify>,
    pub first_video_tx: Arc<AtomicBool>,
    pub start_instant: std::time::Instant,
}

impl WrtcPeer {
    pub async fn create(
        session_opt: Option<&JingleSession>,
        xmpp_opt: Option<&crate::wrtc::xmpp::XmppSession>,
        fallback_ip: &str,
        fallback_port: u16,
        audio_keepalive_ms: u64,
        mode: WrtcMode,
    ) -> anyhow::Result<Self> {
        let (incoming_tx, incoming_rx) = mpsc::channel::<ColibriMessage>(16384);
        let (video_incoming_tx, video_incoming_rx) = mpsc::channel::<Bytes>(16384);
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<ColibriMessage>(16384);
        let (raw_outgoing_tx, mut raw_outgoing_rx) = mpsc::channel::<String>(16384);
        let (connected_tx, _connected_rx) = mpsc::channel::<()>(1);
        let is_connected = Arc::new(AtomicBool::new(false));
        let failed_notify = Arc::new(tokio::sync::Notify::new());
        let dc_is_open = Arc::new(AtomicBool::new(false));
        let first_video_rx = Arc::new(AtomicBool::new(true));
        let first_video_tx = Arc::new(AtomicBool::new(true));

        let local_ssrc = generate_random_ssrc();
        let local_video_ssrc = generate_random_ssrc();
        let video_pt = session_opt.map(|s| s.video_payload_type).unwrap_or(100);
        let has_video_flag = session_opt.map(|s| s.has_video).unwrap_or(false) || mode == WrtcMode::MediaVideo;
        let video_seq = Arc::new(AtomicU16::new(0));
        let video_ts = Arc::new(AtomicU32::new(0));
        let expected_peer_video_ssrc = Arc::new(AtomicU32::new(0));
        let _remote_ssrc = 0;

        let (ws_fallback_tx, mut ws_fallback_rx) = mpsc::channel::<String>(8192);
        let has_ws = Arc::new(AtomicBool::new(false));

        if let Some(session) = session_opt {
            if let Some(ref ws_url) = session.transport.colibri_ws_url {
                let ws_url_c = ws_url.clone();
                let in_tx_ws = incoming_tx.clone();
                let has_ws_c = has_ws.clone();
                tokio::spawn(async move {
                    if let Ok((ws_stream, _)) = tokio_tungstenite::connect_async(&ws_url_c).await {
                        has_ws_c.store(true, Ordering::SeqCst);
                        log::info!("[WRTC WS] Parallel Colibri-WS fallback connected");
                        let (mut ws_sink, mut ws_stream) = ws_stream.split();

                        if has_video_flag {
                            let constraints = ReceiverVideoConstraints::new_all(2160);
                            if let Ok(json) = serde_json::to_string(&constraints) {
                                let _ = ws_sink.send(tokio_tungstenite::tungstenite::Message::Text(json.into())).await;
                            }
                        }

                        let in_tx = in_tx_ws;
                        let has_ws_read = has_ws_c.clone();
                        tokio::spawn(async move {
                            while let Some(msg_res) = ws_stream.next().await {
                                match msg_res {
                                    Ok(tokio_tungstenite::tungstenite::Message::Text(text)) => {
                                        if let Ok(c_msg) = serde_json::from_str::<ColibriMessage>(&text) {
                                            let _ = in_tx.send(c_msg).await;
                                        }
                                    }
                                    Ok(tokio_tungstenite::tungstenite::Message::Binary(bin)) => {
                                        if let Ok(c_msg) = serde_json::from_slice::<ColibriMessage>(&bin) {
                                            let _ = in_tx.send(c_msg).await;
                                        }
                                    }
                                    Ok(tokio_tungstenite::tungstenite::Message::Close(_)) | Err(_) => {
                                        has_ws_read.store(false, Ordering::SeqCst);
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                        });

                        while let Some(json_text) = ws_fallback_rx.recv().await {
                            if ws_sink.send(tokio_tungstenite::tungstenite::Message::Text(json_text.into())).await.is_err() {
                                has_ws_c.store(false, Ordering::SeqCst);
                                break;
                            }
                        }
                    }
                });
            }
        }

        let mut peer_connection_opt = None;
        let mut data_channel_opt = None;
        let mut audio_track_opt = None;
        let mut video_track_opt = None;

        if let (Some(session), Some(xmpp)) = (session_opt, xmpp_opt) {
            log::info!("[WRTC Media] Initializing WebRTC PeerConnection with Audio (Opus) and Video (VP8)...");

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

            let video_codec = RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_VP8.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: "".to_owned(),
                    rtcp_feedback: vec![],
                },
                payload_type: video_pt,
                ..Default::default()
            };
            media_engine.register_codec(video_codec.clone(), RtpCodecKind::Video)?;

            if video_pt != 96 {
                let mut fallback_vcodec = video_codec.clone();
                fallback_vcodec.payload_type = 96;
                let _ = media_engine.register_codec(fallback_vcodec, RtpCodecKind::Video);
            }
            if video_pt != 100 {
                let mut fallback_vcodec2 = video_codec.clone();
                fallback_vcodec2.payload_type = 100;
                let _ = media_engine.register_codec(fallback_vcodec2, RtpCodecKind::Video);
            }

            let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;

            let bind_addr = "0.0.0.0:0".to_string();

            let config = RTCConfigurationBuilder::new()
                .with_ice_servers(vec![])
                .build();

            let setting_engine = SettingEngineBuilder::new()
                .with_answering_dtls_role(RTCDtlsRole::Client)
                .with_ice_timeouts(
                    Some(Duration::from_secs(10)),
                    Some(Duration::from_secs(25)),
                    Some(Duration::from_millis(2000)),
                )
                .with_sctp_max_receive_buffer_size(2 * 1024 * 1024)
                .with_sctp_mtu(1280)
                .with_receive_mtu(1500)
                .build();

            let remote_dc: Arc<Mutex<Option<Arc<dyn DataChannel>>>> = Arc::new(Mutex::new(None));
            let dc_open_notify = Arc::new(tokio::sync::Notify::new());

            let handler = Arc::new(PeerEvents {
                connected_tx,
                is_connected: is_connected.clone(),
                failed_notify: failed_notify.clone(),
                dc_is_open: dc_is_open.clone(),
                dc_open_notify: dc_open_notify.clone(),
                incoming_tx: incoming_tx.clone(),
                remote_dc: remote_dc.clone(),
                video_incoming_tx,
                expected_peer_video_ssrc: expected_peer_video_ssrc.clone(),
                first_video_rx,
                local_video_ssrc,
            });

            let pc_res = PeerConnectionBuilder::new()
                .with_configuration(config)
                .with_setting_engine(setting_engine)
                .with_media_engine(media_engine)
                .with_interceptor_registry(registry)
                .with_handler(handler)
                .with_runtime(Arc::new(TokioRuntime))
                .with_udp_addrs(vec![bind_addr])
                .with_dedicated_reactor_pool_size(1)
                .build()
                .await;

            if let Ok(pc_impl) = pc_res {
                let pc: Arc<dyn PeerConnection> = Arc::new(pc_impl);

                let audio_track_desc = MediaStreamTrack::new(
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
                let audio_track = Arc::new(TrackLocalStaticRTP::new(audio_track_desc));
                let _ = pc
                    .add_track(Arc::clone(&audio_track) as Arc<dyn TrackLocal>)
                    .await;

                let video_track_desc = MediaStreamTrack::new(
                    format!("webrtc-rs-stream-id-{}", RtpCodecKind::Video),
                    format!("webrtc-rs-track-id-{}", RtpCodecKind::Video),
                    format!("webrtc-rs-track-label-{}", RtpCodecKind::Video),
                    RtpCodecKind::Video,
                    vec![RTCRtpEncodingParameters {
                        rtp_coding_parameters: RTCRtpCodingParameters {
                            ssrc: Some(local_video_ssrc),
                            ..Default::default()
                        },
                        codec: video_codec.rtp_codec.clone(),
                        ..Default::default()
                    }],
                );
                let video_track = Arc::new(TrackLocalStaticRTP::new(video_track_desc));
                let _ = pc
                    .add_track(Arc::clone(&video_track) as Arc<dyn TrackLocal>)
                    .await;

                let mut data_channel_res = None;
                if session.has_data_channel && mode != WrtcMode::Ws {
                    let dc_init = RTCDataChannelInit {
                        ordered: false,
                        max_packet_life_time: None,
                        max_retransmits: Some(0),
                        protocol: "http://jitsi.org/protocols/colibri".to_string(),
                        negotiated: None,
                    };
                    match pc.create_data_channel("JVB data channel", Some(dc_init)).await {
                        Ok(dc) => {
                            let dc_is_open_in = dc_is_open.clone();
                            let dc_open_notify_in = dc_open_notify.clone();
                            let dc_in = Arc::clone(&dc);
                            let in_tx = incoming_tx.clone();

                            tokio::spawn(async move {
                                while let Some(event) = dc_in.poll().await {
                                    match event {
                                        DataChannelEvent::OnOpen => {
                                            log::info!("[WRTC DataChannel] 'JVB data channel' state is now OPEN!");
                                            dc_is_open_in.store(true, Ordering::SeqCst);
                                            dc_open_notify_in.notify_waiters();
                                            if has_video_flag {
                                                let constraints = ReceiverVideoConstraints::new_all(2160);
                                                if let Ok(json) = serde_json::to_string(&constraints) {
                                                    let _ = dc_in.send_text(&json).await;
                                                }
                                            }
                                        }
                                        DataChannelEvent::OnClose => {
                                            log::info!("[WRTC DataChannel] 'JVB data channel' closed.");
                                            dc_is_open_in.store(false, Ordering::SeqCst);
                                            break;
                                        }
                                        DataChannelEvent::OnError => {
                                            log::warn!("[WRTC DataChannel] Error event received");
                                        }
                                        DataChannelEvent::OnMessage(msg) => {
                                            if let Ok(colibri_msg) = serde_json::from_slice::<ColibriMessage>(&msg.data) {
                                                let _ = in_tx.send(colibri_msg).await;
                                            } else if let Ok(text) = std::str::from_utf8(&msg.data) {
                                                if let Ok(colibri_msg) = serde_json::from_str::<ColibriMessage>(text) {
                                                    let _ = in_tx.send(colibri_msg).await;
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            });
                            data_channel_res = Some(dc);
                        }
                        Err(e) => {
                            log::warn!("[WRTC DataChannel] Failed to create data channel: {e}");
                        }
                    }
                } else {
                    log::info!("[WRTC DataChannel] JVB bridge does not announce SCTP DataChannel in session-initiate. Operating over Colibri-WS with PacketBatcher.");
                }

                let sdp_str = session.to_sdp(fallback_ip, fallback_port, 0, local_video_ssrc);
                if let Ok(offer) = RTCSessionDescription::offer(sdp_str) {
                    if pc.set_remote_description(offer).await.is_ok() {
                        if let Ok(answer) = pc.create_answer(None).await {
                            let _ = pc.set_local_description(answer.clone()).await;

                            let mut final_sdp = answer.sdp.clone();
                            for _ in 0..50 {
                                if let Some(desc) = pc.local_description().await {
                                    if desc.sdp.contains("a=candidate:") {
                                        final_sdp = desc.sdp;
                                        break;
                                    }
                                }
                                tokio::time::sleep(Duration::from_millis(30)).await;
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
                                    local_video_ssrc,
                                    video_pt,
                                    &local_params.ufrag,
                                    &local_params.pwd,
                                    &local_params.fingerprint,
                                    &local_params.fingerprint_hash,
                                    &local_params.candidates,
                                    session.has_data_channel,
                                    session.has_video || local_video_ssrc != 0,
                                )
                                .await;
                        }
                    }
                }

                let dc_opt_out = data_channel_res.clone();
                let remote_dc_out = remote_dc.clone();
                let dc_is_open_out = dc_is_open.clone();
                let dc_open_notify_out = dc_open_notify.clone();
                let has_ws_out = has_ws.clone();
                let ws_fallback_tx_out = ws_fallback_tx.clone();

                tokio::spawn(async move {
                    if dc_opt_out.is_some() && !dc_is_open_out.load(Ordering::SeqCst) {
                        let _ = tokio::time::timeout(Duration::from_secs(2), dc_open_notify_out.notified()).await;
                    }
                    log::info!(
                        "[WRTC DataChannel] Outgoing sender loop active (is_open={})",
                        dc_is_open_out.load(Ordering::SeqCst)
                    );

                    loop {
                        let (json_str, is_batch, is_astp) = tokio::select! {
                            msg_opt = outgoing_rx.recv() => {
                                match msg_opt {
                                    Some(msg) => {
                                        let is_batch = matches!(msg.msg_payload, WrtcMessage::AstpBatch { .. });
                                        let is_astp = matches!(msg.msg_payload, WrtcMessage::Astp { .. });
                                        let Ok(json_str) = serde_json::to_string(&msg) else { continue; };
                                        (json_str, is_batch, is_astp)
                                    }
                                    None => break,
                                }
                            }
                            raw_opt = raw_outgoing_rx.recv() => {
                                match raw_opt {
                                    Some(raw) => (raw, false, false),
                                    None => break,
                                }
                            }
                        };

                        let mut sent = false;
                        if dc_is_open_out.load(Ordering::SeqCst) {
                            if let Some(ref dc_out) = dc_opt_out {
                                if is_batch {
                                    log::debug!("[JVB DC OUT Batch]");
                                } else if is_astp {
                                    log::trace!("[JVB DC OUT ASTP]");
                                } else {
                                    log::info!("[JVB DC OUT]: {json_str}");
                                }

                                for attempt in 0..3 {
                                    match dc_out.send_text(&json_str).await {
                                        Ok(_) => {
                                            sent = true;
                                            break;
                                        }
                                        Err(_) => {
                                            let r_dc_opt = remote_dc_out.lock().await.clone();
                                            if let Some(r_dc) = r_dc_opt {
                                                if r_dc.send_text(&json_str).await.is_ok() {
                                                    sent = true;
                                                    break;
                                                }
                                            }
                                            if attempt < 2 {
                                                tokio::time::sleep(Duration::from_millis(10)).await;
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if !sent && has_ws_out.load(Ordering::SeqCst) {
                            if is_astp || is_batch {
                                log::trace!("[JVB WS OUT ASTP]");
                            } else {
                                log::info!("[JVB WS OUT]: {json_str}");
                            }
                            if let Err(e) = ws_fallback_tx_out.try_send(json_str.clone()) {
                                match e {
                                    tokio::sync::mpsc::error::TrySendError::Full(_) => {
                                        log::warn!("[WRTC WS] Fallback queue full, frame dropped");
                                    }
                                    tokio::sync::mpsc::error::TrySendError::Closed(_) => {}
                                }
                            } else {
                                sent = true;
                            }
                        }

                        if !sent && json_str.contains("ReceiverVideoConstraints") {
                            // Критично: отправка отложенных ограничений выполняется в фоне,
                            // чтобы не блокировать основной цикл отправки сообщений (discover, ping, auth)!
                            let dc_is_open_bg = dc_is_open_out.clone();
                            let dc_opt_bg = dc_opt_out.clone();
                            let remote_dc_bg = remote_dc_out.clone();
                            let has_ws_bg = has_ws_out.clone();
                            let ws_fallback_tx_bg = ws_fallback_tx_out.clone();
                            let json_str_bg = json_str.clone();
                            tokio::spawn(async move {
                                for _ in 0..30 {
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                    if dc_is_open_bg.load(Ordering::SeqCst) {
                                        if let Some(ref dc_out) = dc_opt_bg {
                                            if dc_out.send_text(&json_str_bg).await.is_ok() {
                                                log::info!("[WRTC Constraints] Sent delayed video constraints via DataChannel");
                                                break;
                                            }
                                        }
                                        let r_dc_opt = remote_dc_bg.lock().await.clone();
                                        if let Some(r_dc) = r_dc_opt {
                                            if r_dc.send_text(&json_str_bg).await.is_ok() {
                                                log::info!("[WRTC Constraints] Sent delayed video constraints via Remote DataChannel");
                                                break;
                                            }
                                        }
                                    }
                                    if has_ws_bg.load(Ordering::SeqCst) {
                                        if ws_fallback_tx_bg.try_send(json_str_bg.clone()).is_ok() {
                                            log::info!("[WRTC Constraints] Sent delayed video constraints via Colibri-WS");
                                            break;
                                        }
                                    }
                                }
                            });
                        }
                    }
                });

                let track_keepalive = Arc::clone(&audio_track);
                let seq_c = Arc::new(AtomicU16::new(0));
                let ts_c = Arc::new(AtomicU32::new(0));
                let interval_ms = if audio_keepalive_ms > 0 && audio_keepalive_ms <= 100 {
                    audio_keepalive_ms as u64
                } else {
                    20
                };
                let samples_per_packet = (48000 * interval_ms / 1000) as u32;
                let is_connected_a = Arc::clone(&is_connected);

                tokio::spawn(async move {
                    let start = std::time::Instant::now();
                    while !is_connected_a.load(Ordering::SeqCst) {
                        if start.elapsed() > Duration::from_secs(25) {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    log::info!(
                        "[WRTC Media] Starting Opus silence keepalive (interval: {}ms, samples: {})",
                        interval_ms, samples_per_packet
                    );
                    let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
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
                        if let Err(e) = track_keepalive.write_rtp(rtp_packet).await {
                            log::trace!("[WRTC Media] Opus silence write_rtp transient error: {e}");
                        }
                    }
                });

                let video_track_keepalive = Arc::clone(&video_track);
                let video_seq_c = Arc::clone(&video_seq);
                let video_ts_c = Arc::clone(&video_ts);
                let v_pt = video_pt;
                let v_ssrc = local_video_ssrc;
                let is_connected_v = Arc::clone(&is_connected);
                tokio::spawn(async move {
                    let start = std::time::Instant::now();
                    while !is_connected_v.load(Ordering::SeqCst) {
                        if start.elapsed() > Duration::from_secs(25) {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    log::info!("[WRTC Media] Starting VP8 video keepalive (interval: 1000ms)");
                    let mut interval = tokio::time::interval(Duration::from_millis(1000));
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                    loop {
                        interval.tick().await;
                        let seq = video_seq_c.fetch_add(1, Ordering::Relaxed);
                        let ts = video_ts_c.fetch_add(3000, Ordering::Relaxed);

                        let mut keepalive_payload = BytesMut::with_capacity(4 + VP8_KEYFRAME_HEADER.len());
                        let pic_id = (seq % 0x7FFF) as u16;

                        keepalive_payload.put_u8(0x90);
                        keepalive_payload.put_u8(0x80);
                        keepalive_payload.put_u8(0x80 | ((pic_id >> 8) as u8));
                        keepalive_payload.put_u8((pic_id & 0xFF) as u8);
                        keepalive_payload.put_slice(&VP8_KEYFRAME_HEADER);

                        let rtp_packet = RtpPacket {
                            header: RtpHeader {
                                version: 2,
                                padding: false,
                                extension: false,
                                marker: true,
                                payload_type: v_pt,
                                sequence_number: seq,
                                timestamp: ts,
                                ssrc: v_ssrc,
                                csrc: vec![],
                                extension_profile: 0,
                                extensions: vec![],
                                extensions_padding: 0,
                            },
                            payload: keepalive_payload.freeze(),
                        };
                        if let Err(e) = video_track_keepalive.write_rtp(rtp_packet).await {
                            log::trace!("[WRTC Media] VP8 video keepalive transient error: {e}");
                        }
                    }
                });

                peer_connection_opt = Some(pc);
                data_channel_opt = data_channel_res;
                audio_track_opt = Some(audio_track);
                video_track_opt = Some(video_track);
            }
        }

        Ok(Self {
            peer_connection: peer_connection_opt,
            data_channel: data_channel_opt,
            audio_track: audio_track_opt,
            video_track: video_track_opt,
            ssrc: local_ssrc,
            video_ssrc: local_video_ssrc,
            video_payload_type: video_pt,
            video_seq,
            video_ts,
            expected_peer_video_ssrc,
            outgoing_tx,
            raw_outgoing_tx,
            incoming_rx: Mutex::new(incoming_rx),
            video_incoming_rx: Mutex::new(video_incoming_rx),
            mode,
            dc_is_open,
            has_ws,
            is_connected,
            failed_notify,
            first_video_tx,
            start_instant: std::time::Instant::now(),
        })
    }

    pub fn effective_mode(&self, p2p_open: bool) -> &'static str {
        match self.mode {
            WrtcMode::MediaVideo => "VIDEO",
            WrtcMode::Ws => "WS",
            WrtcMode::JvbDatachannel => "JVB_DC",
            WrtcMode::P2pDirect => "P2P",
            WrtcMode::Auto => {
                if p2p_open {
                    "P2P"
                } else if self.dc_is_open.load(Ordering::SeqCst) {
                    "JVB_DC"
                } else if self.has_ws.load(Ordering::SeqCst) {
                    "WS"
                } else if self.video_track.is_some() {
                    "VIDEO"
                } else {
                    "WS"
                }
            }
        }
    }

    pub fn set_expected_peer_video_ssrc(&self, ssrc: u32) {
        self.expected_peer_video_ssrc.store(ssrc, Ordering::SeqCst);
    }

    pub async fn add_remote_video_ssrc(&self, ssrc: u32) {
        if let Some(ref pc) = self.peer_connection {
            if let Some(mut remote_desc) = pc.remote_description().await {
                if !remote_desc.sdp.contains(&format!("a=ssrc:{}", ssrc)) {
                    let mut new_sdp = String::new();
                    let mut in_video = false;
                    for line in remote_desc.sdp.lines() {
                        new_sdp.push_str(line);
                        new_sdp.push_str("\r\n");
                        if line.starts_with("m=video") {
                            in_video = true;
                        } else if line.starts_with("m=") && !line.starts_with("m=video") {
                            in_video = false;
                        }

                        if in_video && (line.starts_with("a=sendrecv") || line.starts_with("a=recvonly") || line.starts_with("a=sendonly") || line.starts_with("a=mid:video")) {
                            new_sdp.push_str(&format!("a=ssrc:{} cname:anet_dyn\r\n", ssrc));
                            new_sdp.push_str(&format!("a=ssrc:{} msid:anet_dyn v0\r\n", ssrc));
                        }
                    }
                    remote_desc.sdp = new_sdp;
                    if let Err(e) = pc.set_remote_description(remote_desc).await {
                        log::warn!("[WRTC Media] Failed to inject remote SSRC {}: {}", ssrc, e);
                    } else {
                        log::info!("[WRTC Media] Successfully injected remote SSRC {} into PC", ssrc);
                        if let Ok(answer) = pc.create_answer(None).await {
                            let _ = pc.set_local_description(answer).await;
                        }
                    }
                }
            }
        }
    }

    pub async fn send_video_frame(&self, astp_data: &[u8]) -> anyhow::Result<()> {
        let Some(ref track) = self.video_track else {
            anyhow::bail!("Video track not initialized");
        };

        if self.first_video_tx.swap(false, Ordering::Relaxed) {
            log::info!(
                "[WRTC Media Video OUT] First video frame transmitted (SSRC: {}, len: {} bytes)",
                self.video_ssrc, astp_data.len()
            );
        }

        let seq = self.video_seq.fetch_add(1, Ordering::Relaxed);
        let elapsed_ms = self.start_instant.elapsed().as_millis() as u64;
        let ts = ((elapsed_ms * 90) & 0xFFFFFFFF) as u32;

        let mut payload = BytesMut::with_capacity(4 + VP8_KEYFRAME_HEADER.len() + astp_data.len());
        let pic_id = (seq % 0x7FFF) as u16;

        payload.put_u8(0x90);
        payload.put_u8(0x80);
        payload.put_u8(0x80 | ((pic_id >> 8) as u8));
        payload.put_u8((pic_id & 0xFF) as u8);

        payload.put_slice(&VP8_KEYFRAME_HEADER);
        payload.put_slice(astp_data);

        let rtp_packet = RtpPacket {
            header: RtpHeader {
                version: 2,
                padding: false,
                extension: false,
                marker: true,
                payload_type: self.video_payload_type,
                sequence_number: seq,
                timestamp: ts,
                ssrc: self.video_ssrc,
                csrc: vec![],
                extension_profile: 0,
                extensions: vec![],
                extensions_padding: 0,
            },
            payload: payload.freeze(),
        };

        track
            .write_rtp(rtp_packet)
            .await
            .map_err(|e| anyhow::anyhow!("VP8 write_rtp error: {e}"))
    }

    pub async fn send_video_constraints(&self, constraints: &ReceiverVideoConstraints) -> anyhow::Result<()> {
        let json = serde_json::to_string(constraints)?;
        self.raw_outgoing_tx
            .send(json)
            .await
            .map_err(|_| anyhow::anyhow!("WebRTC DataChannel write channel closed"))
    }

    pub async fn recv_video_frame(&self) -> Option<Bytes> {
        let mut rx = self.video_incoming_rx.lock().await;
        rx.recv().await
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
