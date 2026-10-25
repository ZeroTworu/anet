use crate::config::WrtcConfig;
use crate::consts::{
    TAG_UNTAGGED, VP8_ASTP_PREFIX_LEN, VP8_INTERFRAME_HEADER, VP8_KEYFRAME_1080P_HEADER,
    VP8_KEYFRAME_HEADER, WRTC_BURST_KEYFRAME_COUNT, WRTC_BURST_KEYFRAME_INTERVAL_MS,
    WRTC_COLIBRI_CHANNEL_CAPACITY, WRTC_CONSTRAINTS_RETRY_ATTEMPTS,
    WRTC_CONSTRAINTS_RETRY_INTERVAL_MS, WRTC_DC_SEND_MAX_RETRIES, WRTC_DC_SEND_RETRY_DELAY_MS,
    WRTC_ICE_GATHER_POLL_ATTEMPTS, WRTC_ICE_GATHER_POLL_INTERVAL_MS,
    WRTC_INITIAL_FORCE_KEYFRAMES, WRTC_KEYFRAME_INTERVAL_MASK, WRTC_OPUS_CHANNELS,
    WRTC_OPUS_CLOCK_RATE, WRTC_OPUS_PAYLOAD_TYPE, WRTC_OPUS_SILENCE_FRAME,
    WRTC_P2P_CHANNEL_CAPACITY, WRTC_REASSERT_FORCE_KEYFRAMES, WRTC_VIDEO_CHANNEL_CAPACITY,
    WRTC_VP8_CLOCK_RATE, WRTC_VP8_FALLBACK_PAYLOAD_TYPE, WRTC_VP8_PRIMARY_PAYLOAD_TYPE,
    WRTC_VP8_RTP_TS_STEP, WRTC_WS_FALLBACK_CHANNEL_CAPACITY,
};
use crate::wrtc::colibri::{
    is_valid_vp8_frame_header, ColibriMessage, ReceiverVideoConstraints, WrtcMessage, WrtcMode,
};
use crate::wrtc::jingle::{append_remote_video_ssrc_to_sdp, JingleSession};
use crate::wrtc::xmpp_xml::XmppIceServer;
use bytes::{BufMut, Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use rtc::interceptor::Registry;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{MediaEngine, MIME_TYPE_OPUS, MIME_TYPE_VP8};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceServer};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::rtp::{Header as RtpHeader, Packet as RtpPacket};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};
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
use webrtc::runtime::{
    AsyncInterval, AsyncTcpListener, AsyncTcpStream, AsyncUdpSocket, JoinHandle as WrtcJoinHandle,
    Runtime as WrtcRuntime, TokioRuntime,
};

#[derive(Debug)]
struct TunedTokioRuntime {
    inner: TokioRuntime,
    udp_socket_buffer_size: usize,
}

impl WrtcRuntime for TunedTokioRuntime {
    fn spawn(
        &self,
        future: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
    ) -> Box<dyn WrtcJoinHandle> {
        self.inner.spawn(future)
    }

    fn spawn_reactor(
        &self,
        reactor_pool_size: usize,
        future: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
    ) -> Box<dyn WrtcJoinHandle> {
        self.inner.spawn_reactor(reactor_pool_size, future)
    }

    fn wrap_udp_socket(
        &self,
        sock: std::net::UdpSocket,
    ) -> std::io::Result<Arc<dyn AsyncUdpSocket>> {
        let sock_ref = socket2::SockRef::from(&sock);
        let _ = sock_ref.set_recv_buffer_size(self.udp_socket_buffer_size);
        let _ = sock_ref.set_send_buffer_size(self.udp_socket_buffer_size);
        if let (Ok(rcv), Ok(snd)) = (sock_ref.recv_buffer_size(), sock_ref.send_buffer_size()) {
            log::info!(
                "[WRTC UDP] Tuned WebRTC UDP socket buffers: SO_RCVBUF={} KiB, SO_SNDBUF={} KiB",
                rcv / 1024,
                snd / 1024
            );
        }
        self.inner.wrap_udp_socket(sock)
    }

    fn wrap_tcp_listener(
        &self,
        listener: std::net::TcpListener,
    ) -> std::io::Result<Arc<dyn AsyncTcpListener>> {
        self.inner.wrap_tcp_listener(listener)
    }

    fn connect_tcp<'a>(
        &'a self,
        remote_addr: std::net::SocketAddr,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<Arc<dyn AsyncTcpStream>>> + Send + 'a>,
    > {
        self.inner.connect_tcp(remote_addr)
    }

    fn resolve_host<'a>(
        &'a self,
        host: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<Vec<std::net::SocketAddr>>> + Send + 'a>,
    > {
        self.inner.resolve_host(host)
    }

    fn now(&self) -> std::time::Instant {
        self.inner.now()
    }

    fn sleep(
        &self,
        duration: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>> {
        self.inner.sleep(duration)
    }

    fn interval(&self, period: Duration) -> Box<dyn AsyncInterval> {
        self.inner.interval(period)
    }

    fn block_on(&self, future: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + '_>>) {
        self.inner.block_on(future)
    }

    fn yield_now(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>> {
        self.inner.yield_now()
    }

    fn name(&self) -> &'static str {
        self.inner.name()
    }
}

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

/// Определяет локальный IPv4-адрес физического сетевого интерфейса до поднятия TUN,
/// чтобы сокет WebRTC не захватывал виртуальный IP `172.112.x.x` после включения маршрута `0.0.0.0/1`.
fn detect_physical_bind_addr(
    session_opt: Option<&JingleSession>,
    fallback_ip: &str,
    fallback_port: u16,
) -> String {
    let (target_ip, target_port) = session_opt
        .and_then(|s| {
            s.transport
                .candidates
                .iter()
                .find(|c| {
                    !c.ip.is_empty()
                        && c.ip != "0.0.0.0"
                        && !c.ip.starts_with("127.")
                        && !c.ip.starts_with("172.112.")
                })
                .map(|c| (c.ip.as_str(), c.port))
        })
        .unwrap_or((fallback_ip, fallback_port));

    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if sock.connect((target_ip, target_port.max(1))).is_ok() {
            if let Ok(local_addr) = sock.local_addr() {
                let ip = local_addr.ip();
                let ip_str = ip.to_string();
                if ip.is_ipv4()
                    && !ip.is_loopback()
                    && !ip.is_unspecified()
                    && !ip_str.starts_with("172.112.")
                {
                    log::info!(
                        "[WRTC Media] Pinned WebRTC UDP socket to physical interface IP: {ip_str}"
                    );
                    return format!("{ip_str}:0");
                }
            }
        }
    }
    "0.0.0.0:0".to_string()
}

struct PeerEvents {
    connected_tx: mpsc::Sender<()>,
    is_connected: Arc<AtomicBool>,
    is_failed: Arc<AtomicBool>,
    has_ws: Arc<AtomicBool>,
    mode: WrtcMode,
    disconnected_at_ms: Arc<AtomicU64>,
    start_instant: std::time::Instant,
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
            self.disconnected_at_ms.store(0, Ordering::SeqCst);
            let _ = self.connected_tx.try_send(());
        } else if state == RTCPeerConnectionState::Disconnected
            || state == RTCPeerConnectionState::Failed
            || state == RTCPeerConnectionState::Closed
        {
            self.is_connected.store(false, Ordering::SeqCst);
            if state == RTCPeerConnectionState::Disconnected {
                let now_ms = (self.start_instant.elapsed().as_millis() as u64).max(1);
                let _ = self.disconnected_at_ms.compare_exchange(
                    0,
                    now_ms,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
            }
            if state == RTCPeerConnectionState::Closed {
                self.is_failed.store(true, Ordering::SeqCst);
                self.failed_notify.notify_waiters();
                self.failed_notify.notify_one();
            } else if state == RTCPeerConnectionState::Failed {
                if self.has_ws.load(Ordering::SeqCst) {
                    log::warn!(
                        "[WRTC Media] UDP PeerConnection entered Failed state, but Colibri-WS is active (mode={:?}). Continuing over Colibri-WS without tearing session.",
                        self.mode
                    );
                } else {
                    self.is_failed.store(true, Ordering::SeqCst);
                    self.failed_notify.notify_waiters();
                    self.failed_notify.notify_one();
                }
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
                                if !is_valid_vp8_frame_header(&data) {
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

    pub fn try_recv_packet(&self) -> Option<Bytes> {
        if let Ok(mut rx) = self.incoming_rx.try_lock() {
            rx.try_recv().ok()
        } else {
            None
        }
    }
}

fn build_ice_server_tiers(discovered: &[XmppIceServer]) -> Vec<(Vec<RTCIceServer>, bool)> {
    let filter_tier = |include_turn: bool, include_tcp_tls: bool| -> (Vec<RTCIceServer>, bool) {
        let mut list = Vec::new();
        let mut has_turn = false;
        for s in discovered {
            if !include_turn && s.is_turn {
                continue;
            }
            if !include_tcp_tls && s.is_tcp_or_tls {
                continue;
            }
            if s.is_turn {
                has_turn = true;
            }
            list.push(RTCIceServer {
                urls: s.urls.clone(),
                username: s.username.clone(),
                credential: s.credential.clone(),
            });
        }
        (list, has_turn)
    };

    let mut tiers = Vec::with_capacity(4);
    for (inc_turn, inc_tcp) in [(true, true), (true, false), (false, false)] {
        let (list, has_turn) = filter_tier(inc_turn, inc_tcp);
        if !list.is_empty() {
            let urls_flat: Vec<&str> = list
                .iter()
                .flat_map(|i| i.urls.iter().map(|u| u.as_str()))
                .collect();
            let already_present = tiers.iter().any(|(existing, _): &(Vec<RTCIceServer>, bool)| {
                let ex_urls: Vec<&str> = existing
                    .iter()
                    .flat_map(|i| i.urls.iter().map(|u| u.as_str()))
                    .collect();
                ex_urls == urls_flat
            });
            if !already_present {
                tiers.push((list, has_turn));
            }
        }
    }
    tiers.push((Vec::new(), false));
    tiers
}

pub async fn create_p2p_channel(
    ice_servers_info: &[XmppIceServer],
    wrtc_cfg: &WrtcConfig,
    bind_addr: &str,
) -> anyhow::Result<P2pSession> {
    let is_open = Arc::new(AtomicBool::new(false));
    let open_notify = Arc::new(tokio::sync::Notify::new());

    let effective_bind_addr = if !bind_addr.is_empty() && bind_addr != "0.0.0.0:0" {
        bind_addr.to_string()
    } else {
        detect_physical_bind_addr(None, "1.1.1.1", 443)
    };
    log::info!(
        "[P2P Direct] Pinned P2P UDP socket to physical interface: {effective_bind_addr}"
    );

    let tiers = build_ice_server_tiers(ice_servers_info);
    let mut last_err = None;
    let mut built_pc = None;

    for (tier_idx, (ice_servers, _)) in tiers.into_iter().enumerate() {
        let mut media_engine = MediaEngine::default();
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;

        let config = RTCConfigurationBuilder::new()
            .with_ice_servers(ice_servers)
            .build();

        let setting_engine = SettingEngineBuilder::new()
            .with_ice_timeouts(
                Some(Duration::from_millis(wrtc_cfg.ice_disconnected_timeout_ms)),
                Some(Duration::from_millis(wrtc_cfg.ice_failed_timeout_ms)),
                Some(Duration::from_millis(wrtc_cfg.ice_keepalive_interval_ms)),
            )
            .with_sctp_max_receive_buffer_size(wrtc_cfg.sctp_max_receive_buffer_size)
            .with_sctp_mtu(wrtc_cfg.sctp_mtu.min(1200) as _)
            .with_receive_mtu(wrtc_cfg.receive_mtu)
            .build();

        let handler = Arc::new(P2pEvents {
            is_open: is_open.clone(),
        });

        match PeerConnectionBuilder::new()
            .with_configuration(config)
            .with_setting_engine(setting_engine)
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .with_handler(handler)
            .with_runtime(Arc::new(TunedTokioRuntime {
                inner: TokioRuntime,
                udp_socket_buffer_size: wrtc_cfg.udp_socket_buffer_size,
            }))
            .with_udp_addrs(vec![effective_bind_addr.clone()])
            .with_dedicated_reactor_pool_size(wrtc_cfg.reactor_pool_size.max(1))
            .build()
            .await
        {
            Ok(pc_res) => {
                built_pc = Some(pc_res);
                break;
            }
            Err(e) => {
                log::debug!(
                    "[P2P Direct] ICE configuration tier {tier_idx} rejected by engine ({e}), trying fallback tier..."
                );
                last_err = Some(e);
            }
        }
    }

    let pc_res = match built_pc {
        Some(pc) => pc,
        None => return Err(anyhow::anyhow!("Failed to build P2P PeerConnection: {:?}", last_err)),
    };

    let pc: Arc<dyn PeerConnection> = Arc::new(pc_res);

    let dc_init = RTCDataChannelInit {
        ordered: false,
        max_packet_life_time: None,
        max_retransmits: Some(0),
        protocol: "anet-tunnel-v1".to_string(),
        negotiated: Some(0),
    };

    let dc: Arc<dyn DataChannel> = pc.create_data_channel("anet-data", Some(dc_init)).await?;

    let (incoming_tx, incoming_rx) = mpsc::channel::<Bytes>(WRTC_P2P_CHANNEL_CAPACITY);
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
    pub is_failed: Arc<AtomicBool>,
    pub disconnected_at_ms: Arc<AtomicU64>,
    pub failed_notify: Arc<tokio::sync::Notify>,
    pub first_video_rx: Arc<AtomicBool>,
    pub first_video_tx: Arc<AtomicBool>,
    pub start_instant: std::time::Instant,
    pub last_video_tx_ms: Arc<AtomicU64>,
    pub video_v2_enabled: Arc<AtomicBool>,
    pub force_keyframe_remaining: Arc<AtomicU32>,
    pub remote_sdp: Mutex<String>,
    pub colibri_ws_ip: Arc<std::sync::Mutex<Option<std::net::IpAddr>>>,
    pub active_video_constraints: Arc<std::sync::Mutex<Option<ReceiverVideoConstraints>>>,
    pub bind_addr: String,
    pub watchdog_disconnected_timeout_ms: u64,
    pub watchdog_channel_grace_secs: u64,
    pub peer_close_timeout_secs: u64,
}

impl WrtcPeer {
    pub async fn create(
        session_opt: Option<&JingleSession>,
        xmpp_opt: Option<&crate::wrtc::xmpp::XmppSession>,
        fallback_ip: &str,
        fallback_port: u16,
        audio_keepalive_ms: u64,
        mode: WrtcMode,
        wrtc_cfg: &WrtcConfig,
    ) -> anyhow::Result<Self> {
        let (incoming_tx, incoming_rx) =
            mpsc::channel::<ColibriMessage>(WRTC_COLIBRI_CHANNEL_CAPACITY);
        let (video_incoming_tx, video_incoming_rx) =
            mpsc::channel::<Bytes>(WRTC_VIDEO_CHANNEL_CAPACITY);
        let (outgoing_tx, mut outgoing_rx) =
            mpsc::channel::<ColibriMessage>(WRTC_COLIBRI_CHANNEL_CAPACITY);
        let (raw_outgoing_tx, mut raw_outgoing_rx) =
            mpsc::channel::<String>(WRTC_COLIBRI_CHANNEL_CAPACITY);
        let (connected_tx, _connected_rx) = mpsc::channel::<()>(1);
        let is_connected = Arc::new(AtomicBool::new(false));
        let is_failed = Arc::new(AtomicBool::new(false));
        let disconnected_at_ms = Arc::new(AtomicU64::new(0));
        let failed_notify = Arc::new(tokio::sync::Notify::new());
        let dc_is_open = Arc::new(AtomicBool::new(false));
        let first_video_rx = Arc::new(AtomicBool::new(true));
        let first_video_tx = Arc::new(AtomicBool::new(true));

        let local_ssrc = generate_random_ssrc();
        let local_video_ssrc = generate_random_ssrc();
        let video_pt = session_opt
            .map(|s| s.video_payload_type)
            .unwrap_or(WRTC_VP8_PRIMARY_PAYLOAD_TYPE);
        let has_video_flag =
            session_opt.map(|s| s.has_video).unwrap_or(false) || mode == WrtcMode::MediaVideo;
        let video_seq = Arc::new(AtomicU16::new(0));
        let video_ts = Arc::new(AtomicU32::new(0));
        let expected_peer_video_ssrc = Arc::new(AtomicU32::new(0));
        let _remote_ssrc = 0;
        let start_instant = std::time::Instant::now();
        let last_video_tx_ms = Arc::new(AtomicU64::new(0));
        let video_v2_enabled = Arc::new(AtomicBool::new(false));
        let force_keyframe_remaining = Arc::new(AtomicU32::new(WRTC_INITIAL_FORCE_KEYFRAMES));
        let mut initial_remote_sdp = String::new();

        let (ws_fallback_tx, mut ws_fallback_rx) =
            mpsc::channel::<String>(WRTC_WS_FALLBACK_CHANNEL_CAPACITY);
        let has_ws = Arc::new(AtomicBool::new(false));
        let colibri_ws_ip: Arc<std::sync::Mutex<Option<std::net::IpAddr>>> =
            Arc::new(std::sync::Mutex::new(None));
        let active_video_constraints: Arc<std::sync::Mutex<Option<ReceiverVideoConstraints>>> =
            Arc::new(std::sync::Mutex::new(None));

        if let Some(session) = session_opt {
            if let Some(ref ws_url) = session.transport.colibri_ws_url {
                let ws_url_c = ws_url.clone();
                let ws_profile = xmpp_opt
                    .map(|x| x.profile.clone())
                    .unwrap_or_else(crate::http_help::BrowserProfile::random);
                let ws_origin = xmpp_opt.map(|x| x.origin.clone());
                let in_tx_ws = incoming_tx.clone();
                let has_ws_c = has_ws.clone();
                let colibri_ws_ip_c = colibri_ws_ip.clone();
                let active_constraints_ws = active_video_constraints.clone();
                let dc_open_ws = dc_is_open.clone();
                let is_failed_ws = is_failed.clone();
                let failed_notify_ws = failed_notify.clone();
                let colibri_connect_timeout = wrtc_cfg.colibri_ws_connect_timeout_secs.max(1);
                let ws_write_timeout = wrtc_cfg.ws_write_timeout_secs.max(1);
                tokio::spawn(async move {
                    let mut reconnect_attempts = 0u32;
                    loop {
                        let connect_res = match ws_profile.build_ws_request(&ws_url_c, ws_origin.as_deref()) {
                            Ok(req) => {
                                tokio::time::timeout(
                                    Duration::from_secs(colibri_connect_timeout),
                                    tokio_tungstenite::connect_async(req),
                                )
                                .await
                            }
                            Err(e) => {
                                log::warn!("[WRTC WS] Failed to build Colibri-WS request: {e}");
                                if !dc_open_ws.load(Ordering::SeqCst) {
                                    is_failed_ws.store(true, Ordering::SeqCst);
                                    failed_notify_ws.notify_waiters();
                                    failed_notify_ws.notify_one();
                                }
                                return;
                            }
                        };

                        if let Ok(Ok((mut ws_stream, _))) = connect_res {
                            reconnect_attempts = 0;
                            let peer_ip = match ws_stream.get_ref() {
                                tokio_tungstenite::MaybeTlsStream::Plain(s) => {
                                    let _ = s.set_nodelay(true);
                                    s.peer_addr().ok().map(|a| a.ip())
                                }
                                tokio_tungstenite::MaybeTlsStream::Rustls(s) => {
                                    let _ = s.get_ref().0.set_nodelay(true);
                                    s.get_ref().0.peer_addr().ok().map(|a| a.ip())
                                }
                                _ => None,
                            };
                            if let Some(ip) = peer_ip {
                                if let Ok(mut g) = colibri_ws_ip_c.lock() {
                                    *g = Some(ip);
                                }
                            }
                            has_ws_c.store(true, Ordering::SeqCst);
                            log::info!(
                                "[WRTC WS] Parallel Colibri-WS fallback connected (remote_ip: {:?})",
                                peer_ip
                            );

                            if has_video_flag {
                                let saved_constraints = active_constraints_ws
                                    .lock()
                                    .ok()
                                    .and_then(|g| g.clone());
                                if let Some(constraints) = saved_constraints {
                                    if let Ok(json) = serde_json::to_string(&constraints) {
                                        let _ = tokio::time::timeout(
                                            Duration::from_secs(ws_write_timeout),
                                            ws_stream.send(
                                                tokio_tungstenite::tungstenite::Message::Text(json.into()),
                                            ),
                                        )
                                        .await;
                                    }
                                }
                            }

                            let mut ws_ping_interval = tokio::time::interval(Duration::from_secs(15));
                            ws_ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                            let mut channel_closed = false;

                            loop {
                                tokio::select! {
                                    msg_opt = ws_stream.next() => {
                                        match msg_opt {
                                            Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) => {
                                                if let Ok(c_msg) = serde_json::from_str::<ColibriMessage>(&text) {
                                                    let _ = in_tx_ws.send(c_msg).await;
                                                }
                                            }
                                            Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(bin))) => {
                                                if let Ok(c_msg) = serde_json::from_slice::<ColibriMessage>(&bin) {
                                                    let _ = in_tx_ws.send(c_msg).await;
                                                }
                                            }
                                            Some(Ok(tokio_tungstenite::tungstenite::Message::Ping(data))) => {
                                                let pong_res = tokio::time::timeout(
                                                    Duration::from_secs(ws_write_timeout),
                                                    ws_stream.send(tokio_tungstenite::tungstenite::Message::Pong(data)),
                                                )
                                                .await;
                                                if pong_res.map_or(true, |r| r.is_err()) {
                                                    log::warn!("[WRTC WS] Colibri-WS pong write failed or timed out");
                                                    break;
                                                }
                                            }
                                            Some(Ok(tokio_tungstenite::tungstenite::Message::Close(frame))) => {
                                                log::warn!("[WRTC WS] Colibri-WS closed by JVB: {frame:?}");
                                                break;
                                            }
                                            Some(Err(e)) => {
                                                log::warn!("[WRTC WS] Colibri-WS read error: {e}");
                                                break;
                                            }
                                            None => {
                                                log::warn!("[WRTC WS] Colibri-WS stream ended");
                                                break;
                                            }
                                            _ => {}
                                        }
                                    }
                                    json_opt = ws_fallback_rx.recv() => {
                                        let Some(json_text) = json_opt else {
                                            channel_closed = true;
                                            break;
                                        };
                                        let send_res = tokio::time::timeout(
                                            Duration::from_secs(ws_write_timeout),
                                            async {
                                                ws_stream
                                                    .feed(tokio_tungstenite::tungstenite::Message::Text(
                                                        json_text.into(),
                                                    ))
                                                    .await?;
                                                for _ in 0..15 {
                                                    match ws_fallback_rx.try_recv() {
                                                        Ok(more_text) => {
                                                            ws_stream
                                                                .feed(
                                                                    tokio_tungstenite::tungstenite::Message::Text(
                                                                        more_text.into(),
                                                                    ),
                                                                )
                                                                .await?;
                                                        }
                                                        Err(_) => break,
                                                    }
                                                }
                                                ws_stream.flush().await
                                            },
                                        )
                                        .await;
                                        if send_res.map_or(true, |r| r.is_err()) {
                                            log::warn!("[WRTC WS] Colibri-WS write failed or timed out");
                                            break;
                                        }
                                    }
                                    _ = ws_ping_interval.tick() => {
                                        let ping_res = tokio::time::timeout(
                                            Duration::from_secs(ws_write_timeout),
                                            ws_stream.send(
                                                tokio_tungstenite::tungstenite::Message::Ping(Vec::new().into()),
                                            ),
                                        )
                                        .await;
                                        if ping_res.map_or(true, |r| r.is_err()) {
                                            log::warn!("[WRTC WS] Colibri-WS keepalive ping failed or timed out");
                                            break;
                                        }
                                    }
                                }
                            }

                            has_ws_c.store(false, Ordering::SeqCst);
                            if channel_closed || is_failed_ws.load(Ordering::SeqCst) {
                                break;
                            }
                        } else {
                            log::warn!("[WRTC WS] Failed or timed out connecting to Colibri-WS: {ws_url_c}");
                        }

                        reconnect_attempts += 1;
                        if reconnect_attempts > 5 || is_failed_ws.load(Ordering::SeqCst) {
                            if !dc_open_ws.load(Ordering::SeqCst) {
                                log::warn!(
                                    "[WRTC WS] Colibri-WS reconnect attempts exhausted ({reconnect_attempts}) and no SCTP DataChannel is open; marking peer failed"
                                );
                                is_failed_ws.store(true, Ordering::SeqCst);
                                failed_notify_ws.notify_waiters();
                                failed_notify_ws.notify_one();
                            }
                            break;
                        }

                        log::info!(
                            "[WRTC WS] Reconnecting Colibri-WS in 500ms (attempt {reconnect_attempts}/5)..."
                        );
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                });
            }
        }

        let mut peer_connection_opt = None;
        let mut data_channel_opt = None;
        let mut audio_track_opt = None;
        let mut video_track_opt = None;

        let bind_addr = detect_physical_bind_addr(session_opt, fallback_ip, fallback_port);

        if let (Some(session), Some(xmpp)) = (session_opt, xmpp_opt) {
            log::info!("[WRTC Media] Initializing WebRTC PeerConnection with Audio (Opus) and Video (VP8)...");

            let audio_codec = RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_OPUS.to_owned(),
                    clock_rate: WRTC_OPUS_CLOCK_RATE,
                    channels: WRTC_OPUS_CHANNELS,
                    sdp_fmtp_line: "".to_owned(),
                    rtcp_feedback: vec![],
                },
                payload_type: WRTC_OPUS_PAYLOAD_TYPE,
                ..Default::default()
            };

            let video_codec = RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_VP8.to_owned(),
                    clock_rate: WRTC_VP8_CLOCK_RATE,
                    channels: 0,
                    sdp_fmtp_line: "".to_owned(),
                    rtcp_feedback: vec![],
                },
                payload_type: video_pt,
                ..Default::default()
            };

            let remote_dc: Arc<Mutex<Option<Arc<dyn DataChannel>>>> = Arc::new(Mutex::new(None));
            let dc_open_notify = Arc::new(tokio::sync::Notify::new());

            let discovered_ice = xmpp.get_ice_servers();
            let tiers = build_ice_server_tiers(&discovered_ice);
            let mut built_pc = None;
            let mut has_turn_configured = false;

            for (tier_idx, (ice_servers, tier_has_turn)) in tiers.into_iter().enumerate() {
                let mut media_engine = MediaEngine::default();
                media_engine.register_codec(audio_codec.clone(), RtpCodecKind::Audio)?;
                media_engine.register_codec(video_codec.clone(), RtpCodecKind::Video)?;

                if video_pt != WRTC_VP8_FALLBACK_PAYLOAD_TYPE {
                    let mut fallback_vcodec = video_codec.clone();
                    fallback_vcodec.payload_type = WRTC_VP8_FALLBACK_PAYLOAD_TYPE;
                    let _ = media_engine.register_codec(fallback_vcodec, RtpCodecKind::Video);
                }
                if video_pt != WRTC_VP8_PRIMARY_PAYLOAD_TYPE {
                    let mut fallback_vcodec2 = video_codec.clone();
                    fallback_vcodec2.payload_type = WRTC_VP8_PRIMARY_PAYLOAD_TYPE;
                    let _ = media_engine.register_codec(fallback_vcodec2, RtpCodecKind::Video);
                }

                // Отключаем стандартные RTP-интерцепторы (NackResponder, NackGenerator, TWCC),
                // чтобы исключить клонирование каждого пакета в кольцевой буфер ретрансляции
                // и блокировки мьютексов BWE/TWCC внутри webrtc-rs при высокоскоростном потоке.
                let registry = Registry::new();

                let tier_urls: Vec<String> = ice_servers
                    .iter()
                    .flat_map(|s| s.urls.clone())
                    .collect();

                let config = RTCConfigurationBuilder::new()
                    .with_ice_servers(ice_servers)
                    .build();

                let setting_engine = SettingEngineBuilder::new()
                    .with_answering_dtls_role(RTCDtlsRole::Client)
                    .with_ice_timeouts(
                        Some(Duration::from_millis(wrtc_cfg.ice_disconnected_timeout_ms)),
                        Some(Duration::from_millis(wrtc_cfg.ice_failed_timeout_ms)),
                        Some(Duration::from_millis(wrtc_cfg.ice_keepalive_interval_ms)),
                    )
                    .with_sctp_max_receive_buffer_size(wrtc_cfg.sctp_max_receive_buffer_size)
                    .with_sctp_mtu(wrtc_cfg.sctp_mtu.min(1200) as _)
                    .with_receive_mtu(wrtc_cfg.receive_mtu)
                    .build();

                let handler = Arc::new(PeerEvents {
                    connected_tx: connected_tx.clone(),
                    is_connected: is_connected.clone(),
                    is_failed: is_failed.clone(),
                    has_ws: has_ws.clone(),
                    mode,
                    disconnected_at_ms: disconnected_at_ms.clone(),
                    start_instant,
                    failed_notify: failed_notify.clone(),
                    dc_is_open: dc_is_open.clone(),
                    dc_open_notify: dc_open_notify.clone(),
                    incoming_tx: incoming_tx.clone(),
                    remote_dc: remote_dc.clone(),
                    video_incoming_tx: video_incoming_tx.clone(),
                    expected_peer_video_ssrc: expected_peer_video_ssrc.clone(),
                    first_video_rx: first_video_rx.clone(),
                    local_video_ssrc,
                });

                match PeerConnectionBuilder::new()
                    .with_configuration(config)
                    .with_setting_engine(setting_engine)
                    .with_media_engine(media_engine)
                    .with_interceptor_registry(registry)
                    .with_handler(handler)
                    .with_runtime(Arc::new(TunedTokioRuntime {
                        inner: TokioRuntime,
                        udp_socket_buffer_size: wrtc_cfg.udp_socket_buffer_size,
                    }))
                    .with_udp_addrs(vec![bind_addr.clone()])
                    .with_dedicated_reactor_pool_size(wrtc_cfg.reactor_pool_size.max(1))
                    .build()
                    .await
                {
                    Ok(pc_impl) => {
                        log::info!(
                            "[WRTC Media] PeerConnection built with ICE tier {tier_idx} (TURN={tier_has_turn}): {:?}",
                            tier_urls
                        );
                        has_turn_configured = tier_has_turn;
                        built_pc = Some(pc_impl);
                        break;
                    }
                    Err(e) => {
                        log::debug!(
                            "[WRTC Media] ICE configuration tier {tier_idx} rejected by engine ({e}), trying fallback tier..."
                        );
                    }
                }
            }

            if let Some(pc_impl) = built_pc {
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
                            let active_constraints_dc = active_video_constraints.clone();

                            tokio::spawn(async move {
                                while let Some(event) = dc_in.poll().await {
                                    match event {
                                        DataChannelEvent::OnOpen => {
                                            log::info!("[WRTC DataChannel] 'JVB data channel' state is now OPEN!");
                                            dc_is_open_in.store(true, Ordering::SeqCst);
                                            dc_open_notify_in.notify_waiters();
                                            if has_video_flag {
                                                let saved_constraints = active_constraints_dc
                                                    .lock()
                                                    .ok()
                                                    .and_then(|g| g.clone());
                                                if let Some(constraints) = saved_constraints {
                                                    if let Ok(json) = serde_json::to_string(&constraints) {
                                                        let _ = dc_in.send_text(&json).await;
                                                    }
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
                initial_remote_sdp = sdp_str.clone();
                if let Ok(offer) = RTCSessionDescription::offer(sdp_str) {
                    if pc.set_remote_description(offer).await.is_ok() {
                        if let Ok(answer) = pc.create_answer(None).await {
                            let _ = pc.set_local_description(answer.clone()).await;

                            let mut final_sdp = answer.sdp.clone();
                            for attempt in 0..WRTC_ICE_GATHER_POLL_ATTEMPTS {
                                if let Some(desc) = pc.local_description().await {
                                    if desc.sdp.contains("a=candidate:") {
                                        final_sdp = desc.sdp;
                                        let has_srflx = final_sdp.contains("typ srflx");
                                        let has_relay = final_sdp.contains("typ relay");
                                        if (has_srflx && (!has_turn_configured || has_relay))
                                            || ((has_srflx || has_relay) && attempt >= 15)
                                            || attempt >= 25
                                        {
                                            break;
                                        }
                                    }
                                }
                                tokio::time::sleep(Duration::from_millis(
                                    WRTC_ICE_GATHER_POLL_INTERVAL_MS,
                                ))
                                .await;
                            }

                            let local_params = crate::wrtc::jingle::parse_sdp_answer(&final_sdp);
                            let cand_summary: Vec<String> = local_params
                                .candidates
                                .iter()
                                .filter_map(|c| {
                                    let p: Vec<&str> = c.split_whitespace().collect();
                                    if p.len() >= 8 && p[6] == "typ" {
                                        Some(format!("{}:{}:{}", p[7], p[4], p[5]))
                                    } else {
                                        None
                                    }
                                })
                                .collect();

                            log::info!(
                                "[WRTC Media] Generated local SDP Answer: ufrag={}, pwd={}, fp={}, candidates count={} {:?}",
                                local_params.ufrag,
                                local_params.pwd,
                                local_params.fingerprint,
                                local_params.candidates.len(),
                                cand_summary
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
                let is_connected_out = is_connected.clone();
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
                        // Используем SCTP DataChannel ТОЛЬКО когда живы и SCTP (dc_is_open), и UDP ICE (is_connected).
                        // Если под БС UDP просел (Disconnected/Failed), мгновенно отправляем ping/constraints/батчи через живой Colibri-WS!
                        if dc_is_open_out.load(Ordering::SeqCst) && is_connected_out.load(Ordering::SeqCst) {
                            if let Some(ref dc_out) = dc_opt_out {
                                if is_batch {
                                    log::debug!("[JVB DC OUT Batch]");
                                } else if is_astp {
                                    log::trace!("[JVB DC OUT ASTP]");
                                } else {
                                    log::info!("[JVB DC OUT]: {json_str}");
                                }

                                for attempt in 0..WRTC_DC_SEND_MAX_RETRIES {
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
                                            if attempt + 1 < WRTC_DC_SEND_MAX_RETRIES {
                                                tokio::time::sleep(Duration::from_millis(
                                                    WRTC_DC_SEND_RETRY_DELAY_MS,
                                                ))
                                                .await;
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        let is_constraints = !is_astp && !is_batch && json_str.contains("ReceiverVideoConstraints");
                        let constraints_copy = if is_constraints { Some(json_str.clone()) } else { None };

                        if !sent && has_ws_out.load(Ordering::SeqCst) {
                            if is_astp || is_batch {
                                log::trace!("[JVB WS OUT ASTP]");
                            } else {
                                log::info!("[JVB WS OUT]: {json_str}");
                            }
                            if let Err(e) = ws_fallback_tx_out.try_send(json_str) {
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

                        if !sent && is_constraints {
                            // Критично: отправка отложенных ограничений выполняется в фоне,
                            // чтобы не блокировать основной цикл отправки сообщений (discover, ping, auth)!
                            let dc_is_open_bg = dc_is_open_out.clone();
                            let is_connected_bg = is_connected_out.clone();
                            let dc_opt_bg = dc_opt_out.clone();
                            let remote_dc_bg = remote_dc_out.clone();
                            let has_ws_bg = has_ws_out.clone();
                            let ws_fallback_tx_bg = ws_fallback_tx_out.clone();
                            let json_str_bg = constraints_copy.unwrap_or_default();
                            tokio::spawn(async move {
                                for _ in 0..WRTC_CONSTRAINTS_RETRY_ATTEMPTS {
                                    tokio::time::sleep(Duration::from_millis(
                                        WRTC_CONSTRAINTS_RETRY_INTERVAL_MS,
                                    ))
                                    .await;
                                    if dc_is_open_bg.load(Ordering::SeqCst) && is_connected_bg.load(Ordering::SeqCst) {
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
                let samples_per_packet =
                    (u64::from(WRTC_OPUS_CLOCK_RATE) * interval_ms / 1000) as u32;
                let is_connected_a = Arc::clone(&is_connected);
                let ice_failed_wait_ms = wrtc_cfg.ice_failed_timeout_ms;

                tokio::spawn(async move {
                    let start = std::time::Instant::now();
                    while !is_connected_a.load(Ordering::SeqCst) {
                        if start.elapsed() > Duration::from_millis(ice_failed_wait_ms) {
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
                    let silence_payload = Bytes::from_static(&WRTC_OPUS_SILENCE_FRAME);
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
                                payload_type: WRTC_OPUS_PAYLOAD_TYPE,
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
                let last_video_tx_c = Arc::clone(&last_video_tx_ms);
                let video_v2_c = Arc::clone(&video_v2_enabled);
                let start_instant_c = start_instant;
                let v_pt = video_pt;
                let v_ssrc = local_video_ssrc;
                let is_connected_v = Arc::clone(&is_connected);
                let video_keepalive_ms = wrtc_cfg.video_keepalive_interval_ms.max(100);
                let video_idle_suppress_ms = (video_keepalive_ms * 4) / 5;
                tokio::spawn(async move {
                    let start = std::time::Instant::now();
                    while !is_connected_v.load(Ordering::SeqCst) {
                        if start.elapsed() > Duration::from_millis(ice_failed_wait_ms) {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    log::info!(
                        "[WRTC Media] Starting VP8 video keepalive (interval: {}ms)",
                        video_keepalive_ms
                    );
                    let mut interval =
                        tokio::time::interval(Duration::from_millis(video_keepalive_ms));
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                    loop {
                        interval.tick().await;
                        let elapsed_ms = start_instant_c.elapsed().as_millis() as u64;
                        if elapsed_ms.saturating_sub(last_video_tx_c.load(Ordering::Relaxed))
                            < video_idle_suppress_ms
                        {
                            // Не инжектируем пустые кадры посреди активного потока данных
                            continue;
                        }

                        let frame_num = video_ts_c.fetch_add(1, Ordering::Relaxed);
                        let seq = (frame_num & 0xFFFF) as u16;
                        video_seq_c.store(seq.wrapping_add(1), Ordering::Relaxed);
                        let pic_id = (frame_num & 0x7FFF) as u16;
                        let ts = frame_num.wrapping_mul(WRTC_VP8_RTP_TS_STEP);

                        let mut keepalive_payload = BytesMut::with_capacity(4 + VP8_KEYFRAME_HEADER.len());

                        keepalive_payload.put_u8(0x90);
                        keepalive_payload.put_u8(0x80);
                        keepalive_payload.put_u8(0x80 | ((pic_id >> 8) as u8));
                        keepalive_payload.put_u8((pic_id & 0xFF) as u8);
                        if video_v2_c.load(Ordering::Relaxed) {
                            keepalive_payload.put_slice(&VP8_KEYFRAME_1080P_HEADER);
                        } else {
                            keepalive_payload.put_slice(&VP8_KEYFRAME_HEADER);
                        }

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
            is_failed,
            disconnected_at_ms,
            failed_notify,
            first_video_rx,
            first_video_tx,
            start_instant,
            last_video_tx_ms,
            video_v2_enabled,
            force_keyframe_remaining,
            remote_sdp: Mutex::new(initial_remote_sdp),
            colibri_ws_ip,
            active_video_constraints,
            bind_addr,
            watchdog_disconnected_timeout_ms: wrtc_cfg
                .watchdog_disconnected_timeout_secs
                .saturating_mul(1000)
                .max(1000),
            watchdog_channel_grace_secs: wrtc_cfg.watchdog_channel_grace_secs.max(1),
            peer_close_timeout_secs: wrtc_cfg.peer_close_timeout_secs.max(1),
        })
    }

    pub fn colibri_ws_ip(&self) -> Option<std::net::IpAddr> {
        self.colibri_ws_ip.lock().ok().and_then(|g| *g)
    }

    pub fn check_dead_reason(&self) -> Option<&'static str> {
        if self.is_failed.load(Ordering::SeqCst) {
            return Some("PeerConnection or Colibri-WS failed/closed");
        }
        // Если активен TCP/TLS канал Colibri-WS (has_ws == true), проседание или блокировка
        // UDP ICE (например, при активных Белых Списках оператора) НЕ должны рвать живую сессию!
        if !self.has_ws.load(Ordering::SeqCst) {
            let disc_ms = self.disconnected_at_ms.load(Ordering::SeqCst);
            if disc_ms > 0 {
                let now_ms = self.start_instant.elapsed().as_millis() as u64;
                if now_ms.saturating_sub(disc_ms) >= self.watchdog_disconnected_timeout_ms {
                    return Some("PeerConnection remained Disconnected past watchdog timeout (and no Colibri-WS active)");
                }
            }
        }
        if self.start_instant.elapsed() > Duration::from_secs(self.watchdog_channel_grace_secs)
            && !self.has_ws.load(Ordering::SeqCst)
            && (!self.dc_is_open.load(Ordering::SeqCst) || !self.is_connected.load(Ordering::SeqCst))
        {
            return Some("Both Colibri-WS and DataChannel are closed/disconnected");
        }
        None
    }

    pub fn set_video_v2(&self, enabled: bool) {
        self.video_v2_enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn is_video_v2(&self) -> bool {
        self.video_v2_enabled.load(Ordering::Relaxed)
    }

    pub fn force_next_keyframe(&self) {
        self.force_keyframe_remaining
            .store(WRTC_REASSERT_FORCE_KEYFRAMES, Ordering::Relaxed);
        if let Some(ref track) = self.video_track {
            let track_c = Arc::clone(track);
            let video_seq_c = Arc::clone(&self.video_seq);
            let video_ts_c = Arc::clone(&self.video_ts);
            let video_v2_c = Arc::clone(&self.video_v2_enabled);
            let v_pt = self.video_payload_type;
            let v_ssrc = self.video_ssrc;
            tokio::spawn(async move {
                for _ in 0..WRTC_BURST_KEYFRAME_COUNT {
                    let frame_num = video_ts_c.fetch_add(1, Ordering::Relaxed);
                    let seq = (frame_num & 0xFFFF) as u16;
                    video_seq_c.store(seq.wrapping_add(1), Ordering::Relaxed);
                    let pic_id = (frame_num & 0x7FFF) as u16;
                    let ts = frame_num.wrapping_mul(WRTC_VP8_RTP_TS_STEP);

                    let mut keepalive_payload = BytesMut::with_capacity(4 + VP8_KEYFRAME_HEADER.len());
                    keepalive_payload.put_u8(0x90);
                    keepalive_payload.put_u8(0x80);
                    keepalive_payload.put_u8(0x80 | ((pic_id >> 8) as u8));
                    keepalive_payload.put_u8((pic_id & 0xFF) as u8);
                    if video_v2_c.load(Ordering::Relaxed) {
                        keepalive_payload.put_slice(&VP8_KEYFRAME_1080P_HEADER);
                    } else {
                        keepalive_payload.put_slice(&VP8_KEYFRAME_HEADER);
                    }

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
                    let _ = track_c.write_rtp(rtp_packet).await;
                    tokio::time::sleep(Duration::from_millis(WRTC_BURST_KEYFRAME_INTERVAL_MS)).await;
                }
            });
        }
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
        if self.mode == WrtcMode::Ws || ssrc == 0 || ssrc == self.video_ssrc || ssrc == 10002 {
            return;
        }
        let Some(ref pc) = self.peer_connection else {
            return;
        };

        let mut sdp_guard = self.remote_sdp.lock().await;
        if sdp_guard.is_empty() {
            return;
        }
        if sdp_guard.contains(&format!("a=mid:v_{ssrc}\r\n"))
            || sdp_guard.contains(&format!("a=ssrc:{ssrc} "))
        {
            self.force_next_keyframe();
            return;
        }

        let updated_sdp = append_remote_video_ssrc_to_sdp(&sdp_guard, ssrc, self.video_payload_type);
        match RTCSessionDescription::offer(updated_sdp.clone()) {
            Ok(offer) => {
                if let Err(e) = pc.set_remote_description(offer).await {
                    log::warn!(
                        "[WRTC Media] add_remote_video_ssrc({ssrc}) set_remote_description error: {e}"
                    );
                    return;
                }
                match pc.create_answer(None).await {
                    Ok(answer) => {
                        if let Err(e) = pc.set_local_description(answer).await {
                            log::warn!(
                                "[WRTC Media] add_remote_video_ssrc({ssrc}) set_local_description error: {e}"
                            );
                            return;
                        }
                        *sdp_guard = updated_sdp;
                        self.force_next_keyframe();
                        log::info!(
                            "[WRTC Media] Bound remote video SSRC {ssrc} to dedicated Recvonly transceiver (mid=v_{ssrc})"
                        );
                    }
                    Err(e) => {
                        log::warn!(
                            "[WRTC Media] add_remote_video_ssrc({ssrc}) create_answer error: {e}"
                        );
                    }
                }
            }
            Err(e) => {
                log::warn!("[WRTC Media] add_remote_video_ssrc({ssrc}) invalid SDP offer: {e}");
            }
        }
    }

    pub async fn send_video_frame(&self, astp_data: &[u8]) -> anyhow::Result<()> {
        self.send_video_frame_tagged(TAG_UNTAGGED, astp_data).await
    }

    pub async fn send_video_frame_tagged(&self, client_tag: u16, astp_data: &[u8]) -> anyhow::Result<()> {
        let mut payload = BytesMut::with_capacity(VP8_ASTP_PREFIX_LEN + astp_data.len());
        payload.put_bytes(0, VP8_ASTP_PREFIX_LEN);
        payload.put_slice(astp_data);
        self.send_video_frame_preallocated(client_tag, payload).await?;
        Ok(())
    }

    /// Заполняет 26-байтный заголовок VP8 + Client Tag напрямую в начало преаллоцированного `BytesMut`
    /// (созданного через `wrap_packet_slice_with_headroom`) и отправляет RTP-пакет без повторных аллокаций
    /// и без `memcpy` зашифрованного ASTP-пейлоуда. Возвращает замороженный `Bytes` (срез `26..` содержит ASTP).
    pub async fn send_video_frame_preallocated(
        &self,
        client_tag: u16,
        mut payload: BytesMut,
    ) -> anyhow::Result<Bytes> {
        let Some(ref track) = self.video_track else {
            anyhow::bail!("Video track not initialized");
        };
        if payload.len() < VP8_ASTP_PREFIX_LEN {
            anyhow::bail!("Preallocated VP8 buffer is shorter than VP8_ASTP_PREFIX_LEN");
        }

        if self.first_video_tx.swap(false, Ordering::Relaxed) {
            log::info!(
                "[WRTC Media Video OUT] First video frame transmitted (SSRC: {}, tag: 0x{:04X}, len: {} bytes, v2: {})",
                self.video_ssrc,
                client_tag,
                payload.len() - VP8_ASTP_PREFIX_LEN,
                self.video_v2_enabled.load(Ordering::Relaxed)
            );
        }

        // Единый монотонный атомарный счетчик кадров: гарантирует уникальную тройку (seq, pic_id, ts)
        // для каждого пакета и полностью исключает коллизии timestamp в Vp8FrameMap JVB при бурстах >1 пакета/мс.
        let frame_num = self.video_ts.fetch_add(1, Ordering::Relaxed);
        let seq = (frame_num & 0xFFFF) as u16;
        self.video_seq.store(seq.wrapping_add(1), Ordering::Relaxed);
        let pic_id = (frame_num & 0x7FFF) as u16;
        let ts = frame_num.wrapping_mul(WRTC_VP8_RTP_TS_STEP);

        let elapsed_ms = self.start_instant.elapsed().as_millis() as u64;
        self.last_video_tx_ms.store(elapsed_ms, Ordering::Relaxed);

        let force_kf = self
            .force_keyframe_remaining
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |rem| {
                if rem > 0 {
                    Some(rem - 1)
                } else {
                    None
                }
            })
            .is_ok();

        let vp8_hdr = if self.video_v2_enabled.load(Ordering::Relaxed) {
            if force_kf || (frame_num & WRTC_KEYFRAME_INTERVAL_MASK) == 0 {
                &VP8_KEYFRAME_1080P_HEADER
            } else {
                &VP8_INTERFRAME_HEADER
            }
        } else {
            &VP8_KEYFRAME_HEADER
        };

        payload[0] = 0x90;
        payload[1] = 0x80;
        payload[2] = 0x80 | ((pic_id >> 8) as u8);
        payload[3] = (pic_id & 0xFF) as u8;
        payload[4..24].copy_from_slice(vp8_hdr);
        payload[24..26].copy_from_slice(&client_tag.to_be_bytes());

        let frozen = payload.freeze();
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
            payload: frozen.clone(),
        };

        track
            .write_rtp(rtp_packet)
            .await
            .map_err(|e| anyhow::anyhow!("VP8 write_rtp error: {e}"))?;
        Ok(frozen)
    }

    pub async fn send_video_constraints(&self, constraints: &ReceiverVideoConstraints) -> anyhow::Result<()> {
        if let Ok(mut g) = self.active_video_constraints.lock() {
            *g = Some(constraints.clone());
        }
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

    pub fn try_recv_video_frame(&self) -> Option<Bytes> {
        if let Ok(mut rx) = self.video_incoming_rx.try_lock() {
            rx.try_recv().ok()
        } else {
            None
        }
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
        let close_secs = self.peer_close_timeout_secs;
        if let Some(ref pc) = self.peer_connection {
            let _ = tokio::time::timeout(Duration::from_secs(close_secs), pc.close()).await;
        }
        Ok(())
    }
}

impl Drop for WrtcPeer {
    fn drop(&mut self) {
        let close_secs = self.peer_close_timeout_secs;
        if let Some(pc) = self.peer_connection.take() {
            tokio::spawn(async move {
                let _ = tokio::time::timeout(Duration::from_secs(close_secs), pc.close()).await;
            });
        }
    }
}
