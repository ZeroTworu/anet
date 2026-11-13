use crate::config::WrtcConfig;
use crate::consts::{
    TAG_UNTAGGED, VP8_ASTP_PREFIX_LEN, VP8_KEYFRAME_1080P_HEADER,
    WRTC_COLIBRI_CHANNEL_CAPACITY, WRTC_CONSTRAINTS_RETRY_ATTEMPTS,
    WRTC_CONSTRAINTS_RETRY_INTERVAL_MS, WRTC_DC_SEND_MAX_RETRIES, WRTC_DC_SEND_RETRY_DELAY_MS,
    WRTC_DEFAULT_MAX_VIDEO_HEIGHT, WRTC_ICE_GATHER_POLL_ATTEMPTS, WRTC_ICE_GATHER_POLL_INTERVAL_MS,
    WRTC_INITIAL_FORCE_KEYFRAMES, WRTC_OPUS_CHANNELS,
    WRTC_OPUS_CLOCK_RATE, WRTC_OPUS_PAYLOAD_TYPE, WRTC_OPUS_SILENCE_FRAME,
    WRTC_P2P_CHANNEL_CAPACITY, WRTC_REASSERT_FORCE_KEYFRAMES, WRTC_VIDEO_CHANNEL_CAPACITY,
    WRTC_VP8_CLOCK_RATE, WRTC_VP8_FALLBACK_PAYLOAD_TYPE, WRTC_VP8_PRIMARY_PAYLOAD_TYPE,
    WRTC_WS_FALLBACK_CHANNEL_CAPACITY,
};
use crate::http_help::BrowserProfile;
use crate::transport_trait::VpnStream;
use crate::wrtc::colibri::{
    is_valid_vp8_frame_header, ColibriMessage, ReceiverVideoConstraints, WrtcMessage, WrtcMode,
};
use crate::wrtc::jingle::{
    append_remote_audio_ssrc_to_sdp, append_remote_video_ssrc_to_sdp, is_valid_jvb_candidate_ip,
    parse_sdp_answer, JingleSession,
};
use crate::wrtc::stealth::generate_random_uuid_v4;
use crate::wrtc::turns_proxy::{spawn_turns_udp_proxy, TurnsProxyHandle};
use crate::wrtc::xmpp::XmppSession;
use crate::wrtc::xmpp_xml::XmppIceServer;
use anyhow::{anyhow, bail, Error as AnyhowError, Result as AnyhowResult};
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use http::Uri;
use log::{info, trace, warn};
use rand::random;
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
use socket2::{SockRef, TcpKeepalive};
use std::collections::HashSet;
use std::future::Future;
use std::io::{IoSliceMut, Result as IoResult};
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::pin::Pin;
use std::str::from_utf8;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context as TaskContext, Poll};
use std::thread::available_parallelism;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::runtime::Handle as TokioHandle;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::task::AbortHandle;
use tokio::time::{
    interval, sleep, sleep_until, timeout, Instant as TokioInstant, MissedTickBehavior,
};
use tokio_tungstenite::{client_async_with_config, tungstenite::Message as WsMessage};
use webrtc::data_channel::{DataChannel, DataChannelEvent, RTCDataChannelInit};
use webrtc::media_stream::track_local::static_rtp::TrackLocalStaticRTP;
use webrtc::media_stream::track_local::TrackLocal;
use webrtc::media_stream::track_remote::{TrackRemote, TrackRemoteEvent};
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCPeerConnectionState,
};
use webrtc::runtime::{
    AsyncInterval, AsyncTcpListener, AsyncTcpStream, AsyncUdpSocket, JoinHandle as WrtcJoinHandle,
    RecvMeta, Runtime as WrtcRuntime, TokioRuntime, Transmit,
};

const _: () = assert!(rtc::turn::ANET_RTC_TURN_PATCHED);

#[derive(Debug)]
struct HybridAsyncUdpSocket {
    primary: Arc<dyn AsyncUdpSocket>,
    loopback: Option<Arc<dyn AsyncUdpSocket>>,
}

impl AsyncUdpSocket for HybridAsyncUdpSocket {
    fn local_addr(&self) -> IoResult<SocketAddr> {
        self.primary.local_addr()
    }

    fn poll_send(&self, cx: &mut TaskContext<'_>, transmit: &Transmit<'_>) -> Poll<IoResult<usize>> {
        if transmit.destination.ip().is_loopback() {
            if let Some(ref lo) = self.loopback {
                return match lo.poll_send(cx, transmit) {
                    Poll::Ready(Err(e)) => {
                        trace!(
                            "[WRTC UDP] Transient loopback send error to {} ignored to preserve TURN/ICE state: {e}",
                            transmit.destination
                        );
                        Poll::Ready(Ok(transmit.contents.len()))
                    }
                    other => other,
                };
            }
        }
        match self.primary.poll_send(cx, transmit) {
            Poll::Ready(Err(e)) => {
                trace!(
                    "[WRTC UDP] Transient UDP send error to {} ignored to preserve TURN allocation: {e}",
                    transmit.destination
                );
                Poll::Ready(Ok(transmit.contents.len()))
            }
            other => other,
        }
    }

    fn poll_recv(
        &self,
        cx: &mut TaskContext<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<IoResult<usize>> {
        if let Poll::Ready(res) = self.primary.poll_recv(cx, bufs, meta) {
            return Poll::Ready(res);
        }
        if let Some(ref lo) = self.loopback {
            if let Poll::Ready(res) = lo.poll_recv(cx, bufs, meta) {
                return Poll::Ready(res);
            }
        }
        Poll::Pending
    }

    fn max_gso_segments(&self) -> usize {
        1
    }

    fn max_gro_segments(&self) -> usize {
        self.primary.max_gro_segments()
    }
}

#[derive(Debug)]
struct TunedTokioRuntime {
    inner: TokioRuntime,
    udp_socket_buffer_size: usize,
}

impl WrtcRuntime for TunedTokioRuntime {
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) -> Box<dyn WrtcJoinHandle> {
        self.inner.spawn(future)
    }

    fn spawn_reactor(
        &self,
        reactor_pool_size: usize,
        future: Pin<Box<dyn Future<Output = ()> + Send>>,
    ) -> Box<dyn WrtcJoinHandle> {
        self.inner.spawn_reactor(reactor_pool_size, future)
    }

    fn wrap_udp_socket(&self, sock: UdpSocket) -> IoResult<Arc<dyn AsyncUdpSocket>> {
        let sock_ref = SockRef::from(&sock);
        let _ = sock_ref.set_recv_buffer_size(self.udp_socket_buffer_size);
        let _ = sock_ref.set_send_buffer_size(self.udp_socket_buffer_size);
        if let (Ok(rcv), Ok(snd)) = (sock_ref.recv_buffer_size(), sock_ref.send_buffer_size()) {
            info!(
                "[WRTC UDP] Tuned WebRTC UDP socket buffers: SO_RCVBUF={} KiB, SO_SNDBUF={} KiB",
                rcv / 1024,
                snd / 1024
            );
        }
        let primary = self.inner.wrap_udp_socket(sock)?;
        let need_loopback = primary
            .local_addr()
            .map(|a| a.is_ipv4() && !a.ip().is_loopback())
            .unwrap_or(false);
        let loopback = if need_loopback {
            if let Ok(lo_std) = UdpSocket::bind("127.0.0.1:0") {
                let lo_ref = SockRef::from(&lo_std);
                let _ = lo_ref.set_recv_buffer_size(self.udp_socket_buffer_size);
                let _ = lo_ref.set_send_buffer_size(self.udp_socket_buffer_size);
                self.inner.wrap_udp_socket(lo_std).ok()
            } else {
                None
            }
        } else {
            None
        };
        Ok(Arc::new(HybridAsyncUdpSocket { primary, loopback }))
    }

    fn wrap_tcp_listener(&self, listener: TcpListener) -> IoResult<Arc<dyn AsyncTcpListener>> {
        self.inner.wrap_tcp_listener(listener)
    }

    fn connect_tcp<'a>(
        &'a self,
        remote_addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = IoResult<Arc<dyn AsyncTcpStream>>> + Send + 'a>> {
        self.inner.connect_tcp(remote_addr)
    }

    fn resolve_host<'a>(
        &'a self,
        host: &'a str,
    ) -> Pin<Box<dyn Future<Output = IoResult<Vec<SocketAddr>>> + Send + 'a>> {
        let fut = self.inner.resolve_host(host);
        Box::pin(async move {
            let addrs = fut.await?;
            let ipv4_addrs: Vec<SocketAddr> =
                addrs.iter().copied().filter(|a| a.is_ipv4()).collect();
            if !ipv4_addrs.is_empty() {
                Ok(ipv4_addrs)
            } else {
                Ok(addrs)
            }
        })
    }

    fn now(&self) -> Instant {
        self.inner.now()
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        self.inner.sleep(duration)
    }

    fn interval(&self, period: Duration) -> Box<dyn AsyncInterval> {
        self.inner.interval(period)
    }

    fn block_on(&self, future: Pin<Box<dyn Future<Output = ()> + '_>>) {
        self.inner.block_on(future)
    }

    fn yield_now(&self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        self.inner.yield_now()
    }

    fn name(&self) -> &'static str {
        self.inner.name()
    }
}

fn generate_random_ssrc() -> u32 {
    (random::<u32>() & 0x7FFFFFFF) | 0x1000
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
                .find(|c| is_valid_jvb_candidate_ip(&c.ip))
                .map(|c| (c.ip.as_str(), c.port))
        })
        .unwrap_or((fallback_ip, fallback_port));

    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        if sock.connect((target_ip, target_port.max(1))).is_ok() {
            if let Ok(local_addr) = sock.local_addr() {
                let ip = local_addr.ip();
                let ip_str = ip.to_string();
                if ip.is_ipv4()
                    && !ip.is_loopback()
                    && !ip.is_unspecified()
                    && !ip_str.starts_with("172.112.")
                {
                    info!(
                        "[WRTC Media] Pinned WebRTC UDP socket to physical interface IP: {ip_str}"
                    );
                    return format!("{ip_str}:0");
                }
            }
        }
    }
    "0.0.0.0:0".to_string()
}

/// Выделяет `count` уникальных локальных эфемерных UDP-портов на заданном адресе интерфейса (`ip:0`),
/// чтобы ICE-агент `webrtc-rs` создавал `count` независимых UDP-сокетов с различными исходными портами
/// для равномерного распределения по сетевым маршрутам.
fn allocate_distinct_udp_bind_addrs(bind_addr: &str, count: usize) -> Vec<String> {
    let target_count = count.clamp(1, 16);
    if target_count <= 1 {
        return vec![bind_addr.to_string()];
    }
    let mut held_sockets = Vec::with_capacity(target_count);
    let mut addrs = Vec::with_capacity(target_count);
    for _ in 0..target_count {
        if let Ok(sock) = UdpSocket::bind(bind_addr) {
            if let Ok(local_addr) = sock.local_addr() {
                addrs.push(local_addr.to_string());
                held_sockets.push(sock);
            }
        }
    }
    drop(held_sockets);
    if addrs.is_empty() {
        vec![bind_addr.to_string()]
    } else {
        addrs
    }
}

struct PeerEvents {
    connected_tx: mpsc::Sender<()>,
    is_connected: Arc<AtomicBool>,
    is_failed: Arc<AtomicBool>,
    has_ws: Arc<AtomicBool>,
    mode: WrtcMode,
    disconnected_at_ms: Arc<AtomicU64>,
    start_instant: Instant,
    failed_notify: Arc<Notify>,
    dc_is_open: Arc<AtomicBool>,
    dc_open_notify: Arc<Notify>,
    incoming_tx: mpsc::Sender<ColibriMessage>,
    remote_dc: Arc<Mutex<Option<Arc<dyn DataChannel>>>>,
    video_incoming_tx: mpsc::Sender<Bytes>,
    expected_peer_video_ssrc: Arc<AtomicU32>,
    first_video_rx: Arc<AtomicBool>,
    local_video_ssrc: u32,
    bg_tasks: Arc<StdMutex<Vec<AbortHandle>>>,
    xmpp_endpoints: Arc<StdMutex<HashSet<String>>>,
}

#[async_trait]
impl PeerConnectionEventHandler for PeerEvents {
    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        info!("[WRTC Media] WebRTC PeerConnection state: {state:?}");
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
                if self.has_ws.load(Ordering::SeqCst) || self.mode == WrtcMode::Ws {
                    warn!(
                        "[WRTC Media] UDP PeerConnection entered Failed state, but WebSocket transport is active (mode={:?}, has_ws={}). Continuing without tearing session.",
                        self.mode,
                        self.has_ws.load(Ordering::SeqCst)
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
        info!("[WRTC Media] Inbound remote track: kind={kind:?}");
        if kind == RtpCodecKind::Video {
            let in_tx = self.video_incoming_tx.clone();
            let expected_ssrc = self.expected_peer_video_ssrc.clone();
            let first_rx = self.first_video_rx.clone();
            let local_v_ssrc = self.local_video_ssrc;
            let t = tokio::spawn(async move {
                while let Some(event) = track.poll().await {
                    match event {
                        TrackRemoteEvent::OnRtpPacket(pkt) => {
                            if pkt.header.ssrc == local_v_ssrc {
                                continue;
                            }

                            let raw_payload = pkt.payload;

                            if let Some(mut data) = strip_vp8_payload_descriptor(raw_payload) {
                                if !is_valid_vp8_frame_header(&data) {
                                    continue;
                                }

                                let exp = expected_ssrc.load(Ordering::Relaxed);
                                if exp != 0 && pkt.header.ssrc != exp {
                                    continue;
                                }

                                data = data.slice(VP8_KEYFRAME_1080P_HEADER.len()..);
                                if data.is_empty() {
                                    continue;
                                }

                                if first_rx.swap(false, Ordering::Relaxed) {
                                    info!(
                                        "[WRTC Media Video IN] First video frame received (SSRC: {}, len: {} bytes)",
                                        pkt.header.ssrc, data.len()
                                    );
                                }
                                let _ = in_tx.try_send(data);
                            }
                        }
                        TrackRemoteEvent::OnEnded => {
                            info!("[WRTC Media] Remote video track ended");
                            break;
                        }
                        _ => {}
                    }
                }
            });
            if let Ok(mut guard) = self.bg_tasks.lock() {
                guard.push(t.abort_handle());
            }
        } else if kind == RtpCodecKind::Audio {
            let t = tokio::spawn(async move {
                while let Some(event) = track.poll().await {
                    if matches!(event, TrackRemoteEvent::OnEnded) {
                        break;
                    }
                }
            });
            if let Ok(mut guard) = self.bg_tasks.lock() {
                guard.push(t.abort_handle());
            }
        }
    }

    async fn on_data_channel(&self, data_channel: Arc<dyn DataChannel>) {
        if self.mode == WrtcMode::Ws {
            return;
        }
        let label = data_channel.label().await.unwrap_or_default();
        let proto = data_channel.protocol().await.unwrap_or_default();
        info!(
            "[WRTC DataChannel] Inbound DataChannel negotiated by JVB/peer: label='{label}', protocol='{proto}'"
        );
        *self.remote_dc.lock().await = Some(Arc::clone(&data_channel));
        self.dc_is_open.store(true, Ordering::SeqCst);
        self.dc_open_notify.notify_waiters();

        let in_tx = self.incoming_tx.clone();
        let dc_is_open_c = self.dc_is_open.clone();
        let dc_poll = Arc::clone(&data_channel);
        let xmpp_eps_dc = self.xmpp_endpoints.clone();

        let t = tokio::spawn(async move {
            while let Some(event) = dc_poll.poll().await {
                match event {
                    DataChannelEvent::OnOpen => {
                        info!("[WRTC DataChannel] Inbound DataChannel state is OPEN!");
                        dc_is_open_c.store(true, Ordering::SeqCst);
                    }
                    DataChannelEvent::OnClose => {
                        info!("[WRTC DataChannel] Inbound DataChannel closed.");
                        dc_is_open_c.store(false, Ordering::SeqCst);
                        break;
                    }
                    DataChannelEvent::OnMessage(msg) => {
                        if let Ok(c_msg) = serde_json::from_slice::<ColibriMessage>(&msg.data) {
                            if let Some(ref sender) = c_msg.from {
                                if let Ok(mut set) = xmpp_eps_dc.lock() {
                                    set.remove(sender);
                                }
                            }
                            let _ = in_tx.send(c_msg).await;
                        } else if let Ok(text) = from_utf8(&msg.data) {
                            if let Ok(c_msg) = serde_json::from_str::<ColibriMessage>(text) {
                                if let Some(ref sender) = c_msg.from {
                                    if let Ok(mut set) = xmpp_eps_dc.lock() {
                                        set.remove(sender);
                                    }
                                }
                                let _ = in_tx.send(c_msg).await;
                            }
                        }
                    }
                    _ => {}
                }
            }
        });
        if let Ok(mut guard) = self.bg_tasks.lock() {
            guard.push(t.abort_handle());
        }
    }
}

struct P2pEvents {
    is_open: Arc<AtomicBool>,
    is_connected: Arc<AtomicBool>,
    is_failed: Arc<AtomicBool>,
    disconnected_at_ms: Arc<AtomicU64>,
    start_instant: Instant,
}

#[async_trait]
impl PeerConnectionEventHandler for P2pEvents {
    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        info!("[P2P Direct] WebRTC PeerConnection state: {state:?}");
        match state {
            RTCPeerConnectionState::Connected => {
                self.is_connected.store(true, Ordering::SeqCst);
                self.disconnected_at_ms.store(0, Ordering::SeqCst);
            }
            RTCPeerConnectionState::Disconnected => {
                self.is_connected.store(false, Ordering::SeqCst);
                let now_ms = (self.start_instant.elapsed().as_millis() as u64).max(1);
                let _ = self.disconnected_at_ms.compare_exchange(
                    0,
                    now_ms,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
            }
            RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed => {
                self.is_connected.store(false, Ordering::SeqCst);
                self.is_open.store(false, Ordering::SeqCst);
                self.is_failed.store(true, Ordering::SeqCst);
            }
            _ => {}
        }
    }
}

pub struct P2pSession {
    pub pc: Arc<dyn PeerConnection>,
    pub dc: Arc<dyn DataChannel>,
    pub is_open: Arc<AtomicBool>,
    pub is_connected: Arc<AtomicBool>,
    pub is_failed: Arc<AtomicBool>,
    pub disconnected_at_ms: Arc<AtomicU64>,
    pub start_instant: Instant,
    pub open_notify: Arc<Notify>,
    pub incoming_rx: Mutex<mpsc::Receiver<Bytes>>,
    pub turns_proxies: Vec<TurnsProxyHandle>,
    pub active_ice_servers: StdMutex<Vec<RTCIceServer>>,
    pub bg_tasks: StdMutex<Vec<AbortHandle>>,
    pub peer_close_timeout_secs: u64,
    pub pc_closed: AtomicBool,
}

impl P2pSession {
    #[inline]
    pub fn is_ready(&self) -> bool {
        self.is_open.load(Ordering::Relaxed)
            && self.is_connected.load(Ordering::Relaxed)
            && !self.is_failed.load(Ordering::Relaxed)
    }

    pub fn should_renegotiate(&self, disconnected_timeout_ms: u64, handshake_timeout_ms: u64) -> bool {
        if self.is_failed.load(Ordering::SeqCst) {
            return true;
        }
        let now_ms = self.start_instant.elapsed().as_millis() as u64;
        let disc_ms = self.disconnected_at_ms.load(Ordering::SeqCst);
        if disc_ms > 0 && now_ms.saturating_sub(disc_ms) >= disconnected_timeout_ms {
            return true;
        }
        if !self.is_open.load(Ordering::SeqCst) && now_ms >= handshake_timeout_ms {
            return true;
        }
        false
    }

    pub async fn send_packet(&self, data: &Bytes) -> AnyhowResult<()> {
        if !self.is_ready() {
            bail!("P2P DataChannel is not ready (disconnected or closed)");
        }
        self.dc
            .send(BytesMut::from(data.as_ref()))
            .await
            .map_err(|e| anyhow!("P2P DataChannel send error: {e}"))?;
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

    pub async fn rotate_turn_credentials(&self, discovered: &[XmppIceServer]) {
        let Some(fresh_turn) = discovered
            .iter()
            .find(|s| s.is_turn && !s.username.is_empty() && !s.credential.is_empty())
        else {
            return;
        };
        let updated_servers = {
            let Ok(mut guard) = self.active_ice_servers.lock() else {
                return;
            };
            if guard.is_empty() {
                return;
            }
            let mut changed = false;
            for srv in guard.iter_mut() {
                if !srv.username.is_empty()
                    && (srv.username != fresh_turn.username
                        || srv.credential != fresh_turn.credential)
                {
                    srv.username = fresh_turn.username.clone();
                    srv.credential = fresh_turn.credential.clone();
                    changed = true;
                }
            }
            if !changed {
                return;
            }
            guard.clone()
        };
        let new_cfg = RTCConfigurationBuilder::new()
            .with_ice_servers(updated_servers)
            .build();
        if let Err(e) = self.pc.set_configuration(new_cfg).await {
            warn!("[P2P Direct] TURN credential rotation warning: {e}");
        } else {
            info!(
                "[P2P Direct] Rotated live TURN credentials via extdisco (username={})",
                fresh_turn.username
            );
        }
    }

    pub async fn close(&self) {
        self.is_open.store(false, Ordering::SeqCst);
        self.is_connected.store(false, Ordering::SeqCst);
        self.is_failed.store(true, Ordering::SeqCst);
        if let Ok(mut tasks) = self.bg_tasks.lock() {
            for handle in tasks.drain(..) {
                handle.abort();
            }
        }
        if !self.pc_closed.swap(true, Ordering::SeqCst) {
            let _ = timeout(
                Duration::from_secs(self.peer_close_timeout_secs.max(1)),
                self.pc.close(),
            )
            .await;
        }
    }
}

impl Drop for P2pSession {
    fn drop(&mut self) {
        self.is_open.store(false, Ordering::SeqCst);
        self.is_connected.store(false, Ordering::SeqCst);
        self.is_failed.store(true, Ordering::SeqCst);
        if let Ok(mut tasks) = self.bg_tasks.lock() {
            for handle in tasks.drain(..) {
                handle.abort();
            }
        }
        if !self.pc_closed.swap(true, Ordering::SeqCst) {
            let pc = Arc::clone(&self.pc);
            let close_secs = self.peer_close_timeout_secs.max(1);
            if let Ok(handle) = TokioHandle::try_current() {
                handle.spawn(async move {
                    let _ = timeout(Duration::from_secs(close_secs), pc.close()).await;
                });
            }
        }
    }
}

struct IceTierEntry {
    label: &'static str,
    servers: Vec<RTCIceServer>,
    display_urls: Vec<String>,
    has_turn: bool,
}

fn build_ice_server_tiers(
    discovered: &[XmppIceServer],
    wrtc_cfg: &WrtcConfig,
    allow_turn: bool,
) -> (Vec<IceTierEntry>, Vec<TurnsProxyHandle>) {
    let mut proxies: Vec<TurnsProxyHandle> = Vec::new();
    let connect_timeout = Duration::from_secs(wrtc_cfg.http_connect_timeout_secs.max(5));

    let mut proxy_by_idx: Vec<Option<(String, String)>> = Vec::with_capacity(discovered.len());
    for s in discovered {
        if allow_turn && s.is_turn && s.is_tcp_or_tls {
            let use_tls = s
                .urls
                .iter()
                .any(|u| u.starts_with("turns:") || u.starts_with("stuns:"));
            let remote_url = s
                .urls
                .first()
                .cloned()
                .unwrap_or_else(|| format!("turns:{}:{}", s.host, s.port));
            match spawn_turns_udp_proxy(
                s.host.clone(),
                s.port,
                use_tls,
                remote_url.clone(),
                connect_timeout,
                wrtc_cfg.udp_socket_buffer_size,
            ) {
                Ok(handle) => {
                    let local_url = handle.local_turn_url.clone();
                    let disp = format!("{remote_url} (via {local_url})");
                    proxies.push(handle);
                    proxy_by_idx.push(Some((local_url, disp)));
                }
                Err(e) => {
                    warn!(
                        "[WRTC TURNS Proxy] Failed to spawn local UDP bridge for {remote_url}: {e}"
                    );
                    proxy_by_idx.push(None);
                }
            }
        } else {
            proxy_by_idx.push(None);
        }
    }

    let filter_tier = |include_turn: bool, include_tcp_tls: bool| -> (Vec<RTCIceServer>, Vec<String>, bool) {
        let mut list = Vec::new();
        let mut display_urls = Vec::new();
        let mut has_turn = false;
        for (idx, s) in discovered.iter().enumerate() {
            if !include_turn && s.is_turn {
                continue;
            }
            if s.is_tcp_or_tls {
                if include_turn && s.is_turn {
                    if include_tcp_tls {
                        if let Some((ref local_url, ref disp)) = proxy_by_idx[idx] {
                            has_turn = true;
                            list.push(RTCIceServer {
                                urls: vec![local_url.clone()],
                                username: s.username.clone(),
                                credential: s.credential.clone(),
                            });
                            display_urls.push(disp.clone());
                        }
                    }
                    if s.port == 443 && s.host.ends_with(".ktalk.host") {
                        let udp_ktalk_turn = format!("turn:{}:34788", s.host);
                        has_turn = true;
                        list.push(RTCIceServer {
                            urls: vec![udp_ktalk_turn.clone()],
                            username: s.username.clone(),
                            credential: s.credential.clone(),
                        });
                        display_urls.push(udp_ktalk_turn);
                    }
                }
                continue;
            }
            if s.is_turn {
                has_turn = true;
            }
            display_urls.extend(s.urls.iter().cloned());
            list.push(RTCIceServer {
                urls: s.urls.clone(),
                username: s.username.clone(),
                credential: s.credential.clone(),
            });
        }
        (list, display_urls, has_turn)
    };

    let mut tiers: Vec<IceTierEntry> = Vec::with_capacity(4);
    for (tier_label, inc_turn, inc_tcp) in [
        ("Tier 0: STUN", false, false),
        ("Tier 1: UDP STUN + UDP TURN", true, false),
        ("Tier 2: STUN + TURN + TURNS", true, true),
    ] {
        if inc_turn && !allow_turn {
            continue;
        }
        let (list, display_urls, has_turn) = filter_tier(inc_turn, inc_tcp);
        if !list.is_empty() {
            let urls_flat: Vec<&str> = list
                .iter()
                .flat_map(|i| i.urls.iter().map(|u| u.as_str()))
                .collect();
            let already_present = tiers.iter().any(|existing| {
                let ex_urls: Vec<&str> = existing
                    .servers
                    .iter()
                    .flat_map(|i| i.urls.iter().map(|u| u.as_str()))
                    .collect();
                ex_urls == urls_flat
            });
            if !already_present {
                tiers.push(IceTierEntry {
                    label: tier_label,
                    servers: list,
                    display_urls,
                    has_turn,
                });
            }
        }
    }
    tiers.push(IceTierEntry {
        label: "Tier 3: host",
        servers: Vec::new(),
        display_urls: Vec::new(),
        has_turn: false,
    });
    (tiers, proxies)
}

pub async fn create_p2p_channel(
    ice_servers_info: &[XmppIceServer],
    wrtc_cfg: &WrtcConfig,
    bind_addr: &str,
) -> AnyhowResult<P2pSession> {
    let is_open = Arc::new(AtomicBool::new(false));
    let is_connected = Arc::new(AtomicBool::new(false));
    let is_failed = Arc::new(AtomicBool::new(false));
    let disconnected_at_ms = Arc::new(AtomicU64::new(0));
    let start_instant = Instant::now();
    let open_notify = Arc::new(Notify::new());

    let effective_bind_addr = if !bind_addr.is_empty() && bind_addr != "0.0.0.0:0" {
        bind_addr.to_string()
    } else {
        detect_physical_bind_addr(None, "1.1.1.1", 443)
    };
    info!(
        "[P2P Direct] Pinned P2P UDP socket to physical interface: {effective_bind_addr}"
    );

    let (tiers, turns_proxies) = build_ice_server_tiers(ice_servers_info, wrtc_cfg, true);
    let mut last_err = None;
    let mut built_pc = None;
    let mut active_ice_servers: Vec<RTCIceServer> = Vec::new();

    for tier in tiers {
        let tier_label = tier.label;
        let tier_has_turn = tier.has_turn;
        let tier_urls = tier.display_urls;
        let tier_servers_clone = tier.servers.clone();
        let mut media_engine = MediaEngine::default();
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;

        let config = RTCConfigurationBuilder::new()
            .with_ice_servers(tier.servers)
            .build();

        let setting_engine = SettingEngineBuilder::new()
            .with_ice_timeouts(
                Some(Duration::from_millis(wrtc_cfg.ice_disconnected_timeout_ms)),
                Some(Duration::from_millis(wrtc_cfg.ice_failed_timeout_ms)),
                Some(Duration::from_millis(wrtc_cfg.ice_keepalive_interval_ms)),
            )
            .with_turn_allocation_refresh_interval_cap(Duration::from_secs(
                wrtc_cfg.turn_refresh_interval_secs.max(10),
            ))
            .with_sctp_max_receive_buffer_size(wrtc_cfg.sctp_max_receive_buffer_size)
            .with_sctp_mtu(wrtc_cfg.sctp_mtu.min(1200) as _)
            .with_receive_mtu(wrtc_cfg.receive_mtu)
            .build();

        let handler = Arc::new(P2pEvents {
            is_open: is_open.clone(),
            is_connected: is_connected.clone(),
            is_failed: is_failed.clone(),
            disconnected_at_ms: disconnected_at_ms.clone(),
            start_instant,
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
            .with_udp_addrs(allocate_distinct_udp_bind_addrs(
                &effective_bind_addr,
                wrtc_cfg.udp_ice_socket_count.clamp(1, 16),
            ))
            .with_dedicated_reactor_pool_size(
                available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1)
                    .clamp(1, wrtc_cfg.reactor_pool_size.max(1)),
            )
            .build()
            .await
        {
            Ok(pc_res) => {
                info!(
                    "[P2P Direct] PeerConnection built with {tier_label} (TURN={tier_has_turn}): {:?}",
                    tier_urls
                );
                active_ice_servers = tier_servers_clone;
                built_pc = Some(pc_res);
                break;
            }
            Err(e) => {
                info!(
                    "[P2P Direct] ICE {tier_label} rejected by engine ({e}), falling back to next tier..."
                );
                last_err = Some(e);
            }
        }
    }

    let pc_res = match built_pc {
        Some(pc) => pc,
        None => return Err(anyhow!("Failed to build P2P PeerConnection: {:?}", last_err)),
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
    let in_tx = incoming_tx;

    let is_open_c = is_open.clone();
    let is_connected_c = is_connected.clone();
    let is_failed_c = is_failed.clone();
    let disconnected_at_c = disconnected_at_ms.clone();
    let notify_c = open_notify.clone();
    let dc_poll = Arc::clone(&dc);

    let dc_task = tokio::spawn(async move {
        while let Some(event) = dc_poll.poll().await {
            match event {
                DataChannelEvent::OnOpen => {
                    info!("[P2P Direct] established: DataChannel 'anet-data' is now OPEN!");
                    is_connected_c.store(true, Ordering::SeqCst);
                    disconnected_at_c.store(0, Ordering::SeqCst);
                    is_open_c.store(true, Ordering::SeqCst);
                    notify_c.notify_waiters();
                }
                DataChannelEvent::OnClose => {
                    info!("[P2P Direct] DataChannel closed");
                    is_open_c.store(false, Ordering::SeqCst);
                    is_failed_c.store(true, Ordering::SeqCst);
                    break;
                }
                DataChannelEvent::OnMessage(msg) => {
                    let _ = in_tx.try_send(msg.data.into());
                }
                _ => {}
            }
        }
    });

    Ok(P2pSession {
        pc,
        dc,
        is_open,
        is_connected,
        is_failed,
        disconnected_at_ms,
        start_instant,
        open_notify,
        incoming_rx: Mutex::new(incoming_rx),
        turns_proxies,
        active_ice_servers: StdMutex::new(active_ice_servers),
        bg_tasks: StdMutex::new(vec![dc_task.abort_handle()]),
        peer_close_timeout_secs: wrtc_cfg.peer_close_timeout_secs.max(1),
        pc_closed: AtomicBool::new(false),
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
    pub failed_notify: Arc<Notify>,
    pub first_video_rx: Arc<AtomicBool>,
    pub first_video_tx: Arc<AtomicBool>,
    pub start_instant: Instant,
    pub last_video_tx_ms: Arc<AtomicU64>,
    pub force_keyframe_remaining: Arc<AtomicU32>,
    pub video_write_lock: Arc<Mutex<u32>>,
    pub remote_sdp: Mutex<String>,
    pub colibri_ws_ip: Arc<StdMutex<Option<IpAddr>>>,
    pub active_video_constraints: Arc<StdMutex<Option<ReceiverVideoConstraints>>>,
    pub bind_addr: String,
    pub ice_tier_summary: String,
    pub local_candidates_summary: Vec<String>,
    pub turns_proxies: Vec<TurnsProxyHandle>,
    pub active_ice_servers: StdMutex<Vec<RTCIceServer>>,
    pub bg_tasks: Arc<StdMutex<Vec<AbortHandle>>>,
    pub watchdog_disconnected_timeout_ms: u64,
    pub watchdog_channel_grace_secs: u64,
    pub peer_close_timeout_secs: u64,
    pub pc_closed: AtomicBool,
}

impl WrtcPeer {
    pub async fn create(
        session_opt: Option<&JingleSession>,
        xmpp_opt: Option<&XmppSession>,
        fallback_ip: &str,
        fallback_port: u16,
        audio_keepalive_ms: u64,
        mode: WrtcMode,
        wrtc_cfg: &WrtcConfig,
    ) -> AnyhowResult<Self> {
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
        let failed_notify = Arc::new(Notify::new());
        let dc_is_open = Arc::new(AtomicBool::new(false));
        let first_video_rx = Arc::new(AtomicBool::new(true));
        let first_video_tx = Arc::new(AtomicBool::new(true));

        let local_ssrc = generate_random_ssrc();
        let local_video_ssrc = generate_random_ssrc();
        let video_pt = session_opt
            .map(|s| s.video_payload_type)
            .unwrap_or(WRTC_VP8_PRIMARY_PAYLOAD_TYPE);
        let has_video_flag = matches!(mode, WrtcMode::MediaVideo | WrtcMode::Auto)
            && (session_opt.map(|s| s.has_video).unwrap_or(false) || mode == WrtcMode::MediaVideo);
        let use_sctp_dc = !matches!(mode, WrtcMode::Ws);
        let video_seq = Arc::new(AtomicU16::new(0));
        let video_ts = Arc::new(AtomicU32::new(0));
        let expected_peer_video_ssrc = Arc::new(AtomicU32::new(0));
        let _remote_ssrc = 0;
        let start_instant = Instant::now();
        let last_video_tx_ms = Arc::new(AtomicU64::new(0));
        let force_keyframe_remaining = Arc::new(AtomicU32::new(WRTC_INITIAL_FORCE_KEYFRAMES));
        let video_write_lock = Arc::new(Mutex::new(0u32));
        let mut initial_remote_sdp = String::new();

        let (ws_fallback_tx, mut ws_fallback_rx) =
            mpsc::channel::<String>(WRTC_WS_FALLBACK_CHANNEL_CAPACITY);
        let has_ws = Arc::new(AtomicBool::new(false));
        let ws_open_notify = Arc::new(Notify::new());
        let xmpp_endpoints: Arc<StdMutex<HashSet<String>>> =
            Arc::new(StdMutex::new(HashSet::new()));
        let colibri_ws_ip: Arc<StdMutex<Option<IpAddr>>> = Arc::new(StdMutex::new(None));
        let active_video_constraints: Arc<StdMutex<Option<ReceiverVideoConstraints>>> =
            Arc::new(StdMutex::new(None));

        let bg_tasks: Arc<StdMutex<Vec<AbortHandle>>> = Arc::new(StdMutex::new(Vec::new()));

        if let Some(session) = session_opt {
            if let Some(ref ws_url) = session.transport.colibri_ws_url {
                let ws_url_c = ws_url.clone();
                let ws_profile = xmpp_opt
                    .map(|x| x.profile.clone())
                    .unwrap_or_else(BrowserProfile::random);
                let ws_origin = xmpp_opt.map(|x| x.origin.clone());
                let has_xmpp_fallback = xmpp_opt.is_some();
                let in_tx_ws = incoming_tx.clone();
                let has_ws_c = has_ws.clone();
                let ws_open_notify_c = ws_open_notify.clone();
                let xmpp_eps_ws = xmpp_endpoints.clone();
                let colibri_ws_ip_c = colibri_ws_ip.clone();
                let active_constraints_ws = active_video_constraints.clone();
                let dc_open_ws = dc_is_open.clone();
                let is_connected_ws = is_connected.clone();
                let is_failed_ws = is_failed.clone();
                let failed_notify_ws = failed_notify.clone();
                let colibri_connect_timeout = wrtc_cfg.colibri_ws_connect_timeout_secs.max(1);
                let colibri_read_timeout =
                    Duration::from_secs(wrtc_cfg.colibri_ws_read_timeout_secs.max(5));
                let ws_write_timeout = wrtc_cfg.ws_write_timeout_secs.max(1);
                let hop_attempts = wrtc_cfg.tcp_port_hop_attempts.clamp(1, 32);
                let hop_timeout =
                    Duration::from_millis(wrtc_cfg.tcp_port_hop_timeout_ms.max(200));
                let ws_task = tokio::spawn(async move {
                    let mut reconnect_attempts = 0u32;
                    loop {
                        if is_failed_ws.load(Ordering::SeqCst) {
                            break;
                        }
                        let req = match ws_profile.build_ws_request(&ws_url_c, ws_origin.as_deref()) {
                            Ok(r) => r,
                            Err(e) => {
                                warn!("[WRTC WS] Failed to build Colibri-WS request: {e}");
                                if !dc_open_ws.load(Ordering::SeqCst)
                                    && !(has_video_flag && is_connected_ws.load(Ordering::SeqCst))
                                    && !has_xmpp_fallback
                                {
                                    is_failed_ws.store(true, Ordering::SeqCst);
                                    failed_notify_ws.notify_waiters();
                                    failed_notify_ws.notify_one();
                                }
                                return;
                            }
                        };

                        let parsed_uri = ws_url_c.parse::<Uri>().ok();
                        let is_wss = parsed_uri
                            .as_ref()
                            .and_then(|u| u.scheme_str())
                            .map(|s| s.eq_ignore_ascii_case("wss") || s.eq_ignore_ascii_case("https"))
                            .unwrap_or(true);
                        let target_host = parsed_uri
                            .as_ref()
                            .and_then(|u| u.host())
                            .unwrap_or("")
                            .to_string();
                        let target_port = parsed_uri
                            .as_ref()
                            .and_then(|u| u.port_u16())
                            .unwrap_or(if is_wss { 443 } else { 80 });

                        let connect_res = timeout(
                            Duration::from_secs(colibri_connect_timeout),
                            async {
                                let mut connected_tcp = None;
                                for attempt in 1..=hop_attempts {
                                    match timeout(
                                        hop_timeout,
                                        TcpStream::connect((target_host.as_str(), target_port)),
                                    )
                                    .await
                                    {
                                        Ok(Ok(s)) => {
                                            connected_tcp = Some(s);
                                            break;
                                        }
                                        Ok(Err(e)) => {
                                            warn!(
                                                "[WRTC WS] Colibri TCP connect attempt {attempt}/{hop_attempts} error: {e}"
                                            );
                                        }
                                        Err(_) => {
                                            warn!(
                                                "[WRTC WS] Colibri TCP port-hop attempt {attempt}/{hop_attempts} timed out after {:?}, hopping port...",
                                                hop_timeout
                                            );
                                        }
                                    }
                                }
                                let tcp = match connected_tcp {
                                    Some(s) => s,
                                    None => {
                                        TcpStream::connect((target_host.as_str(), target_port))
                                            .await?
                                    }
                                };
                                let peer_ip = tcp.peer_addr().ok().map(|a| a.ip());
                                let _ = tcp.set_nodelay(true);
                                let sock_ref = SockRef::from(&tcp);
                                let ka = TcpKeepalive::new()
                                    .with_time(Duration::from_secs(10))
                                    .with_interval(Duration::from_secs(5));
                                let _ = sock_ref.set_tcp_keepalive(&ka);
                                let stream: Box<dyn VpnStream> = if is_wss {
                                    let tls = ws_profile.connect_ws_tls(&target_host, tcp).await?;
                                    Box::new(tls)
                                } else {
                                    Box::new(tcp)
                                };
                                let (ws_stream, _resp) =
                                    client_async_with_config(req, stream, None).await?;
                                Ok::<_, AnyhowError>((ws_stream, peer_ip))
                            },
                        )
                        .await;

                        if let Ok(Ok((mut ws_stream, peer_ip))) = connect_res {
                            reconnect_attempts = 0;
                            if let Some(ip) = peer_ip {
                                if let Ok(mut g) = colibri_ws_ip_c.lock() {
                                    *g = Some(ip);
                                }
                            }
                            has_ws_c.store(true, Ordering::SeqCst);
                            ws_open_notify_c.notify_waiters();
                            info!(
                                "[WRTC WS] Parallel Colibri-WS fallback connected (remote_ip: {:?})",
                                peer_ip
                            );

                            // Активируем endpoint message transport в JVB отправкой ClientHello
                            let _ = timeout(
                                Duration::from_secs(ws_write_timeout),
                                ws_stream.send(WsMessage::Text(
                                    r#"{"colibriClass":"ClientHello"}"#.into(),
                                )),
                            )
                            .await;

                            let initial_constraints = if has_video_flag {
                                active_constraints_ws
                                    .lock()
                                    .ok()
                                    .and_then(|g| g.clone())
                                    .or_else(|| {
                                        Some(ReceiverVideoConstraints::new_all(
                                            WRTC_DEFAULT_MAX_VIDEO_HEIGHT,
                                        ))
                                    })
                            } else {
                                Some(ReceiverVideoConstraints::new_all(0))
                            };
                            if let Some(constraints) = initial_constraints {
                                if let Ok(json) = serde_json::to_string(&constraints) {
                                    let _ = timeout(
                                        Duration::from_secs(ws_write_timeout),
                                        ws_stream.send(WsMessage::Text(json.into())),
                                    )
                                    .await;
                                }
                            }

                            let mut ws_ping_interval = interval(Duration::from_secs(10));
                            ws_ping_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
                            let mut last_inbound_at = TokioInstant::now();
                            let mut channel_closed = false;

                            loop {
                                tokio::select! {
                                    msg_opt = ws_stream.next() => {
                                        match msg_opt {
                                            Some(Ok(WsMessage::Text(text))) => {
                                                last_inbound_at = TokioInstant::now();
                                                if let Ok(c_msg) = serde_json::from_str::<ColibriMessage>(&text) {
                                                    if let Some(ref sender) = c_msg.from {
                                                        if let Ok(mut set) = xmpp_eps_ws.lock() {
                                                            set.remove(sender);
                                                        }
                                                    }
                                                    let _ = in_tx_ws.send(c_msg).await;
                                                }
                                            }
                                            Some(Ok(WsMessage::Binary(bin))) => {
                                                last_inbound_at = TokioInstant::now();
                                                if let Ok(c_msg) = serde_json::from_slice::<ColibriMessage>(&bin) {
                                                    if let Some(ref sender) = c_msg.from {
                                                        if let Ok(mut set) = xmpp_eps_ws.lock() {
                                                            set.remove(sender);
                                                        }
                                                    }
                                                    let _ = in_tx_ws.send(c_msg).await;
                                                }
                                            }
                                            Some(Ok(WsMessage::Ping(data))) => {
                                                last_inbound_at = TokioInstant::now();
                                                let pong_res = timeout(
                                                    Duration::from_secs(ws_write_timeout),
                                                    ws_stream.send(WsMessage::Pong(data)),
                                                )
                                                .await;
                                                if pong_res.map_or(true, |r| r.is_err()) {
                                                    warn!("[WRTC WS] Colibri-WS pong write failed or timed out");
                                                    break;
                                                }
                                            }
                                            Some(Ok(WsMessage::Pong(_))) => {
                                                last_inbound_at = TokioInstant::now();
                                            }
                                            Some(Ok(WsMessage::Close(frame))) => {
                                                warn!("[WRTC WS] Colibri-WS closed by JVB: {frame:?}");
                                                break;
                                            }
                                            Some(Err(e)) => {
                                                warn!("[WRTC WS] Colibri-WS read error: {e}");
                                                break;
                                            }
                                            None => {
                                                warn!("[WRTC WS] Colibri-WS stream ended");
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
                                        let send_res = timeout(
                                            Duration::from_secs(ws_write_timeout),
                                            async {
                                                ws_stream
                                                    .feed(WsMessage::Text(json_text.into()))
                                                    .await?;
                                                for _ in 0..15 {
                                                    match ws_fallback_rx.try_recv() {
                                                        Ok(more_text) => {
                                                            ws_stream
                                                                .feed(WsMessage::Text(
                                                                    more_text.into(),
                                                                ))
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
                                            warn!("[WRTC WS] Colibri-WS write failed or timed out");
                                            break;
                                        }
                                    }
                                    _ = ws_ping_interval.tick() => {
                                        let ping_res = timeout(
                                            Duration::from_secs(ws_write_timeout),
                                            ws_stream.send(WsMessage::Ping(Vec::new().into())),
                                        )
                                        .await;
                                        if ping_res.map_or(true, |r| r.is_err()) {
                                            warn!("[WRTC WS] Colibri-WS keepalive ping failed or timed out");
                                            break;
                                        }
                                    }
                                    _ = sleep_until(last_inbound_at + colibri_read_timeout) => {
                                        warn!(
                                            "[WRTC WS] Colibri-WS read timeout ({:?} without inbound frames); reconnecting background socket...",
                                            colibri_read_timeout
                                        );
                                        break;
                                    }
                                }
                            }

                            has_ws_c.store(false, Ordering::SeqCst);
                            if channel_closed || is_failed_ws.load(Ordering::SeqCst) {
                                break;
                            }
                        } else {
                            warn!("[WRTC WS] Failed or timed out connecting to Colibri-WS: {ws_url_c}");
                        }

                        if is_failed_ws.load(Ordering::SeqCst) {
                            break;
                        }
                        reconnect_attempts += 1;
                        if reconnect_attempts > 5 {
                            if !dc_open_ws.load(Ordering::SeqCst)
                                && !(has_video_flag && is_connected_ws.load(Ordering::SeqCst))
                                && !has_xmpp_fallback
                            {
                                warn!(
                                    "[WRTC WS] Colibri-WS reconnect attempts exhausted ({reconnect_attempts}) and no active UDP media/SCTP/XMPP channel; marking peer failed"
                                );
                                is_failed_ws.store(true, Ordering::SeqCst);
                                failed_notify_ws.notify_waiters();
                                failed_notify_ws.notify_one();
                                break;
                            }
                            info!(
                                "[WRTC WS] Colibri-WS still unreachable (attempt {reconnect_attempts}), continuing over active tunnel/XMPP fallback and retrying in 5s..."
                            );
                            sleep(Duration::from_secs(5)).await;
                            continue;
                        }

                        info!(
                            "[WRTC WS] Reconnecting Colibri-WS in 500ms (attempt {reconnect_attempts}/5)..."
                        );
                        sleep(Duration::from_millis(500)).await;
                    }
                });
                if let Ok(mut g) = bg_tasks.lock() {
                    g.push(ws_task.abort_handle());
                }
            }
        }

        let mut peer_connection_opt = None;
        let mut data_channel_opt = None;
        let mut audio_track_opt = None;
        let mut video_track_opt = None;

        let bind_addr = detect_physical_bind_addr(session_opt, fallback_ip, fallback_port);

        let mut ice_tier_summary = "Tier 3: host".to_string();
        let mut local_candidates_summary: Vec<String> = Vec::new();
        let mut turns_proxies: Vec<TurnsProxyHandle> = Vec::new();
        let mut active_ice_servers: Vec<RTCIceServer> = Vec::new();

        if let (Some(session), Some(xmpp)) = (session_opt, xmpp_opt) {
            xmpp.set_colibri_sink_with_tracker(incoming_tx.clone(), xmpp_endpoints.clone());
            let xmpp_json_sender = xmpp.muc_json_sender();
            info!("[WRTC Media] Initializing WebRTC PeerConnection with Audio (Opus) and Video (VP8)...");

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
            let dc_open_notify = Arc::new(Notify::new());

            let discovered_ice = xmpp.get_ice_servers();
            let (tiers, built_proxies) =
                build_ice_server_tiers(&discovered_ice, wrtc_cfg, wrtc_cfg.jvb_use_turn);
            turns_proxies = built_proxies;
            let mut built_pc = None;
            let mut has_turn_configured = false;

            for tier in tiers {
                let tier_label = tier.label;
                let tier_has_turn = tier.has_turn;
                let tier_urls = tier.display_urls;
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

                let tier_servers_clone = tier.servers.clone();
                let config = RTCConfigurationBuilder::new()
                    .with_ice_servers(tier.servers)
                    .build();

                let setting_engine = SettingEngineBuilder::new()
                    .with_answering_dtls_role(RTCDtlsRole::Client)
                    .with_ice_timeouts(
                        Some(Duration::from_millis(wrtc_cfg.ice_disconnected_timeout_ms)),
                        Some(Duration::from_millis(wrtc_cfg.ice_failed_timeout_ms)),
                        Some(Duration::from_millis(wrtc_cfg.ice_keepalive_interval_ms)),
                    )
                    .with_turn_allocation_refresh_interval_cap(Duration::from_secs(
                        wrtc_cfg.turn_refresh_interval_secs.max(10),
                    ))
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
                    bg_tasks: bg_tasks.clone(),
                    xmpp_endpoints: xmpp_endpoints.clone(),
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
                    .with_udp_addrs(allocate_distinct_udp_bind_addrs(
                        &bind_addr,
                        wrtc_cfg.udp_ice_socket_count.clamp(1, 16),
                    ))
                    .with_dedicated_reactor_pool_size(
                        available_parallelism()
                            .map(|n| n.get())
                            .unwrap_or(1)
                            .clamp(1, wrtc_cfg.reactor_pool_size.max(1)),
                    )
                    .build()
                    .await
                {
                    Ok(pc_impl) => {
                        info!(
                            "[WRTC Media] PeerConnection built with {tier_label} (TURN={tier_has_turn}): {:?}",
                            tier_urls
                        );
                        ice_tier_summary = format!("{tier_label} {:?}", tier_urls);
                        has_turn_configured = tier_has_turn;
                        active_ice_servers = tier_servers_clone;
                        built_pc = Some(pc_impl);
                        break;
                    }
                    Err(e) => {
                        info!(
                            "[WRTC Media] ICE {tier_label} rejected by engine ({e}), falling back to next tier..."
                        );
                    }
                }
            }

            if let Some(pc_impl) = built_pc {
                let pc: Arc<dyn PeerConnection> = Arc::new(pc_impl);

                let media_stream_id = generate_random_uuid_v4();
                let audio_track_id = generate_random_uuid_v4();
                let video_track_id = generate_random_uuid_v4();

                let audio_track_desc = MediaStreamTrack::new(
                    media_stream_id.clone(),
                    audio_track_id.clone(),
                    audio_track_id,
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
                    media_stream_id,
                    video_track_id.clone(),
                    video_track_id,
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
                let local_ep_for_dc = xmpp_opt.map(|x| x.endpoint_id.clone()).unwrap_or_default();
                if session.has_data_channel && use_sctp_dc {
                    let dc_init = RTCDataChannelInit {
                        ordered: true,
                        max_packet_life_time: None,
                        max_retransmits: None,
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
                            let xmpp_eps_dc_in = xmpp_endpoints.clone();

                            let dc_poll_task = tokio::spawn(async move {
                                while let Some(event) = dc_in.poll().await {
                                    match event {
                                        DataChannelEvent::OnOpen => {
                                            info!("[WRTC DataChannel] 'JVB data channel' state is now OPEN!");
                                            dc_is_open_in.store(true, Ordering::SeqCst);
                                            dc_open_notify_in.notify_waiters();
                                            let _ = dc_in
                                                .send_text(r#"{"colibriClass":"ClientHello"}"#)
                                                .await;
                                            if has_video_flag {
                                                if !local_ep_for_dc.is_empty() {
                                                    let vtype_msg = format!(
                                                        r#"{{"colibriClass":"SourceVideoTypeMessage","sourceName":"{}-v0","videoType":"camera"}}"#,
                                                        local_ep_for_dc
                                                    );
                                                    let _ = dc_in.send_text(&vtype_msg).await;
                                                }
                                                let constraints = active_constraints_dc
                                                    .lock()
                                                    .ok()
                                                    .and_then(|g| g.clone())
                                                    .unwrap_or_else(|| {
                                                        ReceiverVideoConstraints::new_all(
                                                            WRTC_DEFAULT_MAX_VIDEO_HEIGHT,
                                                        )
                                                    });
                                                if let Ok(json) = serde_json::to_string(&constraints) {
                                                    info!(
                                                        "[WRTC DataChannel] Sent initial ReceiverVideoConstraints on open: {json}"
                                                    );
                                                    let _ = dc_in.send_text(&json).await;
                                                }
                                            }
                                        }
                                        DataChannelEvent::OnClose => {
                                            info!("[WRTC DataChannel] 'JVB data channel' closed.");
                                            dc_is_open_in.store(false, Ordering::SeqCst);
                                            break;
                                        }
                                        DataChannelEvent::OnError => {
                                            warn!("[WRTC DataChannel] Error event received");
                                        }
                                        DataChannelEvent::OnMessage(msg) => {
                                            if let Ok(colibri_msg) = serde_json::from_slice::<ColibriMessage>(&msg.data) {
                                                if let Some(ref sender) = colibri_msg.from {
                                                    if let Ok(mut set) = xmpp_eps_dc_in.lock() {
                                                        set.remove(sender);
                                                    }
                                                }
                                                let _ = in_tx.send(colibri_msg).await;
                                            } else if let Ok(text) = from_utf8(&msg.data) {
                                                if let Ok(colibri_msg) = serde_json::from_str::<ColibriMessage>(text) {
                                                    if let Some(ref sender) = colibri_msg.from {
                                                        if let Ok(mut set) = xmpp_eps_dc_in.lock() {
                                                            set.remove(sender);
                                                        }
                                                    }
                                                    let _ = in_tx.send(colibri_msg).await;
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            });
                            if let Ok(mut g) = bg_tasks.lock() {
                                g.push(dc_poll_task.abort_handle());
                            }
                            data_channel_res = Some(dc);
                        }
                        Err(e) => {
                            warn!("[WRTC DataChannel] Failed to create data channel: {e}");
                        }
                    }
                } else {
                    info!("[WRTC DataChannel] Operating strictly over Colibri-WS / XMPP with PacketBatcher (use_sctp_dc={use_sctp_dc}).");
                }

                let sdp_str = session.to_sdp(fallback_ip, fallback_port, 0, local_video_ssrc);
                initial_remote_sdp = sdp_str.clone();
                if let Ok(offer) = RTCSessionDescription::offer(sdp_str) {
                    if pc.set_remote_description(offer).await.is_ok() {
                        if let Ok(answer) = pc.create_answer(None).await {
                            let _ = pc.set_local_description(answer.clone()).await;

                            let mut final_sdp = answer.sdp.clone();
                            let gather_attempts = if mode == WrtcMode::Ws {
                                4
                            } else {
                                WRTC_ICE_GATHER_POLL_ATTEMPTS
                            };
                            for attempt in 0..gather_attempts {
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
                                sleep(Duration::from_millis(WRTC_ICE_GATHER_POLL_INTERVAL_MS))
                                    .await;
                            }

                            let local_params = parse_sdp_answer(&final_sdp);
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

                            info!(
                                "[WRTC Media] Generated local SDP Answer: ufrag={}, pwd={}, fp={}, candidates count={} {:?}",
                                local_params.ufrag,
                                local_params.pwd,
                                local_params.fingerprint,
                                local_params.candidates.len(),
                                cand_summary
                            );
                            local_candidates_summary = cand_summary;

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
                                    session.has_data_channel && use_sctp_dc,
                                    has_video_flag,
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
                let ws_open_notify_out = ws_open_notify.clone();
                let ws_fallback_tx_out = ws_fallback_tx.clone();
                let xmpp_eps_out = xmpp_endpoints.clone();
                let active_constraints_out = active_video_constraints.clone();

                let has_colibri_ws_cfg = session.transport.colibri_ws_url.is_some();
                let sender_task = tokio::spawn(async move {
                    if use_sctp_dc && dc_opt_out.is_some() && !dc_is_open_out.load(Ordering::SeqCst) {
                        let _ = timeout(
                            Duration::from_millis(800),
                            dc_open_notify_out.notified(),
                        )
                        .await;
                    } else if !use_sctp_dc && has_colibri_ws_cfg && !has_ws_out.load(Ordering::SeqCst) {
                        let _ = timeout(
                            Duration::from_millis(1200),
                            ws_open_notify_out.notified(),
                        )
                        .await;
                    }
                    info!(
                        "[WRTC DataChannel] Outgoing sender loop active (is_open={}, has_ws={}, use_sctp_dc={})",
                        dc_is_open_out.load(Ordering::SeqCst),
                        has_ws_out.load(Ordering::SeqCst),
                        use_sctp_dc
                    );

                    loop {
                        let (json_str, msg_to_opt, is_batch, is_astp, is_keepalive) = tokio::select! {
                            msg_opt = outgoing_rx.recv() => {
                                match msg_opt {
                                    Some(msg) => {
                                        let is_batch = matches!(msg.msg_payload, WrtcMessage::AstpBatch { .. });
                                        let is_astp = matches!(msg.msg_payload, WrtcMessage::Astp { .. });
                                        let is_keepalive = matches!(msg.msg_payload, WrtcMessage::Ping | WrtcMessage::Pong);
                                        let msg_to_opt = msg.to.clone();
                                        let Ok(json_str) = serde_json::to_string(&msg) else { continue; };
                                        (json_str, msg_to_opt, is_batch, is_astp, is_keepalive)
                                    }
                                    None => break,
                                }
                            }
                            raw_opt = raw_outgoing_rx.recv() => {
                                match raw_opt {
                                    Some(raw) => (raw, None, false, false, false),
                                    None => break,
                                }
                            }
                        };

                        let target_is_xmpp_only = msg_to_opt
                            .as_deref()
                            .map(|to_ep| {
                                xmpp_eps_out
                                    .lock()
                                    .map(|set| set.contains(to_ep))
                                    .unwrap_or(false)
                            })
                            .unwrap_or(false);

                        let mut sent = false;
                        // Используем SCTP DataChannel ТОЛЬКО когда разрешён SCTP (use_sctp_dc), живы и SCTP (dc_is_open), и UDP ICE (is_connected),
                        // И при этом удалённый пир НЕ находится в режиме только XMPP MUC (target_is_xmpp_only == false).
                        if !target_is_xmpp_only
                            && use_sctp_dc
                            && dc_is_open_out.load(Ordering::SeqCst)
                            && is_connected_out.load(Ordering::SeqCst)
                        {
                            if let Some(ref dc_out) = dc_opt_out {
                                if is_batch || is_astp || is_keepalive {
                                    trace!("[JVB DC OUT]: {json_str}");
                                } else {
                                    info!("[JVB DC OUT]: {json_str}");
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
                                                sleep(Duration::from_millis(
                                                    WRTC_DC_SEND_RETRY_DELAY_MS,
                                                ))
                                                .await;
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        let is_constraints = !is_astp && !is_batch && !is_keepalive && json_str.contains("ReceiverVideoConstraints");
                        let constraints_copy = if is_constraints { Some(json_str.clone()) } else { None };

                        if !sent && !target_is_xmpp_only && has_ws_out.load(Ordering::SeqCst) {
                            if is_astp || is_batch || is_keepalive {
                                trace!("[JVB WS OUT]: {json_str}");
                            } else {
                                info!("[JVB WS OUT]: {json_str}");
                            }
                            if let Err(e) = ws_fallback_tx_out.try_send(json_str.clone()) {
                                match e {
                                    TrySendError::Full(_) => {
                                        warn!("[WRTC WS] Fallback queue full, frame dropped");
                                    }
                                    TrySendError::Closed(_) => {}
                                }
                            } else {
                                sent = true;
                            }
                        } else if !sent && !target_is_xmpp_only && !has_colibri_ws_cfg && use_sctp_dc {
                            if let Some(ref dc_out) = dc_opt_out {
                                if !dc_is_open_out.load(Ordering::SeqCst) {
                                    let _ = timeout(
                                        Duration::from_millis(250),
                                        dc_open_notify_out.notified(),
                                    )
                                    .await;
                                }
                                if dc_is_open_out.load(Ordering::SeqCst)
                                    && dc_out.send_text(&json_str).await.is_ok()
                                {
                                    sent = true;
                                }
                            }
                        }

                        // Резервная доставка через XMPP MUC `<json-message>`, когда ни SCTP DataChannel, ни Colibri-WS
                        // недоступны (например, под Белыми Списками, когда `*.ktalk.host` заблокирован, а сигналинг `*.ktalk.ru` жив),
                        // либо когда целевой пир (`target_is_xmpp_only`) общается через XMPP MUC.
                        if !sent && !is_constraints {
                            if is_astp || is_batch || is_keepalive {
                                trace!("[XMPP MUC JSON OUT]: {json_str}");
                            } else {
                                info!("[XMPP MUC JSON OUT]: {json_str}");
                            }
                            if xmpp_json_sender.try_send_json(msg_to_opt.as_deref(), &json_str) {
                                sent = true;
                            }
                        }

                        if !sent && is_constraints {
                            // Критично: отправка отложенных ограничений выполняется в фоне,
                            // чтобы не блокировать основной цикл отправки сообщений (discover, ping, auth)!
                            // На каждой попытке берём актуальное значение из `active_video_constraints`,
                            // чтобы запоздавший начальный `new_all` не перезаписал свежий `for_endpoint`.
                            let dc_is_open_bg = dc_is_open_out.clone();
                            let is_connected_bg = is_connected_out.clone();
                            let dc_opt_bg = dc_opt_out.clone();
                            let remote_dc_bg = remote_dc_out.clone();
                            let has_ws_bg = has_ws_out.clone();
                            let ws_fallback_tx_bg = ws_fallback_tx_out.clone();
                            let active_constraints_bg = active_constraints_out.clone();
                            let fallback_json_bg = constraints_copy.unwrap_or_default();
                            tokio::spawn(async move {
                                for _ in 0..WRTC_CONSTRAINTS_RETRY_ATTEMPTS {
                                    sleep(Duration::from_millis(
                                        WRTC_CONSTRAINTS_RETRY_INTERVAL_MS,
                                    ))
                                    .await;
                                    let latest_json = active_constraints_bg
                                        .lock()
                                        .ok()
                                        .and_then(|g| g.as_ref().and_then(|c| serde_json::to_string(c).ok()))
                                        .unwrap_or_else(|| fallback_json_bg.clone());
                                    if use_sctp_dc && dc_is_open_bg.load(Ordering::SeqCst) && is_connected_bg.load(Ordering::SeqCst) {
                                        if let Some(ref dc_out) = dc_opt_bg {
                                            if dc_out.send_text(&latest_json).await.is_ok() {
                                                info!("[WRTC Constraints] Sent delayed video constraints via DataChannel");
                                                break;
                                            }
                                        }
                                        let r_dc_opt = remote_dc_bg.lock().await.clone();
                                        if let Some(r_dc) = r_dc_opt {
                                            if r_dc.send_text(&latest_json).await.is_ok() {
                                                info!("[WRTC Constraints] Sent delayed video constraints via Remote DataChannel");
                                                break;
                                            }
                                        }
                                    }
                                    if has_ws_bg.load(Ordering::SeqCst) {
                                        if ws_fallback_tx_bg.try_send(latest_json).is_ok() {
                                            info!("[WRTC Constraints] Sent delayed video constraints via Colibri-WS");
                                            break;
                                        }
                                    }
                                }
                            });
                        }
                    }
                });
                if let Ok(mut g) = bg_tasks.lock() {
                    g.push(sender_task.abort_handle());
                }

                // В режиме WrtcMode::Ws НЕ запускаем генераторы UDP RTP (Opus / VP8 keepalive),
                // чтобы случайный пробившийся UDP-пакет под мобильными БС не переключил JVB с живого
                // TCP/TLS Colibri-WS на полуживой UDP-транспорт.
                if mode != WrtcMode::Ws {
                    let track_keepalive = Arc::clone(&audio_track);
                    let seq_c = Arc::new(AtomicU16::new(0));
                    let ts_c = Arc::new(AtomicU32::new(0));
                    // Если активен видеопоток (has_video_flag), не спамим 50 пакетов/сек пустого Opus-аудио,
                    // так как VP8 RTP и ICE STUN уже поддерживают NAT-маппинг, а 50 pps аудио в стандартном Jitsi
                    // вызывают форвардинг немаппированного аудио-SSRC и спам в логах webrtc::peer_connection::driver.
                    let interval_ms = if has_video_flag {
                        5000
                    } else if audio_keepalive_ms > 0 && audio_keepalive_ms <= 100 {
                        audio_keepalive_ms as u64
                    } else {
                        20
                    };
                    let samples_per_packet =
                        (u64::from(WRTC_OPUS_CLOCK_RATE) * interval_ms.min(100) / 1000) as u32;
                    let is_connected_a = Arc::clone(&is_connected);
                    let is_failed_a = Arc::clone(&is_failed);
                    let ice_failed_wait_ms = wrtc_cfg.ice_failed_timeout_ms;

                    let opus_task = tokio::spawn(async move {
                        let start = Instant::now();
                        while !is_connected_a.load(Ordering::SeqCst) {
                            if is_failed_a.load(Ordering::SeqCst)
                                || start.elapsed() > Duration::from_millis(ice_failed_wait_ms)
                            {
                                return;
                            }
                            sleep(Duration::from_millis(50)).await;
                        }
                        info!(
                            "[WRTC Media] Starting Opus silence keepalive (interval: {}ms, samples: {})",
                            interval_ms, samples_per_packet
                        );
                        let mut ka_interval = interval(Duration::from_millis(interval_ms));
                        ka_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
                        let silence_payload = Bytes::from_static(&WRTC_OPUS_SILENCE_FRAME);
                        loop {
                            ka_interval.tick().await;
                            if is_failed_a.load(Ordering::SeqCst) {
                                break;
                            }
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
                                trace!("[WRTC Media] Opus silence write_rtp transient error: {e}");
                            }
                        }
                    });
                    if let Ok(mut g) = bg_tasks.lock() {
                        g.push(opus_task.abort_handle());
                    }

                    if has_video_flag {
                        let video_track_keepalive = Arc::clone(&video_track);
                        let video_seq_c = Arc::clone(&video_seq);
                        let video_ts_c = Arc::clone(&video_ts);
                        let last_video_tx_c = Arc::clone(&last_video_tx_ms);
                        let video_write_lock_c = Arc::clone(&video_write_lock);
                        let start_instant_c = start_instant;
                        let v_pt = video_pt;
                        let v_ssrc = local_video_ssrc;
                        let is_connected_v = Arc::clone(&is_connected);
                        let is_failed_v = Arc::clone(&is_failed);
                        let video_keepalive_ms = wrtc_cfg.video_keepalive_interval_ms.max(100);
                        let video_idle_suppress_ms = (video_keepalive_ms * 4) / 5;
                        let vp8_task = tokio::spawn(async move {
                            let start = Instant::now();
                            while !is_connected_v.load(Ordering::SeqCst) {
                                if is_failed_v.load(Ordering::SeqCst)
                                    || start.elapsed() > Duration::from_millis(ice_failed_wait_ms)
                                {
                                    return;
                                }
                                sleep(Duration::from_millis(50)).await;
                            }
                            info!(
                                "[WRTC Media] Starting VP8 video keepalive (interval: {}ms)",
                                video_keepalive_ms
                            );
                            let mut ka_interval =
                                interval(Duration::from_millis(video_keepalive_ms));
                            ka_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

                            loop {
                                ka_interval.tick().await;
                                if is_failed_v.load(Ordering::SeqCst) {
                                    break;
                                }
                                let elapsed_ms = start_instant_c.elapsed().as_millis() as u64;
                                if elapsed_ms.saturating_sub(last_video_tx_c.load(Ordering::Relaxed))
                                    < video_idle_suppress_ms
                                {
                                    // Не инжектируем пустые кадры посреди активного потока данных
                                    continue;
                                }

                                let mut last_ts_guard = video_write_lock_c.lock().await;
                                let elapsed_ms = start_instant_c.elapsed().as_millis() as u64;
                                if elapsed_ms.saturating_sub(last_video_tx_c.load(Ordering::Relaxed))
                                    < video_idle_suppress_ms
                                {
                                    continue;
                                }

                                let frame_num = video_ts_c.fetch_add(1, Ordering::Relaxed);
                                let seq = (frame_num & 0xFFFF) as u16;
                                video_seq_c.store(seq.wrapping_add(1), Ordering::Relaxed);
                                let pic_id = (frame_num & 0x7FFF) as u16;
                                let wall_ts =
                                    ((start_instant_c.elapsed().as_micros() * 90) / 1000) as u32;
                                let ts = if wall_ts <= *last_ts_guard {
                                    last_ts_guard.wrapping_add(1)
                                } else {
                                    wall_ts
                                };
                                *last_ts_guard = ts;

                                let mut keepalive_payload =
                                    BytesMut::with_capacity(4 + VP8_KEYFRAME_1080P_HEADER.len());

                                keepalive_payload.put_u8(0x90);
                                keepalive_payload.put_u8(0x80);
                                keepalive_payload.put_u8(0x80 | ((pic_id >> 8) as u8));
                                keepalive_payload.put_u8((pic_id & 0xFF) as u8);
                                keepalive_payload.put_slice(&VP8_KEYFRAME_1080P_HEADER);

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
                                    trace!("[WRTC Media] VP8 video keepalive transient error: {e}");
                                }
                            }
                        });
                        if let Ok(mut g) = bg_tasks.lock() {
                            g.push(vp8_task.abort_handle());
                        }
                    }
                }

                peer_connection_opt = Some(pc);
                data_channel_opt = data_channel_res;
                audio_track_opt = Some(audio_track);
                video_track_opt = if has_video_flag { Some(video_track) } else { None };
            }
        }

        if mode == WrtcMode::Ws
            && session_opt
                .and_then(|s| s.transport.colibri_ws_url.as_ref())
                .is_some()
        {
            for _ in 0..80 {
                if has_ws.load(Ordering::SeqCst) || is_failed.load(Ordering::SeqCst) {
                    break;
                }
                sleep(Duration::from_millis(25)).await;
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
            force_keyframe_remaining,
            video_write_lock,
            remote_sdp: Mutex::new(initial_remote_sdp),
            colibri_ws_ip,
            active_video_constraints,
            bind_addr,
            ice_tier_summary,
            local_candidates_summary,
            turns_proxies,
            active_ice_servers: StdMutex::new(active_ice_servers),
            bg_tasks,
            watchdog_disconnected_timeout_ms: wrtc_cfg
                .watchdog_disconnected_timeout_secs
                .saturating_mul(1000)
                .max(1000),
            watchdog_channel_grace_secs: wrtc_cfg.watchdog_channel_grace_secs.max(1),
            peer_close_timeout_secs: wrtc_cfg.peer_close_timeout_secs.max(1),
            pc_closed: AtomicBool::new(false),
        })
    }

    pub fn colibri_ws_ip(&self) -> Option<IpAddr> {
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
        let video_media_alive = matches!(self.mode, WrtcMode::MediaVideo | WrtcMode::Auto)
            && self.video_track.is_some()
            && self.is_connected.load(Ordering::SeqCst);
        let sctp_dc_alive =
            self.dc_is_open.load(Ordering::SeqCst) && self.is_connected.load(Ordering::SeqCst);
        if self.start_instant.elapsed() > Duration::from_secs(self.watchdog_channel_grace_secs)
            && !self.has_ws.load(Ordering::SeqCst)
            && !sctp_dc_alive
            && !video_media_alive
        {
            return Some(
                "All WRTC channels (Colibri-WS, DataChannel, and MediaVideo ICE) are closed/disconnected",
            );
        }
        None
    }

    pub fn force_next_keyframe(&self) {
        self.force_keyframe_remaining
            .store(WRTC_REASSERT_FORCE_KEYFRAMES, Ordering::Relaxed);
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
        if !matches!(self.mode, WrtcMode::MediaVideo | WrtcMode::Auto)
            || ssrc == 0
            || ssrc == self.video_ssrc
            || ssrc == 10002
        {
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
                    warn!(
                        "[WRTC Media] add_remote_video_ssrc({ssrc}) set_remote_description error: {e}"
                    );
                    return;
                }
                match pc.create_answer(None).await {
                    Ok(answer) => {
                        if let Err(e) = pc.set_local_description(answer).await {
                            warn!(
                                "[WRTC Media] add_remote_video_ssrc({ssrc}) set_local_description error: {e}"
                            );
                            return;
                        }
                        *sdp_guard = updated_sdp;
                        self.force_next_keyframe();
                        info!(
                            "[WRTC Media] Bound remote video SSRC {ssrc} to dedicated Recvonly transceiver (mid=v_{ssrc})"
                        );
                    }
                    Err(e) => {
                        warn!(
                            "[WRTC Media] add_remote_video_ssrc({ssrc}) create_answer error: {e}"
                        );
                    }
                }
            }
            Err(e) => {
                warn!("[WRTC Media] add_remote_video_ssrc({ssrc}) invalid SDP offer: {e}");
            }
        }
    }

    pub async fn add_remote_audio_ssrc(&self, ssrc: u32) {
        if ssrc == 0 || ssrc == self.ssrc || ssrc == 10001 {
            return;
        }
        let Some(ref pc) = self.peer_connection else {
            return;
        };

        let mut sdp_guard = self.remote_sdp.lock().await;
        if sdp_guard.is_empty() {
            return;
        }
        if sdp_guard.contains(&format!("a=mid:a_{ssrc}\r\n"))
            || sdp_guard.contains(&format!("a=ssrc:{ssrc} "))
        {
            return;
        }

        let updated_sdp = append_remote_audio_ssrc_to_sdp(&sdp_guard, ssrc);
        match RTCSessionDescription::offer(updated_sdp.clone()) {
            Ok(offer) => {
                if let Err(e) = pc.set_remote_description(offer).await {
                    warn!(
                        "[WRTC Media] add_remote_audio_ssrc({ssrc}) set_remote_description error: {e}"
                    );
                    return;
                }
                match pc.create_answer(None).await {
                    Ok(answer) => {
                        if let Err(e) = pc.set_local_description(answer).await {
                            warn!(
                                "[WRTC Media] add_remote_audio_ssrc({ssrc}) set_local_description error: {e}"
                            );
                            return;
                        }
                        *sdp_guard = updated_sdp;
                    }
                    Err(e) => {
                        warn!(
                            "[WRTC Media] add_remote_audio_ssrc({ssrc}) create_answer error: {e}"
                        );
                    }
                }
            }
            Err(e) => {
                warn!("[WRTC Media] add_remote_audio_ssrc({ssrc}) invalid SDP offer: {e}");
            }
        }
    }

    pub async fn send_video_frame(&self, astp_data: &[u8]) -> AnyhowResult<()> {
        self.send_video_frame_tagged(TAG_UNTAGGED, astp_data).await
    }

    pub async fn send_video_frame_tagged(&self, client_tag: u16, astp_data: &[u8]) -> AnyhowResult<()> {
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
    ) -> AnyhowResult<Bytes> {
        let Some(ref track) = self.video_track else {
            bail!("Video track not initialized");
        };
        if payload.len() < VP8_ASTP_PREFIX_LEN {
            bail!("Preallocated VP8 buffer is shorter than VP8_ASTP_PREFIX_LEN");
        }

        if self.first_video_tx.swap(false, Ordering::Relaxed) {
            info!(
                "[WRTC Media Video OUT] First video frame transmitted (SSRC: {}, tag: 0x{:04X}, len: {} bytes)",
                self.video_ssrc,
                client_tag,
                payload.len() - VP8_ASTP_PREFIX_LEN
            );
        }

        // Сериализуем инкремент (seq, pic_id, ts) и вызов write_rtp через video_write_lock,
        // чтобы при параллельной отправке кадры гарантированно попадали в сокет и JVB
        // строго в порядке возрастания seq и реального 90 кГц RTP timestamp.
        let mut last_ts_guard = self.video_write_lock.lock().await;

        let frame_num = self.video_ts.fetch_add(1, Ordering::Relaxed);
        let seq = (frame_num & 0xFFFF) as u16;
        self.video_seq.store(seq.wrapping_add(1), Ordering::Relaxed);
        let pic_id = (frame_num & 0x7FFF) as u16;
        let wall_ts = ((self.start_instant.elapsed().as_micros() * 90) / 1000) as u32;
        let ts = if wall_ts <= *last_ts_guard {
            last_ts_guard.wrapping_add(1)
        } else {
            wall_ts
        };
        *last_ts_guard = ts;

        let elapsed_ms = self.start_instant.elapsed().as_millis() as u64;
        self.last_video_tx_ms.store(elapsed_ms, Ordering::Relaxed);

        payload[0] = 0x90;
        payload[1] = 0x80;
        payload[2] = 0x80 | ((pic_id >> 8) as u8);
        payload[3] = (pic_id & 0xFF) as u8;
        payload[4..24].copy_from_slice(&VP8_KEYFRAME_1080P_HEADER);
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
            .map_err(|e| anyhow!("VP8 write_rtp error: {e}"))?;
        Ok(frozen)
    }

    pub async fn send_video_constraints(&self, constraints: &ReceiverVideoConstraints) -> AnyhowResult<()> {
        if let Ok(mut g) = self.active_video_constraints.lock() {
            *g = Some(constraints.clone());
        }
        let json = serde_json::to_string(constraints)?;
        self.raw_outgoing_tx
            .send(json)
            .await
            .map_err(|_| anyhow!("WebRTC DataChannel write channel closed"))
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

    pub async fn send(&self, msg: ColibriMessage) -> AnyhowResult<()> {
        self.outgoing_tx
            .send(msg)
            .await
            .map_err(|_| anyhow!("WebRTC DataChannel write channel closed"))
    }

    pub async fn recv(&self) -> Option<ColibriMessage> {
        let mut rx = self.incoming_rx.lock().await;
        rx.recv().await
    }

    pub async fn rotate_turn_credentials(&self, discovered: &[XmppIceServer]) {
        let Some(ref pc) = self.peer_connection else {
            return;
        };
        let Some(fresh_turn) = discovered
            .iter()
            .find(|s| s.is_turn && !s.username.is_empty() && !s.credential.is_empty())
        else {
            return;
        };
        let updated_servers = {
            let Ok(mut guard) = self.active_ice_servers.lock() else {
                return;
            };
            if guard.is_empty() {
                return;
            }
            let mut changed = false;
            for srv in guard.iter_mut() {
                if !srv.username.is_empty()
                    && (srv.username != fresh_turn.username
                        || srv.credential != fresh_turn.credential)
                {
                    srv.username = fresh_turn.username.clone();
                    srv.credential = fresh_turn.credential.clone();
                    changed = true;
                }
            }
            if !changed {
                return;
            }
            guard.clone()
        };
        let new_cfg = RTCConfigurationBuilder::new()
            .with_ice_servers(updated_servers)
            .build();
        if let Err(e) = pc.set_configuration(new_cfg).await {
            warn!("[WRTC Media] TURN credential rotation warning: {e}");
        } else {
            info!(
                "[WRTC Media] Rotated live TURN credentials via extdisco (username={})",
                fresh_turn.username
            );
        }
    }

    pub async fn close(&self) -> AnyhowResult<()> {
        self.is_failed.store(true, Ordering::SeqCst);
        self.is_connected.store(false, Ordering::SeqCst);
        self.has_ws.store(false, Ordering::SeqCst);
        if let Ok(mut tasks) = self.bg_tasks.lock() {
            for handle in tasks.drain(..) {
                handle.abort();
            }
        }
        if !self.pc_closed.swap(true, Ordering::SeqCst) {
            let close_secs = self.peer_close_timeout_secs;
            if let Some(ref pc) = self.peer_connection {
                let _ = timeout(Duration::from_secs(close_secs), pc.close()).await;
            }
        }
        Ok(())
    }
}

impl Drop for WrtcPeer {
    fn drop(&mut self) {
        self.is_failed.store(true, Ordering::SeqCst);
        self.is_connected.store(false, Ordering::SeqCst);
        self.has_ws.store(false, Ordering::SeqCst);
        if let Ok(mut tasks) = self.bg_tasks.lock() {
            for handle in tasks.drain(..) {
                handle.abort();
            }
        }
        if !self.pc_closed.swap(true, Ordering::SeqCst) {
            let close_secs = self.peer_close_timeout_secs;
            if let Some(pc) = self.peer_connection.take() {
                if let Ok(handle) = TokioHandle::try_current() {
                    handle.spawn(async move {
                        let _ = timeout(Duration::from_secs(close_secs), pc.close()).await;
                    });
                }
            }
        }
    }
}
