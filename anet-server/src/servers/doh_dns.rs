use crate::auth_handler::ServerAuthHandler;
use crate::client_registry::{ClientRegistry, ClientTransportInfo};
use crate::config::Config;
use anet_common::astp_lite::AstpLiteCipher;
use anet_common::base32;
use anet_common::consts::CHANNEL_BUFFER_SIZE;
use anet_common::dns_proto::{build_dns_txt_response, parse_dns_query};
use anet_common::doh_chunking::DohReassemblyQueue;
use anyhow::Result;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use bytes::Bytes;
use dashmap::DashMap;
use log::{debug, info, warn};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

const DOH_TCP_MAX_MSS: u16 = 640;
const MAX_SINGLE_DOWNLINK_PKT: usize = 720;
const DOWNLINK_FRAG_DATA_LEN: usize = 640;
const CODEL_MAX_SOJOURN: Duration = Duration::from_millis(600);
const MAX_BULK_QUEUE_LEN: usize = 64;
const MAX_PRIO_QUEUE_LEN: usize = 128;
const DOWNLINK_ARQ_RTO: Duration = Duration::from_millis(380);
const DOWNLINK_SACK_FAST_RTO: Duration = Duration::from_millis(120);
const DOWNLINK_MAX_INFLIGHT: usize = 64;
const DOWNLINK_MAX_RETRIES: u8 = 5;
const RECENT_DNS_CACHE_TTL: Duration = Duration::from_secs(8);
const RECENT_DNS_CACHE_MAX: usize = 256;

#[derive(Clone)]
struct InflightDownlinkFrame {
    seq: u32,
    encoded_b64: String,
    sent_at: Instant,
    retries: u8,
}

struct DohRxState {
    rx_router: mpsc::Receiver<Bytes>,
    pending_frags: VecDeque<Bytes>,
    prio_queue: VecDeque<(Bytes, Instant)>,
    bulk_queue: VecDeque<(Bytes, Instant)>,
    next_frag_id: u16,
    next_dl_seq: u32,
    highest_cum_ack: u32,
    highest_sacked_seq: u32,
    inflight_dl: BTreeMap<u32, InflightDownlinkFrame>,
    recent_queries: HashMap<u64, (Instant, Option<String>)>,
    recent_order: VecDeque<u64>,
}

impl DohRxState {
    fn process_downlink_ack(&mut self, ack_seq: u32, sack_bitmap: u16) {
        if ack_seq > self.highest_cum_ack {
            self.highest_cum_ack = ack_seq;
        }
        let cum = self.highest_cum_ack;
        if cum > 0 {
            self.inflight_dl.retain(|&seq, _| seq > cum);
        }
        for bit in 0..16u32 {
            if (sack_bitmap & (1u16 << bit)) != 0 {
                let sacked_seq = ack_seq.wrapping_add(1 + bit);
                self.inflight_dl.remove(&sacked_seq);
                if sacked_seq > self.highest_sacked_seq {
                    self.highest_sacked_seq = sacked_seq;
                }
            }
        }
    }

    fn check_recent_query(&mut self, qname_hash: u64) -> Option<Option<String>> {
        let now = Instant::now();
        if let Some((ts, cached)) = self.recent_queries.get(&qname_hash) {
            if now.duration_since(*ts) <= RECENT_DNS_CACHE_TTL {
                return Some(cached.clone());
            }
        }
        None
    }

    fn record_recent_query(&mut self, qname_hash: u64, resp_b64: Option<String>) {
        let now = Instant::now();
        while self.recent_order.len() >= RECENT_DNS_CACHE_MAX {
            if let Some(old_key) = self.recent_order.pop_front() {
                self.recent_queries.remove(&old_key);
            }
        }
        self.recent_queries.insert(qname_hash, (now, resp_b64));
        self.recent_order.push_back(qname_hash);
    }
}

fn hash_qname(qname: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    qname.hash(&mut hasher);
    hasher.finish()
}

struct DohClientSession {
    rx_state: Mutex<DohRxState>,
    cipher: Arc<AstpLiteCipher>,
}

fn create_doh_session(
    registry: &ClientRegistry,
    client_info: &ClientTransportInfo,
) -> Arc<DohClientSession> {
    let (tx_router, rx_router) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
    registry.finalize_client(&client_info.assigned_ip, tx_router);
    let cipher = Arc::new(AstpLiteCipher::new(client_info.cipher.raw_key()));
    Arc::new(DohClientSession {
        rx_state: Mutex::new(DohRxState {
            rx_router,
            pending_frags: VecDeque::new(),
            prio_queue: VecDeque::new(),
            bulk_queue: VecDeque::new(),
            next_frag_id: 1,
            next_dl_seq: 1,
            highest_cum_ack: 0,
            highest_sacked_seq: 0,
            inflight_dl: BTreeMap::new(),
            recent_queries: HashMap::new(),
            recent_order: VecDeque::new(),
        }),
        cipher,
    })
}

/// Returns true if the IP packet is latency-sensitive (ICMP ping/probe, DNS port 53, or small TCP SYN/ACK/control).
fn is_priority_packet(pkt: &[u8]) -> bool {
    if pkt.len() < 20 {
        return true;
    }
    let version = pkt[0] >> 4;
    if version == 4 {
        let ihl = ((pkt[0] & 0x0F) as usize) * 4;
        let proto = pkt[9];
        // ICMPv4
        if proto == 1 {
            return true;
        }
        // UDP DNS (src or dst port 53)
        if proto == 17 && pkt.len() >= ihl + 4 {
            let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
            let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
            if src_port == 53 || dst_port == 53 {
                return true;
            }
        }
        // Small TCP control packets (SYN, ACK, FIN, RST)
        if proto == 6 && pkt.len() <= 100 {
            return true;
        }
    } else if version == 6 && pkt.len() >= 40 {
        let next_hdr = pkt[6];
        // ICMPv6
        if next_hdr == 58 {
            return true;
        }
        if next_hdr == 17 && pkt.len() >= 44 {
            let src_port = u16::from_be_bytes([pkt[40], pkt[41]]);
            let dst_port = u16::from_be_bytes([pkt[42], pkt[43]]);
            if src_port == 53 || dst_port == 53 {
                return true;
            }
        }
        if next_hdr == 6 && pkt.len() <= 120 {
            return true;
        }
    }
    false
}

/// Clamps TCP MSS option on IPv4/IPv6 SYN / SYN-ACK packets so TCP segments fit cleanly inside single DoH DNS responses.
fn clamp_tcp_mss(pkt: &mut [u8], max_mss: u16) {
    if pkt.len() < 40 {
        return;
    }
    let version = pkt[0] >> 4;
    let tcp_start = if version == 4 {
        let ihl = ((pkt[0] & 0x0F) as usize) * 4;
        if ihl < 20 || pkt[9] != 6 {
            return;
        }
        let frag_off = u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1FFF;
        if frag_off != 0 {
            return;
        }
        ihl
    } else if version == 6 {
        if pkt.len() < 60 || pkt[6] != 6 {
            return;
        }
        40
    } else {
        return;
    };

    if pkt.len() < tcp_start + 20 {
        return;
    }
    let flags = pkt[tcp_start + 13];
    // Only inspect SYN packets (SYN=0x02, not RST=0x04)
    if (flags & 0x02) == 0 || (flags & 0x04) != 0 {
        return;
    }
    let doff = ((pkt[tcp_start + 12] >> 4) as usize) * 4;
    if doff <= 20 || pkt.len() < tcp_start + doff {
        return;
    }

    let opts_end = tcp_start + doff;
    let mut idx = tcp_start + 20;
    let mut modified = false;

    while idx < opts_end {
        let kind = pkt[idx];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            idx += 1;
            continue;
        }
        if idx + 1 >= opts_end {
            break;
        }
        let opt_len = pkt[idx + 1] as usize;
        if opt_len < 2 || idx + opt_len > opts_end {
            break;
        }
        if kind == 2 && opt_len == 4 {
            let old_mss = u16::from_be_bytes([pkt[idx + 2], pkt[idx + 3]]);
            if old_mss > max_mss {
                let new_bytes = max_mss.to_be_bytes();
                pkt[idx + 2] = new_bytes[0];
                pkt[idx + 3] = new_bytes[1];
                modified = true;
            }
            break;
        }
        idx += opt_len;
    }

    if !modified {
        return;
    }

    // Recompute TCP checksum
    pkt[tcp_start + 16] = 0;
    pkt[tcp_start + 17] = 0;
    let tcp_len = pkt.len() - tcp_start;
    let mut sum: u32 = 0;

    if version == 4 {
        for i in (12..20).step_by(2) {
            sum += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
        }
        sum += 6u32;
        sum += tcp_len as u32;
    } else {
        for i in (8..40).step_by(2) {
            sum += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
        }
        sum += 6u32;
        sum += tcp_len as u32;
    }

    let tcp_slice = &pkt[tcp_start..];
    let mut i = 0;
    while i + 1 < tcp_slice.len() {
        sum += u16::from_be_bytes([tcp_slice[i], tcp_slice[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_slice.len() {
        sum += (tcp_slice[i] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let csum = !(sum as u16);
    let csum_bytes = csum.to_be_bytes();
    pkt[tcp_start + 16] = csum_bytes[0];
    pkt[tcp_start + 17] = csum_bytes[1];
}

fn enqueue_classified_packet(state: &mut DohRxState, raw_pkt: Bytes, now: Instant) {
    let mut vec = raw_pkt.to_vec();
    clamp_tcp_mss(&mut vec, DOH_TCP_MAX_MSS);
    let pkt = Bytes::from(vec);

    if is_priority_packet(&pkt) {
        if state.prio_queue.len() >= MAX_PRIO_QUEUE_LEN {
            state.prio_queue.pop_front();
        }
        state.prio_queue.push_back((pkt, now));
    } else {
        while let Some((_, ts)) = state.bulk_queue.front() {
            if now.duration_since(*ts) > CODEL_MAX_SOJOURN {
                state.bulk_queue.pop_front();
            } else {
                break;
            }
        }
        if state.bulk_queue.len() >= MAX_BULK_QUEUE_LEN {
            state.bulk_queue.pop_front();
        }
        state.bulk_queue.push_back((pkt, now));
    }
}

fn drain_channel_into_queues(state: &mut DohRxState) {
    let now = Instant::now();
    while let Ok(pkt) = state.rx_router.try_recv() {
        enqueue_classified_packet(state, pkt, now);
    }
    while let Some((_, ts)) = state.bulk_queue.front() {
        if now.duration_since(*ts) > CODEL_MAX_SOJOURN {
            state.bulk_queue.pop_front();
        } else {
            break;
        }
    }
}

fn pop_next_packet(state: &mut DohRxState) -> Option<(Bytes, bool)> {
    let now = Instant::now();
    if let Some((pkt, _)) = state.prio_queue.pop_front() {
        return Some((pkt, true));
    }
    while let Some((pkt, ts)) = state.bulk_queue.pop_front() {
        if now.duration_since(ts) <= CODEL_MAX_SOJOURN {
            return Some((pkt, false));
        }
    }
    None
}

async fn pop_downlink_payload(
    session: &DohClientSession,
    _client_info: &ClientTransportInfo,
    session_id: u32,
    max_raw_bytes: usize,
    wait_timeout: Duration,
    qname_hash: Option<u64>,
    dl_ack: Option<(u32, u16)>,
) -> Option<String> {
    let lock_deadline = tokio::time::Instant::now() + Duration::from_millis(200);
    let mut state = tokio::time::timeout_at(lock_deadline, session.rx_state.lock())
        .await
        .ok()?;

    if let Some((ack_seq, sack_bitmap)) = dl_ack {
        state.process_downlink_ack(ack_seq, sack_bitmap);
    }

    if let Some(qhash) = qname_hash {
        if let Some(cached_opt) = state.check_recent_query(qhash) {
            return cached_opt;
        }
    }

    drain_channel_into_queues(&mut state);

    // 0. Check DownlinkArqWindow for frames needing fast SACK retransmission or RTO retransmission
    {
        let now = Instant::now();
        let highest_sacked = state.highest_sacked_seq;
        let mut expired_keys = Vec::new();
        let mut retransmit_b64 = None;

        for (&seq, frame) in state.inflight_dl.iter_mut() {
            let elapsed = now.duration_since(frame.sent_at);
            let fast_nack = seq < highest_sacked && elapsed >= DOWNLINK_SACK_FAST_RTO;
            let rto_expired = elapsed >= DOWNLINK_ARQ_RTO;

            if fast_nack || rto_expired {
                if frame.retries >= DOWNLINK_MAX_RETRIES {
                    expired_keys.push(seq);
                } else {
                    frame.sent_at = now;
                    frame.retries += 1;
                    retransmit_b64 = Some(frame.encoded_b64.clone());
                    break;
                }
            }
        }

        for k in expired_keys {
            state.inflight_dl.remove(&k);
        }

        if let Some(b64) = retransmit_b64 {
            if let Some(qhash) = qname_hash {
                state.record_recent_query(qhash, Some(b64.clone()));
            }
            return Some(b64);
        }
    }

    if state.pending_frags.is_empty()
        && state.prio_queue.is_empty()
        && state.bulk_queue.is_empty()
        && !wait_timeout.is_zero()
    {
        let wait_deadline = tokio::time::Instant::now() + wait_timeout;
        if let Ok(Some(pkt)) = tokio::time::timeout_at(wait_deadline, state.rx_router.recv()).await
        {
            enqueue_classified_packet(&mut state, pkt, Instant::now());
            drain_channel_into_queues(&mut state);
        }
    }

    // Evict oldest inflight frame if window is full so new traffic never deadlocks
    while state.inflight_dl.len() >= DOWNLINK_MAX_INFLIGHT {
        if let Some(& oldest_seq) = state.inflight_dl.keys().next() {
            state.inflight_dl.remove(&oldest_seq);
        } else {
            break;
        }
    }

    let mut packet_buf: Vec<u8> = Vec::new();

    // 1. If there is a pending fragment of a large packet, send it immediately as a 0x01 frame
    if let Some(frag_frame) = state.pending_frags.pop_front() {
        packet_buf = frag_frame.to_vec();
    } else if let Some((first_pkt, _is_prio)) = pop_next_packet(&mut state) {
        if first_pkt.len() > MAX_SINGLE_DOWNLINK_PKT {
            // Split oversized packet into <= 460B fragments with 0x01 header:
            // [0x01, pkt_id_be16, frag_idx: u8, total_frags: u8, data...]
            let pkt_id = state.next_frag_id;
            state.next_frag_id = state.next_frag_id.wrapping_add(1);
            let total_frags =
                ((first_pkt.len() + DOWNLINK_FRAG_DATA_LEN - 1) / DOWNLINK_FRAG_DATA_LEN).min(16);
            for idx in 0..total_frags {
                let start = idx * DOWNLINK_FRAG_DATA_LEN;
                let end = (start + DOWNLINK_FRAG_DATA_LEN).min(first_pkt.len());
                let mut fbuf = Vec::with_capacity(5 + (end - start));
                fbuf.push(0x01);
                fbuf.extend_from_slice(&pkt_id.to_be_bytes());
                fbuf.push(idx as u8);
                fbuf.push(total_frags as u8);
                fbuf.extend_from_slice(&first_pkt[start..end]);
                if idx == 0 {
                    packet_buf = fbuf;
                } else {
                    state.pending_frags.push_back(Bytes::from(fbuf));
                }
            }
        } else {
            // Normal packet (<= 500B): try batching additional packets that fit strictly within max_raw_bytes
            let mut packets: Vec<Bytes> = Vec::with_capacity(8);
            let mut total_raw = first_pkt.len();
            packets.push(first_pkt);

            while packets.len() < 12 {
                let Some((next_pkt, next_is_prio)) = pop_next_packet(&mut state) else {
                    break;
                };
                let needed = if packets.len() == 1 {
                    1 + 2 + total_raw + 2 + next_pkt.len()
                } else {
                    total_raw + 2 + next_pkt.len()
                };

                if next_pkt.len() <= MAX_SINGLE_DOWNLINK_PKT && needed <= max_raw_bytes {
                    total_raw = needed;
                    packets.push(next_pkt);
                } else {
                    // Put back at the front so it is never lost and never exceeds max_raw_bytes!
                    if next_is_prio {
                        state.prio_queue.push_front((next_pkt, Instant::now()));
                    } else {
                        state.bulk_queue.push_front((next_pkt, Instant::now()));
                    }
                    break;
                }
            }

            if packets.len() == 1 {
                packet_buf = packets[0].to_vec();
            } else {
                packet_buf = Vec::with_capacity(total_raw);
                packet_buf.push(0x00); // Batch marker
                for pkt in &packets {
                    packet_buf.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
                    packet_buf.extend_from_slice(pkt);
                }
            }
        }
    }

    if packet_buf.is_empty() {
        if let Some(qhash) = qname_hash {
            state.record_recent_query(qhash, None);
        }
        return None;
    }

    let seq = state.next_dl_seq;
    state.next_dl_seq = state.next_dl_seq.wrapping_add(1);

    session
        .cipher
        .apply_keystream(seq, session_id, &mut packet_buf);

    let mut downlink_bytes = Vec::with_capacity(4 + packet_buf.len());
    downlink_bytes.extend_from_slice(&seq.to_be_bytes());
    downlink_bytes.extend_from_slice(&packet_buf);

    let b64 = BASE64_STANDARD.encode(&downlink_bytes);
    state.inflight_dl.insert(
        seq,
        InflightDownlinkFrame {
            seq,
            encoded_b64: b64.clone(),
            sent_at: Instant::now(),
            retries: 0,
        },
    );
    if let Some(qhash) = qname_hash {
        state.record_recent_query(qhash, Some(b64.clone()));
    }

    Some(b64)
}

/// Определяет основной внешний IPv4-адрес сервера через таблицу маршрутизации ядра (без отправки пакетов).
fn detect_primary_ipv4() -> Option<std::net::IpAddr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("1.1.1.1:53").ok()?;
    let ip = sock.local_addr().ok()?.ip();
    if ip.is_unspecified() || ip.is_loopback() {
        None
    } else {
        Some(ip)
    }
}

pub async fn run_doh_dns_server(
    config: Arc<Config>,
    registry: Arc<ClientRegistry>,
    tun_tx: mpsc::Sender<Bytes>,
    auth_handler: ServerAuthHandler,
) -> Result<()> {
    let raw_bind = config.server.doh_bind_to.trim();
    let bind_to = if !raw_bind.contains(':') {
        format!("0.0.0.0:{}", raw_bind)
    } else {
        raw_bind.to_string()
    };
    let domain_zone = config
        .doh_transport
        .domain
        .trim_matches('.')
        .to_ascii_lowercase();
    let poll_hold_timeout_ms = config.doh_transport.poll_hold_timeout_ms;

    info!(
        "[DoH-DNS] Initializing authoritative UDP DNS server on {} for zone '*.{}' (Hold: {}ms)",
        bind_to, domain_zone, poll_hold_timeout_ms
    );

    let socket = match UdpSocket::bind(&bind_to).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            let mut fallback_socket = None;
            if e.kind() == std::io::ErrorKind::AddrInUse && bind_to.starts_with("0.0.0.0:") {
                if let Some(port_str) = bind_to.strip_prefix("0.0.0.0:") {
                    if let Ok(port) = port_str.parse::<u16>() {
                        if let Some(primary_ip) = detect_primary_ipv4() {
                            let fallback_addr = SocketAddr::new(primary_ip, port);
                            match UdpSocket::bind(fallback_addr).await {
                                Ok(s) => {
                                    warn!(
                                        "[DoH-DNS] Could not bind wildcard {} ({}) — likely systemd-resolved occupying 127.0.0.53:{}. Automatically bound to primary interface {} instead.",
                                        bind_to, e, port, fallback_addr
                                    );
                                    fallback_socket = Some(Arc::new(s));
                                }
                                Err(fallback_err) => {
                                    warn!(
                                        "[DoH-DNS] Fallback bind to primary interface {} also failed: {}",
                                        fallback_addr, fallback_err
                                    );
                                }
                            }
                        }
                    }
                }
            }

            match fallback_socket {
                Some(s) => s,
                None => {
                    return Err(anyhow::Error::new(e).context(format!(
                        "Failed to bind UDP {} for DoH DNS (hint: check if systemd-resolved/dnsmasq occupies port 53 via `ss -ulpn | grep :53`, or set `doh_bind_to = \"<SERVER_PUBLIC_IP>:53\"`)",
                        bind_to
                    )));
                }
            }
        }
    };

    let active_sessions: Arc<DashMap<u32, Arc<DohClientSession>>> = Arc::new(DashMap::new());
    let reassembler: Arc<Mutex<DohReassemblyQueue>> =
        Arc::new(Mutex::new(DohReassemblyQueue::new(Duration::from_secs(10))));
    let handshake_reassembler: Arc<Mutex<DohReassemblyQueue>> =
        Arc::new(Mutex::new(DohReassemblyQueue::new(Duration::from_secs(15))));
    let temp_handshake_responses: Arc<DashMap<u32, (String, Instant)>> = Arc::new(DashMap::new());
    let phase_handshake_responses: Arc<DashMap<(u32, u32), (String, Instant)>> =
        Arc::new(DashMap::new());

    // Background garbage collector for incomplete packets and handshake state
    {
        let reassembler = reassembler.clone();
        let handshake_reassembler = handshake_reassembler.clone();
        let temp_responses = temp_handshake_responses.clone();
        let phase_responses = phase_handshake_responses.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                reassembler.lock().await.cleanup();
                handshake_reassembler.lock().await.cleanup();
                temp_responses.retain(|_, (_, created)| created.elapsed() < Duration::from_secs(30));
                phase_responses
                    .retain(|_, (_, created)| created.elapsed() < Duration::from_secs(30));
            }
        });
    }

    let mut buf = [0u8; 4096];

    loop {
        let (len, remote_addr) = match socket.recv_from(&mut buf).await {
            Ok(res) => res,
            Err(e) => {
                warn!("[DoH-DNS] recv_from error: {}", e);
                continue;
            }
        };

        let raw_query = buf[..len].to_vec();
        let socket = socket.clone();
        let config = config.clone();
        let registry = registry.clone();
        let tun_tx = tun_tx.clone();
        let auth_handler = auth_handler.clone();
        let domain_zone = domain_zone.clone();
        let active_sessions = active_sessions.clone();
        let reassembler = reassembler.clone();
        let handshake_reassembler = handshake_reassembler.clone();
        let temp_handshake_responses = temp_handshake_responses.clone();
        let phase_handshake_responses = phase_handshake_responses.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_dns_datagram(
                raw_query,
                remote_addr,
                socket,
                domain_zone,
                poll_hold_timeout_ms,
                config,
                registry,
                tun_tx,
                auth_handler,
                active_sessions,
                reassembler,
                handshake_reassembler,
                temp_handshake_responses,
                phase_handshake_responses,
            )
            .await
            {
                debug!("[DoH-DNS] Error handling DNS query from {}: {}", remote_addr, e);
            }
        });
    }
}

async fn handle_dns_datagram(
    raw_query: Vec<u8>,
    remote_addr: SocketAddr,
    socket: Arc<UdpSocket>,
    domain_zone: String,
    poll_hold_timeout_ms: u64,
    _config: Arc<Config>,
    registry: Arc<ClientRegistry>,
    tun_tx: mpsc::Sender<Bytes>,
    auth_handler: ServerAuthHandler,
    active_sessions: Arc<DashMap<u32, Arc<DohClientSession>>>,
    reassembler: Arc<Mutex<DohReassemblyQueue>>,
    handshake_reassembler: Arc<Mutex<DohReassemblyQueue>>,
    temp_handshake_responses: Arc<DashMap<u32, (String, Instant)>>,
    phase_handshake_responses: Arc<DashMap<(u32, u32), (String, Instant)>>,
) -> Result<()> {
    let parsed_q = match parse_dns_query(&raw_query) {
        Some(q) => q,
        None => return Ok(()),
    };

    // Validate domain zone suffix
    if !parsed_q.qname.ends_with(&domain_zone) {
        let resp = build_dns_txt_response(&raw_query, &parsed_q, None, 0);
        let _ = socket.send_to(&resp, remote_addr).await;
        return Ok(());
    }

    let prefix = parsed_q
        .qname
        .trim_end_matches(&domain_zone)
        .trim_end_matches('.');

    // Filter out QNAME-minimization probes: non-TXT queries (A, NS, SOA) or empty zone apex
    if parsed_q.qtype != anet_common::dns_proto::DNS_QTYPE_TXT || prefix.is_empty() {
        let resp = build_dns_txt_response(&raw_query, &parsed_q, None, 0);
        let _ = socket.send_to(&resp, remote_addr).await;
        return Ok(());
    }

    let qhash = hash_qname(&parsed_q.qname);

    // Case 1: Downlink Poll query ("poll.<sid_hex>.<dl_ack_hex>.<dl_sack_hex>.<nonce_hex>" or legacy "poll.<sid_hex>.<nonce_hex>")
    if prefix.starts_with("poll.") {
        let parts: Vec<&str> = prefix.split('.').collect();
        if parts.len() >= 2 {
            let session_id = match u32::from_str_radix(parts[1], 16) {
                Ok(sid) => sid,
                Err(_) => {
                    let resp = build_dns_txt_response(&raw_query, &parsed_q, None, 0);
                    let _ = socket.send_to(&resp, remote_addr).await;
                    return Ok(());
                }
            };

            let dl_ack = if parts.len() >= 5 {
                let ack_seq = u32::from_str_radix(parts[2], 16).unwrap_or(0);
                let sack_bitmap = u16::from_str_radix(parts[3], 16).unwrap_or(0);
                Some((ack_seq, sack_bitmap))
            } else {
                None
            };

            let prefix_bytes = session_id.to_be_bytes();
            if let Some(client_info) = registry.get_by_prefix(&prefix_bytes) {
                client_info.last_activity.store(
                    std::time::SystemTime::now()
                        .duration_since(std::time::SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    Ordering::Relaxed,
                );

                let session = active_sessions
                    .entry(session_id)
                    .or_insert_with(|| create_doh_session(&registry, &client_info))
                    .value()
                    .clone();

                let effective_hold_ms = poll_hold_timeout_ms.min(45);
                if let Some(b64) = pop_downlink_payload(
                    &session,
                    &client_info,
                    session_id,
                    820,
                    Duration::from_millis(effective_hold_ms),
                    Some(qhash),
                    dl_ack,
                )
                .await
                {
                    let resp =
                        build_dns_txt_response(&raw_query, &parsed_q, Some(b64.as_bytes()), 0);
                    let _ = socket.send_to(&resp, remote_addr).await;
                    return Ok(());
                } else {
                    let resp = build_dns_txt_response(&raw_query, &parsed_q, None, 0);
                    let _ = socket.send_to(&resp, remote_addr).await;
                    return Ok(());
                }
            } else if let Some(saved) = temp_handshake_responses.get(&session_id) {
                let resp =
                    build_dns_txt_response(&raw_query, &parsed_q, Some(saved.0.as_bytes()), 0);
                let _ = socket.send_to(&resp, remote_addr).await;
                return Ok(());
            } else {
                let resp = build_dns_txt_response(&raw_query, &parsed_q, None, 0);
                let _ = socket.send_to(&resp, remote_addr).await;
                return Ok(());
            }
        }
    }

    // Case 2: Handshake query ("hs.<session_id_hex>.<chunk_idx>.<total_chunks>.<base32_chunk>")
    if prefix.starts_with("hs.") {
        let parts: Vec<&str> = prefix.splitn(5, '.').collect();
        if parts.len() == 5 {
            let temp_session_id = u32::from_str_radix(parts[1], 16).unwrap_or(0);
            let b32_str = base32::join_labels(parts[4]);

            if let Ok(chunk_raw) = base32::decode(&b32_str) {
                if let Ok(hdr) = anet_common::doh_chunking::DohChunkHeader::decode(&chunk_raw) {
                    if let Some(cached) =
                        phase_handshake_responses.get(&(temp_session_id, hdr.sequence))
                    {
                        let dns_resp = build_dns_txt_response(
                            &raw_query,
                            &parsed_q,
                            Some(cached.0.as_bytes()),
                            0,
                        );
                        let _ = socket.send_to(&dns_resp, remote_addr).await;
                        return Ok(());
                    }
                    if hdr.sequence > 0 && hdr.chunk_index == 0 {
                        temp_handshake_responses.remove(&temp_session_id);
                    }
                }

                let assembled_opt = {
                    let mut reasm = handshake_reassembler.lock().await;
                    reasm.feed(&chunk_raw)?
                };

                if let Some((_sid, seq, full_handshake)) = assembled_opt {
                    if let Some(cached) = phase_handshake_responses.get(&(temp_session_id, seq)) {
                        let dns_resp = build_dns_txt_response(
                            &raw_query,
                            &parsed_q,
                            Some(cached.0.as_bytes()),
                            0,
                        );
                        let _ = socket.send_to(&dns_resp, remote_addr).await;
                        return Ok(());
                    }

                    info!(
                        "[DoH-DNS] Handshake phase {} packet reassembled (sid={:08x}, len={} bytes, resolver={})",
                        seq,
                        temp_session_id,
                        full_handshake.len(),
                        remote_addr
                    );

                    let hs_addr = SocketAddr::from((
                        [
                            127,
                            254,
                            ((temp_session_id >> 16) & 0xFF) as u8,
                            ((temp_session_id >> 8) & 0xFF) as u8,
                        ],
                        (temp_session_id & 0xFFFF) as u16,
                    ));
                    let (response_opt, authenticated) = auth_handler
                        .process_handshake_packet(full_handshake, hs_addr, "doh")
                        .await?;

                    if let Some((client_info, _)) = authenticated {
                        let session_id = u32::from_be_bytes(client_info.nonce_prefix);
                        active_sessions
                            .entry(session_id)
                            .or_insert_with(|| create_doh_session(&registry, &client_info));
                    }

                    if let Some(resp) = response_opt {
                        let b64 = BASE64_STANDARD.encode(&resp);
                        let now = Instant::now();
                        phase_handshake_responses
                            .insert((temp_session_id, seq), (b64.clone(), now));
                        temp_handshake_responses.insert(temp_session_id, (b64.clone(), now));

                        let dns_resp = build_dns_txt_response(
                            &raw_query,
                            &parsed_q,
                            Some(b64.as_bytes()),
                            0,
                        );
                        let _ = socket.send_to(&dns_resp, remote_addr).await;
                        return Ok(());
                    }
                }

                let dns_resp = build_dns_txt_response(&raw_query, &parsed_q, Some(b"ACK"), 0);
                let _ = socket.send_to(&dns_resp, remote_addr).await;
                return Ok(());
            }
        }
    }

    // Case 3: Data Uplink chunk ("<base36_or_base32_chunk_labels>")
    let b32_str = base32::join_labels(prefix);
    if let Ok(chunk_raw) = base32::decode_base36(&b32_str).or_else(|_| base32::decode(&b32_str)) {
        // Filter out intermediate QNAME-minimization suffixes whose session_id does not belong to an active client
        let (hdr, _) = match anet_common::doh_chunking::DohChunkHeader::decode_with_len(&chunk_raw) {
            Ok(h) => h,
            Err(_) => {
                let resp = build_dns_txt_response(&raw_query, &parsed_q, None, 0);
                let _ = socket.send_to(&resp, remote_addr).await;
                return Ok(());
            }
        };
        let prefix_bytes = hdr.session_id.to_be_bytes();
        let Some(client_info) = registry.get_by_prefix(&prefix_bytes) else {
            let resp = build_dns_txt_response(&raw_query, &parsed_q, None, 0);
            let _ = socket.send_to(&resp, remote_addr).await;
            return Ok(());
        };

        let session = active_sessions
            .entry(hdr.session_id)
            .or_insert_with(|| create_doh_session(&registry, &client_info))
            .value()
            .clone();

        let (assembled_opt, (ul_cum_ack, ul_nacks)) = {
            let mut reasm = reassembler.lock().await;
            let res = reasm.feed(&chunk_raw)?;
            let fb = reasm.get_session_feedback(hdr.session_id);
            (res, fb)
        };

        let mut completed_uplink = false;
        if let Some((session_id, seq, full_payload)) = assembled_opt {
            completed_uplink = true;
            client_info.last_activity.store(
                std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                Ordering::Relaxed,
            );

            let mut decrypted = full_payload.to_vec();
            session.cipher.apply_keystream(seq, session_id, &mut decrypted);

            if decrypted.first() == Some(&0x00) {
                // Unpack batched uplink packets: [0x00, len_be16, pkt1, len_be16, pkt2, ...]
                let mut pos = 1;
                while pos + 2 <= decrypted.len() {
                    let pkt_len = u16::from_be_bytes([decrypted[pos], decrypted[pos + 1]]) as usize;
                    pos += 2;
                    if pos + pkt_len <= decrypted.len() {
                        let mut single_pkt = decrypted[pos..pos + pkt_len].to_vec();
                        clamp_tcp_mss(&mut single_pkt, DOH_TCP_MAX_MSS);
                        if tun_tx.try_send(Bytes::from(single_pkt)).is_ok() {
                            registry.record_rx(&client_info, pkt_len, "doh");
                        }
                        pos += pkt_len;
                    } else {
                        break;
                    }
                }
            } else if !decrypted.is_empty() {
                let packet_len = decrypted.len();
                clamp_tcp_mss(&mut decrypted, DOH_TCP_MAX_MSS);
                if tun_tx.try_send(Bytes::from(decrypted)).is_ok() {
                    registry.record_rx(&client_info, packet_len, "doh");
                }
            }
        }

        // Piggyback ready downlink packets (or quick replies such as in-tunnel ICMP Echo Reply)
        // directly in the TXT response of the uplink query (capped at 510 raw bytes so UDP DNS <= 994B).
        let piggyback_wait = if completed_uplink {
            Duration::from_millis(3)
        } else {
            Duration::ZERO
        };
        if let Some(b64) = pop_downlink_payload(
            &session,
            &client_info,
            hdr.session_id,
            680,
            piggyback_wait,
            Some(qhash),
            None,
        )
        .await
        {
            let resp = build_dns_txt_response(&raw_query, &parsed_q, Some(b64.as_bytes()), 0);
            let _ = socket.send_to(&resp, remote_addr).await;
            return Ok(());
        }

        // Encode Uplink ARQ cumulative ACK + selective chunk NACK mask in the TXT ACK response:
        // Format: "OK:<ul_cum_ack_hex>[:<pkt_seq_hex>:<recv_mask_hex>]"
        let mut ack_txt = format!("OK:{:x}", ul_cum_ack);
        for (nseq, nmask) in ul_nacks {
            ack_txt.push_str(&format!(":{:x}:{:x}", nseq, nmask));
        }

        let resp = build_dns_txt_response(&raw_query, &parsed_q, Some(ack_txt.as_bytes()), 0);
        let _ = socket.send_to(&resp, remote_addr).await;
        return Ok(());
    }

    let resp = build_dns_txt_response(&raw_query, &parsed_q, None, 0);
    let _ = socket.send_to(&resp, remote_addr).await;
    Ok(())
}
