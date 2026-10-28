use super::{ClientTransport, ConnectionResult};
use crate::auth::{AuthChannel, AuthHandler};
use crate::config::{CoreConfig, ServerConfig};
use anet_common::astp_lite::AstpLiteCipher;
use anet_common::base32;
use anet_common::dns_proto::{build_doh_query, parse_dns_txt_response};
use anet_common::doh_chunking::{calculate_max_chunk_payload, split_into_chunks};
use anet_common::handshake_fragmentation::FragmentConfig;
use anet_common::http_help::BrowserProfile;
use anet_common::stream_framing::{frame_packet_into, read_next_packet};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use bytes::{Bytes, BytesMut};
use log::{debug, info, warn};
use reqwest::{Client, Url};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncWriteExt, WriteHalf};
use tokio::sync::{Mutex, Notify, Semaphore};

const RESOLVER_COOLDOWN_MS: u64 = 2_000;
const DOH_TCP_MAX_MSS: u16 = 640;
const CODEL_MAX_SOJOURN: Duration = Duration::from_millis(600);
const MAX_BULK_QUEUE_LEN: usize = 48;
const MAX_PRIO_QUEUE_LEN: usize = 128;

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
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
        // ICMPv4 (in-tunnel RTT probe and user `ping`)
        if proto == 1 {
            return true;
        }
        // UDP DNS (port 53)
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

/// Clamps TCP MSS option on IPv4/IPv6 SYN / SYN-ACK packets so TCP segments fit cleanly inside DoH chunks/responses.
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

struct UplinkQueueInner {
    prio: VecDeque<(Bytes, Instant)>,
    bulk: VecDeque<(Bytes, Instant)>,
    closed: bool,
}

struct DohUplinkQueue {
    inner: std::sync::Mutex<UplinkQueueInner>,
    notify: Notify,
}

impl DohUplinkQueue {
    fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(UplinkQueueInner {
                prio: VecDeque::new(),
                bulk: VecDeque::new(),
                closed: false,
            }),
            notify: Notify::new(),
        }
    }

    fn push(&self, raw_pkt: Bytes) {
        let mut vec = raw_pkt.to_vec();
        clamp_tcp_mss(&mut vec, DOH_TCP_MAX_MSS);
        let pkt = Bytes::from(vec);
        let now = Instant::now();
        let is_prio = is_priority_packet(&pkt);

        {
            let mut guard = self.inner.lock().unwrap();
            if is_prio {
                if guard.prio.len() >= MAX_PRIO_QUEUE_LEN {
                    guard.prio.pop_front();
                }
                guard.prio.push_back((pkt, now));
            } else {
                while let Some((_, ts)) = guard.bulk.front() {
                    if now.duration_since(*ts) > CODEL_MAX_SOJOURN {
                        guard.bulk.pop_front();
                    } else {
                        break;
                    }
                }
                if guard.bulk.len() >= MAX_BULK_QUEUE_LEN {
                    guard.bulk.pop_front();
                }
                guard.bulk.push_back((pkt, now));
            }
        }
        self.notify.notify_one();
    }

    fn close(&self) {
        self.inner.lock().unwrap().closed = true;
        self.notify.notify_waiters();
    }

    /// Pops either a single packet or a coalesced `0x00` batch of small packets (fitting in 1 chunk `<= max_payload`).
    /// Returns `Some((payload_bytes, is_priority))` or `None` when closed and empty.
    async fn pop_batch(&self, max_payload: usize) -> Option<(Vec<u8>, bool)> {
        loop {
            let notified = self.notify.notified();
            {
                let mut guard = self.inner.lock().unwrap();
                let now = Instant::now();

                while let Some((_, ts)) = guard.bulk.front() {
                    if now.duration_since(*ts) > CODEL_MAX_SOJOURN {
                        guard.bulk.pop_front();
                    } else {
                        break;
                    }
                }

                let first_opt = if let Some((pkt, _)) = guard.prio.pop_front() {
                    Some((pkt, true))
                } else {
                    guard.bulk.pop_front().map(|(pkt, _)| (pkt, false))
                };

                if let Some((first_pkt, mut is_prio)) = first_opt {
                    // If the first packet is small enough that another packet might fit inside a single chunk (`max_payload`),
                    // greedily coalesce waiting packets so multiple small packets (ACKs, pings, DNS) use just 1 DNS query!
                    if 1 + 2 + first_pkt.len() + 22 <= max_payload {
                        let mut packets: Vec<Bytes> = Vec::with_capacity(4);
                        let mut total_raw = first_pkt.len();
                        packets.push(first_pkt);

                        while packets.len() < 6 {
                            let next_opt = if let Some((p, _)) = guard.prio.pop_front() {
                                Some((p, true))
                            } else {
                                guard.bulk.pop_front().map(|(p, _)| (p, false))
                            };

                            let Some((next_pkt, next_prio)) = next_opt else {
                                break;
                            };

                            let needed = if packets.len() == 1 {
                                1 + 2 + total_raw + 2 + next_pkt.len()
                            } else {
                                total_raw + 2 + next_pkt.len()
                            };

                            if needed <= max_payload {
                                total_raw = needed;
                                is_prio = is_prio || next_prio;
                                packets.push(next_pkt);
                            } else {
                                if next_prio {
                                    guard.prio.push_front((next_pkt, now));
                                } else {
                                    guard.bulk.push_front((next_pkt, now));
                                }
                                break;
                            }
                        }

                        if packets.len() == 1 {
                            return Some((packets[0].to_vec(), is_prio));
                        } else {
                            let mut buf = Vec::with_capacity(total_raw);
                            buf.push(0x00);
                            for p in &packets {
                                buf.extend_from_slice(&(p.len() as u16).to_be_bytes());
                                buf.extend_from_slice(p);
                            }
                            return Some((buf, is_prio));
                        }
                    } else {
                        return Some((first_pkt.to_vec(), is_prio));
                    }
                }

                if guard.closed {
                    return None;
                }
            }
            notified.await;
        }
    }
}

struct PartialDownlinkPacket {
    total_frags: u8,
    received: u8,
    frags: Vec<Option<Bytes>>,
    created_at: Instant,
}

const REORDER_GAP_TIMEOUT: Duration = Duration::from_millis(420);
const REORDER_MAX_WINDOW: usize = 64;

struct DohDownlinkState {
    seen_seqs: VecDeque<u32>,
    partials: HashMap<u16, PartialDownlinkPacket>,
    cum_ack_seq: u32,
    reorder_buf: std::collections::BTreeMap<u32, (BytesMut, Instant)>,
    dl_feedback: Arc<AtomicU64>,
}

impl DohDownlinkState {
    fn new(dl_feedback: Arc<AtomicU64>) -> Self {
        Self {
            seen_seqs: VecDeque::with_capacity(256),
            partials: HashMap::new(),
            cum_ack_seq: 0,
            reorder_buf: std::collections::BTreeMap::new(),
            dl_feedback,
        }
    }

    fn check_and_record_seq(&mut self, seq: u32) -> bool {
        if seq <= self.cum_ack_seq || self.seen_seqs.contains(&seq) {
            self.update_feedback_atomic();
            return false;
        }
        if self.seen_seqs.len() >= 256 {
            self.seen_seqs.pop_front();
        }
        self.seen_seqs.push_back(seq);
        true
    }

    fn update_feedback_atomic(&self) {
        let mut sack_bitmap = 0u16;
        for bit in 0..16u32 {
            let target = self.cum_ack_seq.wrapping_add(1 + bit);
            if self.reorder_buf.contains_key(&target) || self.seen_seqs.contains(&target) {
                sack_bitmap |= 1u16 << bit;
            }
        }
        let packed = ((self.cum_ack_seq as u64) << 16) | (sack_bitmap as u64);
        self.dl_feedback.store(packed, Ordering::Release);
    }

    fn insert_and_drain_ordered(&mut self, seq: u32, framed_bytes: BytesMut) -> BytesMut {
        let now = Instant::now();
        if self.cum_ack_seq == 0 && seq == 1 {
            self.cum_ack_seq = 1;
            let mut out = framed_bytes;
            while let Some((&next_seq, _)) = self.reorder_buf.iter().next() {
                if next_seq == self.cum_ack_seq + 1 {
                    let (buf, _) = self.reorder_buf.remove(&next_seq).unwrap();
                    out.extend_from_slice(&buf);
                    self.cum_ack_seq = next_seq;
                } else {
                    break;
                }
            }
            self.update_feedback_atomic();
            return out;
        }

        if seq == self.cum_ack_seq + 1 {
            self.cum_ack_seq = seq;
            let mut out = framed_bytes;
            while let Some((&next_seq, _)) = self.reorder_buf.iter().next() {
                if next_seq == self.cum_ack_seq + 1 {
                    let (buf, _) = self.reorder_buf.remove(&next_seq).unwrap();
                    out.extend_from_slice(&buf);
                    self.cum_ack_seq = next_seq;
                } else {
                    break;
                }
            }
            self.update_feedback_atomic();
            return out;
        }

        // Out-of-order frame (seq > cum_ack_seq + 1): store in reorder_buf
        self.reorder_buf.insert(seq, (framed_bytes, now));

        // If any gap is older than REORDER_GAP_TIMEOUT or buffer exceeds REORDER_MAX_WINDOW, flush past the gap
        let mut out = BytesMut::new();
        loop {
            let should_flush_gap = if self.reorder_buf.len() >= REORDER_MAX_WINDOW {
                true
            } else if let Some((_, (_, first_ts))) = self.reorder_buf.iter().next() {
                now.duration_since(*first_ts) >= REORDER_GAP_TIMEOUT
            } else {
                false
            };

            if !should_flush_gap {
                break;
            }

            let Some((&first_seq, _)) = self.reorder_buf.iter().next() else {
                break;
            };
            let (buf, _) = self.reorder_buf.remove(&first_seq).unwrap();
            out.extend_from_slice(&buf);
            if first_seq > self.cum_ack_seq {
                self.cum_ack_seq = first_seq;
            }

            while let Some((&next_seq, _)) = self.reorder_buf.iter().next() {
                if next_seq <= self.cum_ack_seq + 1 {
                    let (nbuf, _) = self.reorder_buf.remove(&next_seq).unwrap();
                    out.extend_from_slice(&nbuf);
                    if next_seq > self.cum_ack_seq {
                        self.cum_ack_seq = next_seq;
                    }
                } else {
                    break;
                }
            }
        }

        self.update_feedback_atomic();
        out
    }

    fn feed_fragment(&mut self, pkt_id: u16, frag_idx: u8, total_frags: u8, data: &[u8]) -> Option<Bytes> {
        if total_frags == 0 || frag_idx >= total_frags || total_frags > 16 {
            return None;
        }
        let now = Instant::now();
        self.partials
            .retain(|_, v| now.duration_since(v.created_at) < Duration::from_secs(8));

        let entry = self
            .partials
            .entry(pkt_id)
            .or_insert_with(|| PartialDownlinkPacket {
                total_frags,
                received: 0,
                frags: vec![None; total_frags as usize],
                created_at: now,
            });

        let idx = frag_idx as usize;
        if idx < entry.frags.len() && entry.frags[idx].is_none() {
            entry.frags[idx] = Some(Bytes::copy_from_slice(data));
            entry.received += 1;
        }

        if entry.received == entry.total_frags {
            let done = self.partials.remove(&pkt_id).unwrap();
            let mut full = BytesMut::new();
            for f in done.frags.into_iter().flatten() {
                full.extend_from_slice(&f);
            }
            return Some(full.freeze());
        }
        None
    }
}

const UPLINK_ARQ_RTO: Duration = Duration::from_millis(340);
const UPLINK_NACK_FAST_DELAY: Duration = Duration::from_millis(110);
const UPLINK_MAX_INFLIGHT_PKTS: usize = 96;
const UPLINK_MAX_CHUNK_RETRIES: u8 = 4;

struct InflightUplinkPacket {
    chunks: Vec<Vec<u8>>,
    acked_mask: u16,
    last_sent: Vec<Instant>,
    retries: Vec<u8>,
}

struct UplinkArqState {
    enabled: bool,
    cum_ack: u32,
    inflight: std::collections::BTreeMap<u32, InflightUplinkPacket>,
    retransmit_chunks: VecDeque<Vec<u8>>,
}

impl UplinkArqState {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            cum_ack: 0,
            inflight: std::collections::BTreeMap::new(),
            retransmit_chunks: VecDeque::new(),
        }
    }

    fn record_sent_packet(&mut self, seq: u32, chunks: &[Vec<u8>]) {
        if !self.enabled || chunks.is_empty() || chunks.len() > 16 {
            return;
        }
        while self.inflight.len() >= UPLINK_MAX_INFLIGHT_PKTS {
            if let Some(&oldest) = self.inflight.keys().next() {
                self.inflight.remove(&oldest);
            } else {
                break;
            }
        }
        let now = Instant::now();
        let n = chunks.len();
        self.inflight.insert(
            seq,
            InflightUplinkPacket {
                chunks: chunks.to_vec(),
                acked_mask: 0,
                last_sent: vec![now; n],
                retries: vec![0; n],
            },
        );
    }

    fn process_ack_txt(&mut self, txt_str: &str) {
        if !self.enabled {
            return;
        }
        // Format: "OK:<ul_cum_ack_hex>[:<pkt_seq_hex>:<recv_mask_hex>...]"
        let Some(rest) = txt_str.strip_prefix("OK:") else {
            return;
        };
        let parts: Vec<&str> = rest.split(':').collect();
        if parts.is_empty() {
            return;
        }
        let Ok(cum_ack) = u32::from_str_radix(parts[0], 16) else {
            return;
        };
        if cum_ack > self.cum_ack {
            self.cum_ack = cum_ack;
        }
        let c_ack = self.cum_ack;
        if c_ack > 0 {
            self.inflight.retain(|&seq, _| seq > c_ack);
        }

        let now = Instant::now();
        let mut idx = 1;
        while idx + 1 < parts.len() {
            if let (Ok(pkt_seq), Ok(recv_mask)) = (
                u32::from_str_radix(parts[idx], 16),
                u16::from_str_radix(parts[idx + 1], 16),
            ) {
                if let Some(entry) = self.inflight.get_mut(&pkt_seq) {
                    entry.acked_mask |= recv_mask;
                    let total = entry.chunks.len();
                    let full_mask = if total >= 16 {
                        0xFFFF
                    } else {
                        (1u16 << total) - 1
                    };
                    if (entry.acked_mask & full_mask) == full_mask {
                        self.inflight.remove(&pkt_seq);
                    } else {
                        for c_idx in 0..total {
                            if (entry.acked_mask & (1u16 << c_idx)) == 0
                                && now.duration_since(entry.last_sent[c_idx])
                                    >= UPLINK_NACK_FAST_DELAY
                                && entry.retries[c_idx] < UPLINK_MAX_CHUNK_RETRIES
                            {
                                entry.last_sent[c_idx] = now;
                                entry.retries[c_idx] += 1;
                                if self.retransmit_chunks.len() < 128 {
                                    self.retransmit_chunks
                                        .push_back(entry.chunks[c_idx].clone());
                                }
                            }
                        }
                    }
                }
            }
            idx += 2;
        }
    }

    fn collect_rto_retransmits(&mut self) -> Vec<Vec<u8>> {
        if !self.enabled {
            return Vec::new();
        }
        let now = Instant::now();
        let mut expired_pkts = Vec::new();

        for (&seq, entry) in self.inflight.iter_mut() {
            let total = entry.chunks.len();
            let mut all_dead = true;
            for c_idx in 0..total {
                if (entry.acked_mask & (1u16 << c_idx)) != 0 {
                    continue;
                }
                if entry.retries[c_idx] >= UPLINK_MAX_CHUNK_RETRIES {
                    continue;
                }
                all_dead = false;
                if now.duration_since(entry.last_sent[c_idx]) >= UPLINK_ARQ_RTO {
                    entry.last_sent[c_idx] = now;
                    entry.retries[c_idx] += 1;
                    if self.retransmit_chunks.len() < 128 {
                        self.retransmit_chunks
                            .push_back(entry.chunks[c_idx].clone());
                    }
                }
            }
            if all_dead {
                expired_pkts.push(seq);
            }
        }

        for seq in expired_pkts {
            self.inflight.remove(&seq);
        }

        let mut out = Vec::with_capacity(self.retransmit_chunks.len().min(16));
        while out.len() < 16 {
            let Some(chunk) = self.retransmit_chunks.pop_front() else {
                break;
            };
            out.push(chunk);
        }
        out
    }
}

/// Processes a DNS response body (from either a `poll.` query or a piggybacked Uplink chunk query).
/// Returns `Ok(true)` if downlink tunnel packet(s) were received (including buffered out-of-order frames).
async fn process_downlink_dns_body(
    body: &[u8],
    cipher: &AstpLiteCipher,
    session_id: u32,
    dl_state: &Mutex<DohDownlinkState>,
    ul_arq: &std::sync::Mutex<UplinkArqState>,
    tunnel_write: &Mutex<WriteHalf<tokio::io::DuplexStream>>,
    poll_burst_notify: &Notify,
) -> Result<bool> {
    let Some(txt_data) = parse_dns_txt_response(body) else {
        return Ok(false);
    };
    if txt_data.is_empty() || txt_data == b"OK" || txt_data == b"ACK" {
        return Ok(false);
    }
    if txt_data.starts_with(b"OK:") {
        if let Ok(txt_str) = std::str::from_utf8(&txt_data) {
            ul_arq.lock().unwrap().process_ack_txt(txt_str);
        }
        return Ok(false);
    }
    let Ok(mut raw_payload) = BASE64_STANDARD.decode(&txt_data) else {
        return Ok(false);
    };
    if raw_payload.len() < 4 {
        return Ok(false);
    }

    let wire_seq = u32::from_be_bytes(raw_payload[0..4].try_into().unwrap());
    let more_data_pending = (wire_seq & 0x8000_0000) != 0;
    let seq = wire_seq & 0x7FFF_FFFF;
    let ciphertext = &mut raw_payload[4..];

    if more_data_pending {
        poll_burst_notify.notify_waiters();
    }

    let ready_to_write = {
        let mut state = dl_state.lock().await;
        if !state.check_and_record_seq(seq) {
            return Ok(more_data_pending);
        }

        cipher.apply_keystream(seq, session_id, ciphertext);

        let mut frame_buf = BytesMut::new();
        match ciphertext.first().copied() {
            Some(0x00) => {
                // Batched packets: [0x00, len_be16, pkt1, len_be16, pkt2, ...]
                let mut pos = 1;
                while pos + 2 <= ciphertext.len() {
                    let pkt_len =
                        u16::from_be_bytes([ciphertext[pos], ciphertext[pos + 1]]) as usize;
                    pos += 2;
                    if pos + pkt_len <= ciphertext.len() {
                        let mut pkt_vec = ciphertext[pos..pos + pkt_len].to_vec();
                        clamp_tcp_mss(&mut pkt_vec, DOH_TCP_MAX_MSS);
                        frame_packet_into(&mut frame_buf, &pkt_vec);
                        pos += pkt_len;
                    } else {
                        break;
                    }
                }
            }
            Some(0x01) => {
                // Fragmented oversized packet: [0x01, pkt_id_be16, frag_idx, total_frags, data...]
                if ciphertext.len() > 5 {
                    let pkt_id = u16::from_be_bytes([ciphertext[1], ciphertext[2]]);
                    let frag_idx = ciphertext[3];
                    let total_frags = ciphertext[4];
                    if let Some(full_pkt) =
                        state.feed_fragment(pkt_id, frag_idx, total_frags, &ciphertext[5..])
                    {
                        let mut pkt_vec = full_pkt.to_vec();
                        clamp_tcp_mss(&mut pkt_vec, DOH_TCP_MAX_MSS);
                        frame_packet_into(&mut frame_buf, &pkt_vec);
                    }
                }
            }
            Some(_) => {
                clamp_tcp_mss(ciphertext, DOH_TCP_MAX_MSS);
                frame_packet_into(&mut frame_buf, ciphertext);
            }
            None => {}
        }

        state.insert_and_drain_ordered(seq, frame_buf)
    };

    if !ready_to_write.is_empty() {
        let mut guard = tunnel_write.lock().await;
        guard
            .write_all(&ready_to_write)
            .await
            .context("Tunnel stream closed")?;
    }

    Ok(true)
}

struct ResolverPool {
    urls: Vec<String>,
    udp_targets: Vec<Option<std::net::SocketAddr>>,
    profile: BrowserProfile,
    cooldown_until_ms: Vec<AtomicU64>,
    ema_rtt_ms: Vec<AtomicU64>,
    total_sent: Vec<AtomicU64>,
    total_failed: Vec<AtomicU64>,
    cursor: AtomicUsize,
}

impl ResolverPool {
    fn new(
        urls: Vec<String>,
        udp_targets: Vec<Option<std::net::SocketAddr>>,
        profile: BrowserProfile,
    ) -> Self {
        let n = urls.len();
        let cooldown_until_ms = (0..n).map(|_| AtomicU64::new(0)).collect();
        let ema_rtt_ms = (0..n).map(|_| AtomicU64::new(120)).collect();
        let total_sent = (0..n).map(|_| AtomicU64::new(0)).collect();
        let total_failed = (0..n).map(|_| AtomicU64::new(0)).collect();
        Self {
            urls,
            udp_targets,
            profile,
            cooldown_until_ms,
            ema_rtt_ms,
            total_sent,
            total_failed,
            cursor: AtomicUsize::new(0),
        }
    }

    /// Computes a composite Least-Loss / Least-Latency score (`ema_rtt_ms * (1 + 8 * loss_rate)`).
    fn resolver_score(&self, idx: usize) -> u64 {
        let sent = self.total_sent[idx].load(Ordering::Relaxed).max(1);
        let failed = self.total_failed[idx].load(Ordering::Relaxed).min(sent);
        let rtt = self.ema_rtt_ms[idx].load(Ordering::Relaxed).clamp(10, 2000);
        let loss_permille = (failed * 1000) / sent;
        (rtt * (1000 + loss_permille * 8)) / 1000
    }

    /// Selects the next healthy resolver using BalancingLeastLoss with round-robin tie-breaking.
    fn next_healthy(&self) -> (usize, &str) {
        let n = self.urls.len();
        let now = now_epoch_ms();
        let start = self.cursor.fetch_add(1, Ordering::Relaxed);

        let mut best_idx = None;
        let mut best_score = u64::MAX;

        for offset in 0..n {
            let idx = (start + offset) % n;
            let until = self.cooldown_until_ms[idx].load(Ordering::Relaxed);
            if now >= until {
                let score = self.resolver_score(idx);
                // Allow a 25ms band for round-robin rotation among similarly performing resolvers
                if best_idx.is_none() || score + 25 < best_score {
                    best_score = score;
                    best_idx = Some(idx);
                }
            }
        }

        if let Some(idx) = best_idx {
            return (idx, &self.urls[idx]);
        }

        // All resolvers are in cooldown: pick the one whose cooldown expires soonest
        let mut fallback_idx = start % n;
        let mut best_until = u64::MAX;
        for idx in 0..n {
            let until = self.cooldown_until_ms[idx].load(Ordering::Relaxed);
            if until < best_until {
                best_until = until;
                fallback_idx = idx;
            }
        }
        (fallback_idx, &self.urls[fallback_idx])
    }

    /// Selects up to `count` distinct healthy resolvers ordered by BalancingLeastLoss score.
    fn select_distinct_healthy(&self, count: usize) -> Vec<(usize, String)> {
        let n = self.urls.len();
        let target = count.clamp(1, n.max(1));
        let now = now_epoch_ms();
        let start = self.cursor.fetch_add(1, Ordering::Relaxed);

        let mut candidates: Vec<(usize, bool, u64)> = (0..n)
            .map(|offset| {
                let idx = (start + offset) % n;
                let healthy = now >= self.cooldown_until_ms[idx].load(Ordering::Relaxed);
                let score = self.resolver_score(idx);
                (idx, healthy, score)
            })
            .collect();

        candidates.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then_with(|| (a.2 / 25).cmp(&(b.2 / 25)))
        });

        candidates
            .into_iter()
            .take(target)
            .map(|(idx, _, _)| (idx, self.urls[idx].clone()))
            .collect()
    }

    fn mark_failed(&self, idx: usize) {
        self.total_failed[idx].fetch_add(1, Ordering::Relaxed);
        let until = now_epoch_ms() + RESOLVER_COOLDOWN_MS;
        self.cooldown_until_ms[idx].store(until, Ordering::Relaxed);
    }

    fn mark_success(&self, idx: usize, rtt_ms: u64) {
        self.cooldown_until_ms[idx].store(0, Ordering::Relaxed);
        let prev = self.ema_rtt_ms[idx].load(Ordering::Relaxed);
        let updated = ((prev * 7) + rtt_ms.clamp(5, 2000)) / 8;
        self.ema_rtt_ms[idx].store(updated, Ordering::Relaxed);
    }

    /// Sends a single attempt to a specific resolver index (supporting both `doh://`/`https://` and `udp://`) and validates DNS RCODE == 0.
    async fn send_once_to_resolver(
        &self,
        client: &Client,
        idx: usize,
        resolver_url: &str,
        query_bytes: &[u8],
        attempt_timeout: Duration,
    ) -> Result<Bytes> {
        self.total_sent[idx].fetch_add(1, Ordering::Relaxed);
        let started = Instant::now();

        if let Some(udp_rest) = resolver_url.strip_prefix("udp://") {
            let pre_resolved = self.udp_targets.get(idx).copied().flatten();
            let host_port = udp_rest.trim_end_matches('/');
            let target_str = if host_port.contains(':') {
                host_port.to_string()
            } else {
                format!("{}:53", host_port)
            };

            let io_fut = async {
                let remote_addr = if let Some(addr) = pre_resolved {
                    addr
                } else {
                    let mut addrs = tokio::net::lookup_host(&target_str)
                        .await
                        .context("UDP resolver DNS lookup failed")?;
                    addrs
                        .find(|a| a.is_ipv4())
                        .or_else(|| addrs.next())
                        .context("No socket address resolved for UDP resolver")?
                };
                let bind_addr = if remote_addr.is_ipv6() {
                    "[::]:0"
                } else {
                    "0.0.0.0:0"
                };
                let sock = tokio::net::UdpSocket::bind(bind_addr).await?;
                sock.connect(remote_addr).await?;
                sock.send(query_bytes).await?;
                let mut rx_buf = vec![0u8; 2048];
                let n = sock.recv(&mut rx_buf).await?;
                rx_buf.truncate(n);
                Ok::<Vec<u8>, anyhow::Error>(rx_buf)
            };

            match tokio::time::timeout(attempt_timeout, io_fut).await {
                Ok(Ok(body)) => {
                    if body.len() >= 12 {
                        if query_bytes.len() >= 2 && body[0..2] != query_bytes[0..2] {
                            self.mark_failed(idx);
                            bail!("UDP resolver {} txid mismatch", resolver_url);
                        }
                        let rcode = u16::from_be_bytes([body[2], body[3]]) & 0x000F;
                        if rcode == 0 {
                            self.mark_success(idx, started.elapsed().as_millis() as u64);
                            return Ok(Bytes::from(body));
                        } else {
                            self.mark_failed(idx);
                            bail!("UDP resolver {} DNS RCODE {}", resolver_url, rcode);
                        }
                    } else {
                        self.mark_failed(idx);
                        bail!("UDP resolver {} short DNS body", resolver_url);
                    }
                }
                Ok(Err(e)) => {
                    self.mark_failed(idx);
                    return Err(e);
                }
                Err(_) => {
                    self.mark_failed(idx);
                    bail!("UDP resolver {} timed out", resolver_url);
                }
            }
        }

        let http_url = if let Some(rest) = resolver_url.strip_prefix("doh://") {
            format!("https://{}", rest)
        } else {
            resolver_url.to_string()
        };

        let req = self
            .profile
            .apply_to_reqwest(client.post(&http_url), None, None)
            .timeout(attempt_timeout)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(query_bytes.to_vec());

        match req.send().await {
            Ok(res) if res.status().is_success() => match res.bytes().await {
                Ok(body) => {
                    if body.len() >= 12 {
                        let rcode = u16::from_be_bytes([body[2], body[3]]) & 0x000F;
                        if rcode == 0 {
                            self.mark_success(idx, started.elapsed().as_millis() as u64);
                            Ok(body)
                        } else {
                            self.mark_failed(idx);
                            bail!("Resolver {} DNS RCODE {}", resolver_url, rcode)
                        }
                    } else {
                        self.mark_failed(idx);
                        bail!("Resolver {} short DNS body", resolver_url)
                    }
                }
                Err(e) => {
                    self.mark_failed(idx);
                    Err(anyhow::Error::from(e))
                }
            },
            Ok(res) => {
                self.mark_failed(idx);
                bail!("Resolver {} HTTP {}", resolver_url, res.status())
            }
            Err(e) => {
                self.mark_failed(idx);
                Err(anyhow::Error::from(e))
            }
        }
    }

    /// Sends `dup_count` copies of the DNS query in parallel across distinct resolvers (MasterDnsVPN-style hedging).
    /// Returns immediately as soon as the fastest copy succeeds, while any remaining in-flight copy continues in background.
    async fn send_query_hedged(
        self: &Arc<Self>,
        client: &Client,
        query_bytes: &[u8],
        attempt_timeout: Duration,
        dup_count: usize,
    ) -> Result<Bytes> {
        let targets = self.select_distinct_healthy(dup_count);
        if targets.len() <= 1 {
            return self
                .send_query_reliable(client, query_bytes, attempt_timeout)
                .await;
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<Bytes>>(targets.len());
        for (idx, url) in targets {
            let pool = self.clone();
            let c = client.clone();
            let q = query_bytes.to_vec();
            let tx_c = tx.clone();
            tokio::spawn(async move {
                let res = pool
                    .send_once_to_resolver(&c, idx, &url, &q, attempt_timeout)
                    .await;
                let _ = tx_c.send(res).await;
            });
        }
        drop(tx);

        let mut last_err = None;
        while let Some(res) = rx.recv().await {
            match res {
                Ok(body) => return Ok(body),
                Err(e) => last_err = Some(e),
            }
        }

        if let Ok(fallback) = self
            .send_query_reliable(client, query_bytes, attempt_timeout)
            .await
        {
            return Ok(fallback);
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("All hedged DoH resolvers failed")))
    }

    /// Sends a DoH DNS wire query with a fast per-attempt timeout, checking DNS RCODE and failing over across resolvers.
    async fn send_query_reliable(
        &self,
        client: &Client,
        query_bytes: &[u8],
        attempt_timeout: Duration,
    ) -> Result<Bytes> {
        let max_attempts = self.urls.len().clamp(2, 4);
        let mut last_err = None;

        for _ in 0..max_attempts {
            let (idx, resolver_url) = self.next_healthy();
            match self
                .send_once_to_resolver(client, idx, resolver_url, query_bytes, attempt_timeout)
                .await
            {
                Ok(body) => return Ok(body),
                Err(e) => {
                    debug!("[DoH] Resolver {} failed: {}", resolver_url, e);
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("All DoH resolvers failed")))
    }
}

struct DohAuthChannel {
    client: Client,
    pool: Arc<ResolverPool>,
    domain_zone: String,
    temp_session_id: u32,
    hs_seq: AtomicU32,
    max_payload: usize,
    pending_response: Mutex<Option<Bytes>>,
    dup_hs: bool,
}

#[async_trait]
impl AuthChannel for DohAuthChannel {
    async fn send(&self, data: Bytes, _frag: &FragmentConfig) -> Result<()> {
        *self.pending_response.lock().await = None;
        let seq = self.hs_seq.fetch_add(1, Ordering::Relaxed);
        let chunks = split_into_chunks(self.temp_session_id, seq, &data, self.max_payload);
        if chunks.is_empty() {
            bail!("Empty handshake payload");
        }

        let total = chunks.len();
        let hs_dup = if self.dup_hs { 3 } else { 1 };
        for (idx, chunk) in chunks.into_iter().enumerate() {
            let b32_str = base32::encode(&chunk);
            let labels = base32::split_into_labels(&b32_str, 63);
            let qname = format!(
                "hs.{:08x}.{}.{}.{}.{}",
                self.temp_session_id, idx, total, labels, self.domain_zone
            );

            let query_bytes = build_doh_query(&qname, rand::random::<u16>());

            match self
                .pool
                .send_query_hedged(&self.client, &query_bytes, Duration::from_millis(900), hs_dup)
                .await
            {
                Ok(body) => {
                    if let Some(txt_data) = parse_dns_txt_response(&body) {
                        if txt_data != b"ACK" && txt_data != b"OK" && !txt_data.starts_with(b"OK:")
                        {
                            if let Ok(decoded) = BASE64_STANDARD.decode(&txt_data) {
                                if !decoded.is_empty() {
                                    *self.pending_response.lock().await =
                                        Some(Bytes::from(decoded));
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "[DoH Auth] All resolvers failed for handshake chunk {}/{}: {}",
                        idx + 1,
                        total,
                        e
                    );
                }
            }
        }

        Ok(())
    }

    async fn recv(&self, timeout: Duration) -> Result<Bytes> {
        let deadline = tokio::time::Instant::now() + timeout;

        if let Some(resp) = self.pending_response.lock().await.take() {
            return Ok(resp);
        }

        let hs_dup = if self.dup_hs { 2 } else { 1 };
        while tokio::time::Instant::now() < deadline {
            let nonce = rand::random::<u32>();
            let qname = format!(
                "poll.{:08x}.{:08x}.{}",
                self.temp_session_id, nonce, self.domain_zone
            );
            let query_bytes = build_doh_query(&qname, rand::random::<u16>());

            if let Ok(body) = self
                .pool
                .send_query_hedged(&self.client, &query_bytes, Duration::from_millis(900), hs_dup)
                .await
            {
                if let Some(txt_data) = parse_dns_txt_response(&body) {
                    if txt_data != b"ACK" && txt_data != b"OK" && !txt_data.starts_with(b"OK:") {
                        if let Ok(decoded) = BASE64_STANDARD.decode(&txt_data) {
                            if !decoded.is_empty() {
                                return Ok(Bytes::from(decoded));
                            }
                        }
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        bail!("Handshake receive timed out over DoH")
    }
}

pub struct DohTransport {
    config: CoreConfig,
    server: ServerConfig,
}

impl DohTransport {
    pub fn new(config: CoreConfig, server: ServerConfig) -> Self {
        Self { config, server }
    }
}

#[async_trait]
impl ClientTransport for DohTransport {
    async fn connect(&self) -> Result<ConnectionResult> {
        let dsn_url = Url::parse(&self.server.dsn).context("Failed to parse DoH DSN")?;
        let domain_zone = dsn_url
            .host_str()
            .context("No domain zone in DoH DSN")?
            .to_string();

        let mut resolvers = Vec::new();
        let mut arq_enabled = true;
        let mut dup_count = 2usize;
        let mut dup_hs = true;
        let mut hold_ms = 25u64;

        for (k, v) in dsn_url.query_pairs() {
            match k.as_ref() {
                "resolver" => resolvers.push(v.into_owned()),
                "arq" => arq_enabled = v.parse().unwrap_or(true),
                "dup" => dup_count = v.parse::<usize>().unwrap_or(2).clamp(1, 3),
                "dup_hs" => dup_hs = v.parse().unwrap_or(true),
                "hold_ms" => hold_ms = v.parse().unwrap_or(25),
                _ => {}
            }
        }

        if resolvers.is_empty() {
            resolvers.push("doh://77.88.8.7/dns-query".to_string());
            resolvers.push("doh://dns.adguard-dns.com/dns-query".to_string());
        }

        info!(
            "[DoH] Initializing transport for domain '{}' via {} resolvers (ARQ: {}, Hold: {}ms)",
            domain_zone,
            resolvers.len(),
            arq_enabled,
            hold_ms
        );

        // Pre-resolve all DoH and UDP resolver hostnames BEFORE TUN setup or HTTP client creation:
        // 1. Collect IPv4 bypass IPs so RouteManager and Windows AppFilter never fail on IPv6-over-IPv4-gateway routes or hijack DoH packets.
        // 2. Pin hostname -> IPv4 SocketAddrs in reqwest and ResolverPool so runtime queries never depend on system DNS after TUN is up.
        let mut bypass_ips: Vec<std::net::IpAddr> = Vec::new();
        let mut udp_targets: Vec<Option<std::net::SocketAddr>> = Vec::with_capacity(resolvers.len());
        let mut pinned_hosts: HashMap<String, Vec<std::net::SocketAddr>> = HashMap::new();

        for res_url in &resolvers {
            let mut resolved_udp: Option<std::net::SocketAddr> = None;
            let normalized_url = if let Some(rest) = res_url.strip_prefix("doh://") {
                format!("https://{}", rest)
            } else {
                res_url.clone()
            };

            if let Ok(parsed) = Url::parse(&normalized_url) {
                if let Some(host) = parsed.host_str() {
                    let default_port = if parsed.scheme() == "udp" { 53 } else { 443 };
                    let port = parsed.port_or_known_default().unwrap_or(default_port);

                    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                        if ip.is_ipv4() && !bypass_ips.contains(&ip) {
                            bypass_ips.push(ip);
                        }
                        if parsed.scheme() == "udp" {
                            resolved_udp = Some(std::net::SocketAddr::new(ip, port));
                        }
                    } else if let Ok(addrs) = tokio::net::lookup_host((host, port)).await {
                        let all_addrs: Vec<std::net::SocketAddr> = addrs.collect();
                        let v4_addrs: Vec<std::net::SocketAddr> = all_addrs
                            .iter()
                            .copied()
                            .filter(|a| a.is_ipv4())
                            .collect();
                        let chosen = if !v4_addrs.is_empty() {
                            v4_addrs
                        } else {
                            all_addrs
                        };

                        for addr in &chosen {
                            let ip = addr.ip();
                            if ip.is_ipv4() && !bypass_ips.contains(&ip) {
                                bypass_ips.push(ip);
                            }
                        }
                        if parsed.scheme() == "udp" {
                            resolved_udp = chosen.first().copied();
                        } else if !chosen.is_empty() {
                            pinned_hosts.insert(host.to_string(), chosen);
                        }
                    }
                }
            }
            udp_targets.push(resolved_udp);
        }

        let tls_cfg = self.server.effective_tls_config(&self.config.stealth);
        anet_common::boring_tls::set_default_tls_config(tls_cfg.clone());
        let profile = BrowserProfile::with_tls_config(tls_cfg);

        let tx_cookie_jar = Arc::new(reqwest::cookie::Jar::default());
        let mut tx_builder = profile
            .build_reqwest_builder(tx_cookie_jar)
            .context("Failed to initialize BoringSSL TX client builder for DoH")?
            .pool_max_idle_per_host(32)
            .pool_idle_timeout(Some(Duration::from_secs(60)))
            .tcp_nodelay(true)
            .connect_timeout(Duration::from_millis(1000))
            .timeout(Duration::from_millis(1800))
            .http2_adaptive_window(true)
            .local_address(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

        let rx_cookie_jar = Arc::new(reqwest::cookie::Jar::default());
        let mut rx_builder = profile
            .build_reqwest_builder(rx_cookie_jar)
            .context("Failed to initialize BoringSSL RX client builder for DoH")?
            .pool_max_idle_per_host(16)
            .pool_idle_timeout(Some(Duration::from_secs(60)))
            .tcp_nodelay(true)
            .connect_timeout(Duration::from_millis(1000))
            .timeout(Duration::from_millis(1800))
            .http2_adaptive_window(true)
            .local_address(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

        for (host, addrs) in &pinned_hosts {
            tx_builder = tx_builder.resolve_to_addrs(host, addrs);
            rx_builder = rx_builder.resolve_to_addrs(host, addrs);
        }

        let tx_http_client = tx_builder
            .build()
            .context("Failed to build TX HTTP/2 client for DoH")?;

        let rx_http_client = rx_builder
            .build()
            .context("Failed to build RX HTTP/2 client for DoH")?;

        let max_payload = calculate_max_chunk_payload(&domain_zone);
        let hs_max_payload = max_payload.saturating_sub(24).max(32);
        let temp_session_id = rand::random::<u32>() | 0x80000000;

        let resolver_pool = Arc::new(ResolverPool::new(resolvers.clone(), udp_targets, profile));

        let auth_channel = DohAuthChannel {
            client: tx_http_client.clone(),
            pool: resolver_pool.clone(),
            domain_zone: domain_zone.clone(),
            temp_session_id,
            hs_seq: AtomicU32::new(0),
            max_payload: hs_max_payload,
            pending_response: Mutex::new(None),
            dup_hs,
        };

        info!("[DoH] Starting Phase I-IV ASTP handshake over DoH...");
        let auth = AuthHandler::new(&self.config, self.server.server_pub_key.as_deref())?;
        let (auth_response, shared_key) = auth.authenticate_once(&auth_channel).await?;

        let nonce_prefix_bytes: [u8; 4] = auth_response
            .nonce_prefix
            .as_slice()
            .try_into()
            .context("Invalid nonce_prefix length in AuthResponse")?;
        let session_id = u32::from_be_bytes(nonce_prefix_bytes);

        info!(
            "[DoH] Authenticated successfully. Assigned session ID: {:08x} (bypass IPs: {:?})",
            session_id, bypass_ips
        );

        let cipher = Arc::new(AstpLiteCipher::new(&shared_key));
        let sequence = Arc::new(AtomicU32::new(1));
        let health_pause = Arc::new(AtomicBool::new(false));
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let shutdown_notify = Arc::new(Notify::new());

        let (client_stream, internal_router) = tokio::io::duplex(64 * 1024);
        let (mut tunnel_read, tunnel_write) = tokio::io::split(internal_router);
        let uplink_queue = Arc::new(DohUplinkQueue::new());

        let queue_writer = uplink_queue.clone();
        let reader_shutdown_flag = shutdown_flag.clone();
        let reader_shutdown_notify = shutdown_notify.clone();
        let tunnel_reader_task = tokio::spawn(async move {
            while let Ok(Some(packet)) = read_next_packet(&mut tunnel_read).await {
                queue_writer.push(packet);
            }
            reader_shutdown_flag.store(true, Ordering::Release);
            reader_shutdown_notify.notify_waiters();
            queue_writer.close();
        });

        let tunnel_write_mutex = Arc::new(Mutex::new(tunnel_write));
        let dl_feedback = Arc::new(AtomicU64::new(0));
        let downlink_state = Arc::new(Mutex::new(DohDownlinkState::new(dl_feedback.clone())));
        let uplink_arq = Arc::new(std::sync::Mutex::new(UplinkArqState::new(arq_enabled)));
        let poll_burst_notify = Arc::new(Notify::new());

        // 1. Uplink Loop: Prioritizes ICMP/DNS/ACKs, coalesces small packets, records ARQ state, and processes piggybacked replies
        {
            let http_client = tx_http_client.clone();
            let cipher = cipher.clone();
            let sequence = sequence.clone();
            let domain_zone = domain_zone.clone();
            let pool = resolver_pool.clone();
            let uplink_q = uplink_queue.clone();
            let dl_state = downlink_state.clone();
            let ul_arq = uplink_arq.clone();
            let tunnel_write = tunnel_write_mutex.clone();
            let burst_notify = poll_burst_notify.clone();
            let tx_sem = Arc::new(Semaphore::new(28));
            let prio_sem = Arc::new(Semaphore::new(8));
            let tx_shutdown_flag = shutdown_flag.clone();
            let tx_shutdown_notify = shutdown_notify.clone();

            // Background Uplink ARQ / NACK retransmission worker (runs every 110ms)
            if arq_enabled {
                let rto_client = http_client.clone();
                let rto_cipher = cipher.clone();
                let rto_zone = domain_zone.clone();
                let rto_pool = pool.clone();
                let rto_dl = dl_state.clone();
                let rto_ul = ul_arq.clone();
                let rto_tw = tunnel_write.clone();
                let rto_burst = burst_notify.clone();
                let rto_sem = prio_sem.clone();
                let rto_shutdown_flag = shutdown_flag.clone();
                let rto_shutdown_notify = shutdown_notify.clone();

                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_millis(110)) => {}
                            _ = rto_shutdown_notify.notified() => break,
                        }
                        if rto_shutdown_flag.load(Ordering::Acquire) {
                            break;
                        }
                        let retransmits = rto_ul.lock().unwrap().collect_rto_retransmits();
                        for chunk in retransmits {
                            let b36_str = base32::encode_base36(&chunk);
                            let labels = base32::split_into_labels(&b36_str, 63);
                            let qname = format!("{}.{}", labels, rto_zone);
                            let query_bytes = build_doh_query(&qname, rand::random::<u16>());

                            let c = rto_client.clone();
                            let p = rto_pool.clone();
                            let cip = rto_cipher.clone();
                            let dl = rto_dl.clone();
                            let ul = rto_ul.clone();
                            let tw = rto_tw.clone();
                            let bn = rto_burst.clone();
                            let sem = rto_sem.clone();

                            tokio::spawn(async move {
                                let _permit = sem.try_acquire_owned().ok();
                                if let Ok(body) = p
                                    .send_query_hedged(
                                        &c,
                                        &query_bytes,
                                        Duration::from_millis(600),
                                        dup_count.max(2),
                                    )
                                    .await
                                {
                                    let _ = process_downlink_dns_body(
                                        &body,
                                        &cip,
                                        session_id,
                                        &dl,
                                        &ul,
                                        &tw,
                                        &bn,
                                    )
                                    .await;
                                }
                            });
                        }
                    }
                });
            }

            tokio::spawn(async move {
                info!("[DoH TX] Uplink dispatcher loop active (dup={})", dup_count);
                while let Some((mut packet_buf, is_prio)) = uplink_q.pop_batch(max_payload).await {
                    if tx_shutdown_flag.load(Ordering::Acquire) {
                        break;
                    }
                    let raw_seq = sequence.fetch_add(1, Ordering::Relaxed);
                    let seq = ((raw_seq - 1) % 32766) + 1;
                    cipher.apply_keystream(seq, session_id, &mut packet_buf);

                    let chunks = split_into_chunks(session_id, seq, &packet_buf, max_payload);
                    let total_chunks = chunks.len();
                    ul_arq.lock().unwrap().record_sent_packet(seq, &chunks);

                    let pkt_dup = if is_prio || total_chunks == 1 {
                        dup_count
                    } else {
                        1
                    };

                    for chunk in chunks {
                        let b36_str = base32::encode_base36(&chunk);
                        let labels = base32::split_into_labels(&b36_str, 63);
                        let qname = format!("{}.{}", labels, domain_zone);
                        let query_bytes = build_doh_query(&qname, rand::random::<u16>());

                        let client = http_client.clone();
                        let pool_clone = pool.clone();
                        let cipher_c = cipher.clone();
                        let dl_state_c = dl_state.clone();
                        let ul_arq_c = ul_arq.clone();
                        let tunnel_write_c = tunnel_write.clone();
                        let burst_notify_c = burst_notify.clone();

                        // Priority packets (ICMP probes, pings, DNS, TCP SYN/ACK) can grab from `prio_sem` immediately
                        // without waiting behind bulk traffic permits.
                        let permit = if is_prio {
                            match prio_sem.clone().try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => match tx_sem.clone().acquire_owned().await {
                                    Ok(p) => p,
                                    Err(_) => break,
                                },
                            }
                        } else {
                            match tx_sem.clone().acquire_owned().await {
                                Ok(p) => p,
                                Err(_) => break,
                            }
                        };

                        tokio::spawn(async move {
                            let _permit = permit;
                            match pool_clone
                                .send_query_hedged(
                                    &client,
                                    &query_bytes,
                                    Duration::from_millis(650),
                                    pkt_dup,
                                )
                                .await
                            {
                                Ok(body) => {
                                    let _ = process_downlink_dns_body(
                                        &body,
                                        &cipher_c,
                                        session_id,
                                        &dl_state_c,
                                        &ul_arq_c,
                                        &tunnel_write_c,
                                        &burst_notify_c,
                                    )
                                    .await;
                                }
                                Err(e) => {
                                    debug!(
                                        "[DoH TX] Uplink chunk failed across all resolvers: {}",
                                        e
                                    );
                                }
                            }
                        });
                    }
                }
                tx_shutdown_flag.store(true, Ordering::Release);
                tx_shutdown_notify.notify_waiters();
                tunnel_reader_task.abort();
                info!("[DoH TX] Uplink loop exited");
            });
        }

        // 2. Downlink Poller: Adaptive Poll Pacer with 6 concurrent poll workers and immediate MORE_DATA_PENDING burst wakeup
        {
            let poll_concurrency = 6;
            for worker_id in 0..poll_concurrency {
                let http_client = rx_http_client.clone();
                let cipher = cipher.clone();
                let domain_zone = domain_zone.clone();
                let pool = resolver_pool.clone();
                let tunnel_write = tunnel_write_mutex.clone();
                let dl_state = downlink_state.clone();
                let ul_arq = uplink_arq.clone();
                let dl_fb = dl_feedback.clone();
                let burst_notify = poll_burst_notify.clone();
                let rx_shutdown_flag = shutdown_flag.clone();
                let rx_shutdown_notify = shutdown_notify.clone();

                tokio::spawn(async move {
                    debug!("[DoH RX-{}] Adaptive poll worker initialized", worker_id);
                    let mut backoff_ms = 12;

                    loop {
                        if rx_shutdown_flag.load(Ordering::Acquire) {
                            break;
                        }

                        let fb = dl_fb.load(Ordering::Acquire);
                        let dl_ack_seq = (fb >> 16) as u32;
                        let dl_sack_mask = (fb & 0xFFFF) as u16;
                        let nonce_hex = format!("{:08x}", rand::random::<u32>());
                        let qname = format!(
                            "poll.{:08x}.{:x}.{:x}.{}.{}",
                            session_id, dl_ack_seq, dl_sack_mask, nonce_hex, domain_zone
                        );
                        let query_bytes = build_doh_query(&qname, rand::random::<u16>());

                        let query_res = tokio::select! {
                            res = pool.send_query_reliable(
                                &http_client,
                                &query_bytes,
                                Duration::from_millis(850),
                            ) => res,
                            _ = rx_shutdown_notify.notified() => break,
                        };

                        match query_res {
                            Ok(body) => {
                                backoff_ms = 12;
                                match process_downlink_dns_body(
                                    &body,
                                    &cipher,
                                    session_id,
                                    &dl_state,
                                    &ul_arq,
                                    &tunnel_write,
                                    &burst_notify,
                                )
                                .await
                                {
                                    Ok(true) => {
                                        // Received data or MORE_DATA_PENDING: immediately poll again for next batch
                                    }
                                    Ok(false) => {
                                        // Empty poll: sleep up to 12ms or wake immediately on MORE_DATA_PENDING signal
                                        tokio::select! {
                                            _ = tokio::time::sleep(Duration::from_millis(12)) => {}
                                            _ = burst_notify.notified() => {}
                                            _ = rx_shutdown_notify.notified() => break,
                                        }
                                    }
                                    Err(_) => {
                                        rx_shutdown_flag.store(true, Ordering::Release);
                                        rx_shutdown_notify.notify_waiters();
                                        warn!("[DoH RX] Tunnel stream closed; exiting poller.");
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                debug!("[DoH RX-{}] Poll request failed: {}", worker_id, e);
                                tokio::select! {
                                    _ = tokio::time::sleep(Duration::from_millis(backoff_ms)) => {}
                                    _ = rx_shutdown_notify.notified() => break,
                                }
                                backoff_ms = (backoff_ms * 2).min(250);
                            }
                        }
                    }
                    debug!("[DoH RX-{}] Poll worker exited", worker_id);
                });
            }
        }

        info!("[DoH] Transport session fully established.");

        let hook_flag = shutdown_flag.clone();
        let hook_notify = shutdown_notify.clone();
        let hook_queue = uplink_queue.clone();
        let shutdown_hook: super::ShutdownHook = Box::pin(async move {
            hook_flag.store(true, Ordering::Release);
            hook_notify.notify_waiters();
            hook_queue.close();
        });

        Ok(ConnectionResult {
            auth_response,
            vpn_stream: Box::new(client_stream),
            endpoint: None,
            connection: None,
            health_pause: Some(health_pause),
            remote_ip: None,
            bypass_ips,
            effective_mode: None,
            shutdown_hook: Some(shutdown_hook),
        })
    }
}
