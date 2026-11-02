use bytes::Bytes;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Коалесцер пакетов для IMAP, JVB DataChannel и Colibri-WS.
/// Агрегирует несколько IP-пакетов в единый буфер формата:
/// [Len 1: u16 BE][Packet 1][Len 2: u16 BE][Packet 2]...
/// Позволяет снизить PPS с 5000+ до ~200-300 msg/sec и строго соблюдает верхний лимит `max_batch_bytes`.
pub struct PacketBatcher {
    queue: VecDeque<Bytes>,
    current_bytes: usize,
    max_batch_bytes: usize,
    max_delay: Duration,
    first_packet_time: Option<Instant>,
}

impl PacketBatcher {
    pub fn new(max_batch_bytes: usize, max_delay_ms: u64) -> Self {
        Self {
            queue: VecDeque::new(),
            current_bytes: 0,
            max_batch_bytes,
            max_delay: Duration::from_millis(max_delay_ms),
            first_packet_time: None,
        }
    }

    pub fn push(&mut self, packet: Bytes) {
        if self.first_packet_time.is_none() {
            self.first_packet_time = Some(Instant::now());
        }
        self.current_bytes += packet.len() + 2;
        self.queue.push_back(packet);
    }

    pub fn should_flush(&self) -> bool {
        if self.queue.is_empty() {
            return false;
        }
        if self.current_bytes >= self.max_batch_bytes {
            return true;
        }
        if let Some(t) = self.first_packet_time {
            if t.elapsed() >= self.max_delay {
                return true;
            }
        }
        false
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn current_bytes(&self) -> usize {
        self.current_bytes
    }

    /// Собрать накопившиеся пакеты в единый агрегированный буфер,
    /// строго не превышающий `max_batch_bytes` (за исключением случая одного пакета > max_batch_bytes).
    pub fn flush(&mut self) -> Option<Vec<u8>> {
        if self.queue.is_empty() {
            return None;
        }

        let mut out = Vec::with_capacity(self.current_bytes.min(self.max_batch_bytes + 2048));
        while let Some(pkt) = self.queue.front() {
            let entry_len = 2 + pkt.len();
            if !out.is_empty() && out.len() + entry_len > self.max_batch_bytes {
                break;
            }
            let pkt = self.queue.pop_front().unwrap();
            self.current_bytes = self.current_bytes.saturating_sub(entry_len);
            let len = pkt.len() as u16;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&pkt);
        }

        if self.queue.is_empty() {
            self.current_bytes = 0;
            self.first_packet_time = None;
        } else {
            self.first_packet_time = Some(Instant::now());
        }
        Some(out)
    }
}

/// Распаковать агрегированный буфер батча на отдельные пакеты.
pub fn unpack_batch(data: &[u8]) -> Vec<Bytes> {
    let mut packets = Vec::new();
    let mut offset = 0;
    while offset + 2 <= data.len() {
        let len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if len > 0 && offset + len <= data.len() {
            packets.push(Bytes::copy_from_slice(&data[offset..offset + len]));
            offset += len;
        } else {
            break;
        }
    }
    packets
}
