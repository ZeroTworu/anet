use bytes::Bytes;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Определяет, является ли IP-пакет высокоприоритетным интерактивным трафиком
/// (ICMP-пинги и внутритуннельные зонды, DNS UDP/TCP :53, TCP SYN/FIN/RST/ACK и малые кадры <= 256 байт,
/// такие как управляющий сокет iperf3 и сообщения Telegram MTProto).
#[inline]
pub fn is_priority_ip_packet(pkt: &[u8]) -> bool {
    if pkt.len() < 20 {
        return true;
    }
    let version = pkt[0] >> 4;
    if version == 4 {
        let proto = pkt[9];
        // ICMP (1) — всегда максимальный приоритет
        if proto == 1 {
            return true;
        }
        // Любые малые интерактивные пакеты (TCP ACK, мелкие кадры Telegram/SSH/DNS)
        if pkt.len() <= 256 {
            return true;
        }
        let ihl = ((pkt[0] & 0x0f) as usize) * 4;
        if proto == 17 && pkt.len() >= ihl + 4 {
            let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
            let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
            if src_port == 53 || dst_port == 53 || src_port == 853 || dst_port == 853 {
                return true;
            }
        } else if proto == 6 && pkt.len() >= ihl + 14 {
            let flags = pkt[ihl + 13];
            // SYN (0x02), FIN (0x01), RST (0x04)
            if (flags & 0x07) != 0 {
                return true;
            }
        }
        false
    } else if version == 6 && pkt.len() >= 40 {
        let next_hdr = pkt[6];
        // ICMPv6 (58) или малый пакет <= 256 байт
        next_hdr == 58 || pkt.len() <= 256
    } else {
        false
    }
}

/// Коалесцер пакетов для IMAP, JVB DataChannel и Colibri-WS.
/// Агрегирует несколько IP-пакетов в единый буфер формата:
/// [Len 1: u16 BE][Packet 1][Len 2: u16 BE][Packet 2]...
/// Поддерживает двухполосную приоритизацию (Fast-Lane `prio_queue` + `queue`),
/// чтобы ICMP, DNS, TCP SYN/ACK и мелкие пакеты никогда не ждали позади bulk-трафика.
pub struct PacketBatcher {
    prio_queue: VecDeque<Bytes>,
    queue: VecDeque<Bytes>,
    current_bytes: usize,
    bulk_bytes: usize,
    max_batch_bytes: usize,
    max_bulk_bytes: usize,
    max_delay: Duration,
    first_packet_time: Option<Instant>,
}

impl PacketBatcher {
    pub fn new(max_batch_bytes: usize, max_delay_ms: u64) -> Self {
        let max_bulk_bytes = (max_batch_bytes.saturating_mul(2)).max(64 * 1024);
        Self {
            prio_queue: VecDeque::new(),
            queue: VecDeque::new(),
            current_bytes: 0,
            bulk_bytes: 0,
            max_batch_bytes,
            max_bulk_bytes,
            max_delay: Duration::from_millis(max_delay_ms),
            first_packet_time: None,
        }
    }

    /// Классифицирует IP-пакет и помещает его либо в приоритетную, либо в основную очередь.
    #[inline]
    pub fn push(&mut self, packet: Bytes) {
        if is_priority_ip_packet(&packet) {
            self.push_priority(packet);
        } else {
            self.push_bulk(packet);
        }
    }

    #[inline]
    pub fn push_priority(&mut self, packet: Bytes) {
        if self.first_packet_time.is_none() {
            self.first_packet_time = Some(Instant::now());
        }
        self.current_bytes += packet.len() + 2;
        self.prio_queue.push_back(packet);
    }

    #[inline]
    pub fn push_bulk(&mut self, packet: Bytes) {
        if self.first_packet_time.is_none() {
            self.first_packet_time = Some(Instant::now());
        }
        let entry_len = packet.len() + 2;
        self.current_bytes += entry_len;
        self.bulk_bytes += entry_len;
        self.queue.push_back(packet);

        // Активное управление очередью (Head-Drop AQM): не допускаем накопления многомегабайтного
        // Bufferbloat в очереди bulk-трафика, сохраняя свежие сегменты и мгновенно сигнализируя
        // TCP Congestion Control (3 DupACK / Fast Retransmit вместо многосекундного RTO-таймаута).
        while self.bulk_bytes > self.max_bulk_bytes && self.queue.len() > 1 {
            if let Some(dropped) = self.queue.pop_front() {
                let dropped_len = dropped.len() + 2;
                self.current_bytes = self.current_bytes.saturating_sub(dropped_len);
                self.bulk_bytes = self.bulk_bytes.saturating_sub(dropped_len);
            } else {
                break;
            }
        }
    }

    pub fn should_flush(&self) -> bool {
        if self.is_empty() {
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
        self.prio_queue.is_empty() && self.queue.is_empty()
    }

    pub fn has_priority(&self) -> bool {
        !self.prio_queue.is_empty()
    }

    pub fn current_bytes(&self) -> usize {
        self.current_bytes
    }

    /// Собрать накопившиеся пакеты в единый агрегированный буфер,
    /// строго не превышающий `max_batch_bytes` (за исключением случая одного пакета > max_batch_bytes).
    /// Приоритетные пакеты из `prio_queue` всегда упаковываются первыми.
    pub fn flush(&mut self) -> Option<Vec<u8>> {
        if self.is_empty() {
            return None;
        }

        let mut out = Vec::with_capacity(self.current_bytes.min(self.max_batch_bytes + 2048));

        while let Some(pkt) = self.prio_queue.front() {
            let entry_len = 2 + pkt.len();
            if !out.is_empty() && out.len() + entry_len > self.max_batch_bytes {
                break;
            }
            let pkt = self.prio_queue.pop_front().unwrap();
            self.current_bytes = self.current_bytes.saturating_sub(entry_len);
            let len = pkt.len() as u16;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&pkt);
        }

        while let Some(pkt) = self.queue.front() {
            let entry_len = 2 + pkt.len();
            if !out.is_empty() && out.len() + entry_len > self.max_batch_bytes {
                break;
            }
            let pkt = self.queue.pop_front().unwrap();
            self.current_bytes = self.current_bytes.saturating_sub(entry_len);
            self.bulk_bytes = self.bulk_bytes.saturating_sub(entry_len);
            let len = pkt.len() as u16;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&pkt);
        }

        if self.is_empty() {
            self.current_bytes = 0;
            self.bulk_bytes = 0;
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
