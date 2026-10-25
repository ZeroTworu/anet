use bytes::{BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const DOH_HEADER_LEN: usize = 10;
pub const MAX_DNS_FQDN_LEN: usize = 253;
pub const MAX_DNS_LABEL_LEN: usize = 63;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DohChunkHeader {
    pub session_id: u32,
    pub sequence: u32,
    pub chunk_index: u8,
    pub total_chunks: u8,
}

impl DohChunkHeader {
    pub fn encode(&self) -> [u8; DOH_HEADER_LEN] {
        let mut buf = [0u8; DOH_HEADER_LEN];
        buf[0..4].copy_from_slice(&self.session_id.to_be_bytes());
        buf[4..8].copy_from_slice(&self.sequence.to_be_bytes());
        buf[8] = self.chunk_index;
        buf[9] = self.total_chunks;
        buf
    }

    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() < DOH_HEADER_LEN {
            anyhow::bail!("Buffer too short for DohChunkHeader: {} < {}", bytes.len(), DOH_HEADER_LEN);
        }
        let session_id = u32::from_be_bytes(bytes[0..4].try_into()?);
        let sequence = u32::from_be_bytes(bytes[4..8].try_into()?);
        let chunk_index = bytes[8];
        let total_chunks = bytes[9];

        if total_chunks == 0 || chunk_index >= total_chunks {
            anyhow::bail!("Invalid chunk indexing: index {} / total {}", chunk_index, total_chunks);
        }

        Ok(Self {
            session_id,
            sequence,
            chunk_index,
            total_chunks,
        })
    }
}

/// Dynamically calculates the maximum payload bytes that fit inside a single Base32 DNS chunk,
/// ensuring the fully-qualified domain name stays strictly below 253 bytes.
pub fn calculate_max_chunk_payload(domain_zone: &str) -> usize {
    let clean_zone = domain_zone.trim_start_matches('.');
    // 1 dot for root separator + zone length
    let zone_overhead = clean_zone.len() + 1;
    let max_base32_chars = MAX_DNS_FQDN_LEN.saturating_sub(zone_overhead + 6); // margin for dots every 63 chars

    // Base32: 5 bits per char => bytes = chars * 5 / 8
    let max_raw_bytes = (max_base32_chars * 5) / 8;
    // Minus 10 bytes of DohChunkHeader
    max_raw_bytes.saturating_sub(DOH_HEADER_LEN).clamp(32, 135)
}

/// Splits a raw IP packet (or payload) into chunk buffers ready for Base32 encoding.
pub fn split_into_chunks(session_id: u32, sequence: u32, payload: &[u8], max_payload_per_chunk: usize) -> Vec<Vec<u8>> {
    let chunk_size = max_payload_per_chunk.max(32);
    let total_chunks = ((payload.len() + chunk_size - 1) / chunk_size).max(1);

    if total_chunks > 255 {
        // Fallback safety cap
        return vec![];
    }

    let total_u8 = total_chunks as u8;
    let mut chunks = Vec::with_capacity(total_chunks);

    for idx in 0..total_chunks {
        let start = idx * chunk_size;
        let end = (start + chunk_size).min(payload.len());
        let slice = if start < payload.len() { &payload[start..end] } else { &[] };

        let header = DohChunkHeader {
            session_id,
            sequence,
            chunk_index: idx as u8,
            total_chunks: total_u8,
        };

        let mut chunk_buf = Vec::with_capacity(DOH_HEADER_LEN + slice.len());
        chunk_buf.extend_from_slice(&header.encode());
        chunk_buf.extend_from_slice(slice);
        chunks.push(chunk_buf);
    }

    chunks
}

struct PartialPacket {
    total_chunks: u8,
    received_count: u8,
    chunks: Vec<Option<Bytes>>,
    created_at: Instant,
}

/// Reassembly queue for multi-chunk DNS packets with selective repeat tracking and deduplication.
pub struct DohReassemblyQueue {
    packets: HashMap<(u32, u32), PartialPacket>,
    completed: HashMap<(u32, u32), Instant>,
    timeout: Duration,
}

impl DohReassemblyQueue {
    pub fn new(timeout: Duration) -> Self {
        Self {
            packets: HashMap::new(),
            completed: HashMap::new(),
            timeout,
        }
    }

    /// Feeds an incoming raw chunk (header + chunk data).
    /// Returns `Some((session_id, sequence, full_payload))` if the packet is now fully assembled.
    pub fn feed(&mut self, chunk_raw: &[u8]) -> anyhow::Result<Option<(u32, u32, Bytes)>> {
        let header = DohChunkHeader::decode(chunk_raw)?;
        let key = (header.session_id, header.sequence);

        // Ignore duplicate chunks for packets that were already reassembled recently
        if self.completed.contains_key(&key) {
            return Ok(None);
        }

        let payload = Bytes::copy_from_slice(&chunk_raw[DOH_HEADER_LEN..]);

        let entry = self.packets.entry(key).or_insert_with(|| PartialPacket {
            total_chunks: header.total_chunks,
            received_count: 0,
            chunks: vec![None; header.total_chunks as usize],
            created_at: Instant::now(),
        });

        let idx = header.chunk_index as usize;
        if idx < entry.chunks.len() && entry.chunks[idx].is_none() {
            entry.chunks[idx] = Some(payload);
            entry.received_count += 1;
        }

        if entry.received_count == entry.total_chunks {
            let completed = self.packets.remove(&key).unwrap();
            self.completed.insert(key, Instant::now());
            let mut assembled = BytesMut::new();
            for chunk_opt in completed.chunks {
                if let Some(c) = chunk_opt {
                    assembled.put(c);
                }
            }
            return Ok(Some((header.session_id, header.sequence, assembled.freeze())));
        }

        Ok(None)
    }

    /// Garbage-collects incomplete packets and completed deduplication entries older than the configured timeout.
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        let timeout = self.timeout;
        self.packets.retain(|_, v| now.duration_since(v.created_at) <= timeout);
        self.completed.retain(|_, created_at| now.duration_since(*created_at) <= timeout);
    }

    /// Returns a list of missing chunk indices for a specific in-progress packet (used for Selective Repeat ARQ).
    pub fn missing_chunks(&self, session_id: u32, sequence: u32) -> Option<Vec<u8>> {
        self.packets.get(&(session_id, sequence)).map(|p| {
            p.chunks
                .iter()
                .enumerate()
                .filter_map(|(i, c)| if c.is_none() { Some(i as u8) } else { None })
                .collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunking_and_reassembly() {
        let session_id = 0xA1B2C3D4;
        let sequence = 42;
        let payload = vec![0xAB; 300]; // 300 bytes

        let chunks = split_into_chunks(session_id, sequence, &payload, 100);
        assert_eq!(chunks.len(), 3);

        let mut queue = DohReassemblyQueue::new(Duration::from_secs(5));

        // Feed chunks 0 and 2 first (out of order)
        let r0 = queue.feed(&chunks[0]).unwrap();
        assert!(r0.is_none());

        let r2 = queue.feed(&chunks[2]).unwrap();
        assert!(r2.is_none());

        // Check missing chunks
        let missing = queue.missing_chunks(session_id, sequence).unwrap();
        assert_eq!(missing, vec![1]);

        // Feed missing chunk 1
        let r1 = queue.feed(&chunks[1]).unwrap();
        assert!(r1.is_some());

        let (sid, seq, full) = r1.unwrap();
        assert_eq!(sid, session_id);
        assert_eq!(seq, sequence);
        assert_eq!(full.as_ref(), payload.as_slice());

        // Feeding duplicate chunks after completion must be ignored
        assert!(queue.feed(&chunks[1]).unwrap().is_none());
        assert!(queue.feed(&chunks[0]).unwrap().is_none());
    }
}
