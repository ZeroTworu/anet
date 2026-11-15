use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use bytes::Bytes;

const GAP_TIMEOUT: Duration = Duration::from_millis(250);

pub struct ReassemblyQueue {
    next_seq: u64,
    buffer: BTreeMap<u64, Bytes>,
    max_size: usize,
    gap_timeout: Duration,
    gap_since: Option<Instant>,
}

impl ReassemblyQueue {
    pub fn new(max_size: usize) -> Self {
        Self::with_config(max_size, 0, GAP_TIMEOUT)
    }

    pub fn with_config(max_size: usize, initial_seq: u64, gap_timeout: Duration) -> Self {
        Self {
            next_seq: initial_seq,
            buffer: BTreeMap::new(),
            max_size,
            gap_timeout,
            gap_since: None,
        }
    }

    pub fn reset(&mut self, initial_seq: u64) {
        self.next_seq = initial_seq;
        self.buffer.clear();
        self.gap_since = None;
    }

    pub fn has_gap(&self) -> bool {
        !self.buffer.is_empty()
    }

    pub fn gap_remaining(&self) -> Option<Duration> {
        if self.buffer.is_empty() {
            return None;
        }
        let since = self.gap_since?;
        Some(self.gap_timeout.saturating_sub(since.elapsed()))
    }

    pub fn flush_expired(&mut self) -> Vec<Bytes> {
        if self.buffer.is_empty() {
            return Vec::new();
        }
        self.drain_ready()
    }

    /// Вставляет один пакет с порядковым номером `seq` в очередь.
    /// Если в результате вставки образовалась непрерывная цепочка готовых к отправке пакетов,
    /// возвращает их в правильном порядке.
    pub fn insert(&mut self, seq: u64, payload: Bytes) -> Vec<Bytes> {
        if seq < self.next_seq {
            return Vec::new(); // Дубликат или старый пакет — игнорируем
        }

        self.buffer.insert(seq, payload);
        self.drain_ready()
    }

    /// Пакетная вставка нескольких пакетов за один вызов (минимизирует локи мьютекса)
    pub fn insert_batch(&mut self, packets: impl IntoIterator<Item = (u64, Bytes)>) -> Vec<Bytes> {
        for (seq, payload) in packets {
            if seq >= self.next_seq {
                self.buffer.insert(seq, payload);
            }
        }
        self.drain_ready()
    }

    fn drain_ready(&mut self) -> Vec<Bytes> {
        let mut drained = Vec::new();

        // 1. Выгребаем непрерывную цепочку от next_seq
        while let Some(packet) = self.buffer.remove(&self.next_seq) {
            drained.push(packet);
            self.next_seq = self.next_seq.saturating_add(1);
        }

        // 2. Если буфер пуст — разрыва нет, сбрасываем таймер
        if self.buffer.is_empty() {
            self.gap_since = None;
            return drained;
        }

        // 3. В буфере остались пакеты с seq > next_seq (образовалась дыра).
        // Если мы только что продвинули next_seq (drained не пуст) или дыры еще не было —
        // перезапускаем таймер ожидания потерянного/задержанного батча.
        let now = Instant::now();
        if !drained.is_empty() || self.gap_since.is_none() {
            self.gap_since = Some(now);
        }

        // 4. Защита от переполнения буфера ИЛИ зависания дыры (Head-of-Line blocking) дольше gap_timeout
        let gap_expired = self
            .gap_since
            .map(|t| now.duration_since(t) >= self.gap_timeout)
            .unwrap_or(false);

        if self.buffer.len() > self.max_size || gap_expired {
            while let Some(&oldest_seq) = self.buffer.keys().next() {
                if self.buffer.len() <= self.max_size && !gap_expired {
                    break;
                }
                // Перепрыгиваем через пропавший/опоздавший диапазон к первому доступному пакету
                self.next_seq = oldest_seq;
                while let Some(packet) = self.buffer.remove(&self.next_seq) {
                    drained.push(packet);
                    self.next_seq = self.next_seq.saturating_add(1);
                }
                if self.buffer.len() <= self.max_size {
                    break;
                }
            }
            self.gap_since = if self.buffer.is_empty() {
                None
            } else {
                Some(now)
            };
        }

        drained
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::CLIENT_SEQUENCE_START;

    #[test]
    fn custom_initial_seq_orders_without_initial_stall() {
        let mut q = ReassemblyQueue::with_config(64, CLIENT_SEQUENCE_START, Duration::from_millis(50));
        assert!(q.insert(CLIENT_SEQUENCE_START + 1, Bytes::from_static(b"second")).is_empty());
        assert!(q.has_gap());
        assert!(q.gap_remaining().is_some());

        let ready = q.insert(CLIENT_SEQUENCE_START, Bytes::from_static(b"first"));
        assert_eq!(ready, vec![Bytes::from_static(b"first"), Bytes::from_static(b"second")]);
        assert!(!q.has_gap());
        assert!(q.gap_remaining().is_none());
    }

    #[test]
    fn flush_expired_skips_gap_after_timeout() {
        let mut q = ReassemblyQueue::with_config(64, 0, Duration::from_millis(10));
        assert!(q.insert(2, Bytes::from_static(b"two")).is_empty());
        std::thread::sleep(Duration::from_millis(15));
        let flushed = q.flush_expired();
        assert_eq!(flushed, vec![Bytes::from_static(b"two")]);
        assert!(!q.has_gap());
    }
}
