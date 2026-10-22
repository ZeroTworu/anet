use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use bytes::Bytes;

const GAP_TIMEOUT: Duration = Duration::from_millis(30);

pub struct ReassemblyQueue {
    next_seq: u64,
    buffer: BTreeMap<u64, Bytes>,
    max_size: usize,
    gap_since: Option<Instant>,
}

impl ReassemblyQueue {
    pub fn new(max_size: usize) -> Self {
        Self {
            next_seq: 0,
            buffer: BTreeMap::new(),
            max_size,
            gap_since: None,
        }
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
            self.next_seq += 1;
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

        // 4. Защита от переполнения буфера ИЛИ зависания дыры (Head-of-Line blocking) дольше GAP_TIMEOUT
        let gap_expired = self
            .gap_since
            .map(|t| now.duration_since(t) >= GAP_TIMEOUT)
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
                    self.next_seq += 1;
                }
                break;
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

