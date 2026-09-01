use std::collections::BTreeMap;
use bytes::Bytes;

pub struct ReassemblyQueue {
    next_seq: u64,
    buffer: BTreeMap<u64, Bytes>,
    max_size: usize,
}

impl ReassemblyQueue {
    pub fn new(max_size: usize) -> Self {
        Self {
            next_seq: 0,
            buffer: BTreeMap::new(),
            max_size,
        }
    }

    /// Вставляет пакет с порядковым номером `seq` в очередь.
    /// Если в результате вставки образовалась непрерывная цепочка готовых к отправке пакетов,
    /// возвращает их в правильном порядке.
    pub fn insert(&mut self, seq: u64, payload: Bytes) -> Vec<Bytes> {
        if seq < self.next_seq {
            return Vec::new(); // Дубликат или старый пакет — игнорируем
        }

        self.buffer.insert(seq, payload);

        // Ограничиваем размер буфера
        if self.buffer.len() > self.max_size {
            if let Some(&oldest_seq) = self.buffer.keys().next() {
                self.buffer.remove(&oldest_seq);
                self.next_seq = oldest_seq + 1;
            }
        }

        let mut drained = Vec::new();
        while let Some(packet) = self.buffer.remove(&self.next_seq) {
            drained.push(packet);
            self.next_seq += 1;
        }
        drained
    }
}
