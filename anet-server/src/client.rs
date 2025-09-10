use anet_common::encryption::Crypto;
use log::info;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use tokio::sync::mpsc;

pub struct Client {
    pub tx: mpsc::Sender<Vec<u8>>,
    pub crypto: Crypto,
    pub uid: String,
    pub priority: Arc<AtomicU8>,
    pub traffic_counter: Arc<AtomicU64>,
    pub last_updated: Arc<AtomicU64>,
}

impl Client {
    pub fn new(tx: mpsc::Sender<Vec<u8>>, uid: String, crypto_key: String) -> Self {
        let crypto = Crypto::new_from_key(crypto_key);

        Self {
            tx,
            crypto,
            uid,
            priority: Arc::new(AtomicU8::new(128)),
            traffic_counter: Arc::new(AtomicU64::new(0)),
            last_updated: Arc::new(AtomicU64::new(0)),
        }
    }

    pub async fn send(&self, data: Vec<u8>) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        self.traffic_counter
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        self.tx.send(data).await
    }

    pub fn update_priority(&self, current_time: u64) {
        let traffic = self.traffic_counter.load(Ordering::Relaxed);
        let time_since_update = current_time - self.last_updated.load(Ordering::Relaxed);

        if time_since_update > 10 {
            // Обновляем каждые 10 секунд
            // чем больше трафик, тем ниже приоритет
            let new_priority = if traffic > 100 * 1024 * 1024 {
                // > 100 MB
                32
            } else if traffic > 10 * 1024 * 1024 {
                // > 10 MB
                64
            } else if traffic > 1 * 1024 * 1024 {
                // > 1 MB
                128
            } else {
                255
            };
            info!("UID: {} PRIORITY: {}", self.uid, new_priority);
            self.priority.store(new_priority, Ordering::Relaxed);
            self.traffic_counter.store(0, Ordering::Relaxed);
            self.last_updated.store(current_time, Ordering::Relaxed);
        }
    }

    pub fn get_priority(&self) -> u8 {
        self.priority.load(Ordering::Relaxed)
    }
}
