use crate::client::Client;
use crate::utils::extract_ip_dst;
use dashmap::DashMap;
use log::{debug, error, info};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use std::{net::Ipv4Addr, sync::Arc};
use tokio::sync::mpsc;
use tokio::time::interval;

#[derive(Clone)]
pub struct Router {
    clients: Arc<DashMap<Ipv4Addr, Arc<Client>>>,
}

impl Router {
    pub fn new() -> Self {
        Self {
            clients: Arc::new(DashMap::new()),
        }
    }

    pub fn insert(&self, ip: Ipv4Addr, client: Arc<Client>) {
        info!("Connected {}", ip);
        self.clients.insert(ip, client);
    }

    pub fn remove(&self, ip: &Ipv4Addr) {
        info!("Disconnected {}", ip);
        self.clients.remove(ip);
    }

    pub fn snapshot(&self) -> Vec<(Ipv4Addr, Arc<Client>)> {
        self.clients
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect()
    }

    pub fn allocated_ips(&self) -> HashSet<Ipv4Addr> {
        let mut result = HashSet::new();

        for entry in self.clients.iter() {
            result.insert(*entry.key());
        }
        result
    }
}

pub struct PacketBatcher {
    batch_size: usize,
    batch_timeout: Duration,
}

impl PacketBatcher {
    pub fn new(batch_size: usize, batch_timeout_ms: u64) -> Self {
        Self {
            batch_size,
            batch_timeout: Duration::from_millis(batch_timeout_ms),
        }
    }

    pub async fn process_batches(&self, mut rx_from_tun: mpsc::Receiver<Vec<u8>>, router: &Router) {
        let mut batch = Vec::with_capacity(self.batch_size);
        let mut interval = interval(self.batch_timeout);
        loop {
            tokio::select! {
                biased;

                pkt = rx_from_tun.recv() => {
                    if let Some(pkt) = pkt {
                        if pkt.len() > 4 {
                            batch.push(pkt);

                            if batch.len() >= self.batch_size {
                                Self::process_batch(&batch, router).await;
                                batch.clear();
                                batch.reserve(self.batch_size);
                            }
                        }
                    }
                }
                _ = interval.tick() => {
                    if !batch.is_empty() {
                        Self::process_batch(&batch, router).await;
                        batch.clear();
                        batch.reserve(self.batch_size);
                    }

                    // Обновляем приоритеты каждые 10 секунд
                    // if last_priority_update.elapsed() > Duration::from_secs(10) {
                    //     last_priority_update = Instant::now();
                    //     Self::update_priorities(router, last_priority_update.elapsed().as_secs()).await;
                    // }
                }
            }
        }
    }

    async fn process_batch(batch: &Vec<Vec<u8>>, router: &Router) {
        let clients = router.snapshot();
        let client_map: HashMap<Ipv4Addr, Arc<Client>> = clients.into_iter().collect();
        for pkt in batch {
            if let Some(dst) = extract_ip_dst(&pkt) {
                if let Some(client_tx) = client_map.get(&dst) {
                    if let Err(e) = client_tx.send(pkt.to_vec()).await {
                        error!("Route to {dst} present but send failed: {e}");
                    }
                } else {
                    debug!("No route for dst {dst}");
                }
            } else {
                debug!("Non-IPv4 or too-short packet from TLS, dropped");
            }
        }
    }
}
