//! Карта соответствия сетевого сокета процессу.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::RwLock as AsyncRwLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub protocol: u8,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
}

impl FlowKey {
    pub fn new(
        protocol: u8,
        local_addr: IpAddr,
        local_port: u16,
        remote_addr: IpAddr,
        remote_port: u16,
    ) -> Self {
        Self { protocol, local_addr, local_port, remote_addr, remote_port }
    }
}

/// Сведения о процессе, владеющем сокетом.
#[derive(Clone, Debug)]
pub struct FlowOwner {
    pub process_id: u32,
    pub image_name: Option<Arc<str>>,
}

#[derive(Clone, Default)]
pub struct FlowMap {
    /// 5-tuple карта для TCP и connected UDP
    inner: Arc<DashMap<FlowKey, FlowOwner>>,
    /// Порт-карта для connectionless UDP (sendto без connect)
    udp_ports: Arc<DashMap<u16, FlowOwner>>,
}

impl FlowMap {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
            udp_ports: Arc::new(DashMap::new()),
        }
    }

    pub fn insert(&self, key: FlowKey, owner: FlowOwner) {
        self.inner.insert(key, owner);
    }

    /// Регистрация UDP порта из SocketBind
    pub fn insert_udp_port(&self, port: u16, owner: FlowOwner) {
        self.udp_ports.insert(port, owner);
    }

    pub fn remove(&self, key: &FlowKey) {
        self.inner.remove(key);
    }

    /// Удаление UDP порта при SocketClose
    pub fn remove_udp_port(&self, port: u16) {
        self.udp_ports.remove(&port);
    }

    /// Поиск: сначала по 5-tuple, а для UDP (17) — fallback по local_port
    pub fn lookup(&self, key: &FlowKey) -> Option<FlowOwner> {
        if let Some(owner) = self.inner.get(key) {
            return Some(owner.clone());
        }

        if key.protocol == 17 {
            if let Some(owner) = self.udp_ports.get(&key.local_port) {
                return Some(owner.clone());
            }
        }

        None
    }

    pub fn len(&self) -> usize {
        self.inner.len() + self.udp_ports.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty() && self.udp_ports.is_empty()
    }
}

#[derive(Clone, Default)]
pub struct BypassSet {
    inner: Arc<AsyncRwLock<HashSet<IpAddr>>>,
}

impl BypassSet {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AsyncRwLock::new(HashSet::new())),
        }
    }

    pub fn with_initial(ips: impl IntoIterator<Item = IpAddr>) -> Self {
        Self {
            inner: Arc::new(AsyncRwLock::new(ips.into_iter().collect())),
        }
    }

    pub async fn add(&self, ip: IpAddr) {
        self.inner.write().await.insert(ip);
    }

    pub fn contains_blocking(&self, ip: &IpAddr) -> bool {
        self.inner.blocking_read().contains(ip)
    }
}