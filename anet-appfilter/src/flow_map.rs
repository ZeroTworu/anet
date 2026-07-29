//! Карта соответствия сетевого потока процессу.
//!
//! Идея (как в Outpost/Mullvad split-tunnel): сам IP-пакет не содержит
//! информации о процессе, но ОС знает, какому процессу принадлежит сокет.
//! WinDivert на Flow-слое присылает события FlowEstablished / FlowDeleted
//! с готовым `process_id` и 5-tuple. Мы держим карту `5-tuple -> процесс`
//! и на Network-слое по этому ключу решаем: заворачивать пакет в туннель
//! или выпускать напрямую.

//! Карта соответствия сетевого сокета процессу.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::RwLock as AsyncRwLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub protocol: u8,
    pub local_port: u16,
}

impl FlowKey {
    pub fn new(protocol: u8, local_port: u16) -> Self {
        Self {
            protocol,
            local_port,
        }
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
    inner: Arc<DashMap<FlowKey, FlowOwner>>,
}

impl FlowMap {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    pub fn insert(&self, key: FlowKey, owner: FlowOwner) {
        self.inner.insert(key, owner);
    }

    pub fn remove(&self, key: &FlowKey) {
        self.inner.remove(key);
    }

    pub fn lookup(&self, key: &FlowKey) -> Option<FlowOwner> {
        self.inner.get(key).map(|v| v.clone())
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
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
