//! Кэш динамически разрешенных IP-адресов для прямого туннелирования (Direct Split-Tunneling).
//!
//! Когда DNS-перехватчик разрешает домен с действием `Direct`, полученные A/AAAA адреса
//! заносятся в этот кэш со сроком жизни (TTL), полученным из DNS-ответа.

use anet_filter_core::RuleAction;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub action: RuleAction,
    pub expires_at: Instant,
}

/// Потокобезопасный кэш динамических IP-адресов с автоматическим вытеснением по TTL
#[derive(Clone, Debug, Default)]
pub struct DirectIpCache {
    entries: Arc<DashMap<IpAddr, CacheEntry>>,
}

impl DirectIpCache {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
        }
    }

    /// Проверяет наличие IP в кэше и валидность TTL
    pub fn check(&self, ip: &IpAddr) -> Option<RuleAction> {
        if let Some(entry) = self.entries.get(ip) {
            if Instant::now() < entry.expires_at {
                return Some(entry.action);
            } else {
                drop(entry);
                self.entries.remove(ip);
            }
        }
        None
    }

    /// Вставляет набор разрешенных IP-адресов с заданным TTL
    pub fn insert_batch(&self, ips: &[IpAddr], action: RuleAction, ttl: Duration) {
        let ttl_capped = ttl.clamp(Duration::from_secs(10), Duration::from_secs(86400));
        let expires_at = Instant::now() + ttl_capped;

        for ip in ips {
            self.entries.insert(
                *ip,
                CacheEntry {
                    action,
                    expires_at,
                },
            );
        }
    }

    /// Очищает просроченные записи (вызывается периодически фоновым таском)
    pub fn prune_expired(&self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| entry.expires_at > now);
    }

    /// Текущее количество активных записей в кэше
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
