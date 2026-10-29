//! Кэш динамически разрешенных IP-адресов для прямого туннелирования (Direct Split-Tunneling).
//!
//! Когда DNS-перехватчик разрешает домен с действием `Direct`, полученные A/AAAA адреса
//! заносятся в этот кэш со сроком жизни (TTL), полученным из DNS-ответа.

use anet_filter_core::RuleAction;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Максимальное количество записей в DirectIpCache для защиты от переполнения памяти (п. 10.4 ТЗ)
pub const MAX_DIRECT_IP_CACHE_ENTRIES: usize = 50_000;

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
        let expired = {
            if let Some(entry) = self.entries.get(ip) {
                if Instant::now() < entry.expires_at {
                    return Some(entry.action);
                }
                true
            } else {
                false
            }
        };
        if expired {
            self.entries.remove(ip);
        }
        None
    }

    /// Вставляет набор разрешенных IP-адресов с заданным TTL и защитой от переполнения (50 000 записей)
    pub fn insert_batch(&self, ips: &[IpAddr], action: RuleAction, ttl: Duration) {
        if self.entries.len() >= MAX_DIRECT_IP_CACHE_ENTRIES {
            self.prune_expired();
            if self.entries.len() >= MAX_DIRECT_IP_CACHE_ENTRIES {
                // Вытесняем часть старых записей при достижении верхнего лимита
                let to_remove: Vec<IpAddr> = self
                    .entries
                    .iter()
                    .take(1024)
                    .map(|kv| *kv.key())
                    .collect();
                for k in to_remove {
                    self.entries.remove(&k);
                }
            }
        }

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

    /// Очищает просроченные записи (вызывается периодически фоновым таском или при достижении лимита)
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
