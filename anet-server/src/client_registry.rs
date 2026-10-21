use crate::ip_pool::IpPool;
use crate::multikey_udp_socket::StreamSender;
use anet_common::encryption::Cipher;
use anet_common::dto::{TrafficUsageSample, BillingType};
use arc_swap::{ArcSwap, ArcSwapOption};
use bytes::Bytes;
use dashmap::DashMap;
use log::{info, warn};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use std::time::SystemTime;

fn current_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub struct ClientTransportInfo {
    pub cipher: Arc<Cipher>,
    pub sequence: Arc<AtomicU64>,
    pub assigned_ip: String,
    pub session_id: String,
    pub nonce_prefix: [u8; 4],
    pub remote_addr: ArcSwap<SocketAddr>,
    pub fingerprint: String,
    pub user_id: Option<String>,
    pub protocol: String, // "quic" | "ssh" | "vnc" | "ws"
    /// Ограничение скорости в kbps, `None` = без ограничения. Применяется
    /// eBPF-шейпером на TUN-интерфейсе (см. `crate::shaper::Shaper`).
    pub speed_limit_kbps: Option<u32>,

    pub billing_type: Option<BillingType>,
    pub group_name: Option<String>,
    pub traffic_limit: Option<i64>,
    pub traffic_consumed: Option<i64>,

    pub active_sessions: Option<i32>,
    pub allowed_sessions: Option<i32>,

    pub expires_at: Option<String>,

    /// Метка времени последней активности для сторожевого таймера
    pub last_activity: Arc<AtomicU64>,
    /// Момент создания логической сессии для честного вытеснения самой старой сессии (FIFO)
    pub created_at: u64,
}

struct TrafficCounters {
    user_id: Option<String>,
    fingerprint: String,
    protocol: String,
    rx_bytes: AtomicU64,
    tx_bytes: AtomicU64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    fn registry() -> ClientRegistry {
        ClientRegistry::new(IpPool::new(
            "10.0.0.0".parse().unwrap(),
            "255.255.255.0".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            1400,
        ))
    }

    fn client(session_id: &str, fingerprint: &str) -> Arc<ClientTransportInfo> {
        Arc::new(ClientTransportInfo {
            cipher: Arc::new(Cipher::new(&[7u8; 32])),
            sequence: Arc::new(AtomicU64::new(0)),
            assigned_ip: "10.0.0.3".to_string(),
            session_id: session_id.to_string(),
            nonce_prefix: [1, 2, 3, 4],
            remote_addr: ArcSwap::new(Arc::new("127.0.0.1:12345".parse().unwrap())),
            fingerprint: fingerprint.to_string(),
            user_id: None,
            protocol: "quic".to_string(),
            speed_limit_kbps: None,
            traffic_consumed: None,
            billing_type: None,
            group_name: None,
            traffic_limit: None,
            allowed_sessions: None,
            active_sessions: None,
            expires_at: None,
            last_activity: Arc::new(AtomicU64::new(current_timestamp_secs())),
            created_at: current_timestamp_secs(),
        })
    }

    #[tokio::test]
    async fn suspended_session_resumes_only_for_same_identity() {
        let registry = registry();
        let client = client("session-1", "fingerprint-1");
        let (router, _receiver) = mpsc::channel(1);
        registry.pre_register_client(client.clone());
        registry.finalize_client(&client.assigned_ip, router);
        registry.suspend_client(client);

        assert!(!registry.can_resume("session-1", "somebody-else"));
        assert!(
            registry
                .take_suspended("session-1", "somebody-else")
                .is_none()
        );
        assert!(registry.can_resume("session-1", "fingerprint-1"));
        let resumed = registry
            .take_suspended("session-1", "fingerprint-1")
            .expect("session must resume");
        assert_eq!(resumed.assigned_ip, "10.0.0.3");
        assert!(!registry.can_resume("session-1", "fingerprint-1"));
    }

    #[test]
    fn admission_state_can_be_changed_by_control_plane() {
        let registry = registry();
        assert!(registry.is_accepting_connections());
        registry.set_accepting_connections(false);
        assert!(!registry.is_accepting_connections());
        registry.set_accepting_connections(true);
        assert!(registry.is_accepting_connections());
    }

    #[tokio::test]
    async fn traffic_snapshot_counts_decrypted_payload_bytes() {
        let registry = registry();
        let client = client("session-traffic", "fingerprint-traffic");
        let (router, mut receiver) = mpsc::channel(1);
        registry.pre_register_client(client.clone());
        registry.finalize_client(&client.assigned_ip, router);

        registry.record_rx(&client, 120, "quic");
        registry
            .route_packet_to_client(&client.assigned_ip, Bytes::from(vec![0; 80]))
            .await;
        assert_eq!(receiver.recv().await.unwrap().len(), 80);

        let snapshot = registry.traffic_snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].rx_bytes, 120);
        assert_eq!(snapshot[0].tx_bytes, 80);
    }

    #[tokio::test]
    async fn fifo_eviction_removes_oldest_session_when_limit_reached() {
        let registry = registry();
        let mut c1 = (*client("sess-old", "fp-shared")).clone_for_test("10.0.0.3", [1, 0, 0, 1], 100);
        let mut c2 = (*client("sess-new", "fp-shared")).clone_for_test("10.0.0.4", [1, 0, 0, 2], 200);
        c1.allowed_sessions = Some(1);
        c2.allowed_sessions = Some(1);
        let c1 = Arc::new(c1);
        let c2 = Arc::new(c2);

        registry.pre_register_client(c1.clone());
        registry.pre_register_client(c2.clone());

        // Если лимит 1, вытеснение для новой сессии "sess-incoming" при лимите 2 оставит только самую свежую ("sess-new")
        let evicted = registry
            .evict_excess_sessions_for_fingerprint("fp-shared", 2, "sess-incoming")
            .await;
        assert_eq!(evicted, 1);
        assert!(!registry.is_session_active("sess-old"));
        assert!(registry.is_session_active("sess-new"));
    }
}

#[cfg(test)]
impl ClientTransportInfo {
    fn clone_for_test(&self, ip: &str, prefix: [u8; 4], created_at: u64) -> Self {
        Self {
            cipher: self.cipher.clone(),
            sequence: Arc::new(AtomicU64::new(0)),
            assigned_ip: ip.to_string(),
            session_id: self.session_id.clone(),
            nonce_prefix: prefix,
            remote_addr: ArcSwap::new(self.remote_addr.load_full()),
            fingerprint: self.fingerprint.clone(),
            user_id: self.user_id.clone(),
            protocol: self.protocol.clone(),
            speed_limit_kbps: self.speed_limit_kbps,
            billing_type: self.billing_type,
            group_name: self.group_name.clone(),
            traffic_limit: self.traffic_limit,
            traffic_consumed: self.traffic_consumed,
            active_sessions: self.active_sessions,
            allowed_sessions: self.allowed_sessions,
            expires_at: self.expires_at.clone(),
            last_activity: Arc::new(AtomicU64::new(current_timestamp_secs())),
            created_at,
        }
    }
}

struct SuspendedSession {
    client_info: Arc<ClientTransportInfo>,
    expires_at: Instant,
}

const RESUME_WINDOW: Duration = Duration::from_secs(45);

#[derive(Clone)]
pub struct ClientRegistry {
    clients_by_prefix: Arc<DashMap<[u8; 4], Arc<ClientTransportInfo>>>,
    clients_by_addr: Arc<DashMap<SocketAddr, Arc<ClientTransportInfo>>>,
    clients_by_ip: Arc<DashMap<String, Arc<ClientTransportInfo>>>,
    quic_router: Arc<DashMap<String, StreamSender>>,
    suspended_sessions: Arc<DashMap<String, SuspendedSession>>,
    ip_pool: IpPool,
    accepting_connections: Arc<AtomicBool>,
    traffic_totals: Arc<DashMap<String, Arc<TrafficCounters>>>,
    /// TUN-интерфейс появляется только после `TunManager::run()`, т.е. уже
    /// после конструирования реестра — поэтому шейпер подключается
    /// постфактум через `set_shaper`, а не передаётся в `new()`.
    ///
    /// Обёрнуто в Arc: сам ArcSwapOption НЕ реализует Clone (это lock-free
    /// примитив, клонировать его напрямую некорректно), а весь остальной
    /// ClientRegistry рассчитан на дешёвое derive(Clone) через клонирование
    /// Arc-указателей у каждого поля — держим ту же конвенцию.
    shaper: Arc<ArcSwapOption<crate::shaper::Shaper>>,
}

impl ClientRegistry {
    pub fn new(ip_pool: IpPool) -> Self {
        Self {
            clients_by_prefix: Arc::new(DashMap::new()),
            clients_by_addr: Arc::new(DashMap::new()),
            clients_by_ip: Arc::new(DashMap::new()),
            quic_router: Arc::new(DashMap::new()),
            suspended_sessions: Arc::new(DashMap::new()),
            ip_pool,
            accepting_connections: Arc::new(AtomicBool::new(true)),
            traffic_totals: Arc::new(DashMap::new()),
            shaper: Arc::new(ArcSwapOption::empty()),
        }
    }

    pub fn get_by_session(&self, session_id: &str) -> Option<Arc<ClientTransportInfo>> {
        self.clients_by_ip
            .iter()
            .find(|entry| entry.value().session_id == session_id)
            .map(|entry| entry.value().clone())
    }

    pub fn set_shaper(&self, shaper: Arc<crate::shaper::Shaper>) {
        self.shaper.store(Some(shaper));
    }

    fn apply_shaper_limit(&self, client_info: &ClientTransportInfo) {
        let (Some(shaper), Some(kbps)) = (self.shaper.load().clone(), client_info.speed_limit_kbps)
        else {
            return;
        };
        let Ok(ip) = client_info.assigned_ip.parse::<Ipv4Addr>() else {
            return;
        };
        tokio::spawn(async move {
            if let Err(e) = shaper.set_limit(ip, kbps).await {
                warn!("[Shaper] Failed to apply speed limit for {}: {}", ip, e);
            }
        });
    }

    fn clear_shaper_limit(&self, assigned_ip: &str) {
        let Some(shaper) = self.shaper.load().clone() else {
            return;
        };
        let Ok(ip) = assigned_ip.parse::<Ipv4Addr>() else {
            return;
        };
        tokio::spawn(async move {
            shaper.clear_limit(ip).await;
        });
    }

    pub fn get_network_params(&self) -> (String, String, i32) {
        (
            self.ip_pool.netmask.to_string(),
            self.ip_pool.gateway.to_string(),
            self.ip_pool.mtu as i32,
        )
    }

    pub fn active_connection_count(&self) -> usize {
        // quic_router содержит только завершённые и реально обслуживаемые
        // подключения, поэтому это значение подходит для least-connections.
        self.quic_router.len()
    }

    /// Возвращает декларативный снимок живых логических сессий по каждому fingerprint на этой ноде
    /// (включая сессии в окне короткого WebSocket-resume и время создания самой старой сессии для межнодового FIFO).
    pub fn active_session_counts(&self) -> Vec<anet_common::dto::NodeSessionCountItem> {
        let mut stats: std::collections::HashMap<String, (u32, u64)> = std::collections::HashMap::new();
        let mut seen_sessions = std::collections::HashSet::new();

        for entry in self.clients_by_ip.iter() {
            let info = entry.value();
            if !self.quic_router.contains_key(&info.assigned_ip) {
                continue;
            }
            if seen_sessions.insert(info.session_id.clone()) {
                let item = stats
                    .entry(info.fingerprint.clone())
                    .or_insert((0, info.created_at));
                item.0 += 1;
                if info.created_at < item.1 {
                    item.1 = info.created_at;
                }
            }
        }

        let now = Instant::now();
        for entry in self.suspended_sessions.iter() {
            if entry.value().expires_at > now {
                let info = &entry.value().client_info;
                if seen_sessions.insert(info.session_id.clone()) {
                    let item = stats
                        .entry(info.fingerprint.clone())
                        .or_insert((0, info.created_at));
                    item.0 += 1;
                    if info.created_at < item.1 {
                        item.1 = info.created_at;
                    }
                }
            }
        }

        stats
            .into_iter()
            .map(|(fingerprint, (count, oldest_created_at))| {
                anet_common::dto::NodeSessionCountItem {
                    fingerprint,
                    count,
                    oldest_created_at,
                }
            })
            .collect()
    }

    pub fn is_accepting_connections(&self) -> bool {
        self.accepting_connections.load(Ordering::Acquire)
    }

    pub fn set_accepting_connections(&self, accepting: bool) {
        // Admission влияет только на новые handshake; уже установленные
        // логические сессии продолжают работать и могут быть resumed.
        self.accepting_connections.store(accepting, Ordering::Release);
        info!("[ControlPlane] accepting_connections={accepting}");
    }

    pub fn record_rx(&self, client: &ClientTransportInfo, bytes: usize, protocol: &str) {
        client.last_activity.store(current_timestamp_secs(), Ordering::Relaxed);
        self.traffic_counters(client, protocol)
            .rx_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Проверяет и выселяет сессии, от которых не было входящих пакетов дольше timeout_secs
    pub async fn cleanup_inactive_clients(&self, timeout_secs: u64) {
        let now = current_timestamp_secs();
        let dead_clients: Vec<Arc<ClientTransportInfo>> = self.clients_by_ip
            .iter()
            .filter(|entry| {
                let last = entry.value().last_activity.load(Ordering::Relaxed);
                now.saturating_sub(last) > timeout_secs
            })
            .map(|entry| entry.value().clone())
            .collect();

        for client in dead_clients {
            info!(
                "[Registry] Client {} (FP: {}, proto: {}) inactive for >{}s. Evicting dead session.",
                client.assigned_ip, client.fingerprint, client.protocol, timeout_secs
            );
            self.remove_client(&client).await;
        }
    }

    pub fn traffic_snapshot(&self) -> Vec<TrafficUsageSample> {
        let active_sessions: std::collections::HashSet<String> = self.clients_by_prefix
            .iter()
            .map(|entry| format!("{}#{}", entry.value().fingerprint, entry.value().protocol))
            .collect();

        self.traffic_totals
            .iter()
            .filter(|entry| {
                let key = format!("{}#{}", entry.value().fingerprint, entry.value().protocol);
                active_sessions.contains(&key)
            })
            .map(|entry| TrafficUsageSample {
                user_id: entry.value().user_id.clone(),
                fingerprint: entry.value().fingerprint.clone(),
                rx_bytes: entry.value().rx_bytes.load(Ordering::Relaxed),
                tx_bytes: entry.value().tx_bytes.load(Ordering::Relaxed),
                protocol: Some(entry.value().protocol.clone()),
            })
            .collect()
    }

    fn traffic_counters(&self, client: &ClientTransportInfo, protocol: &str) -> Arc<TrafficCounters> {
        let key = format!("{}#{}", client.fingerprint, protocol);
        self.traffic_totals
            .entry(key)
            .or_insert_with(|| Arc::new(TrafficCounters {
                user_id: client.user_id.clone(),
                fingerprint: client.fingerprint.clone(),
                protocol: protocol.to_string(),
                rx_bytes: AtomicU64::new(0),
                tx_bytes: AtomicU64::new(0),
            }))
            .clone()
    }

    pub fn pre_register_client(&self, client_info: Arc<ClientTransportInfo>) {
        let remote_addr = **client_info.remote_addr.load();
        info!(
            "[Registry] Pre-registered client {} for address {}",
            client_info.assigned_ip, remote_addr
        );

        // Если у этого же ключа и протокола висела приостановленная (suspended) сессия,
        // которая не была возобновлена (клиент сделал полный новый handshake), закрываем её сразу,
        // чтобы она не задваивала счётчик active_session_counts.
        let stale_suspended: Vec<String> = self
            .suspended_sessions
            .iter()
            .filter(|e| {
                e.value().client_info.fingerprint == client_info.fingerprint
                    && e.value().client_info.protocol == client_info.protocol
                    && e.key() != &client_info.session_id
            })
            .map(|e| e.key().clone())
            .collect();
        for sid in stale_suspended {
            if let Some((_, suspended)) = self.suspended_sessions.remove(&sid) {
                if suspended.client_info.assigned_ip != client_info.assigned_ip {
                    if let Ok(ip_addr) = suspended.client_info.assigned_ip.parse::<Ipv4Addr>() {
                        self.ip_pool.release(ip_addr);
                    }
                    self.clear_shaper_limit(&suspended.client_info.assigned_ip);
                }
            }
        }

        // Если с этого же remote_addr (например, IP:0 за прокси в WS/AHTTP или тот же endpoint в WRTC/QUIC)
        // тот же ключ делает новый handshake, вытесняем старую сессию сразу при регистрации.
        if let Some((_, displaced)) = self.clients_by_addr.remove(&remote_addr) {
            if displaced.session_id != client_info.session_id
                && displaced.fingerprint == client_info.fingerprint
            {
                info!(
                    "[Registry] Address {} reconnect for FP {}: displacing previous session {} (IP: {})",
                    remote_addr, client_info.fingerprint, displaced.session_id, displaced.assigned_ip
                );
                self.quic_router.remove(&displaced.assigned_ip);
                self.clients_by_prefix.remove(&displaced.nonce_prefix);
                self.clients_by_ip.remove(&displaced.assigned_ip);
                if displaced.assigned_ip != client_info.assigned_ip {
                    self.clear_shaper_limit(&displaced.assigned_ip);
                    if let Ok(ip_addr) = displaced.assigned_ip.parse::<Ipv4Addr>() {
                        self.ip_pool.release(ip_addr);
                    }
                }
            } else if displaced.session_id != client_info.session_id {
                // Если по этому адресу (например, за общим NAT с port=0) был другой пользователь, не теряем его
                self.clients_by_addr.insert(remote_addr, displaced);
            }
        }

        // Если на этом же виртуальном IP (например, static_ip) висела старая сессия,
        // очищаем её маршруты и записи перед регистрацией новой.
        if let Some((_, displaced)) = self.clients_by_ip.remove(&client_info.assigned_ip) {
            if displaced.session_id != client_info.session_id {
                warn!(
                    "[Registry] IP {} was held by old session {} (FP: {}). Displacing old session.",
                    client_info.assigned_ip, displaced.session_id, displaced.fingerprint
                );
                let displaced_addr = **displaced.remote_addr.load();
                self.quic_router.remove(&displaced.assigned_ip);
                self.clients_by_prefix.remove(&displaced.nonce_prefix);
                self.clients_by_addr.remove(&displaced_addr);
            }
        }

        self.clients_by_prefix
            .insert(client_info.nonce_prefix, client_info.clone());
        self.clients_by_addr.insert(remote_addr, client_info.clone());
        self.clients_by_ip
            .insert(client_info.assigned_ip.clone(), client_info.clone());
        self.apply_shaper_limit(&client_info);
    }

    pub fn is_session_active(&self, session_id: &str) -> bool {
        self.clients_by_ip
            .iter()
            .any(|entry| entry.value().session_id == session_id)
    }

    pub fn finalize_client(&self, client_ip: &str, router_sender: StreamSender) {
        self.quic_router
            .insert(client_ip.to_string(), router_sender);
        info!(
            "[Registry] Finalized client {}. Total active clients: {}",
            client_ip,
            self.quic_router.len()
        );
    }

    fn cleanup_traffic_totals_if_no_active_sessions(&self, fingerprint: &str, protocol: &str) {
        let still_active = self.clients_by_ip.iter().any(|e| {
            e.value().fingerprint == fingerprint && e.value().protocol == protocol
        }) || self.suspended_sessions.iter().any(|e| {
            e.value().client_info.fingerprint == fingerprint
                && e.value().client_info.protocol == protocol
        });
        if !still_active {
            let key = format!("{}#{}", fingerprint, protocol);
            self.traffic_totals.remove(&key);
        }
    }

    pub async fn remove_client(&self, client_info: &ClientTransportInfo) {
        let client_ip = &client_info.assigned_ip;
        let remote_addr = **client_info.remote_addr.load();

        self.suspended_sessions.remove(&client_info.session_id);

        // АТОМАРНАЯ ЗАЩИТА: удаляем роутер и записи реестра только если текущая сессия
        // по данному IP действительно совпадает с удаляемой (защита от гонки при реконнекте/перезахвате IP).
        let is_current = self
            .clients_by_ip
            .get(client_ip)
            .is_some_and(|current| current.session_id == client_info.session_id);

        if is_current {
            self.quic_router.remove(client_ip);
            self.clients_by_prefix.remove(&client_info.nonce_prefix);
            self.clients_by_addr.remove(&remote_addr);
            self.clients_by_ip.remove(client_ip);
            self.clear_shaper_limit(client_ip);

            // Очищаем локальные счетчики трафика только если у этого ключа+протокола больше нет живых сессий
            self.cleanup_traffic_totals_if_no_active_sessions(
                &client_info.fingerprint,
                &client_info.protocol,
            );
            // Очищаем локальные счетчики трафика только если больше нет активных сессий с этим fingerprint и протоколом
            let still_has_same_fp = self.clients_by_ip.iter().any(|entry| {
                entry.value().fingerprint == client_info.fingerprint
                    && entry.value().protocol == client_info.protocol
            });
            if !still_has_same_fp {
                let key = format!("{}#{}", client_info.fingerprint, client_info.protocol);
                self.traffic_totals.remove(&key);
            }

            if let Ok(ip_addr) = client_ip.parse::<Ipv4Addr>() {
                self.ip_pool.release(ip_addr);
            }
            info!("[Registry] Client {} removed.", client_ip);
        } else {
            info!(
                "[Registry] Skip removing IP {} routes: session {} already removed or replaced",
                client_ip, client_info.session_id
            );
        }

        info!("[Registry] Client {} removed.", client_ip);
    }

    /// Находит и мгновенно вытесняет предыдущие сессии того же устройства (по fingerprint и протоколу).
    /// Используется при быстром реконнекте клиента для немедленного освобождения IP, закрытия старого роутера
    /// и предотвращения коллизий шифрования и остаточного интернет-трафика.
    /// Исключает текущую только что созданную сессию (по current_session_id), чтобы не вытеснять саму себя!
    pub async fn evict_existing_device_session(
        &self,
        fingerprint: &str,
        protocol: &str,
        current_session_id: &str,
    ) -> Option<Arc<ClientTransportInfo>> {
        let existing_list: Vec<Arc<ClientTransportInfo>> = self
            .clients_by_ip
            .iter()
            .filter(|entry| {
                entry.value().fingerprint == fingerprint
                    && entry.value().protocol == protocol
                    && entry.value().session_id != current_session_id
            })
            .map(|entry| entry.value().clone())
            .collect();

        let mut last_evicted = None;
        for old_client in existing_list {
            info!(
                "[Registry] Device reconnect detected for fingerprint {} (proto: {}). Evicting previous session with IP {}.",
                fingerprint, protocol, old_client.assigned_ip
            );
            self.remove_client(&old_client).await;
            last_evicted = Some(old_client);
        }

        last_evicted
    }

    /// FIFO-вытеснение на локальной ноде: если у данного `fingerprint` на этой ноде
    /// уже открыто `>= allowed_sessions` сессий (не считая `exclude_session_id`),
    /// принудительно закрывает самые старые сессии так, чтобы освободить слот для новой.
    pub async fn evict_excess_sessions_for_fingerprint(
        &self,
        fingerprint: &str,
        allowed_sessions: usize,
        exclude_session_id: &str,
    ) -> usize {
        if allowed_sessions == 0 {
            return 0;
        }

        let mut existing: Vec<Arc<ClientTransportInfo>> = self
            .clients_by_ip
            .iter()
            .filter(|entry| {
                entry.value().fingerprint == fingerprint
                    && entry.value().session_id != exclude_session_id
            })
            .map(|entry| entry.value().clone())
            .collect();

        if existing.len() < allowed_sessions {
            return 0;
        }

        // Сортируем по времени создания (самые старые первыми; если время совпало — по менее свежей активности)
        existing.sort_by_key(|c| (c.created_at, c.last_activity.load(Ordering::Relaxed)));

        let to_evict_count = (existing.len() + 1).saturating_sub(allowed_sessions);
        let mut evicted = 0;

        for old_client in existing.into_iter().take(to_evict_count) {
            info!(
                "[Registry/FIFO] Session limit ({}) reached for FP {}. Evicting oldest local session {} (IP: {}, proto: {}).",
                allowed_sessions, fingerprint, old_client.session_id, old_client.assigned_ip, old_client.protocol
            );
            self.remove_client(&old_client).await;
            evicted += 1;
        }

        evicted
    }

    pub fn suspend_client(&self, client_info: Arc<ClientTransportInfo>) {
        let client_ip = client_info.assigned_ip.clone();
        let remote_addr = **client_info.remote_addr.load();

        // АТОМАРНАЯ ЗАЩИТА: очищаем роутер и переводим сессию в suspended ТОЛЬКО если
        // в таблице активных клиентов сейчас действительно числится именно ЭТА сессия,
        // а не более новая (и она ещё не была вытеснена через remove_client).
        let is_current = self
            .clients_by_ip
            .get(&client_ip)
            .is_some_and(|current| current.session_id == client_info.session_id);

        if !is_current {
            info!(
                "[Registry] Skip suspending IP {}: session {} already removed or superseded",
                client_ip, client_info.session_id
            );
            return;
        }

        self.quic_router.remove(&client_ip);
        self.clients_by_prefix.remove(&client_info.nonce_prefix);
        self.clients_by_addr.remove(&remote_addr);
        self.clients_by_ip.remove(&client_ip);

        // ПРИМЕЧАНИЕ: лимит скорости намеренно НЕ снимается — плановая
        // ротация WS-сессии ожидаемо резюмируется на том же assigned_ip, и
        // держать правило в BPF-карте дешевле, чем пересоздавать его.
        self.suspended_sessions.insert(
            client_info.session_id.clone(),
            SuspendedSession {
                client_info,
                expires_at: Instant::now() + RESUME_WINDOW,
            },
        );
        info!("[Registry] Session {} suspended for WS resume", client_ip);
    }

    pub fn take_suspended(
        &self,
        session_id: &str,
        fingerprint: &str,
    ) -> Option<Arc<ClientTransportInfo>> {
        if session_id.is_empty() {
            return None;
        }
        let valid = self
            .suspended_sessions
            .get(session_id)
            .is_some_and(|entry| {
                entry.expires_at > Instant::now() && entry.client_info.fingerprint == fingerprint
            });
        if !valid {
            return None;
        }
        self.suspended_sessions
            .remove(session_id)
            .map(|(_, session)| session.client_info)
    }

    pub fn can_resume(&self, session_id: &str, fingerprint: &str) -> bool {
        !session_id.is_empty()
            && self
                .suspended_sessions
                .get(session_id)
                .is_some_and(|entry| {
                    entry.expires_at > Instant::now()
                        && entry.client_info.fingerprint == fingerprint
                })
    }

    pub async fn cleanup_suspended(&self) {
        let expired: Vec<String> = self
            .suspended_sessions
            .iter()
            .filter(|entry| entry.expires_at <= Instant::now())
            .map(|entry| entry.key().clone())
            .collect();
        for session_id in expired {
            if let Some((_, session)) = self.suspended_sessions.remove(&session_id) {
                self.finish_suspended(session.client_info).await;
            }
        }
    }

    async fn finish_suspended(&self, client_info: Arc<ClientTransportInfo>) {
        let ip_still_in_use = self
            .clients_by_ip
            .contains_key(&client_info.assigned_ip);
        if !ip_still_in_use {
            if let Ok(ip_addr) = client_info.assigned_ip.parse::<Ipv4Addr>() {
                self.ip_pool.release(ip_addr);
            }
            self.clear_shaper_limit(&client_info.assigned_ip);
        }

        // Очищаем локальные счетчики трафика только если у этого ключа+протокола больше нет живых сессий
        self.cleanup_traffic_totals_if_no_active_sessions(
            &client_info.fingerprint,
            &client_info.protocol,
        );

        info!(
            "[Registry] Suspended session {} expired",
            client_info.session_id
        );
    }

    pub fn allocate_ip(&self) -> Option<Ipv4Addr> {
        self.ip_pool.allocate()
    }

    pub fn get_by_addr(&self, remote_addr: &SocketAddr) -> Option<Arc<ClientTransportInfo>> {
        self.clients_by_addr
            .get(remote_addr)
            .map(|entry| entry.value().clone())
    }

    pub fn get_by_prefix(&self, nonce_prefix: &[u8; 4]) -> Option<Arc<ClientTransportInfo>> {
        self.clients_by_prefix
            .get(nonce_prefix)
            .map(|entry| entry.value().clone())
    }

    pub fn update_client_addr(&self, client_info: &Arc<ClientTransportInfo>, new_addr: SocketAddr) {
        // NAT rebinding is rare. Keep the common path read-only and allocation-free instead of
        // swapping a new Arc for every received QUIC datagram.
        if **client_info.remote_addr.load() == new_addr {
            return;
        }

        let old_addr_arc = client_info.remote_addr.swap(Arc::new(new_addr));
        let old_addr = *old_addr_arc;

        if old_addr == new_addr {
            return;
        }

        if let Some((_, client)) = self.clients_by_addr.remove(&old_addr) {
            self.clients_by_addr.insert(new_addr, client);
            info!(
                "[Registry] Client {} roamed from {} to {}",
                client_info.assigned_ip, old_addr, new_addr
            );
        }
    }

    pub async fn route_packet_to_client(&self, dst_ip: &str, packet: Bytes) {
        if let Some(sender) = self.quic_router.get(dst_ip) {
            let packet_len = packet.len();
            if sender.send(packet).await.is_err() {
                warn!("[Registry] Failed to route to {}: channel closed.", dst_ip);
            } else if let Some(client) = self.clients_by_ip.get(dst_ip) {
                // Извлекаем сохраненный протокол сессии из транспортной структуры
                self.traffic_counters(&client, &client.protocol)
                    .tx_bytes
                    .fetch_add(packet_len as u64, Ordering::Relaxed);
            }
        }
    }

    /// Отключает самую старую сессию пользователя с указанным `fingerprint` (FIFO).
    pub async fn disconnect_by_fingerprint(&self, fingerprint: &str) -> bool {
        let mut matching: Vec<Arc<ClientTransportInfo>> = self
            .clients_by_ip
            .iter()
            .filter(|entry| entry.value().fingerprint == fingerprint)
            .map(|entry| entry.value().clone())
            .collect();

        matching.sort_by_key(|c| (c.created_at, c.last_activity.load(Ordering::Relaxed)));

        if let Some(oldest_client) = matching.into_iter().next() {
            info!(
                "[Registry] Disconnecting oldest session {} (IP: {}, proto: {}) for fingerprint {}",
                oldest_client.session_id, oldest_client.assigned_ip, oldest_client.protocol, fingerprint
            );
            self.remove_client(&oldest_client).await;
            true
        } else {
            false
        }
    }
}
