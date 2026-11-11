use crate::events::{AnetEvent, emit};
use anet_common::config::ConnectivityConfig;
use anet_common::connectivity::{ConnectivityProber, ConnectivitySnapshot};
use anet_common::probe_nodes::{
    DEFAULT_PROBE_TIMEOUT_MS, NodeProbeSnapshot, ProbeTarget, build_initial_snapshot,
    extract_probe_targets_from_toml, probe_targets_with_progress,
};
use log::debug;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::Notify;

const NO_RTT_MARKER: u64 = u64::MAX;
const NODE_PROBE_CONNECTED_INTERVAL_SECS: u64 = 30 * 60;
const NODE_PROBE_DISCONNECTED_INTERVAL_SECS: u64 = 180;

pub struct NodeProbeMonitor {
    targets: Mutex<Vec<ProbeTarget>>,
    config_hash: AtomicU64,
    vpn_connected: AtomicBool,
    last_snapshot: Mutex<NodeProbeSnapshot>,
    wake_notify: Notify,
    task_running: AtomicBool,
    runtime_handle: Mutex<Option<tokio::runtime::Handle>>,
}

static GLOBAL_NODE_PROBE_MONITOR: OnceLock<Arc<NodeProbeMonitor>> = OnceLock::new();

impl NodeProbeMonitor {
    fn new() -> Self {
        Self {
            targets: Mutex::new(Vec::new()),
            config_hash: AtomicU64::new(0),
            vpn_connected: AtomicBool::new(false),
            last_snapshot: Mutex::new(NodeProbeSnapshot::default()),
            wake_notify: Notify::new(),
            task_running: AtomicBool::new(false),
            runtime_handle: Mutex::new(tokio::runtime::Handle::try_current().ok()),
        }
    }

    pub fn global() -> Arc<Self> {
        let mon = GLOBAL_NODE_PROBE_MONITOR
            .get_or_init(|| Arc::new(Self::new()))
            .clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let mut guard = mon.runtime_handle.lock().unwrap();
            if guard.is_none() {
                *guard = Some(handle);
            }
        }
        mon
    }

    pub fn set_runtime_handle(handle: tokio::runtime::Handle) {
        let mon = Self::global();
        *mon.runtime_handle.lock().unwrap() = Some(handle);
    }

    /// Извлекает список всех `[[servers]]` из сырого TOML-конфига и немедленно запускает
    /// быстрый параллельный опрос реальной доступности нод и протоколов.
    pub fn update_config_toml(raw_toml: &str) {
        let monitor = Self::global();
        let targets = extract_probe_targets_from_toml(raw_toml);

        let mut hasher = DefaultHasher::new();
        targets.len().hash(&mut hasher);
        for t in &targets {
            t.endpoint_index.hash(&mut hasher);
            t.group_id.hash(&mut hasher);
            t.group_name.hash(&mut hasher);
            t.server_name.hash(&mut hasher);
            t.dsn.hash(&mut hasher);
            t.host_port.hash(&mut hasher);
            t.protocol.hash(&mut hasher);
        }
        let new_hash = hasher.finish();

        let prev_hash = monitor.config_hash.swap(new_hash, Ordering::SeqCst);

        let should_reprobe = {
            let mut guard = monitor.targets.lock().unwrap();
            let changed = prev_hash != new_hash || guard.len() != targets.len();
            *guard = targets.clone();
            changed
        };

        if !should_reprobe {
            let snap = monitor.last_snapshot.lock().unwrap().clone();
            if !snap.groups.is_empty() {
                emit(AnetEvent::NodeProbeUpdated(snap));
                return;
            }
        }

        let init_snap = build_initial_snapshot(&targets);
        {
            *monitor.last_snapshot.lock().unwrap() = init_snap.clone();
        }
        emit(AnetEvent::NodeProbeUpdated(init_snap));

        if targets.is_empty() {
            return;
        }

        Self::spawn_or_wake(&monitor);
    }

    pub fn set_vpn_connected(connected: bool) {
        let monitor = Self::global();
        monitor.vpn_connected.store(connected, Ordering::SeqCst);
    }

    pub fn trigger_probe_now() {
        let monitor = Self::global();
        let targets = monitor.targets.lock().unwrap().clone();
        if targets.is_empty() {
            return;
        }
        let checking_snap = {
            let mut guard = monitor.last_snapshot.lock().unwrap();
            if guard.groups.is_empty() {
                let s = build_initial_snapshot(&targets);
                *guard = s.clone();
                s
            } else {
                guard.is_checking = true;
                guard.completed_endpoints = 0;
                guard.total_endpoints = targets.len();
                guard.clone()
            }
        };
        emit(AnetEvent::NodeProbeUpdated(checking_snap));
        Self::spawn_or_wake(&monitor);
    }

    pub fn get_last_snapshot() -> NodeProbeSnapshot {
        Self::global().last_snapshot.lock().unwrap().clone()
    }

    /// Возвращает все хосты и порты всех сконфигурированных нод для добавления в bypass-маршруты,
    /// чтобы фоновая проверка раз в 30 минут при активном VPN гарантированно шла мимо туннеля.
    pub fn configured_hosts_and_ports() -> Vec<(String, u16)> {
        let monitor = Self::global();
        let targets = monitor.targets.lock().unwrap();
        let mut out = Vec::with_capacity(targets.len());
        for t in targets.iter() {
            if let Ok(uri) = t.dsn.parse::<http::Uri>() {
                if let Some(host) = uri.host() {
                    let scheme = uri.scheme_str().unwrap_or("quic").to_lowercase();
                    let port = uri.port_u16().unwrap_or(match scheme.as_str() {
                        "https" | "wss" | "wrtc" | "quic" => 443,
                        "http" | "ws" => 80,
                        "ssh" => 22,
                        "vnc" => 5900,
                        _ => 443,
                    });
                    out.push((host.to_string(), port));
                    continue;
                }
            }
            if let Some((h, p_str)) = t.host_port.rsplit_once(':') {
                if let Ok(port) = p_str.parse::<u16>() {
                    out.push((h.trim_matches(['[', ']']).to_string(), port));
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    fn spawn_or_wake(monitor: &Arc<Self>) {
        if monitor
            .task_running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            let monitor_clone = monitor.clone();
            let handle_opt = tokio::runtime::Handle::try_current()
                .ok()
                .or_else(|| monitor.runtime_handle.lock().unwrap().clone());
            if let Some(handle) = handle_opt {
                handle.spawn(async move {
                    monitor_clone.run_loop().await;
                });
            } else {
                monitor.task_running.store(false, Ordering::SeqCst);
            }
        } else {
            monitor.wake_notify.notify_one();
        }
    }

    async fn run_loop(self: Arc<Self>) {
        loop {
            let targets = self.targets.lock().unwrap().clone();
            if targets.is_empty() {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(10)) => {}
                    _ = self.wake_notify.notified() => {}
                }
                continue;
            }

            let probe_started = std::time::Instant::now();
            {
                let mut guard = self.last_snapshot.lock().unwrap();
                if guard.groups.is_empty() {
                    *guard = build_initial_snapshot(&targets);
                } else {
                    guard.is_checking = true;
                    guard.completed_endpoints = 0;
                    guard.total_endpoints = targets.len();
                }
                emit(AnetEvent::NodeProbeUpdated(guard.clone()));
            }

            let timeout_dur = Duration::from_millis(DEFAULT_PROBE_TIMEOUT_MS);
            let self_progress = self.clone();
            let snapshot = tokio::select! {
                res = probe_targets_with_progress(&targets, timeout_dur, move |partial_snap| {
                    *self_progress.last_snapshot.lock().unwrap() = partial_snap.clone();
                    emit(AnetEvent::NodeProbeUpdated(partial_snap));
                }) => res,
                _ = self.wake_notify.notified() => {
                    continue;
                }
            };

            let min_total_dur = Duration::from_millis(900);
            let min_complete_hold = Duration::from_millis(450);
            let elapsed = probe_started.elapsed();
            let hold_dur = if elapsed < min_total_dur {
                (min_total_dur - elapsed).max(min_complete_hold)
            } else {
                min_complete_hold
            };
            tokio::select! {
                _ = tokio::time::sleep(hold_dur) => {}
                _ = self.wake_notify.notified() => {
                    continue;
                }
            }

            {
                *self.last_snapshot.lock().unwrap() = snapshot.clone();
            }
            emit(AnetEvent::NodeProbeUpdated(snapshot));

            let sleep_secs = if self.vpn_connected.load(Ordering::Relaxed) {
                NODE_PROBE_CONNECTED_INTERVAL_SECS
            } else {
                NODE_PROBE_DISCONNECTED_INTERVAL_SECS
            };

            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(sleep_secs)) => {}
                _ = self.wake_notify.notified() => {}
            }
        }
    }
}

pub struct ConnectivityMonitor {
    config: Mutex<ConnectivityConfig>,
    vpn_connected: AtomicBool,
    tunnel_rtt_ms: AtomicU64,
    in_tunnel_global_mask: AtomicU64,
    in_tunnel_global_rtt_ms: AtomicU64,
    in_tunnel_global_updated_ms: AtomicU64,
    in_tunnel_domestic_mask: AtomicU64,
    in_tunnel_domestic_rtt_ms: AtomicU64,
    in_tunnel_domestic_updated_ms: AtomicU64,
    start_instant: std::time::Instant,
    last_snapshot: Mutex<Option<ConnectivitySnapshot>>,
    wake_notify: Notify,
    task_running: AtomicBool,
    runtime_handle: Mutex<Option<tokio::runtime::Handle>>,
}

static GLOBAL_MONITOR: OnceLock<Arc<ConnectivityMonitor>> = OnceLock::new();

impl ConnectivityMonitor {
    fn new(config: ConnectivityConfig) -> Self {
        Self {
            config: Mutex::new(config),
            vpn_connected: AtomicBool::new(false),
            tunnel_rtt_ms: AtomicU64::new(NO_RTT_MARKER),
            in_tunnel_global_mask: AtomicU64::new(0),
            in_tunnel_global_rtt_ms: AtomicU64::new(NO_RTT_MARKER),
            in_tunnel_global_updated_ms: AtomicU64::new(0),
            in_tunnel_domestic_mask: AtomicU64::new(0),
            in_tunnel_domestic_rtt_ms: AtomicU64::new(NO_RTT_MARKER),
            in_tunnel_domestic_updated_ms: AtomicU64::new(0),
            start_instant: std::time::Instant::now(),
            last_snapshot: Mutex::new(None),
            wake_notify: Notify::new(),
            task_running: AtomicBool::new(false),
            runtime_handle: Mutex::new(tokio::runtime::Handle::try_current().ok()),
        }
    }

    pub fn global() -> Arc<Self> {
        let mon = GLOBAL_MONITOR
            .get_or_init(|| Arc::new(Self::new(ConnectivityConfig::default())))
            .clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let mut guard = mon.runtime_handle.lock().unwrap();
            if guard.is_none() {
                *guard = Some(handle.clone());
            }
            NodeProbeMonitor::set_runtime_handle(handle);
        }
        mon
    }

    /// Регистрирует успешный внутритуннельный ICMP Echo Reply от глобального узла (1.1.1.1 / 8.8.8.8 / 9.9.9.9).
    /// На Android, где процесс VPN-клиента исключён из `tun0` через `addDisallowedApplication`,
    /// это позволяет `ConnectivityMonitor` видеть реальную связность «Мир 3/3» сквозь туннель.
    pub fn record_in_tunnel_global_probe(target_idx: usize, rtt_ms: u64) {
        let monitor = Self::global();
        let bit = 1u64 << (target_idx.min(7));
        let prev_mask = monitor.in_tunnel_global_mask.fetch_or(bit, Ordering::Relaxed);
        let now_ms = monitor.start_instant.elapsed().as_millis() as u64;
        monitor
            .in_tunnel_global_updated_ms
            .store(now_ms, Ordering::Relaxed);
        let prev_rtt = monitor.in_tunnel_global_rtt_ms.load(Ordering::Relaxed);
        let next_rtt = if prev_rtt == NO_RTT_MARKER {
            rtt_ms.max(1)
        } else {
            prev_rtt.min(rtt_ms.max(1))
        };
        monitor
            .in_tunnel_global_rtt_ms
            .store(next_rtt, Ordering::Relaxed);
        if prev_mask == 0 {
            monitor.wake_notify.notify_one();
        }
    }

    /// Регистрирует успешный внутритуннельный ICMP Echo Reply от российского узла (77.88.8.8 / 77.88.8.1 / 87.250.250.242).
    pub fn record_in_tunnel_domestic_probe(target_idx: usize, rtt_ms: u64) {
        let monitor = Self::global();
        let bit = 1u64 << (target_idx.min(7));
        let prev_mask = monitor
            .in_tunnel_domestic_mask
            .fetch_or(bit, Ordering::Relaxed);
        let now_ms = monitor.start_instant.elapsed().as_millis() as u64;
        monitor
            .in_tunnel_domestic_updated_ms
            .store(now_ms, Ordering::Relaxed);
        let prev_rtt = monitor.in_tunnel_domestic_rtt_ms.load(Ordering::Relaxed);
        let next_rtt = if prev_rtt == NO_RTT_MARKER {
            rtt_ms.max(1)
        } else {
            prev_rtt.min(rtt_ms.max(1))
        };
        monitor
            .in_tunnel_domestic_rtt_ms
            .store(next_rtt, Ordering::Relaxed);
        if prev_mask == 0 {
            monitor.wake_notify.notify_one();
        }
    }

    /// Обновляет конфигурацию секции `[connectivity]` и запускает фоновый цикл опроса,
    /// если он ещё не запущен в текущем рантайме Tokio.
    pub fn ensure_started(config: ConnectivityConfig) {
        let monitor = Self::global();
        let enabled = config.enabled;
        let global_total = config.global_targets.len();
        let domestic_total = config.domestic_targets.len();

        let config_changed = {
            let mut guard = monitor.config.lock().unwrap();
            let changed = *guard != config;
            *guard = config;
            changed
        };

        {
            let mut snap_guard = monitor.last_snapshot.lock().unwrap();
            if let Some(ref mut snap) = *snap_guard {
                if snap.global_total != global_total || snap.domestic_total != domestic_total {
                    snap.global_total = global_total;
                    snap.domestic_total = domestic_total;
                    snap.global_ok = snap.global_ok.min(global_total);
                    snap.domestic_ok = snap.domestic_ok.min(domestic_total);
                }
            } else {
                let mut init_snap = ConnectivitySnapshot::default();
                init_snap.global_total = global_total;
                init_snap.domestic_total = domestic_total;
                *snap_guard = Some(init_snap);
            }
        }

        if !enabled {
            return;
        }

        if monitor
            .task_running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            let monitor_clone = monitor.clone();
            let handle_opt = tokio::runtime::Handle::try_current()
                .ok()
                .or_else(|| monitor.runtime_handle.lock().unwrap().clone());
            if let Some(handle) = handle_opt {
                handle.spawn(async move {
                    monitor_clone.run_loop().await;
                });
            } else {
                monitor.task_running.store(false, Ordering::SeqCst);
            }
        } else if config_changed {
            monitor.wake_notify.notify_one();
        }
    }

    /// Уведомляет монитор о смене состояния VPN-туннеля (включён / выключен) и немедленно запускает внеочередной опрос.
    pub fn set_vpn_connected(connected: bool) {
        NodeProbeMonitor::set_vpn_connected(connected);
        let monitor = Self::global();
        let prev = monitor.vpn_connected.swap(connected, Ordering::SeqCst);
        if !connected {
            monitor.tunnel_rtt_ms.store(NO_RTT_MARKER, Ordering::Relaxed);
            monitor.in_tunnel_global_mask.store(0, Ordering::Relaxed);
            monitor
                .in_tunnel_global_rtt_ms
                .store(NO_RTT_MARKER, Ordering::Relaxed);
            monitor
                .in_tunnel_global_updated_ms
                .store(0, Ordering::Relaxed);
            monitor.in_tunnel_domestic_mask.store(0, Ordering::Relaxed);
            monitor
                .in_tunnel_domestic_rtt_ms
                .store(NO_RTT_MARKER, Ordering::Relaxed);
            monitor
                .in_tunnel_domestic_updated_ms
                .store(0, Ordering::Relaxed);
        }
        if prev != connected {
            let updated_opt = {
                let mut guard = monitor.last_snapshot.lock().unwrap();
                if let Some(ref mut current) = *guard {
                    current.vpn_connected = connected;
                    if !connected {
                        current.tunnel_rtt_ms = None;
                    }
                    Some(current.clone())
                } else {
                    None
                }
            };
            if let Some(updated) = updated_opt {
                emit(AnetEvent::ConnectivityUpdated(updated));
            }
            monitor.wake_notify.notify_one();
        }
    }

    /// Обновляет замер внутритуннельного ICMP RTT (вызывается раз в 1–2 с при активном туннеле)
    /// и мгновенно синхронизирует линейный индикатор пульса без ожидания следующего HTTP-цикла.
    pub fn update_tunnel_rtt_ms(rtt_ms: Option<u64>) {
        let monitor = Self::global();
        let raw = rtt_ms.unwrap_or(NO_RTT_MARKER);
        let prev = monitor.tunnel_rtt_ms.swap(raw, Ordering::Relaxed);
        if prev == raw {
            return;
        }

        if monitor.vpn_connected.load(Ordering::Relaxed) {
            let updated_opt = {
                let mut guard = monitor.last_snapshot.lock().unwrap();
                if let Some(ref current) = *guard {
                    let updated = current.with_updated_tunnel_rtt(true, rtt_ms);
                    let changed = updated.condition != current.condition
                        || updated.pulse_color != current.pulse_color
                        || updated.display_rtt_ms != current.display_rtt_ms;
                    *guard = Some(updated.clone());
                    if changed {
                        Some(updated)
                    } else {
                        None
                    }
                } else {
                    None
                }
            };
            if let Some(updated) = updated_opt {
                emit(AnetEvent::ConnectivityUpdated(updated));
            }
        }
    }

    /// Возвращает актуальное значение внутритуннельного RTT (если туннель активен и замер получен).
    pub fn get_tunnel_rtt_ms() -> Option<u64> {
        let monitor = Self::global();
        if monitor.vpn_connected.load(Ordering::Relaxed) {
            monitor.current_tunnel_rtt()
        } else {
            None
        }
    }

    /// Принудительно пробуждает фоновый воркер для немедленной проверки контрольных точек
    /// и сразу отправляет промежуточный снимок в UI для визуального отклика.
    pub fn trigger_check_now() {
        let monitor = Self::global();
        let (global_total, domestic_total) = {
            let cfg = monitor.config.lock().unwrap();
            (cfg.global_targets.len(), cfg.domestic_targets.len())
        };

        let checking_snap = {
            let guard = monitor.last_snapshot.lock().unwrap();
            let mut snap = guard.clone().unwrap_or_default();
            snap.vpn_connected = monitor.vpn_connected.load(Ordering::Relaxed);
            snap.global_total = global_total;
            snap.domestic_total = domestic_total;
            snap.title = "Сверяем показания приборов…".to_string();
            snap.subtitle = "Опрашиваем контрольные точки маршрутизации…".to_string();
            snap
        };
        emit(AnetEvent::ConnectivityUpdated(checking_snap));

        if monitor
            .task_running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            let monitor_clone = monitor.clone();
            let handle_opt = tokio::runtime::Handle::try_current()
                .ok()
                .or_else(|| monitor.runtime_handle.lock().unwrap().clone());
            if let Some(handle) = handle_opt {
                handle.spawn(async move {
                    monitor_clone.run_loop().await;
                });
            } else {
                monitor.task_running.store(false, Ordering::SeqCst);
            }
        } else {
            monitor.wake_notify.notify_one();
        }
    }

    /// Возвращает последний вычисленный снимок состояния сети.
    pub fn get_last_snapshot() -> ConnectivitySnapshot {
        let monitor = Self::global();
        let (global_total, domestic_total) = {
            let cfg = monitor.config.lock().unwrap();
            (cfg.global_targets.len(), cfg.domestic_targets.len())
        };
        let mut snap = monitor
            .last_snapshot
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_default();
        snap.global_total = global_total;
        snap.domestic_total = domestic_total;
        snap
    }

    fn current_tunnel_rtt(&self) -> Option<u64> {
        let val = self.tunnel_rtt_ms.load(Ordering::Relaxed);
        if val == NO_RTT_MARKER {
            None
        } else {
            Some(val)
        }
    }

    fn merge_in_tunnel_probes(
        &self,
        mut global_res: anet_common::connectivity::ProbeGroupResult,
        mut domestic_res: anet_common::connectivity::ProbeGroupResult,
    ) -> (
        anet_common::connectivity::ProbeGroupResult,
        anet_common::connectivity::ProbeGroupResult,
    ) {
        let now_ms = self.start_instant.elapsed().as_millis() as u64;
        let max_age_ms = 20_000u64;

        let g_updated = self.in_tunnel_global_updated_ms.load(Ordering::Relaxed);
        if g_updated > 0 && now_ms.saturating_sub(g_updated) <= max_age_ms {
            let g_ok = (self.in_tunnel_global_mask.load(Ordering::Relaxed).count_ones() as usize)
                .min(global_res.total_count.max(3));
            if g_ok > global_res.ok_count {
                global_res.ok_count = g_ok.min(global_res.total_count);
            }
            let g_rtt = self.in_tunnel_global_rtt_ms.load(Ordering::Relaxed);
            if g_rtt != NO_RTT_MARKER {
                global_res.min_rtt_ms = Some(match global_res.min_rtt_ms {
                    Some(prev) => prev.min(g_rtt),
                    None => g_rtt,
                });
            }
        } else if g_updated > 0 {
            self.in_tunnel_global_mask.store(0, Ordering::Relaxed);
            self.in_tunnel_global_rtt_ms
                .store(NO_RTT_MARKER, Ordering::Relaxed);
        }

        let d_updated = self.in_tunnel_domestic_updated_ms.load(Ordering::Relaxed);
        if d_updated > 0 && now_ms.saturating_sub(d_updated) <= max_age_ms {
            let d_ok = (self
                .in_tunnel_domestic_mask
                .load(Ordering::Relaxed)
                .count_ones() as usize)
                .min(domestic_res.total_count.max(3));
            if d_ok > domestic_res.ok_count {
                domestic_res.ok_count = d_ok.min(domestic_res.total_count);
            }
            let d_rtt = self.in_tunnel_domestic_rtt_ms.load(Ordering::Relaxed);
            if d_rtt != NO_RTT_MARKER {
                domestic_res.min_rtt_ms = Some(match domestic_res.min_rtt_ms {
                    Some(prev) => prev.min(d_rtt),
                    None => d_rtt,
                });
            }
        } else if d_updated > 0 {
            self.in_tunnel_domestic_mask.store(0, Ordering::Relaxed);
            self.in_tunnel_domestic_rtt_ms
                .store(NO_RTT_MARKER, Ordering::Relaxed);
        }

        (global_res, domestic_res)
    }

    async fn run_loop(self: Arc<Self>) {
        let mut cached_prober: Option<ConnectivityProber> = None;

        loop {
            let cfg = self.config.lock().unwrap().clone();
            if !cfg.enabled {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                    _ = self.wake_notify.notified() => {}
                }
                continue;
            }

            let prober = match cached_prober {
                Some(ref p) if *p.config() == cfg => p.clone(),
                _ => {
                    let p = ConnectivityProber::new(cfg.clone());
                    cached_prober = Some(p.clone());
                    p
                }
            };

            let vpn_on = self.vpn_connected.load(Ordering::Relaxed);
            let tunnel_rtt = if vpn_on {
                self.current_tunnel_rtt()
            } else {
                None
            };

            let outer_timeout = Duration::from_millis(cfg.timeout_ms.clamp(1200, 4500) * 2 + 2500);
            let (mut global_res, mut domestic_res) = tokio::select! {
                res = tokio::time::timeout(outer_timeout, prober.probe_groups_raw()) => {
                    match res {
                        Ok(pair) => pair,
                        Err(_) => (
                            anet_common::connectivity::ProbeGroupResult {
                                ok_count: 0,
                                total_count: cfg.global_targets.len(),
                                min_rtt_ms: None,
                            },
                            anet_common::connectivity::ProbeGroupResult {
                                ok_count: 0,
                                total_count: cfg.domestic_targets.len(),
                                min_rtt_ms: None,
                            },
                        ),
                    }
                }
                _ = self.wake_notify.notified() => {
                    continue;
                }
            };

            let vpn_now = self.vpn_connected.load(Ordering::Relaxed);
            let tunnel_rtt_now = if vpn_now {
                self.current_tunnel_rtt()
            } else {
                None
            };

            if vpn_now {
                let merged = self.merge_in_tunnel_probes(global_res, domestic_res);
                global_res = merged.0;
                domestic_res = merged.1;
            }

            let final_snapshot =
                ConnectivitySnapshot::evaluate(vpn_now, tunnel_rtt_now, global_res, domestic_res);

            debug!(
                "[Connectivity] Condition={:?}, Color={:?}, RTT={:?}ms, Global={}/{}, Domestic={}/{}",
                final_snapshot.condition,
                final_snapshot.pulse_color,
                final_snapshot.display_rtt_ms,
                final_snapshot.global_ok,
                final_snapshot.global_total,
                final_snapshot.domestic_ok,
                final_snapshot.domestic_total
            );

            {
                *self.last_snapshot.lock().unwrap() = Some(final_snapshot.clone());
            }
            emit(AnetEvent::ConnectivityUpdated(final_snapshot));

            let interval_secs = cfg.probe_interval_secs.clamp(2, 60);
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(interval_secs)) => {}
                _ = self.wake_notify.notified() => {}
            }
        }
    }
}

