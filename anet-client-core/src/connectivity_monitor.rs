use crate::events::{AnetEvent, emit};
use anet_common::config::ConnectivityConfig;
use anet_common::connectivity::{ConnectivityProber, ConnectivitySnapshot};
use log::debug;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::Notify;

const NO_RTT_MARKER: u64 = u64::MAX;

pub struct ConnectivityMonitor {
    config: Mutex<ConnectivityConfig>,
    vpn_connected: AtomicBool,
    tunnel_rtt_ms: AtomicU64,
    last_snapshot: Mutex<Option<ConnectivitySnapshot>>,
    wake_notify: Notify,
    task_running: AtomicBool,
}

static GLOBAL_MONITOR: OnceLock<Arc<ConnectivityMonitor>> = OnceLock::new();

impl ConnectivityMonitor {
    fn new(config: ConnectivityConfig) -> Self {
        Self {
            config: Mutex::new(config),
            vpn_connected: AtomicBool::new(false),
            tunnel_rtt_ms: AtomicU64::new(NO_RTT_MARKER),
            last_snapshot: Mutex::new(None),
            wake_notify: Notify::new(),
            task_running: AtomicBool::new(false),
        }
    }

    pub fn global() -> Arc<Self> {
        GLOBAL_MONITOR
            .get_or_init(|| Arc::new(Self::new(ConnectivityConfig::default())))
            .clone()
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
            if tokio::runtime::Handle::try_current().is_ok() {
                tokio::spawn(async move {
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
        let monitor = Self::global();
        let prev = monitor.vpn_connected.swap(connected, Ordering::SeqCst);
        if !connected {
            monitor.tunnel_rtt_ms.store(NO_RTT_MARKER, Ordering::Relaxed);
        }
        if prev != connected {
            monitor.wake_notify.notify_one();
        }
    }

    /// Обновляет замер внутритуннельного ICMP RTT (вызывается раз в 1–2 с при активном туннеле)
    /// и мгновенно синхронизирует линейный индикатор пульса без ожидания следующего HTTP-цикла.
    pub fn update_tunnel_rtt_ms(rtt_ms: Option<u64>) {
        let monitor = Self::global();
        let raw = rtt_ms.unwrap_or(NO_RTT_MARKER);
        monitor.tunnel_rtt_ms.store(raw, Ordering::Relaxed);

        if monitor.vpn_connected.load(Ordering::Relaxed) {
            let mut guard = monitor.last_snapshot.lock().unwrap();
            if let Some(ref current) = *guard {
                let updated = current.with_updated_tunnel_rtt(true, rtt_ms);
                *guard = Some(updated.clone());
                drop(guard);
                emit(AnetEvent::ConnectivityUpdated(updated));
            }
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
            let mut guard = monitor.last_snapshot.lock().unwrap();
            let mut snap = guard.clone().unwrap_or_default();
            snap.global_total = global_total;
            snap.domestic_total = domestic_total;
            snap.title = "Сверяем показания приборов…".to_string();
            snap.subtitle = "Опрашиваем контрольные точки маршрутизации…".to_string();
            *guard = Some(snap.clone());
            snap
        };
        emit(AnetEvent::ConnectivityUpdated(checking_snap));

        if monitor
            .task_running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            let monitor_clone = monitor.clone();
            if tokio::runtime::Handle::try_current().is_ok() {
                tokio::spawn(async move {
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

    async fn run_loop(self: Arc<Self>) {
        loop {
            let cfg = self.config.lock().unwrap().clone();
            if !cfg.enabled {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                    _ = self.wake_notify.notified() => {}
                }
                continue;
            }

            let prober = ConnectivityProber::new(cfg.clone());
            let vpn_on = self.vpn_connected.load(Ordering::Relaxed);
            let tunnel_rtt = if vpn_on {
                self.current_tunnel_rtt()
            } else {
                None
            };

            let snapshot = tokio::select! {
                res = prober.probe_once(vpn_on, tunnel_rtt) => res,
                _ = self.wake_notify.notified() => {
                    // Внеочередное пробуждение (смена конфига, переключение VPN или ручной клик "Перепроверить")
                    // немедленно перезапускает опрос с актуальными параметрами.
                    continue;
                }
            };

            // Если во время HTTP-опроса статус VPN успел измениться, пересчитываем актуальный флаг
            let vpn_now = self.vpn_connected.load(Ordering::Relaxed);
            let tunnel_rtt_now = if vpn_now {
                self.current_tunnel_rtt()
            } else {
                None
            };
            let final_snapshot = if vpn_now != vpn_on || tunnel_rtt_now != tunnel_rtt {
                snapshot.with_updated_tunnel_rtt(vpn_now, tunnel_rtt_now)
            } else {
                snapshot
            };

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

