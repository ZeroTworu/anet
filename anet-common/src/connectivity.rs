use crate::config::ConnectivityConfig;
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use std:: collections::VecDeque;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Цветовой код линейного индикатора пульса и щита состояния сети.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PulseColor {
    /// Красный: отсутствие связи (либо провайдер молчит, либо туннель не пропускает трафик)
    Red = 0,
    /// Жёлтый: частичная связность (доступен только внутренний сегмент или только узел туннеля)
    Yellow = 1,
    /// Зелёный: полная связность (доступны глобальные контрольные точки)
    Green = 2,
}

impl PulseColor {
    pub fn code(self) -> i32 {
        self as i32
    }

    pub fn hex_color(self) -> &'static str {
        match self {
            PulseColor::Red => "#EF4444",
            PulseColor::Yellow => "#F59E0B",
            PulseColor::Green => "#22C55E",
        }
    }
}

/// Явная матрица из 6 состояний сетевой связности.
/// Разделяет состояния при выключенном и включённом VPN-туннеле.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum NetworkCondition {
    /// [0] VPN выключен: недоступны ни внешние, ни локальные контрольные точки.
    Offline = 0,
    /// [1] VPN выключен: внешние контрольные точки не отвечают, но локальные ресурсы доступны.
    DomesticOnly = 1,
    /// [2] VPN выключен: внешние контрольные точки отвечают напрямую.
    DirectOnline = 2,
    /// [3] VPN включён: нет отклика ни от узла туннеля (ICMP), ни от внешних контрольных точек.
    TunnelLost = 3,
    /// [4] VPN включён: узел туннеля отвечает (или доступны локальные точки), но внешние маршруты за ним недоступны.
    TunnelOnlyNoWorld = 4,
    /// [5] VPN включён: внешние контрольные точки успешно отвечают через туннель.
    TunnelFullOnline = 5,
}

impl NetworkCondition {
    pub fn code(self) -> i32 {
        self as i32
    }

    pub fn pulse_color(self) -> PulseColor {
        match self {
            NetworkCondition::Offline | NetworkCondition::TunnelLost => PulseColor::Red,
            NetworkCondition::DomesticOnly | NetworkCondition::TunnelOnlyNoWorld => {
                PulseColor::Yellow
            }
            NetworkCondition::DirectOnline | NetworkCondition::TunnelFullOnline => {
                PulseColor::Green
            }
        }
    }

    /// Возвращает заголовок и описание для виджета «Щит диагностики сети»
    /// в нейтральной технической стилистике с лёгкой иронией.
    pub fn describe(
        self,
        domestic_ok: usize,
        domestic_total: usize,
        global_ok: usize,
        global_total: usize,
    ) -> (String, String) {
        match self {
            NetworkCondition::Offline => (
                "Тишина в эфире".to_string(),
                "Провайдер ушёл в себя. Не открывается вообще ничего".to_string(),
            ),
            NetworkCondition::DomesticOnly => (
                "Суверенный режим связи".to_string(),
                format!(
                    "Внешние маршруты приболели, живы только местные узлы ({}/{}). Включите туннель для стабилизации",
                    domestic_ok,
                    domestic_total.max(1)
                ),
            ),
            NetworkCondition::DirectOnline => {
                let total = global_total.max(1);
                let subtitle = if global_ok >= total {
                    format!(
                        "Прямой канал дышит сам ({}/{}), глобальная сеть отвечает без костылей",
                        global_ok, total
                    )
                } else {
                    format!(
                        "Прямой канал живой ({}/{}), основные внешние узлы отвечают",
                        global_ok, total
                    )
                };
                ("Магистраль в норме".to_string(), subtitle)
            }
            NetworkCondition::TunnelLost => (
                "Канал в коме".to_string(),
                "Туннель открыт, но пакеты уходят в небытие. Реанимируем…".to_string(),
            ),
            NetworkCondition::TunnelOnlyNoWorld => (
                "Связь только до узла".to_string(),
                "До сервера достучались, но дальше него жизни пока нет".to_string(),
            ),
            NetworkCondition::TunnelFullOnline => {
                let total = global_total.max(1);
                let subtitle = if global_ok >= total {
                    format!(
                        "Все внешние маршруты в строю ({}/{}). Полёт нормальный",
                        global_ok, total
                    )
                } else {
                    format!(
                        "Внешние маршруты на связи ({}/{}). Полёт нормальный",
                        global_ok, total
                    )
                };
                ("Связь стабилизирована".to_string(), subtitle)
            }
        }
    }
}

/// Полный снимок состояния связности для отображения линейного пульса и щита диагностики.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectivitySnapshot {
    pub condition: NetworkCondition,
    pub pulse_color: PulseColor,
    pub vpn_connected: bool,
    /// Итоговый пинг (в мс) для отображения на линейном индикаторе пульса:
    /// - при активном туннеле: внутритуннельный ICMP RTT (либо HTTP RTT до внешнего узла до первого ICMP-ответа);
    /// - без туннеля: минимальный HTTP/TCP RTT до доступной контрольной точки.
    pub display_rtt_ms: Option<u64>,
    pub tunnel_rtt_ms: Option<u64>,
    pub global_rtt_ms: Option<u64>,
    pub domestic_rtt_ms: Option<u64>,
    pub global_ok: usize,
    pub global_total: usize,
    pub domestic_ok: usize,
    pub domestic_total: usize,
    pub title: String,
    pub subtitle: String,
    pub updated_at_ms: u64,
}

impl Default for ConnectivitySnapshot {
    fn default() -> Self {
        let condition = NetworkCondition::Offline;
        let (title, subtitle) = condition.describe(0, 0, 0, 0);
        Self {
            condition,
            pulse_color: condition.pulse_color(),
            vpn_connected: false,
            display_rtt_ms: None,
            tunnel_rtt_ms: None,
            global_rtt_ms: None,
            domestic_rtt_ms: None,
            global_ok: 0,
            global_total: 0,
            domestic_ok: 0,
            domestic_total: 0,
            title,
            subtitle,
            updated_at_ms: now_unix_ms(),
        }
    }
}

impl ConnectivitySnapshot {
    /// Вычисляет состояние сети на основе статуса VPN, внутритуннельного пинга и результатов опроса контрольных точек.
    pub fn evaluate(
        vpn_connected: bool,
        tunnel_rtt_ms: Option<u64>,
        global_probe: ProbeGroupResult,
        domestic_probe: ProbeGroupResult,
    ) -> Self {
        let condition = if !vpn_connected {
            if global_probe.ok_count > 0 {
                NetworkCondition::DirectOnline
            } else if domestic_probe.ok_count > 0 {
                NetworkCondition::DomesticOnly
            } else {
                NetworkCondition::Offline
            }
        } else if global_probe.ok_count > 0 {
            NetworkCondition::TunnelFullOnline
        } else if tunnel_rtt_ms.is_some() || domestic_probe.ok_count > 0 {
            NetworkCondition::TunnelOnlyNoWorld
        } else {
            NetworkCondition::TunnelLost
        };

        let display_rtt_ms = match condition {
            NetworkCondition::Offline | NetworkCondition::TunnelLost => None,
            NetworkCondition::DomesticOnly => domestic_probe.min_rtt_ms,
            NetworkCondition::DirectOnline => global_probe.min_rtt_ms.or(domestic_probe.min_rtt_ms),
            NetworkCondition::TunnelOnlyNoWorld => {
                tunnel_rtt_ms.or(domestic_probe.min_rtt_ms)
            }
            NetworkCondition::TunnelFullOnline => {
                tunnel_rtt_ms.or(global_probe.min_rtt_ms)
            }
        };

        let (title, subtitle) = condition.describe(
            domestic_probe.ok_count,
            domestic_probe.total_count,
            global_probe.ok_count,
            global_probe.total_count,
        );

        Self {
            condition,
            pulse_color: condition.pulse_color(),
            vpn_connected,
            display_rtt_ms,
            tunnel_rtt_ms,
            global_rtt_ms: global_probe.min_rtt_ms,
            domestic_rtt_ms: domestic_probe.min_rtt_ms,
            global_ok: global_probe.ok_count,
            global_total: global_probe.total_count,
            domestic_ok: domestic_probe.ok_count,
            domestic_total: domestic_probe.total_count,
            title,
            subtitle,
            updated_at_ms: now_unix_ms(),
        }
    }

    /// Быстрое обновление внутритуннельного RTT между циклами HTTP-опроса.
    pub fn with_updated_tunnel_rtt(&self, vpn_connected: bool, tunnel_rtt_ms: Option<u64>) -> Self {
        let mut next = self.clone();
        next.vpn_connected = vpn_connected;
        next.tunnel_rtt_ms = tunnel_rtt_ms;
        if vpn_connected {
            if next.global_ok > 0 {
                next.condition = NetworkCondition::TunnelFullOnline;
                next.display_rtt_ms = tunnel_rtt_ms.or(next.global_rtt_ms);
            } else if tunnel_rtt_ms.is_some() || next.domestic_ok > 0 {
                next.condition = NetworkCondition::TunnelOnlyNoWorld;
                next.display_rtt_ms = tunnel_rtt_ms.or(next.domestic_rtt_ms);
            } else {
                next.condition = NetworkCondition::TunnelLost;
                next.display_rtt_ms = None;
            }
            next.pulse_color = next.condition.pulse_color();
            let (title, subtitle) = next.condition.describe(
                next.domestic_ok,
                next.domestic_total,
                next.global_ok,
                next.global_total,
            );
            next.title = title;
            next.subtitle = subtitle;
        }
        next.updated_at_ms = now_unix_ms();
        next
    }
}

/// Результат опроса группы контрольных точек (глобальных или локальных).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeGroupResult {
    pub ok_count: usize,
    pub total_count: usize,
    pub min_rtt_ms: Option<u64>,
}

/// Кроссплатформенный пробер контрольных точек.
/// ВАЖНО: намеренно использует обычные системные сокеты без bypass_ips / protect(fd),
/// чтобы до включения VPN проверять физический канал провайдера, а после включения VPN —
/// реальную проходимость трафика сквозь поднятый TUN-интерфейс.
#[derive(Clone)]
pub struct ConnectivityProber {
    client: reqwest::Client,
    config: ConnectivityConfig,
}

impl ConnectivityProber {
    pub fn new(config: ConnectivityConfig) -> Self {
        let timeout = Duration::from_millis(config.timeout_ms.clamp(500, 15_000));
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(0)
            .user_agent("Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/126.0.0.0")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self { client, config }
    }

    pub fn config(&self) -> &ConnectivityConfig {
        &self.config
    }

    /// Одновременно опрашивает все глобальные и локальные контрольные точки и формирует снимок состояния.
    pub async fn probe_once(
        &self,
        vpn_connected: bool,
        tunnel_rtt_ms: Option<u64>,
    ) -> ConnectivitySnapshot {
        let (global_res, domestic_res) = tokio::join!(
            self.probe_group(&self.config.global_targets),
            self.probe_group(&self.config.domestic_targets),
        );

        ConnectivitySnapshot::evaluate(vpn_connected, tunnel_rtt_ms, global_res, domestic_res)
    }

    async fn probe_group(&self, targets: &[String]) -> ProbeGroupResult {
        if targets.is_empty() {
            return ProbeGroupResult::default();
        }

        let futures = targets
            .iter()
            .map(|url| probe_single_target(&self.client, url));
        let results = join_all(futures).await;

        let mut ok_count = 0usize;
        let mut min_rtt_ms: Option<u64> = None;

        for rtt in results.into_iter().flatten() {
            ok_count += 1;
            min_rtt_ms = Some(match min_rtt_ms {
                Some(prev) => prev.min(rtt),
                None => rtt,
            });
        }

        ProbeGroupResult {
            ok_count,
            total_count: targets.len(),
            min_rtt_ms,
        }
    }
}

async fn probe_single_target(client: &reqwest::Client, target: &str) -> Option<u64> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return None;
    }

    let start = Instant::now();
    let resp = client
        .get(trimmed)
        .header("Cache-Control", "no-cache, no-store")
        .send()
        .await
        .ok()?;

    // Любой осмысленный HTTP-ответ от целевого сервера (2xx, 3xx, 401/403/404)
    // подтверждает успешное прохождение DNS + TCP + TLS хендшейка.
    let status = resp.status().as_u16();
    if (100..600).contains(&status) {
        let elapsed_ms = start.elapsed().as_millis() as u64;
        Some(elapsed_ms.max(1))
    } else {
        None
    }
}

/// Одна точка замера скорости для построения сглаженного графика (sparkline) в карточке «СКОРОСТЬ / ТРАФИК».
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpeedSample {
    /// Входящая скорость (Download), байт/сек
    pub rx_bps: u64,
    /// Исходящая скорость (Upload), байт/сек
    pub tx_bps: u64,
}

/// Снимок телеметрии скорости и трафика за сессию, готовый для прямой отрисовки в UI (Android / Desktop / iOS).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    pub rx_bps: u64,
    pub tx_bps: u64,
    pub total_rx_bytes: u64,
    pub total_tx_bytes: u64,
    pub rtt_ms: Option<u64>,
    pub peak_bps: u64,
    pub rx_speed_str: String,
    pub tx_speed_str: String,
    pub total_rx_str: String,
    pub total_tx_str: String,
    /// Нормализованные точки кривой Download (`0.0..=1.0`, до 60 точек за последние 60 секунд)
    pub rx_curve: Vec<f32>,
    /// Нормализованные точки кривой Upload (`0.0..=1.0`, до 60 точек за последние 60 секунд)
    pub tx_curve: Vec<f32>,
}

/// Кольцевой буфер истории скоростей (по умолчанию 60 секунд) с автоматической нормализацией кривых.
#[derive(Debug, Clone)]
pub struct TelemetryRingBuffer {
    capacity: usize,
    samples: VecDeque<SpeedSample>,
}

impl Default for TelemetryRingBuffer {
    fn default() -> Self {
        Self::new(60)
    }
}

impl TelemetryRingBuffer {
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(2);
        let mut samples = VecDeque::with_capacity(cap);
        for _ in 0..cap {
            samples.push_back(SpeedSample::default());
        }
        Self {
            capacity: cap,
            samples,
        }
    }

    pub fn clear(&mut self) {
        self.samples.clear();
        for _ in 0..self.capacity {
            self.samples.push_back(SpeedSample::default());
        }
    }

    pub fn push_sample(
        &mut self,
        rx_bps: u64,
        tx_bps: u64,
        total_rx_bytes: u64,
        total_tx_bytes: u64,
        rtt_ms: Option<u64>,
    ) -> TelemetrySnapshot {
        if self.samples.len() >= self.capacity {
            self.samples.pop_front();
        }
        self.samples.push_back(SpeedSample { rx_bps, tx_bps });

        // Минимум 64 КБ/с для масштаба по оси Y, чтобы мелкий фоновый трафик не выглядел как 100% пик
        let mut peak_bps: u64 = 64 * 1024;
        for s in &self.samples {
            peak_bps = peak_bps.max(s.rx_bps).max(s.tx_bps);
        }

        let denom = peak_bps as f32;
        let mut rx_curve = Vec::with_capacity(self.samples.len());
        let mut tx_curve = Vec::with_capacity(self.samples.len());

        for s in &self.samples {
            rx_curve.push((s.rx_bps as f32 / denom).clamp(0.0, 1.0));
            tx_curve.push((s.tx_bps as f32 / denom).clamp(0.0, 1.0));
        }

        TelemetrySnapshot {
            rx_bps,
            tx_bps,
            total_rx_bytes,
            total_tx_bytes,
            rtt_ms,
            peak_bps,
            rx_speed_str: format_speed_ru(rx_bps),
            tx_speed_str: format_speed_ru(tx_bps),
            total_rx_str: format_bytes_ru(total_rx_bytes),
            total_tx_str: format_bytes_ru(total_tx_bytes),
            rx_curve,
            tx_curve,
        }
    }
}

/// Форматирование объёма трафика (Б / КБ / МБ / ГБ).
pub fn format_bytes_ru(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    let b = bytes as f64;
    if b < KIB {
        format!("{} Б", bytes)
    } else if b < MIB {
        format!("{:.1} КБ", b / KIB)
    } else if b < GIB {
        format!("{:.2} МБ", b / MIB)
    } else {
        format!("{:.2} ГБ", b / GIB)
    }
}

/// Форматирование скорости передачи данных (Б/с / КБ/с / МБ/с / ГБ/с).
pub fn format_speed_ru(bytes_per_sec: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    let bps = bytes_per_sec as f64;
    if bps < KIB {
        format!("{} Б/с", bytes_per_sec)
    } else if bps < MIB {
        format!("{:.1} КБ/с", bps / KIB)
    } else if bps < GIB {
        format!("{:.1} МБ/с", bps / MIB)
    } else {
        format!("{:.2} ГБ/с", bps / GIB)
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_six_state_matrix_evaluation() {
        let zero = ProbeGroupResult {
            ok_count: 0,
            total_count: 5,
            min_rtt_ms: None,
        };
        let dom_ok = ProbeGroupResult {
            ok_count: 3,
            total_count: 5,
            min_rtt_ms: Some(28),
        };
        let glob_ok = ProbeGroupResult {
            ok_count: 4,
            total_count: 5,
            min_rtt_ms: Some(64),
        };

        // 1. Offline (VPN Off, 0 global, 0 domestic)
        let s0 = ConnectivitySnapshot::evaluate(false, None, zero, zero);
        assert_eq!(s0.condition, NetworkCondition::Offline);
        assert_eq!(s0.pulse_color, PulseColor::Red);
        assert_eq!(s0.display_rtt_ms, None);

        // 2. DomesticOnly (VPN Off, 0 global, >0 domestic)
        let s1 = ConnectivitySnapshot::evaluate(false, None, zero, dom_ok);
        assert_eq!(s1.condition, NetworkCondition::DomesticOnly);
        assert_eq!(s1.pulse_color, PulseColor::Yellow);
        assert_eq!(s1.display_rtt_ms, Some(28));

        // 3. DirectOnline (VPN Off, >0 global)
        let s2 = ConnectivitySnapshot::evaluate(false, None, glob_ok, dom_ok);
        assert_eq!(s2.condition, NetworkCondition::DirectOnline);
        assert_eq!(s2.pulse_color, PulseColor::Green);
        assert_eq!(s2.display_rtt_ms, Some(64));

        // 4. TunnelLost (VPN On, tunnel ICMP None, 0 global)
        let s3 = ConnectivitySnapshot::evaluate(true, None, zero, zero);
        assert_eq!(s3.condition, NetworkCondition::TunnelLost);
        assert_eq!(s3.pulse_color, PulseColor::Red);
        assert_eq!(s3.display_rtt_ms, None);

        // 5. TunnelOnlyNoWorld (VPN On, tunnel ICMP Some(42), 0 global)
        let s4 = ConnectivitySnapshot::evaluate(true, Some(42), zero, zero);
        assert_eq!(s4.condition, NetworkCondition::TunnelOnlyNoWorld);
        assert_eq!(s4.pulse_color, PulseColor::Yellow);
        assert_eq!(s4.display_rtt_ms, Some(42));

        // 6. TunnelFullOnline (VPN On, tunnel ICMP Some(55), >0 global)
        let s5 = ConnectivitySnapshot::evaluate(true, Some(55), glob_ok, dom_ok);
        assert_eq!(s5.condition, NetworkCondition::TunnelFullOnline);
        assert_eq!(s5.pulse_color, PulseColor::Green);
        assert_eq!(s5.display_rtt_ms, Some(55));
    }

    #[test]
    fn test_telemetry_ring_buffer_normalization() {
        let mut ring = TelemetryRingBuffer::new(4);
        let snap = ring.push_sample(1024 * 1024, 512 * 1024, 10_000_000, 5_000_000, Some(45));
        assert_eq!(snap.rx_curve.len(), 4);
        assert_eq!(snap.tx_curve.len(), 4);
        assert!((snap.rx_curve[3] - 1.0).abs() < 1e-4);
        assert!((snap.tx_curve[3] - 0.5).abs() < 1e-4);
    }
}
