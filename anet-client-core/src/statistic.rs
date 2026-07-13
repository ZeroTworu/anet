use std::time::Duration;
use log::info;
use quinn::Connection;
use std::sync::Arc;
use tokio::time::sleep;
use tokio::sync::Notify;
use std::sync::atomic::{AtomicU64, Ordering};
use crate::events::status;

const KIB: f64 = 1024.0;
const MIB: f64 = 1024.0 * 1024.0;
const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

/// Форматирование байт в человекочитаемый вид
fn format_bytes(bytes: u64) -> String {
    let bytes_f = bytes as f64;
    if bytes_f < KIB {
        format!("{} B", bytes)
    } else if bytes_f < MIB {
        format!("{:.2} KiB", bytes_f / KIB)
    } else if bytes_f < GIB {
        format!("{:.2} MiB", bytes_f / MIB)
    } else {
        format!("{:.2} GiB", bytes_f / GIB)
    }
}

/// Унифицированный снимок состояния сети
#[derive(Debug, Clone, Default)]
pub struct StatsSnapshot {
    pub rtt_ms: Option<f64>,
    pub cwnd_bytes: Option<u64>,
    pub lost_packets: Option<u64>,
    pub mtu_bytes: Option<u16>,
    pub total_rx_bytes: u64,
    pub total_tx_bytes: u64,
    pub total_rx_packets: u64,
    pub total_tx_packets: u64,
}

/// Абстрактный интерфейс для получения метрик сетевой сессии
pub trait StatsProvider: Send + Sync {
    fn get_stats(&self) -> StatsSnapshot;
    fn is_closed(&self) -> bool;
}

/// Реализация статистики для нативного QUIC-соединения (Quinn)
pub struct QuicStatsProvider {
    connection: Connection,
}

impl QuicStatsProvider {
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }
}

impl StatsProvider for QuicStatsProvider {
    fn get_stats(&self) -> StatsSnapshot {
        let stats = self.connection.stats();
        StatsSnapshot {
            rtt_ms: Some(stats.path.rtt.as_secs_f64() * 1000.0),
            cwnd_bytes: Some(stats.path.cwnd),
            lost_packets: Some(stats.path.lost_packets),
            mtu_bytes: Some(stats.path.current_mtu),
            total_rx_bytes: stats.udp_rx.bytes,
            total_tx_bytes: stats.udp_tx.bytes,
            total_rx_packets: stats.udp_rx.datagrams,
            total_tx_packets: stats.udp_tx.datagrams,
        }
    }

    fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }
}

/// Реализация статистики для потоковых соединений (SSH, VNC) через счетчики моста
pub struct StreamStatsProvider {
    total_rx_bytes: Arc<AtomicU64>,
    total_tx_bytes: Arc<AtomicU64>,
    total_rx_packets: Arc<AtomicU64>,
    total_tx_packets: Arc<AtomicU64>,
}

impl StreamStatsProvider {
    pub fn new(
        total_rx_bytes: Arc<AtomicU64>,
        total_tx_bytes: Arc<AtomicU64>,
        total_rx_packets: Arc<AtomicU64>,
        total_tx_packets: Arc<AtomicU64>,
    ) -> Self {
        Self {
            total_rx_bytes,
            total_tx_bytes,
            total_rx_packets,
            total_tx_packets,
        }
    }
}

impl StatsProvider for StreamStatsProvider {
    fn get_stats(&self) -> StatsSnapshot {
        StatsSnapshot {
            rtt_ms: None,
            cwnd_bytes: None,
            lost_packets: None,
            mtu_bytes: None,
            total_rx_bytes: self.total_rx_bytes.load(Ordering::Relaxed),
            total_tx_bytes: self.total_tx_bytes.load(Ordering::Relaxed),
            total_rx_packets: self.total_rx_packets.load(Ordering::Relaxed),
            total_tx_packets: self.total_tx_packets.load(Ordering::Relaxed),
        }
    }

    fn is_closed(&self) -> bool {
        false // Закрытие контролируется извне через задачу монитора
    }
}

/// Запуск периодического мониторинга статистики сессии
pub fn start_stats_monitor(
    provider: Arc<dyn StatsProvider>,
    interval_minutes: u64,
    shutdown_notify: Arc<Notify>,
) -> tokio::task::JoinHandle<()> {
    info!(
        "[STATS] Monitor enabled. Interval: {} minute(s).",
        interval_minutes
    );
    status(format!(
        "[STATS] Monitor enabled. Interval: {} minute(s).",
        interval_minutes
    ));

    tokio::spawn(async move {
        let interval = Duration::from_secs(interval_minutes * 60);
        let mut last_stats = provider.get_stats();
        let start_time = std::time::Instant::now();

        loop {
            tokio::select! {
                _ = sleep(interval) => {
                    if provider.is_closed() {
                        break;
                    }

                    let current_stats = provider.get_stats();
                    let elapsed_since_start = (std::time::Instant::now() - start_time)
                        .as_secs_f64()
                        .max(1.0);

                    // Считаем разницу переданных данных за интервал
                    let rx_bytes_delta = current_stats
                        .total_rx_bytes
                        .saturating_sub(last_stats.total_rx_bytes);
                    let tx_bytes_delta = current_stats
                        .total_tx_bytes
                        .saturating_sub(last_stats.total_tx_bytes);
                        
                    let interval_secs = interval.as_secs_f64();
                    
                    // Расчет скорости передачи в мегабитах
                    let rx_mbps = if interval_secs > 0.0 {
                        (rx_bytes_delta * 8) as f64 / (1000.0 * 1000.0 * interval_secs)
                    } else {
                        0.0
                    };
                    let tx_mbps = if interval_secs > 0.0 {
                        (tx_bytes_delta * 8) as f64 / (1000.0 * 1000.0 * interval_secs)
                    } else {
                        0.0
                    };

                    // Форматируем опциональные QUIC метрики
                    let rtt_str = current_stats.rtt_ms
                        .map(|rtt| format!("{:>6.2}ms", rtt))
                        .unwrap_or_else(|| "N/A".to_string());
                        
                    let cwnd_str = current_stats.cwnd_bytes
                        .map(|cwnd| format!("{:>9}", format_bytes(cwnd)))
                        .unwrap_or_else(|| "N/A".to_string());
                        
                    let lost_str = current_stats.lost_packets
                        .map(|lost| {
                            let last_lost = last_stats.lost_packets.unwrap_or(0);
                            format!("{:<5}", lost.saturating_sub(last_lost))
                        })
                        .unwrap_or_else(|| "N/A".to_string());
                        
                    let mtu_str = current_stats.mtu_bytes
                        .map(|mtu| format!("{} B", mtu))
                        .unwrap_or_else(|| "N/A".to_string());

                    let statistic = format!(
                        "\n\
                            [STATS] Session time: {:.1} min\n\
                            [+] Path: RTT: {} | Cwnd: {} | Lost (Tx): {} | MTU: {}\n\
                            [+] Speed (Rx/Tx): {:>6.2} / {:>6.2} Mbps (avg for last interval)\n\
                            [+] Total Rx: {:>12} | Datagrams: {}\n\
                            [+] Total Tx: {:>12} | Datagrams: {}",
                        elapsed_since_start / 60.0,
                        rtt_str,
                        cwnd_str,
                        lost_str,
                        mtu_str,
                        rx_mbps.max(0.0),
                        tx_mbps.max(0.0),
                        format_bytes(current_stats.total_rx_bytes),
                        current_stats.total_rx_packets,
                        format_bytes(current_stats.total_tx_bytes),
                        current_stats.total_tx_packets,
                    );
                    info!("{}", statistic);
                    status(statistic);
                    last_stats = current_stats;
                }
                _ = shutdown_notify.notified() => {
                    break;
                }
            }
        }
        info!("[STATS] Connection closed, stopping stats monitor.");
    })
}
