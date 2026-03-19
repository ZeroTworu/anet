use std::time::Duration;
use log::info;
use quinn::Connection;
use tokio::time::sleep;
use crate::events::status;

const KIB: f64 = 1024.0;
const MIB: f64 = 1024.0 * 1024.0;
const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

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


pub fn start_stats_monitor(connection: Connection, interval_minutes: u64) {
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
        let mut last_stats = connection.stats();
        let start_time = std::time::Instant::now();
        loop {
            sleep(interval).await;
            if connection.close_reason().is_some() {
                break;
            }

            let current_stats = connection.stats();
            let elapsed_since_start = (std::time::Instant::now() - start_time)
                .as_secs_f64()
                .max(1.0);

            let rx_bytes_delta = current_stats
                .udp_rx
                .bytes
                .saturating_sub(last_stats.udp_rx.bytes);
            let tx_bytes_delta = current_stats
                .udp_tx
                .bytes
                .saturating_sub(last_stats.udp_tx.bytes);
            let interval_secs = interval.as_secs_f64();
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

            let path = &current_stats.path;

            let statistic = format!(
                "\n\
                    [STATS] Session time: {:.1} min\n\
                    [+] Path: RTT: {:>6.2}ms | Cwnd: {:>9} | Lost (Tx): {:<5} | MTU: {} B\n\
                    [+] Speed (Rx/Tx): {:>6.2} / {:>6.2} Mbps (avg for last interval)\n\
                    [+] Total Rx: {:>12} | Datagrams: {}\n\
                    [+] Total Tx: {:>12} | Datagrams: {}",
                elapsed_since_start / 60.0,
                path.rtt.as_secs_f64() * 1000.0,
                format_bytes(path.cwnd),
                path.lost_packets - last_stats.path.lost_packets,
                path.current_mtu,
                rx_mbps.max(0.0),
                tx_mbps.max(0.0),
                format_bytes(current_stats.udp_rx.bytes),
                current_stats.udp_rx.datagrams,
                format_bytes(current_stats.udp_tx.bytes),
                current_stats.udp_tx.datagrams,
            );
            info!("{}", statistic);
            status(statistic);
            last_stats = current_stats;
        }
        info!("[STATS] Connection closed, stopping stats monitor.");
    });
}
