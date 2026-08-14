// Файл: anet-common/src/quic_settings.rs

use anyhow::Result;
use log::info;
use quinn::congestion::{BbrConfig, ControllerFactory, CubicConfig};
use quinn::{IdleTimeout, MtuDiscoveryConfig, TransportConfig, VarInt};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};

const BYTES_IN_MEGABIT: u64 = 125_000;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct QuicConfig {
    pub algorithm: String,
    pub expected_rtt_ms: u32,

    // ИЗМЕНЕНО: Разделяем пропускную способность для более точного расчета
    /// Bandwidth for incoming traffic (e.g., download speed).
    pub bandwidth_down_mbps: u32,
    /// Bandwidth for outgoing traffic (e.g., upload speed).
    pub bandwidth_up_mbps: u32,

    // ИЗМЕНЕНО: Разделяем окна, делаем их опциональными
    /// Stream receive window size (bytes). If not set, calculated automatically.
    pub stream_receive_window: Option<u64>,
    /// Connection receive window size (bytes). If not set, calculated automatically.
    pub receive_window: Option<u64>,
    /// Connection send window size (bytes). If not set, calculated automatically.
    pub send_window: Option<u64>,

    pub max_mtu: u16,

    pub enable_gso: bool,
    pub idle_timeout_seconds: Option<u64>,
    pub keep_alive_interval_seconds: Option<u64>,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            algorithm: "bbr".to_string(),
            expected_rtt_ms: 60,
            bandwidth_down_mbps: 200, // Значения по умолчанию
            bandwidth_up_mbps: 100,
            stream_receive_window: None,
            receive_window: None,
            send_window: None,
            enable_gso: true,
            idle_timeout_seconds: Some(3600),
            max_mtu: 1500,
            keep_alive_interval_seconds: Some(20),
        }
    }
}

/// Helper to calculate window size based on BDP.
/// BDP = bandwidth (bytes/sec) * RTT (sec)
/// We use BDP * 2.5 as a common recommendation for window size.
fn calculate_window_from_bdp(mbps: u32, rtt_ms: u32) -> u64 {
    let bandwidth_bytes_per_sec = mbps as u64 * BYTES_IN_MEGABIT;
    let rtt_seconds_float = rtt_ms as f64 / 1000.0;
    let bdp = (bandwidth_bytes_per_sec as f64 * rtt_seconds_float) as u64;

    // Window should be at least 2-3x BDP. Let's take 2.5x.
    // Also, ensure a reasonable minimum window size (e.g., 1MB).
    (bdp * 5 / 2).max(1_048_576)
}

pub fn build_transport_config(cfg: &QuicConfig, mtu: u16) -> Result<TransportConfig> {
    let mut config = TransportConfig::default();
    let rtt_duration = Duration::from_millis(cfg.expected_rtt_ms.max(1) as u64);

    let final_receive_window = cfg
        .receive_window
        .unwrap_or_else(|| calculate_window_from_bdp(cfg.bandwidth_down_mbps, cfg.expected_rtt_ms));

    let final_send_window = cfg
        .send_window
        .unwrap_or_else(|| calculate_window_from_bdp(cfg.bandwidth_up_mbps, cfg.expected_rtt_ms));

    // The VPN uses one long-lived bidirectional stream, so its flow-control window must not
    // become the connection bottleneck.
    let final_stream_receive_window = cfg.stream_receive_window.unwrap_or(final_receive_window);

    let factory: Arc<dyn ControllerFactory + Send + Sync> =
        match cfg.algorithm.to_lowercase().as_str() {
            "bbr" => {
                info!("QUIC Transport using BBR Congestion Control.");
                Arc::new(BbrConfig::default())
            }
            _ => {
                // "cubic" or default
                info!("QUIC Transport using CUBIC Congestion Control.");
                Arc::new(CubicConfig::default())
            }
        };

    config.congestion_controller_factory(factory);
    config.initial_rtt(rtt_duration);
    // The encrypted UDP adapter advertises one datagram per transmit. A GSO super-packet cannot
    // be encrypted as one datagram without changing QUIC packet boundaries.
    config.enable_segmentation_offload(false);
    if cfg.enable_gso {
        info!("QUIC GSO disabled: the encrypted UDP adapter requires per-datagram nonces.");
    }

    // --- ПРИМЕНЯЕМ РАЗДЕЛЬНЫЕ ОКНА ---
    info!(
        "QUIC Transport Windows: Recv (Conn/Stream) = {} / {} bytes. Send = {} bytes. RTT = {}",
        final_receive_window, final_stream_receive_window, final_send_window, cfg.expected_rtt_ms
    );
    config
        .receive_window(VarInt::from_u64(final_receive_window)?)
        .stream_receive_window(VarInt::from_u64(final_stream_receive_window)?)
        .send_window(final_send_window);

    // Настройка MTU Discovery
    let envelope_limit =
        (crate::consts::PADDING_MTU - crate::consts::TRANSPORT_ENVELOPE_OVERHEAD) as u16;
    let initial_mtu = mtu.min(envelope_limit).max(1200);
    let max_mtu = cfg.max_mtu.min(envelope_limit).max(initial_mtu);
    let mut mtu_config = MtuDiscoveryConfig::default();
    mtu_config.upper_bound(max_mtu);
    config
        .initial_mtu(initial_mtu)
        .mtu_discovery_config(Some(mtu_config));
    info!(
        "QUIC MTU: initial {}, discovery ceiling {} ({} bytes reserved for encryption).",
        initial_mtu,
        max_mtu,
        crate::consts::TRANSPORT_ENVELOPE_OVERHEAD
    );

    // Таймаут
    if let Some(timeout_secs) = cfg.idle_timeout_seconds
        && timeout_secs > 0
    {
        let timeout = IdleTimeout::try_from(Duration::from_secs(timeout_secs))?;
        config.max_idle_timeout(Some(timeout));
        info!(
            "QUIC Transport: Max Idle Timeout set to {} seconds.",
            timeout_secs
        );
    }

    // Настройка Keep-Alive (Пингов) во избежание протухания NAT-таблиц провайдеров
    if let Some(interval_secs) = cfg.keep_alive_interval_seconds
        && interval_secs > 0
    {
        config.keep_alive_interval(Some(Duration::from_secs(interval_secs)));
        info!(
            "QUIC Transport: Keep-Alive Interval set to {} seconds.",
            interval_secs
        );
    }

    Ok(config)
}
