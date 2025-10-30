// Файл: anet-common/src/quic_settings.rs

use anyhow::Result;
use log::info;
use quinn::congestion::{BbrConfig, ControllerFactory, CubicConfig};
use quinn::{MtuDiscoveryConfig, TransportConfig, VarInt, IdleTimeout};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};

const BDP_FACTOR: u64 = 5;
const MTU_MAX_UPPER_BOUND: u16 = 1500;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct QuicConfig {
    /// Preferred congestion control algorithm (BBR or CUBIC)
    pub algorithm: String,

    /// Estimated Round Trip Time in milliseconds. Used to calculate optimal windows.
    pub expected_rtt_ms: u32,

    /// Bandwidth in Mbits/s used for dynamic window calculation (optional override)
    pub bandwidth_mbps: Option<u32>,

    /// Stream flow control window size (bytes). If 0, calculated automatically based on RTT/BW.
    pub stream_receive_window: u64,

    /// Connection flow control window size (bytes). If 0, calculated automatically based on RTT/BW.
    pub receive_window: u64,

    pub enable_gso: bool,

    /// Таймаут
    pub idle_timeout_seconds: Option<u64>,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            algorithm: "bbr".to_string(),
            expected_rtt_ms: 60, // Уфа -> Франкфурт
            bandwidth_mbps: Some(200),
            // ~10 MiB для 6x BDP
            stream_receive_window: 10_485_760, // 10 MiB
            // ~40 MiB
            receive_window: 41_943_040, // 40 MiB
            enable_gso: true,
            idle_timeout_seconds: Some(3600),
        }
    }
}

/// Строит готовый quinn::TransportConfig на основе настроек.
pub fn build_transport_config(cfg: &QuicConfig, mtu: u16) -> Result<TransportConfig> {
    let mut config = TransportConfig::default();

    let expected_rtt_ms = cfg.expected_rtt_ms.max(1);
    let rtt_duration = Duration::from_millis(expected_rtt_ms as u64);

    // Выбор алгоритма контроля перегрузки
    let factory: Arc<dyn ControllerFactory + Send + Sync> =
        match cfg.algorithm.to_lowercase().as_str() {
            "bbr" => {
                info!("QUIC Transport using BBR Congestion Control.");

                // Используем явное преобразование Box<T> -> Arc<dyn Trait>
                let bbr_config_box: Box<dyn ControllerFactory + Send + Sync> =
                    Box::new(BbrConfig::default());
                bbr_config_box.into()
            }
            "cubic" | _ => {
                info!("QUIC Transport using CUBIC Congestion Control.");
                let cubic_config_box: Box<dyn ControllerFactory + Send + Sync> =
                    Box::new(CubicConfig::default());
                cubic_config_box.into()
            }
        };

    // Приведение Box<ControllerFactory> к Arc<dyn ControllerFactory + Send + Sync>
    config.congestion_controller_factory(factory);
    config.initial_rtt(rtt_duration);
    config.enable_segmentation_offload(cfg.enable_gso);

    // Расчет окон BDP (остальной код без изменений)
    let final_stream_window = if cfg.stream_receive_window > 0 {
        cfg.stream_receive_window
    } else {
        let bandwidth_bytes_per_sec = cfg.bandwidth_mbps.unwrap_or(200) as u64 * 125_000;
        let bdp_bytes = (bandwidth_bytes_per_sec / 1000) * expected_rtt_ms as u64;

        // BDP * FACTOR / 10 (как было задумано в предыдущей версии)
        (bdp_bytes.max(2 * 1024 * 1024) * BDP_FACTOR) / 5
    };

    let final_conn_window = if cfg.receive_window > 0 {
        cfg.receive_window
    } else {
        final_stream_window.max(8_388_608) * 4
    };

    // Применяем Flow Control
    info!(
        "QUIC Transport: Flow Control Windows (Stream/Conn) = {} / {} bytes, RTT = {}",
        final_stream_window, final_conn_window, expected_rtt_ms
    );
    config
        .stream_receive_window(VarInt::from_u64(final_stream_window)?)
        .receive_window(VarInt::from_u64(final_conn_window)?)
        .send_window(final_stream_window * 2);

    // Настройка MTU Discovery
    let mut mtu_config = MtuDiscoveryConfig::default();
    mtu_config.upper_bound(MTU_MAX_UPPER_BOUND);

    config
        .initial_mtu(mtu.into())
        .mtu_discovery_config(Some(mtu_config));

    if let Some(timeout_secs) = cfg.idle_timeout_seconds {
        if timeout_secs > 0 {
            let timeout_duration = Duration::from_secs(timeout_secs);
            let timeout = IdleTimeout::try_from(timeout_duration)
                .map_err(|e| anyhow::anyhow!("Invalid idle timeout value: {}", e))?;
            config.max_idle_timeout(Some(timeout));
            info!("QUIC Transport: Max Idle Timeout set to {} seconds.", timeout_secs);
        }

    }
    Ok(config)
}
