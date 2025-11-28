include!(concat!(env!("OUT_DIR"), "/built.rs"));

use anet_client_cli::router::DesktopRouteManager;
use anet_client_cli::tun_factory::DesktopTunFactory;
use anet_client_core::AnetClient;
use anet_client_core::config::CoreConfig;
use anyhow::Result;
use clap::Parser;
use log::{info, warn};
use quinn::Connection;
use std::process::exit;
use std::time::Duration;
use tokio::fs::read_to_string;
use tokio::signal;
use tokio::time::sleep;

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

fn generate_ascii_art(build_type: &str, commit_hash: &str, build_time: &str) -> String {
    // Обрезаем строки до нужной длины, чтобы они помещались в рамку
    let build_type_display = if build_type.len() > 10 {
        &build_type[..10]
    } else {
        build_type
    };
    let commit_hash_display = if commit_hash.len() > 7 {
        &commit_hash[..7]
    } else {
        commit_hash
    };
    let build_time_display = if build_time.len() > 19 {
        &build_time[..19]
    } else {
        build_time
    };

    format!(
        r#"
                    ╔═══════════════════════════════════════════════════════════════╗
                    ║                                                               ║
                    ║                 █████╗ ███╗   ██╗███████╗████████╗            ║
                    ║                 ██╔══██╗████╗  ██║██╔════╝╚══██╔══╝           ║
                    ║                 ███████║██╔██╗ ██║█████╗     ██║              ║
                    ║                 ██╔══██║██║╚██╗██║██╔══╝     ██║              ║
                    ║                 ██║  ██║██║ ╚████║███████╗   ██║              ║
                    ║                 ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝              ║
                    ║                           by Hanyuufag                        ║
                    ╠═══════════════════════════════════════════════════════════════╣
                    ║                                                               ║
                    ║                   Build Type: {:<16}                ║
                    ║                   Commit Hash: {:<16}               ║
                    ║                   Build Time:  {:<19}            ║
                    ║                                                               ║
                    ║               >> Welcome to the digital revolution! <<        ║
                    ║                                                               ║
                    ╚═══════════════════════════════════════════════════════════════╝
"#,
        build_type_display, commit_hash_display, build_time_display
    )
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    if let Err(e) = rustls::crypto::ring::default_provider().install_default() {
        warn!("Failed to install default crypto provider: {:?}", e);
        // Продолжаем, так как Quinn может использовать свой
    }
    let config = load().await?;

    let ascii_art = generate_ascii_art(BUILD_TYPE, COMMIT_HASH, BUILD_TIME);
    println!("{}", ascii_art);

    let route_mgr = Box::new(DesktopRouteManager::new());
    let cfg = config.clone();
    let tun_fac = Box::new(DesktopTunFactory::new(config.main.tun_name));
    let client = AnetClient::new(cfg, tun_fac, route_mgr);

    client.start().await?;

    if config.stats.enabled {
        start_stats_monitor(client.get_stats().unwrap(), config.stats.interval_minutes);
    }

    info!("VPN Running. Press Ctrl+C to stop.");
    signal::ctrl_c().await?;
    info!("Received Ctrl+C. Shutting down...");

    client.stop().await?;

    Ok(())
}

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long, default_value = "./client.toml")]
    cfg: String,
}
async fn load() -> anyhow::Result<CoreConfig> {
    let opt = Opt::parse();
    let toml_str = read_to_string(&opt.cfg).await;

    match toml_str {
        Ok(toml_str) => {
            let cfg: CoreConfig = toml::from_str(&toml_str)?;
            Ok(cfg)
        }
        Err(_) => {
            warn!(
                "\n\
                Cannot find client config file in {}, use '-c' or '--cfg' \n\
                './anet-client -c /home/anet/anet/config.toml' for example,
                ",
                opt.cfg,
            );
            exit(-1)
        }
    }
}

fn start_stats_monitor(connection: Connection, interval_minutes: u64) {
    info!(
        "[STATS] Monitor enabled. Interval: {} minute(s).",
        interval_minutes
    );
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

            info!(
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
            last_stats = current_stats;
        }
        info!("[STATS] Connection closed, stopping stats monitor.");
    });
}
