include!(concat!(env!("OUT_DIR"), "/built.rs"));
use anet_client::client::ANetClient;
use anet_client::config::{load, Config};
use anyhow::Result;
use log::{info, warn};
use tokio::signal;

#[cfg(unix)]
use anet_client::lrm::LinuxRouteManager;

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

    let ascii_art = generate_ascii_art(BUILD_TYPE, COMMIT_HASH, BUILD_TIME);
    println!("{}", ascii_art);

    let cfg = load().await?;
    let client = ANetClient::new(&cfg)?;

    configure_tcp_settings(&cfg).await?;

    let params = client.connect().await?;

    #[cfg(unix)]
    let mut linux_router = LinuxRouteManager::new(
        &params,
        cfg.address.split(':').collect::<Vec<&str>>()[0].to_string(),
    );

    #[cfg(unix)]
    linux_router.backup_original_routes()?;

    #[cfg(unix)]
    linux_router.setup_vpn_routing()?;

    info!("Press Ctrl-C to exit.");
    signal::ctrl_c().await?;

    #[cfg(unix)]
    linux_router.restore_original_routing()?;

    info!("Shutting down...");
    Ok(())
}

async fn configure_tcp_settings(cfg: &Config) -> Result<()> {
    // Windows TCP настройки
    #[cfg(windows)]
    {
        if !cfg.windows_tcp.enable_tcp_tuning {
            info!("Windows TCP tuning is disabled in config");
            return Ok(());
        }

        use anet_client::windows_tcp_tuner::WindowsTcpTuner;

        info!("Detecting current TCP congestion control on Windows...");
        match WindowsTcpTuner::get_current_algorithm() {
            Ok(algo) => info!("Current TCP algorithm: {}", algo),
            Err(e) => warn!("Could not detect TCP algorithm: {}", e),
        }

        info!("Setting TCP congestion control to {}...", cfg.windows_tcp.congestion_algorithm);
        if let Err(e) = WindowsTcpTuner::set_congestion_control(&cfg.windows_tcp.congestion_algorithm) {
            warn!("Failed to set TCP congestion control: {}", e);
            warn!("This is not critical, but may affect performance");
        } else {
            info!("Successfully configured Windows TCP settings");
        }
    }

    // Unix/Linux TCP настройки
    #[cfg(unix)]
    {
        if !cfg.unix_tcp.enable_tcp_tuning {
            info!("Unix TCP tuning is disabled in config");
            return Ok(());
        }

        use anet_client::unix_tcp_tuner::UnixTcpTuner;

        info!("Detecting current TCP congestion control on Unix...");
        match UnixTcpTuner::get_current_algorithm() {
            Ok(algo) => info!("Current TCP algorithm: {}", algo),
            Err(e) => warn!("Could not detect TCP algorithm: {}", e),
        }

        match UnixTcpTuner::get_available_algorithms() {
            Ok(algorithms) => info!("Available TCP algorithms: {:?}", algorithms),
            Err(e) => warn!("Could not get available algorithms: {}", e),
        }

        // Пытаемся установить предпочтительный алгоритм
        info!("Attempting to set preferred algorithm: {}...", cfg.unix_tcp.preferred_algorithm);
        if let Err(e) = UnixTcpTuner::set_congestion_control(&cfg.unix_tcp.preferred_algorithm) {
            warn!("Failed to set preferred algorithm: {}", e);

            // Fallback на резервный алгоритм
            info!("Attempting fallback to: {}...", cfg.unix_tcp.fallback_algorithm);
            if let Err(e) = UnixTcpTuner::set_congestion_control(&cfg.unix_tcp.fallback_algorithm) {
                warn!("Failed to set fallback algorithm: {}", e);
            } else {
                info!("Successfully configured TCP with fallback algorithm");
            }
        } else {
            info!("Successfully configured TCP with preferred algorithm");
        }

        // Проверяем финальные настройки
        match UnixTcpTuner::get_current_algorithm() {
            Ok(algo) => info!("Final TCP algorithm: {}", algo),
            Err(e) => warn!("Could not verify final TCP algorithm: {}", e),
        }
    }

    Ok(())
}
