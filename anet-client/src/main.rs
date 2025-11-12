include!(concat!(env!("OUT_DIR"), "/built.rs"));

use anet_client::client::ANetClient;
use anet_client::config::load;
use anyhow::Result;
use log::{error, info, warn};
use std::time::Duration;

#[cfg(unix)]
use anet_client::linux_router::LinuxRouteManager;

#[cfg(windows)]
use anet_client::windows_router::WindowsRouteManager;
use anet_common::atun::TunManager;
use anet_common::tun_params::TunParams;

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
    if let Err(e) = rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|e| anyhow::anyhow!("Failed to install crypto provider: {:?}", e))
    {
        warn!("{}", e);
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    let ascii_art = generate_ascii_art(BUILD_TYPE, COMMIT_HASH, BUILD_TIME);
    println!("{}", ascii_art);

    let cfg = load().await;
    let cfg = match cfg {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Error on reade config: {}", e);
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    };

    let client = ANetClient::new(&cfg);
    let client = match client {
        Ok(client) => client,
        Err(e) => {
            error!("Error on create ANet Client: {}", e);
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    };

    let server_ip_str = cfg.main.address.split(':').next().unwrap().to_string();

    // --- DH АУТЕНТИФИКАЦИЯ (Возвращает (AuthResponse, SharedKey)) ---
    let auth_result = client.authenticate().await;

    let (auth_response, shared_key) = match auth_result {
        Ok(res) => res,
        Err(e) => {
            error!("Error on auth: {}", e);
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    };

    #[cfg(unix)]
    let mut linux_router = LinuxRouteManager::new(&auth_response.gateway.as_str(), server_ip_str);

    #[cfg(windows)]
    let mut windows_router =
        WindowsRouteManager::new(&auth_response.gateway.as_str(), server_ip_str);

    let tun_params = TunParams::from_auth_response(&auth_response, "anet-client");
    let tun_manager = TunManager::new(tun_params);
    let tun_manager = match tun_manager {
        Ok(tun_manager) => tun_manager,
        Err(e) => {
            error!("Error on create TunManager: {}", e);
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    };

    // Меняем роутинг
    #[cfg(unix)]
    {
        linux_router.backup_original_routes()?;
        linux_router.setup_vpn_routing()?;
    }

    #[cfg(windows)]
    windows_router.setup_vpn_routing()?;

    // ПЕРЕДАЧА DH КЛЮЧА В QUIC
    let endpoint = client
        .run_quic_vpn(&auth_response, &tun_manager, shared_key)
        .await;

    match endpoint {
        Ok(endpoint) => {
            info!("Press Ctrl-C to exit.");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = endpoint.wait_idle() => {},
            }

            #[cfg(unix)]
            linux_router.restore_original_routing();
            #[cfg(windows)]
            windows_router.restore_original_routing();

            info!("Shutdown");
            Ok(())
        }
        Err(e) => {
            error!("Error on start up: {}", e);

            #[cfg(unix)]
            linux_router.restore_original_routing();
            #[cfg(windows)]
            windows_router.restore_original_routing();

            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}
