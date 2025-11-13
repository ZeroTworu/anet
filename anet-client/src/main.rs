include!(concat!(env!("OUT_DIR"), "/built.rs"));

use anet_client::client::ANetClient;
use anet_client::config::load;
use anet_client::router::RouteManager;
use anyhow::Result;
use log::{error, info, warn};

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
        error!("Failed to install crypto provider: {:?}", e);
    }

    let ascii_art = generate_ascii_art(BUILD_TYPE, COMMIT_HASH, BUILD_TIME);
    println!("{}", ascii_art);

    let cfg = load().await?;
    let client = ANetClient::new(&cfg)?;
    let server_ip_str = cfg.main.address.split(':').next().unwrap().to_string();

    let (auth_response, shared_key) = client.authenticate().await?;

    let mut router = RouteManager::new(server_ip_str);

    #[cfg(unix)]
    router.backup_original_routes()?;

    router.setup_exclusion_route()?;

    let endpoint_result = client.run_quic_vpn(&auth_response, shared_key).await;

    if endpoint_result.is_ok() {
        #[cfg(unix)]
        {
            if let Err(e) =
                router.set_vpn_as_default_gateway(&auth_response.gateway, &cfg.main.tun_name)
            {
                error!("CRITICAL: Failed to set VPN as default gateway: {}", e);
                router.restore_routing()?;
                return Err(e);
            }
        }
    }

    match endpoint_result {
        Ok(endpoint) => {
            info!("VPN is running. Press Ctrl-C to exit.");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => info!("Ctrl-C received. Shutting down."),
                _ = endpoint.wait_idle() => warn!("Connection lost. Exiting."),
            }
        }
        Err(e) => {
            error!("Error starting VPN operation: {}", e);
        }
    }

    // ЭТАП 4: Восстановление маршрутов при выходе.
    router.restore_routing()?;

    info!("Shutdown complete.");
    Ok(())
}
