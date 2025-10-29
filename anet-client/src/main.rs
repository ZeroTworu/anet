include!(concat!(env!("OUT_DIR"), "/built.rs"));
use anet_client::client::ANetClient;
use anet_client::config::load;
use anyhow::Result;
use log::{info, warn};

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
    if let Err(e) = rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|e| anyhow::anyhow!("Failed to install crypto provider: {:?}", e))
    {
        warn!("{}", e);
        // Можно запустить процесс дальше, но проблема в том, что build() падает
        // Return Err(e) if crucial. Here, we must prevent panic.
    }

    let ascii_art = generate_ascii_art(BUILD_TYPE, COMMIT_HASH, BUILD_TIME);
    println!("{}", ascii_art);

    let cfg = load().await?;
    let client = ANetClient::new(&cfg)?;

    let (params, endpoint) = client.connect().await?;

    #[cfg(unix)]
    let mut linux_router = LinuxRouteManager::new(
        &params,
        cfg.main.address.split(':').collect::<Vec<&str>>()[0].to_string(),
    );

    #[cfg(unix)]
    {
        linux_router.backup_original_routes()?;
        linux_router.setup_vpn_routing()?;
    }

    info!("Press Ctrl-C to exit.");
    endpoint.wait_idle().await;

    #[cfg(unix)]
    linux_router.restore_original_routing()?;

    info!("Shutting down...");
    Ok(())
}
