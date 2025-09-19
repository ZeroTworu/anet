include!(concat!(env!("OUT_DIR"), "/built.rs"));
use anet_client::client::ANetClient;
use anet_client::config::load;
use anyhow::Result;
use log::info;

#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};

#[cfg(unix)]
use anet_client::lrm::LinuxRouteManager;

#[cfg(windows)]
use tokio::signal::windows::ctrl_c;

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

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let ascii_art = generate_ascii_art(BUILD_TYPE, COMMIT_HASH, BUILD_TIME);
    println!("{}", ascii_art);
    let cfg = load().await?;
    let client = ANetClient::new(&cfg)?;

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

    #[cfg(unix)]
    let mut sig = signal(SignalKind::terminate())?;

    #[cfg(windows)]
    let mut sig = ctrl_c()?;

    info!("Press Ctrl-C to exit.");

    sig.recv().await;

    #[cfg(unix)]
    linux_router.restore_original_routing()?;

    info!("Shutting down...");
    Ok(())
}
