include!(concat!(env!("OUT_DIR"), "/built.rs"));

use anet_client_cli::tun_factory::DesktopTunFactory;
use anet_client_core::client::AnetClient;
use anet_client_core::config::CoreConfig;
use anet_client_core::platform::{create_route_manager, requires_elevated_privileges};
use anyhow::Result;
use clap::Parser;
use log::{error, info, warn};
use std::process::exit;
use tokio::fs::read_to_string;
use tokio::signal;


/// Check if the current process has elevated privileges (root/admin)
fn check_privileges() -> bool {
    #[cfg(unix)]
    {
        // On Unix systems, check if running as root (UID 0)
        unsafe { libc::geteuid() == 0 }
    }

    #[cfg(windows)]
    {
        // On Windows, we don't require elevation for wintun
        // The driver handles privilege escalation
        true
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
                    ╠═══════════════════════════════════════════════════════════════╣
                    ║                                                               ║
                    ║                   Build Type: {:<16}                ║
                    ║                   Commit Hash: {:<16}               ║
                    ║                   Build Time:  {:<19}            ║
                    ║                                                               ║
                    ║                                                               ║
                    ╚═══════════════════════════════════════════════════════════════╝
"#,
        build_type_display, commit_hash_display, build_time_display
    )
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Check for elevated privileges on platforms that require it
    if requires_elevated_privileges() && !check_privileges() {
        error!("This program requires elevated privileges (root/sudo).");
        error!("Please run with: sudo ./anet-client -c <config.toml>");
        #[cfg(target_os = "macos")]
        error!("On macOS, you need root access to create TUN interfaces and modify routes.");
        #[cfg(target_os = "linux")]
        error!("On Linux, you need root access to create TUN interfaces and modify routes.");
        exit(1);
    }

    if let Err(e) = rustls::crypto::ring::default_provider().install_default() {
        warn!("Failed to install default crypto provider: {:?}", e);
        // Продолжаем, так как Quinn может использовать свой
    }
    let config = load().await?;

    let ascii_art = generate_ascii_art(BUILD_TYPE, COMMIT_HASH, BUILD_TIME);
    println!("{}", ascii_art);

    let route_mgr = create_route_manager(config.main.manual_routing)?;
    let cfg = config.clone();
    let tun_fac = Box::new(DesktopTunFactory::new(
        config.main.tun_name,
        config.main.dns_server_list.clone(),
    ));
    let client = AnetClient::new(cfg, tun_fac, route_mgr);

    client.start().await?;

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
