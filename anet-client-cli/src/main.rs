include!(concat!(env!("OUT_DIR"), "/built.rs"));

use anet_client_cli::tun_factory::DesktopTunFactory;
use anet_client_core::client::AnetClient;
use anet_client_core::config::CoreConfig;
use anet_client_core::platform::{create_route_manager, requires_elevated_privileges};
use anyhow::Result;
use clap::Parser;
use log::{error, info};
use std::process::exit;
use tokio::fs::read_to_string;
use tokio::signal;

fn generate_ascii_art(tag: &str, build_type: &str, commit_hash: &str, build_time: &str) -> String {
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
                    ║                   Version:     {:<16}               ║
                    ║                   Build Type:  {:<16}               ║
                    ║                   Commit Hash: {:<16}               ║
                    ║                   Build Time:  {:<19}            ║
                    ║                                                               ║
                    ╚═══════════════════════════════════════════════════════════════╝
"#,
        tag, build_type, commit_hash, build_time
    )
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Проверка прав
    #[cfg(unix)]
    if unsafe { libc::geteuid() != 0 } && requires_elevated_privileges() {
        error!("ALCO-NET требует прав root (sudo).");
        exit(1);
    }

    let config = load().await?;

    // Вывод арта с тегом
    println!("{}", generate_ascii_art(GIT_TAG, BUILD_TYPE, COMMIT_HASH, BUILD_TIME));

    let route_mgr = create_route_manager(config.main.manual_routing)?;
    let tun_fac = Box::new(
        DesktopTunFactory::new(
            config.main.tun_name.clone(),
        ));
    let client = AnetClient::new(config, tun_fac, route_mgr);

    if let Err(e) = client.start().await {
        error!("Handshake Failed: {}", e);
        exit(1);
    }

    info!("VPN Running. Press Ctrl+C to stop.");
    signal::ctrl_c().await?;
    client.stop().await?;
    Ok(())
}

#[derive(Debug, Parser)]
pub struct Opt { #[clap(short, long, default_value = "./client.toml")] cfg: String }
async fn load() -> anyhow::Result<CoreConfig> {
    let opt = Opt::parse();
    let toml_str = read_to_string(&opt.cfg).await?;
    Ok(toml::from_str(&toml_str)?)
}
