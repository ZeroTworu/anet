include!(concat!(env!("OUT_DIR"), "/built.rs"));

use anet_client_cli::tun_factory::DesktopTunFactory;
use anet_client_core::client::AnetClient;
use anet_client_core::config::CoreConfig;
use anet_client_core::platform::{create_route_manager, requires_elevated_privileges};
use anyhow::Result;
use clap::Parser;
use log::{error, info};
use std::process::exit;
use std::sync::Arc;
use tokio::fs::read_to_string;
use tokio::signal;

fn format_banner_row(label: &str, value: &str) -> String {
    let prefix = format!("║                   {:<13}", label);
    let total_content_width = 63;
    let prefix_len = prefix.chars().count() - 1; // excluding '║'
    let val_space = total_content_width.saturating_sub(prefix_len);
    let val_chars_count = value.chars().count();
    if val_chars_count > val_space {
        let truncated: String = value.chars().take(val_space.saturating_sub(3)).collect();
        format!("{}{:<width$}║", prefix, format!("{}...", truncated), width = val_space)
    } else {
        let pad = val_space - val_chars_count;
        format!("{}{}{}║", prefix, value, " ".repeat(pad))
    }
}

fn generate_ascii_art(tag: &str, build_type: &str, commit_hash: &str, build_time: &str) -> String {
    let row_version = format_banner_row("Version:", tag);
    let row_build_type = format_banner_row("Build Type:", build_type);
    let row_commit_hash = format_banner_row("Commit Hash:", commit_hash);
    let row_build_time = format_banner_row("Build Time:", build_time);

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
                    {}
                    {}
                    {}
                    {}
                    ║                                                               ║
                    ╚═══════════════════════════════════════════════════════════════╝
"#,
        row_version, row_build_type, row_commit_hash, row_build_time
    )
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info,rtc::peer_connection::handler=error"),
    )
    .init();

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
            !config.main.per_app.is_empty(),
        ));
    let client = Arc::new(AnetClient::new(config, tun_fac, route_mgr));


    let client_for_task = client.clone();
    let mut run_task = tokio::spawn(async move {
        if let Err(e) = client_for_task.start().await {
            error!("VPN connection loop exited with error: {}", e);
        }
    });

    info!("VPN Running. Press Ctrl+C to stop.");

    tokio::select! {
        res = &mut run_task => {
            // Цикл подключения завершился сам по себе (например, ошибка
            // конфигурации ещё до первого коннекта) — ждать Ctrl+C уже нечего.
            if let Err(e) = res {
                error!("VPN task panicked: {}", e);
            }
            exit(1);
        }
        ctrlc_result = signal::ctrl_c() => {
            ctrlc_result?;
            info!("Ctrl+C received. Stopping VPN and restoring system state...");
            client.stop().await?;
            let _ = run_task.await;
        }
    }

    Ok(())
}

#[derive(Debug, Parser)]
pub struct Opt { #[clap(short, long, default_value = "./client.toml")] cfg: String }
async fn load() -> anyhow::Result<CoreConfig> {
    let opt = Opt::parse();
    let toml_str = read_to_string(&opt.cfg).await?;
    Ok(toml::from_str(&toml_str)?)
}
