include!(concat!(env!("OUT_DIR"), "/built.rs"));
use anet_client::client::ANetClient;
use anet_client::config::load;
use anyhow::Result;
use log::info;

#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
#[cfg(windows)]
use tokio::signal::windows::ctrl_c;

fn generate_ascii_art(build_type: &str, commit_hash: &str, build_time: &str) -> String {
    format!(
        r#"
        ╔═══════════════════════════════════════════════════════════════╗
        ║                                                               ║
        ║               █████╗ ███╗   ██╗███████╗████████╗              ║
        ║               ██╔══██╗████╗  ██║██╔════╝╚══██╔══╝             ║
        ║               ███████║██╔██╗ ██║█████╗     ██║                ║
        ║               ██╔══██║██║╚██╗██║██╔══╝     ██║                ║
        ║               ██║  ██║██║ ╚████║███████╗   ██║                ║
        ║               ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝                ║
        ║                                                               ║
        ╠═══════════════════════════════════════════════════════════════╣
        ║                                                               ║
        ║                   Build Type: {:16}                           ║
        ║                   Commit Hash: {:16}                          ║
        ║                   Build Time:  {:16}                          ║
        ║                                                               ║
        ║           >> Welcome to the digital revolution! <<            ║
        ║                                                               ║
        ╚═══════════════════════════════════════════════════════════════╝
"#,
        build_type, commit_hash, build_time
    )
}



#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let ascii_art = generate_ascii_art(BUILD_TYPE, COMMIT_HASH, BUILD_TIME);
    println!("{}", ascii_art);
    let cfg = load().await?;
    let client = ANetClient::new(&cfg)?;
    client.connect().await?;

    #[cfg(unix)]
    let mut sig = signal(SignalKind::terminate())?;
    #[cfg(windows)]
    let mut sig = ctrl_c()?;
    info!("Press Ctrl-C to exit.");

    sig.recv().await;
    info!("Shutting down...");
    Ok(())
}
