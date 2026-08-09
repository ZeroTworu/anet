use anet_client_core::traits::TunFactory;
use anet_common::atun::TunManager;
use anet_common::protocol::AuthResponse;
use anet_common::tun_params::TunParams;
use anyhow::Result;
use bytes::Bytes;
use tokio::sync::mpsc;

pub struct DesktopTunFactory {
    tun_name: String,
}

impl DesktopTunFactory {
    pub fn new(tun_name: String) -> Self {
        Self { tun_name }
    }
}

#[async_trait::async_trait]
impl TunFactory for DesktopTunFactory {
    async fn create_tun(
        &self,
        auth: &AuthResponse,
    ) -> Result<(mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>, String)> {
        // Windows + per-app: тот же WinDivert-совместимый путь (wintun без шлюза),
        // что и в anet-client-gui — маршрутизацией конкретных приложений
        // занимается anet-appfilter, а не системный default route.
        #[cfg(target_os = "windows")]
        if self.per_app_mode {
            return windows_per_app::create_tun(&self.tun_name, auth).await;
        }

        // Linux/macOS, а также Windows без per-app (full tunnel) — общий путь.
        let params = TunParams::from_auth_response(auth, &self.tun_name);
        let mut manager = TunManager::new(params)?;
        let result = manager.run_with_name().await?;
        Ok((result.tx, result.rx, result.interface_name))
    }
}

// ============================================================================
// WINDOWS + PER-APP: аналог anet-client-gui/src/tun_factory.rs
// ============================================================================
#[cfg(target_os = "windows")]
mod windows_per_app {
    use anet_common::protocol::AuthResponse;
    use anyhow::{Context, Result};
    use bytes::Bytes;
    use log::{debug, error, info};
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    fn run_silent_cmd(prog: &str, args: &[&str]) -> Result<()> {
        let mut command = Command::new(prog);
        command.args(args);
        command.creation_flags(CREATE_NO_WINDOW);
        command.stdout(std::process::Stdio::null());
        command.stderr(std::process::Stdio::piped());
        command.stdin(std::process::Stdio::null());

        debug!("Exec: {} {:?}", prog, args);

        let output = command
            .output()
            .with_context(|| format!("Failed to exec {}", prog))?;

        if !output.status.success() {
            let err_text = String::from_utf8_lossy(&output.stderr);
            error!("Command failed: {} {:?}\nSTDERR: {}", prog, args, err_text);
            anyhow::bail!("Command failed: {}", err_text.trim());
        }
        Ok(())
    }

    pub(super) async fn create_tun(
        tun_name: &str,
        auth: &AuthResponse,
    ) -> Result<(mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>, String)> {
        info!("Step 1: Loading wintun.dll...");
        if !std::path::Path::new("wintun.dll").exists() {
            anyhow::bail!("CRITICAL: wintun.dll not found in current directory!");
        }

        let wintun = unsafe { wintun::load_from_path("wintun.dll").context("Failed to load wintun.dll")? };

        info!("Step 2: Creating adapter '{}'...", tun_name);
        let adapter = match wintun::Adapter::create(&wintun, tun_name, tun_name, None) {
            Ok(a) => a,
            Err(e) => {
                error!("Create failed: {}. Trying open...", e);
                wintun::Adapter::open(&wintun, tun_name).context("Failed to open existing Wintun adapter")?
            }
        };

        info!("Step 3: Starting session...");
        let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?);

        info!("Step 4: Waiting for Windows to register interface...");
        let start = std::time::Instant::now();
        let mut target_name = String::new();
        let mut found = false;

        while start.elapsed() < Duration::from_secs(15) {
            let interfaces = netdev::get_interfaces();
            if let Some(iface) = interfaces.iter().find(|i| {
                let name = i.name.to_lowercase();
                let friendly = i.friendly_name.as_deref().unwrap_or("").to_lowercase();
                let target = tun_name.to_lowercase();
                name == target || friendly == target ||
                    name == format!("{} Tunnel", target) || friendly == format!("{} Tunnel", target) ||
                    friendly.starts_with(&target) || name.starts_with(&target)
            }) {
                target_name = iface.friendly_name.clone().unwrap_or(iface.name.clone());
                info!(">> TUN FOUND: '{}' (Real system name: '{}', Index: {})", tun_name, target_name, iface.index);
                found = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        if !found {
            error!("TIMEOUT: Adapter '{}' did not appear in netdev list after 15s.", tun_name);
            target_name = tun_name.to_string();
        }

        let ip = &auth.ip;
        let mask = &auth.netmask;
        let mtu = auth.mtu;

        // Per-app режим: НЕ настраиваем шлюз на адаптере Wintun — это предотвратит
        // перехват дефолтного маршрута ОС. Маршрутизацией конкретных приложений
        // занимается anet-appfilter через WinDivert.
        info!("Step 5: Configuring IP {}/{} via netsh (Per-App wildcard mode, no gateway)...", ip, mask);
        let set_ip_args = vec![
            "interface",
            "ip",
            "set",
            "address",
            target_name.as_str(),
            "static",
            ip,
            mask,
        ];

        if let Err(e) = run_silent_cmd("netsh", &set_ip_args) {
            error!("IP Config failed! Check interface name or permissions.");
            return Err(e);
        }

        if mtu > 0 {
            info!("Step 7: Setting MTU...");
            let mtu_str = mtu.to_string();
            let _ = run_silent_cmd(
                "netsh",
                &[
                    "interface",
                    "ipv4",
                    "set",
                    "subinterface",
                    target_name.as_str(),
                    &format!("mtu={}", mtu_str),
                    "store=active",
                ],
            );
        }

        info!("Wintun interface is fully UP.");

        let (tx_to_tun, mut rx_to_tun) = mpsc::channel::<Bytes>(1024);
        let (tx_from_tun, rx_from_tun) = mpsc::channel::<Bytes>(1024);

        let reader_session = session.clone();
        let writer_session = session.clone();
        let tx_from_tun_clone = tx_from_tun.clone();

        std::thread::spawn(move || {
            loop {
                match reader_session.receive_blocking() {
                    Ok(packet) => {
                        let bytes = Bytes::copy_from_slice(packet.bytes());
                        if tx_from_tun_clone.blocking_send(bytes).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            info!("Wintun reader thread exited normally.");
        });

        tokio::spawn(async move {
            while let Some(packet) = rx_to_tun.recv().await {
                match writer_session.allocate_send_packet(packet.len() as u16) {
                    Ok(mut p) => {
                        p.bytes_mut().copy_from_slice(&packet);
                        writer_session.send_packet(p);
                    }
                    Err(e) => error!("Wintun alloc error: {}", e),
                }
            }
        });

        let tx_monitor = tx_from_tun.clone();
        tokio::spawn(async move {
            tx_monitor.closed().await;
            drop(adapter);
            info!("Wintun adapter dropped cleanly via channel monitor.");
        });

        Ok((tx_to_tun, rx_from_tun, target_name))
    }
}