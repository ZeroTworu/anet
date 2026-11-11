/// Единая фабрика TUN-интерфейса для десктопных платформ (`anet-client-cli` и `anet-client-gui`).
///
/// - **Windows**: прямая реализация поверх `wintun.dll` + `netsh` (`CREATE_NO_WINDOW`).
///   Поддерживает как полный туннель (Full-Tunnel с шлюзом и метрикой 1), так и
///   per-app wildcard-режим (адаптер без шлюза для split tunneling через `anet-appfilter` / WinDivert),
///   а также любые значения IPv4 MTU (от 576 байт, включая `mtu = 990` для WRTC поверх CF WARP)
///   без ошибки `ERROR_INVALID_PARAMETER (os error 87)`.
/// - **Linux / macOS**: делегирует в кроссплатформенный `anet_common::atun::TunManager`.
pub struct DesktopTunFactory {
    tun_name: String,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    per_app_mode: bool,
}

impl DesktopTunFactory {
    pub fn new(tun_name: String, per_app_mode: bool) -> Self {
        Self {
            tun_name,
            per_app_mode,
        }
    }
}

// ============================================================================
// WINDOWS: wintun + netsh (Full-Tunnel и Per-App режимы, для CLI и GUI)
// ============================================================================
#[cfg(target_os = "windows")]
mod windows_impl {
    use super::DesktopTunFactory;
    use crate::traits::TunFactory;
    use anet_common::consts::CHANNEL_BUFFER_SIZE;
    use anet_common::protocol::AuthResponse;
    use anyhow::{Context, Result};
    use async_trait::async_trait;
    use bytes::Bytes;
    use log::{debug, error, info, warn};
    use std::os::windows::process::CommandExt;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    impl DesktopTunFactory {
        fn resolve_wintun_dll_path() -> Result<PathBuf> {
            if let Ok(exe_path) = std::env::current_exe() {
                if let Some(exe_dir) = exe_path.parent() {
                    let candidate = exe_dir.join("wintun.dll");
                    if candidate.exists() {
                        return Ok(candidate);
                    }
                }
            }

            let cwd_candidate = PathBuf::from("wintun.dll");
            if cwd_candidate.exists() {
                return Ok(cwd_candidate);
            }

            anyhow::bail!(
                "CRITICAL: wintun.dll not found next to executable or in current working directory!"
            )
        }

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

        fn purge_stale_adapters(wintun: &wintun::Wintun, base_name: &str, force_all: bool) {
            let candidates = [
                base_name.to_string(),
                format!("{} 1", base_name),
                format!("{} 2", base_name),
                format!("{} 3", base_name),
            ];

            let existing_ifaces = netdev::get_interfaces();
            for candidate in &candidates {
                let cand_lower = candidate.to_lowercase();
                let visible_in_netdev = existing_ifaces.iter().any(|i| {
                    i.name.eq_ignore_ascii_case(&cand_lower)
                        || i.friendly_name
                            .as_deref()
                            .is_some_and(|f| f.eq_ignore_ascii_case(&cand_lower))
                });

                if !force_all && !visible_in_netdev {
                    continue;
                }

                if let Ok(existing) = wintun::Adapter::open(wintun, candidate) {
                    info!(
                        "[WinTun] Found existing/stale adapter '{}', deleting...",
                        candidate
                    );
                    if let Ok(raw_adapter) = Arc::try_unwrap(existing) {
                        let _ = raw_adapter.delete();
                    }
                    std::thread::sleep(Duration::from_millis(150));
                }
            }
        }
    }

    #[async_trait]
    impl TunFactory for DesktopTunFactory {
        async fn create_tun(
            &self,
            auth: &AuthResponse,
        ) -> Result<(mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>, String)> {
            let dll_path = Self::resolve_wintun_dll_path()?;
            info!(
                "Step 1: Loading '{}' & creating adapter '{}'...",
                dll_path.display(),
                self.tun_name
            );

            let tun_name_init = self.tun_name.clone();
            let (adapter, session) = tokio::task::spawn_blocking(
                move || -> Result<(Arc<wintun::Adapter>, Arc<wintun::Session>)> {
                    let wintun = unsafe {
                        wintun::load_from_path(&dll_path).context("Failed to load wintun.dll")?
                    };

                    // 1. Удаляем только реально существующие в системе старые адаптеры (без спама 0x00000490 в лог)
                    Self::purge_stale_adapters(&wintun, &tun_name_init, false);

                    // 2. Создание чистого Wintun адаптера (при ошибке — принудительная зачистка и повтор)
                    let adapter = match wintun::Adapter::create(
                        &wintun,
                        &tun_name_init,
                        &tun_name_init,
                        None,
                    ) {
                        Ok(a) => a,
                        Err(e) => {
                            warn!(
                                "Wintun Adapter::create('{}') failed ({}). Cleaning up orphans and retrying...",
                                tun_name_init, e
                            );
                            Self::purge_stale_adapters(&wintun, &tun_name_init, true);
                            std::thread::sleep(Duration::from_millis(500));
                            wintun::Adapter::create(&wintun, &tun_name_init, &tun_name_init, None)
                                .context("Failed to create Wintun adapter after orphan cleanup")?
                        }
                    };

                    info!("Step 3: Starting session...");
                    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?);
                    Ok((adapter, session))
                },
            )
            .await
            .context("Wintun initialization task panicked")??;

            info!("Step 4: Waiting for Windows to register interface...");
            let start = std::time::Instant::now();
            let mut target_name = String::new();
            let mut found = false;

            while start.elapsed() < Duration::from_secs(15) {
                let interfaces = netdev::get_interfaces();
                if let Some(iface) = interfaces.iter().find(|i| {
                    let name = i.name.to_lowercase();
                    let friendly = i.friendly_name.as_deref().unwrap_or("").to_lowercase();
                    let target = self.tun_name.to_lowercase();
                    name == target
                        || friendly == target
                        || name == format!("{} tunnel", target)
                        || friendly == format!("{} tunnel", target)
                        || friendly.starts_with(&target)
                        || name.starts_with(&target)
                }) {
                    target_name = iface.friendly_name.clone().unwrap_or(iface.name.clone());
                    info!(
                        ">> TUN FOUND: '{}' (Real system name: '{}', Index: {})",
                        self.tun_name, target_name, iface.index
                    );
                    found = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }

            if !found {
                error!(
                    "TIMEOUT: Adapter '{}' did not appear in netdev list after 15s.",
                    self.tun_name
                );
                target_name = self.tun_name.clone();
            }

            let ip = &auth.ip;
            let mask = &auth.netmask;
            let gateway = &auth.gateway;
            let mtu = auth.mtu;

            // Если активен раздельный туннель по приложениям (per-app), НЕ настраиваем шлюз на адаптере Wintun,
            // чтобы не перехватывать системный default route (маршрутизацией занимается WinDivert).
            let set_ip_args = if self.per_app_mode {
                info!(
                    "Step 5: Configuring IP {}/{} via netsh (Per-App wildcard mode, no gateway)...",
                    ip, mask
                );
                vec![
                    "interface",
                    "ip",
                    "set",
                    "address",
                    target_name.as_str(),
                    "static",
                    ip,
                    mask,
                ]
            } else {
                info!(
                    "Step 5: Configuring IP {}/{} via netsh (Full tunnel mode with gateway {})...",
                    ip, mask, gateway
                );
                vec![
                    "interface",
                    "ip",
                    "set",
                    "address",
                    target_name.as_str(),
                    "static",
                    ip,
                    mask,
                    gateway,
                    "1",
                ]
            };

            // Даем сетевому стеку Windows время на инициализацию интерфейса
            tokio::time::sleep(Duration::from_millis(500)).await;

            let mut ip_configured = false;
            for attempt in 1..=5 {
                if let Ok(()) = Self::run_silent_cmd("netsh", &set_ip_args) {
                    ip_configured = true;
                    break;
                }
                warn!(
                    "Attempt {}/5: Netsh failed to set IP on '{}'. Retrying in 500ms...",
                    attempt, target_name
                );
                tokio::time::sleep(Duration::from_millis(500)).await;
            }

            if !ip_configured {
                error!("IP Config failed after 5 attempts! Check interface name or permissions.");
                anyhow::bail!("Failed to assign IP address to interface '{}'", target_name);
            }

            if mtu > 0 {
                let effective_ipv4_mtu = mtu.clamp(576, 65535);
                info!("Step 7: Setting IPv4 MTU={}...", effective_ipv4_mtu);
                let mtu_arg = format!("mtu={}", effective_ipv4_mtu);
                let _ = Self::run_silent_cmd(
                    "netsh",
                    &[
                        "interface",
                        "ipv4",
                        "set",
                        "subinterface",
                        target_name.as_str(),
                        &mtu_arg,
                        "store=active",
                    ],
                );
            }

            info!("Wintun interface is fully UP.");

            let (tx_to_tun, mut rx_to_tun) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
            let (tx_from_tun, rx_from_tun) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);

            let reader_session = session.clone();
            let writer_session = session.clone();
            let tx_from_tun_clone = tx_from_tun.clone();

            let reader_handle = std::thread::spawn(move || {
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

            let writer_task = tokio::spawn(async move {
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

            // Асинхронный монитор жизни адаптера:
            // Ждет закрытия канала tx_from_tun (когда клиент завершает сессию),
            // останавливает сессию Wintun, дожидается выхода reader/writer потоков и удаляет адаптер из ОС.
            let tx_monitor = tx_from_tun.clone();
            tokio::spawn(async move {
                tx_monitor.closed().await;

                let _ = session.shutdown();
                writer_task.abort();
                let _ = writer_task.await;
                drop(session);

                tokio::task::spawn_blocking(move || {
                    let _ = reader_handle.join();
                    match Arc::try_unwrap(adapter) {
                        Ok(raw_adapter) => {
                            if let Err(e) = raw_adapter.delete() {
                                debug!("[WinTun] Adapter delete returned: {:?}", e);
                            } else {
                                info!("[WinTun] Adapter deleted cleanly from Windows.");
                            }
                        }
                        Err(arc) => {
                            warn!(
                                "[WinTun] Could not unwrap Adapter (strong_count={}), skipping delete.",
                                Arc::strong_count(&arc)
                            );
                        }
                    }
                })
                .await
                .ok();
            });

            Ok((tx_to_tun, rx_from_tun, target_name))
        }
    }
}

// ============================================================================
// LINUX / MACOS: общий кроссплатформенный TunManager (anet-common/src/atun.rs)
// ============================================================================
#[cfg(not(target_os = "windows"))]
mod portable_impl {
    use super::DesktopTunFactory;
    use crate::traits::TunFactory;
    use anet_common::atun::TunManager;
    use anet_common::protocol::AuthResponse;
    use anet_common::tun_params::TunParams;
    use anyhow::Result;
    use bytes::Bytes;
    use tokio::sync::mpsc;

    #[async_trait::async_trait]
    impl TunFactory for DesktopTunFactory {
        async fn create_tun(
            &self,
            auth: &AuthResponse,
        ) -> Result<(mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>, String)> {
            let params = TunParams::from_auth_response(auth, &self.tun_name);
            let mut manager = TunManager::new(params)?;
            let result = manager.run_with_name().await?;
            Ok((result.tx, result.rx, result.interface_name))
        }
    }
}
