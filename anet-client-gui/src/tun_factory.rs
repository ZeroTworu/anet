use anet_client_core::traits::TunFactory;
use anet_common::protocol::AuthResponse;
use anyhow::Result;
use bytes::Bytes;
use tokio::sync::mpsc;

/// Фабрика TUN-интерфейса для десктопных платформ.
///
/// - **Windows**: собственная реализация поверх `wintun` + `netsh`. Умеет
///   per-app wildcard-режим (адаптер без шлюза) для split tunneling через
///   `anet-appfilter` (WinDivert).
/// - **Linux/macOS**: делегирует в кроссплатформенный `anet_common::atun::TunManager`
///   (тот же путь, что уже использует `anet-client-cli`). `per_app_mode` на
///   этих платформах пока ни на что не влияет — per-app split tunneling
///   реализован только для Windows/WinDivert.
pub struct DesktopTunFactory {
    tun_name: String,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    per_app_mode: bool,
}

impl DesktopTunFactory {
    pub fn new(tun_name: String, per_app_mode: bool) -> Self {
        Self { tun_name, per_app_mode }
    }
}

// ============================================================================
// WINDOWS: wintun + netsh, с поддержкой per-app wildcard-режима
// ============================================================================
#[cfg(target_os = "windows")]
mod windows_impl {
    use super::DesktopTunFactory;
    use anet_client_core::traits::TunFactory;
    use anet_common::protocol::AuthResponse;
    use anyhow::Context;
    use anyhow::Result;
    use async_trait::async_trait;
    use bytes::Bytes;
    use log::{debug, error, info};
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    impl DesktopTunFactory {
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
    }

    #[async_trait]
    impl TunFactory for DesktopTunFactory {
        async fn create_tun(
            &self,
            auth: &AuthResponse,
        ) -> Result<(mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>, String)> {
            info!("Step 1: Loading wintun.dll...");
            if !std::path::Path::new("wintun.dll").exists() {
                anyhow::bail!("CRITICAL: wintun.dll not found in current directory!");
            }

            let wintun = unsafe { wintun::load_from_path("wintun.dll").context("Failed to load wintun.dll")? };

            info!("Step 2: Creating adapter '{}'...", self.tun_name);
            let adapter = match wintun::Adapter::create(&wintun, &self.tun_name, &self.tun_name, None) {
                Ok(a) => a,
                Err(e) => {
                    error!("Create failed: {}. Trying open...", e);
                    wintun::Adapter::open(&wintun, &self.tun_name).context("Failed to open existing Wintun adapter")?
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
                    let target = self.tun_name.to_lowercase();
                    name == target || friendly == target ||
                        name == format!("{} Tunnel", target) || friendly == format!("{} Tunnel", target) ||
                        friendly.starts_with(&target) || name.starts_with(&target)
                }) {
                    target_name = iface.friendly_name.clone().unwrap_or(iface.name.clone());
                    info!(">> TUN FOUND: '{}' (Real system name: '{}', Index: {})", self.tun_name, target_name, iface.index);
                    found = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }

            if !found {
                error!("TIMEOUT: Adapter '{}' did not appear in netdev list after 15s.", self.tun_name);
                target_name = self.tun_name.clone();
            }

            let ip = &auth.ip;
            let mask = &auth.netmask;
            let gateway = &auth.gateway;
            let mtu = auth.mtu;

            // Если активен раздельный туннель (per-app), мы НЕ настраиваем шлюз на адаптере Wintun.
            // Это предотвратит перехват дефолтного маршрута операционной системы.
            let set_ip_args = if self.per_app_mode {
                info!("Step 5: Configuring IP {}/{} via netsh (Per-App wildcard mode, no gateway)...", ip, mask);
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
                info!("Step 5: Configuring IP {}/{} via netsh (Full tunnel mode with gateway {})...", ip, mask, gateway);
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

            // Небольшая задержка перед настройкой, чтобы Windows успела перевести интерфейс в готовность
            tokio::time::sleep(Duration::from_millis(500)).await;

            let mut ip_configured = false;
            for attempt in 1..=5 {
                if let Ok(()) = Self::run_silent_cmd("netsh", &set_ip_args) {
                    ip_configured = true;
                    break;
                }
                log::warn!("Attempt {}/5: Netsh failed to set IP on '{}'. Retrying in 500ms...", attempt, target_name);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }

            if !ip_configured {
                error!("IP Config failed after 5 attempts! Check interface name or permissions.");
                anyhow::bail!("Failed to assign IP address to interface '{}'", target_name);
            }

            if let Err(e) = Self::run_silent_cmd("netsh", &set_ip_args) {
                error!("IP Config failed! Check interface name or permissions.");
                return Err(e);
            }

            if mtu > 0 {
                info!("Step 7: Setting MTU...");
                let mtu_str = mtu.to_string();
                let _ = Self::run_silent_cmd(
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

            // Клонируем канал отправки, чтобы основной не был закрыт преждевременно
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
                        Err(_) => break, // Выход при закрытии адаптера
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

            // Асинхронный монитор жизни адаптера.
            // Ждет закрытия канала tx_from_tun (когда клиент завершает сессию)
            // и принудительно уничтожает Wintun-адаптер.
            let tx_monitor = tx_from_tun.clone();
            tokio::spawn(async move {
                tx_monitor.closed().await;
                drop(adapter);
                info!("Wintun adapter dropped cleanly via channel monitor.");
            });

            Ok((tx_to_tun, rx_from_tun, target_name))
        }
    }
}

// ============================================================================
// LINUX / MACOS: общий кроссплатформенный TunManager (как в anet-client-cli)
// ============================================================================
#[cfg(not(target_os = "windows"))]
mod portable_impl {
    use super::DesktopTunFactory;
    use anet_client_core::traits::TunFactory;
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
