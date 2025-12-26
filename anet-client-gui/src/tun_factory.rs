use anet_client_core::traits::TunFactory;
use anet_common::protocol::AuthResponse;
#[cfg(target_os = "windows")]
use anyhow::{Context};
use anyhow::{Result};
use async_trait::async_trait;
use bytes::{Bytes};
#[cfg(target_os = "windows")]
use bytes::{BytesMut};
#[cfg(target_os = "windows")]
use log::{error, info, debug};
#[cfg(target_os = "windows")]
use std::sync::Arc;
use tokio::sync::mpsc;
#[cfg(target_os = "windows")]
use std::time::Duration;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
#[cfg(target_os = "windows")]
use std::process::Command;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

pub struct DesktopTunFactory {
    tun_name: String,
}

impl DesktopTunFactory {
    pub fn new(tun_name: String) -> Self {
        Self { tun_name }
    }

    #[cfg(target_os = "windows")]
    fn run_silent_cmd(prog: &str, args: &[&str]) -> Result<()> {
        let mut command = Command::new(prog);
        command.args(args);
        command.creation_flags(CREATE_NO_WINDOW);

        // ВРЕМЕННО: Включаем stderr, чтобы видеть ошибки в логах программы!
        command.stdout(std::process::Stdio::null());
        command.stderr(std::process::Stdio::piped()); // <--- Piped вместо Null
        command.stdin(std::process::Stdio::null());

        debug!("Exec: {} {:?}", prog, args); // Логируем команду

        let output = command.output()
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
    #[cfg(target_os = "windows")]
    async fn create_tun(
        &self,
        auth: &AuthResponse,
    ) -> Result<(mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>, String)> {
        info!("Step 1: Loading wintun.dll...");
        // Проверяем наличие файла для диагностики
        if !std::path::Path::new("wintun.dll").exists() {
            anyhow::bail!("CRITICAL: wintun.dll not found in current directory!");
        }

        let wintun = unsafe { wintun::load_from_path("wintun.dll")
            .context("Failed to load wintun.dll")? };

        info!("Step 2: Creating adapter '{}'...", self.tun_name);
        let adapter = match wintun::Adapter::create(&wintun, &self.tun_name, &self.tun_name, None) {
            Ok(a) => a,
            Err(e) => {
                error!("Create failed: {}. Trying open...", e);
                wintun::Adapter::open(&wintun, &self.tun_name)
                    .context("Failed to open existing Wintun adapter")?
            }
        };

        info!("Step 3: Starting session...");
        let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?);

        // ВАЖНО: Даем винде время одуплиться, что интерфейс появился
        info!("Step 4: Waiting for Windows to register interface...");
        let start = std::time::Instant::now();
        let mut target_name = String::new();
        let mut found = false;

        // Ждем до 15 секунд (в виртуалках бывает туго)
        while start.elapsed() < Duration::from_secs(15) {
            let interfaces = netdev::get_interfaces();

            // Ищем интерфейс, который ПОХОЖ на наш
            if let Some(iface) = interfaces.iter().find(|i| {
                let name = i.name.to_lowercase();
                let friendly = i.friendly_name.as_deref().unwrap_or("").to_lowercase();
                let target = self.tun_name.to_lowercase();
                // 1. Точное совпадение
                name == target || friendly == target ||
                    // 2. Совпадение с суффиксом " Tunnel" (стандарт Wintun)
                    name == format!("{} Tunnel", target) || friendly == format!("{} Tunnel", target) ||
                    // 3. Просто начинается с имени
                    friendly.starts_with(&target) || name.starts_with(&target)


            }) {
                target_name = iface.friendly_name.clone().unwrap_or(iface.name.clone());

                info!(">> TUN FOUND: '{}' (Real system name: '{}', Index: {})",
                      self.tun_name, target_name, iface.index);
                found = true;
                break;
            }

            // Ждем перед следующей попыткой
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        if !found {
            error!("TIMEOUT: Adapter '{}' did not appear in netdev list after 15s.", self.tun_name);
            // Можно попробовать продолжить с дефолтным именем, но скорее всего netsh упадет
            target_name = self.tun_name.clone();
        }

        let ip = &auth.ip;
        let mask = &auth.netmask;
        let gateway = &auth.gateway;
        let mtu = auth.mtu;

        info!("Step 5: Configuring IP {}/{} via netsh...", ip, mask);

        let set_ip_args = [
            "interface", "ip", "set", "address",
            target_name.as_str(),
            "static",
            ip,
            mask,
            gateway,
            "1"
        ];

        if let Err(e) = Self::run_silent_cmd("netsh", &set_ip_args) {
            error!("IP Config failed! Check interface name or permissions.");
            return Err(e);
        }

        info!("Step 6: Setting DNS...");
        let _ = Self::run_silent_cmd("netsh", &[
            "interface", "ip", "set", "dns",
            target_name.as_str(), "static", "1.1.1.1"
        ]);

        if mtu > 0 {
            info!("Step 7: Setting MTU...");
            let mtu_str = mtu.to_string();
            let _ = Self::run_silent_cmd("netsh", &[
                "interface", "ipv4", "set", "subinterface",
                target_name.as_str(),
                &format!("mtu={}", mtu_str),
                "store=active"
            ]);
        }

        info!("Wintun interface is fully UP.");

        let (tx_to_tun, mut rx_to_tun) = mpsc::channel::<Bytes>(1024);
        let (tx_from_tun, rx_from_tun) = mpsc::channel::<Bytes>(1024);

        let reader_session = session.clone();
        let writer_session = session.clone();

        std::thread::spawn(move || {
            loop {
                match reader_session.receive_blocking() {
                    Ok(packet) => {
                        let bytes = Bytes::copy_from_slice(packet.bytes());
                        if tx_from_tun.blocking_send(bytes).is_err() { break; }
                    },
                    Err(_) => break,
                }
            }
        });

        tokio::spawn(async move {
            while let Some(packet) = rx_to_tun.recv().await {
                match writer_session.allocate_send_packet(packet.len() as u16) {
                    Ok(mut p) => {
                        p.bytes_mut().copy_from_slice(&packet);
                        writer_session.send_packet(p);
                    },
                    Err(e) => error!("Wintun alloc error: {}", e),
                }
            }
        });

        Ok((tx_to_tun, rx_from_tun, self.tun_name.clone()))
    }

    #[cfg(not(target_os = "windows"))]
    async fn create_tun(
        &self,
        _auth: &AuthResponse,
    ) -> Result<(mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>, String)> {
        anyhow::bail!("This factory supports Windows only via Wintun {}", self.tun_name);
    }
}