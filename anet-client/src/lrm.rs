use anet_common::AuthResponse;
use anyhow::{Context, Result};
use log::{info, warn};
use std::net::Ipv4Addr;
use std::process::Command;

// код на 99% сгенерен дипсиком, т.к. я не знаю iptables
pub struct LinuxRouteManager {
    vpn_gateway: Ipv4Addr,
    vpn_interface: String,
    original_gateway: Option<String>,
    original_interface: Option<String>,
    vpn_server_ip: String,
}

impl LinuxRouteManager {
    pub fn new(params: &AuthResponse, vpn_server_ip: String) -> Self {
        Self {
            vpn_gateway: params.gateway.parse().unwrap(),
            vpn_interface: "anet-client".to_string(),
            original_gateway: None,
            original_interface: None,
            vpn_server_ip,
        }
    }

    // Сохраняем оригинальные маршруты
    pub fn backup_original_routes(&mut self) -> Result<()> {
        let output = Command::new("ip")
            .args(&["route", "show", "default"])
            .output()
            .context("Failed to get default routes")?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        if let Some(line) = output_str.lines().next() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 && parts[0] == "default" && parts[1] == "via" {
                self.original_gateway = Some(parts[2].to_string());
                self.original_interface = Some(parts[4].to_string());
            }
        }

        info!(
            "Original gateway: {:?}, interface: {:?}",
            self.original_gateway, self.original_interface
        );
        Ok(())
    }

    // Настраиваем маршрутизацию через VPN
    // anet-client/lrm.rs

    // ... (new, backup_original_routes остаются без изменений) ...

    pub fn setup_vpn_routing(&self) -> Result<()> {
        info!("Setting up simplified VPN routing (default gateway override)...");

        // 1. Убеждаемся, что маршрут до самого VPN-сервера существует
        // и идет через старый шлюз. Это САМЫЙ ВАЖНЫЙ шаг.
        if let (Some(gateway), Some(interface)) = (&self.original_gateway, &self.original_interface)
        {
            // Используем 'add' или 'replace', чтобы гарантировать его наличие
            let _ = Command::new("ip")
                .args(&[
                    "route",
                    "replace", // 'replace' безопасно, т.к. создаст маршрут, если его нет, или обновит
                    &self.vpn_server_ip,
                    "via",
                    gateway,
                    "dev",
                    interface,
                ])
                .status();
            info!(
                "Ensured route to VPN server {} via {}",
                self.vpn_server_ip, gateway
            );
        } else {
            warn!(
                "Original gateway not found, cannot create exception route for VPN server. Connectivity may be lost."
            );
            // В этом случае продолжать опасно, но для теста оставим.
        }

        // 2. Теперь мы можем безопасно заменить шлюз по умолчанию
        let status = Command::new("ip")
            .args(&[
                "route",
                "replace",
                "default",
                "via",
                &self.vpn_gateway.to_string(),
                "dev",
                &self.vpn_interface,
            ])
            .status();

        match status {
            Ok(exit_status) if exit_status.success() => {
                info!("Successfully replaced default route to point to VPN.");
            }
            _ => {
                return Err(anyhow::anyhow!("Failed to replace default route."));
            }
        }

        info!("Simplified VPN routing setup completed.");
        Ok(())
    }

    // Убедимся, что таблица маршрутизации существует
    fn ensure_route_table(&self) {
        // Проверяем, существует ли уже таблица 200 в /etc/iproute2/rt_tables
        let output = Command::new("grep")
            .args(&["-q", "^200", "/etc/iproute2/rt_tables"])
            .status();

        if let Ok(status) = output {
            if !status.success() {
                // Добавляем таблицу
                let _ = Command::new("sh")
                    .args(&["-c", "echo '200 vpn' | tee -a /etc/iproute2/rt_tables"]);
            }
        }
    }

    // Восстанавливаем оригинальную маршрутизацию
    pub fn restore_original_routing(&self) -> Result<()> {
        info!("Restoring original routing...");

        // 1. Просто восстанавливаем старый шлюз по умолчанию.
        // Это автоматически сделает маршрут на VPN-сервер ненужным,
        // но мы удалим его для чистоты.
        if let (Some(gateway), Some(interface)) = (&self.original_gateway, &self.original_interface)
        {
            let _ = Command::new("ip")
                .args(&[
                    "route", "replace", "default", "via", gateway, "dev", interface,
                ])
                .status();
            info!("Restored original default route via {}", gateway);
        }

        // 2. Удаляем маршрут к VPN-серверу
        let _ = Command::new("ip")
            .args(&["route", "del", &self.vpn_server_ip])
            .status();

        info!("Original routing restored.");
        Ok(())
    }
}
