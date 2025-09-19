use anet_common::tun_params::TunParams;
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
    pub fn new(params: &TunParams, vpn_server_ip: String) -> Self {
        Self {
            vpn_gateway: params.gateway,
            vpn_interface: params.name.clone(),
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
    pub fn setup_vpn_routing(&self) -> Result<()> {
        self.ensure_route_table();

        // Добавляем маршрут к VPN-серверу через оригинальный интерфейс
        if let (Some(gateway), Some(interface)) = (&self.original_gateway, &self.original_interface)
        {
            let status = Command::new("ip")
                .args(&[
                    "route",
                    "add",
                    &self.vpn_server_ip,
                    "via",
                    gateway,
                    "dev",
                    interface,
                ])
                .status();

            match status {
                Ok(exit_status) if exit_status.success() => info!("Added route to VPN server"),
                Ok(exit_status) => warn!(
                    "Route to VPN server already exists or failed to add: {}",
                    exit_status
                ),
                Err(e) => warn!("Failed to add route to VPN server: {}", e),
            }
        }

        // Критическое исправление: добавляем правило для исключения трафика к VPN-серверу
        let status = Command::new("ip")
            .args(&[
                "rule",
                "add",
                "from",
                "all",
                "to",
                &self.vpn_server_ip,
                "prio",
                "100",
                "table",
                "main",
            ])
            .status();
        match status {
            Ok(exit_status) if exit_status.success() => {
                info!("Added exclusion rule for VPN server")
            }
            Ok(exit_status) => warn!("Exclusion rule already exists: {}", exit_status),
            Err(e) => warn!("Failed to add exclusion rule: {}", e),
        }

        // Основное правило для маршрутизации через VPN
        let status = Command::new("ip")
            .args(&["rule", "add", "from", "all", "prio", "200", "table", "200"])
            .status();
        match status {
            Ok(exit_status) if exit_status.success() => info!("Added routing rule"),
            Ok(exit_status) => warn!("Routing rule already exists: {}", exit_status),
            Err(e) => warn!("Failed to add routing rule: {}", e),
        }

        // Маршрут по умолчанию через VPN
        let status = Command::new("ip")
            .args(&[
                "route",
                "add",
                "default",
                "via",
                &self.vpn_gateway.to_string(),
                "dev",
                &self.vpn_interface,
                "table",
                "200",
            ])
            .status();
        match status {
            Ok(exit_status) if exit_status.success() => info!("Added default route to VPN table"),
            Ok(exit_status) => warn!("Default route already exists: {}", exit_status),
            Err(e) => warn!("Failed to add default route: {}", e),
        }

        info!("VPN routing setup completed");
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
                    .args(&["-c", "echo '200 vpn' | sudo tee -a /etc/iproute2/rt_tables"]);
            }
        }
    }

    // Восстанавливаем оригинальную маршрутизацию
    pub fn restore_original_routing(&self) -> Result<()> {
        // Удаляем правило исключения для VPN-сервера
        let _ = Command::new("ip")
            .args(&[
                "rule",
                "del",
                "from",
                "all",
                "to",
                &self.vpn_server_ip,
                "prio",
                "100",
                "table",
                "main",
            ])
            .status();

        // Удаляем VPN правила
        let _ = Command::new("ip")
            .args(&["rule", "del", "from", "all", "table", "200"])
            .status();

        // Очищаем VPN таблицу
        let _ = Command::new("ip")
            .args(&["route", "flush", "table", "200"])
            .status();

        // Удаляем маршрут к VPN-серверу
        if let (Some(gateway), Some(interface)) = (&self.original_gateway, &self.original_interface)
        {
            let _ = Command::new("ip")
                .args(&[
                    "route",
                    "del",
                    &self.vpn_server_ip,
                    "via",
                    gateway,
                    "dev",
                    interface,
                ])
                .status();
        }

        // Восстанавливаем оригинальный маршрут по умолчанию
        if let (Some(gateway), Some(interface)) = (&self.original_gateway, &self.original_interface)
        {
            let status = Command::new("ip")
                .args(&[
                    "route", "replace", "default", "via", gateway, "dev", interface,
                ])
                .status();

            match status {
                Ok(exit_status) if exit_status.success() => {
                    info!("Restored original default route")
                }
                Ok(_) => warn!("Failed to restore original default route"),
                Err(e) => warn!("Failed to restore original default route: {}", e),
            }
        }

        info!("Original routing restored");
        Ok(())
    }
}
