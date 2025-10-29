use anyhow::{Context, Result};
use log::{error, info, warn};
use std::net::Ipv4Addr;
use std::process::Command;

pub struct WindowsRouteManager {
    vpn_gateway: Ipv4Addr,
    vpn_server_ip: String,
    interface_metric: u32,
    original_default_gateway: Option<String>,
}

impl WindowsRouteManager {
    pub fn new(vpn_gateway: &str, vpn_server_ip: String) -> Self {
        Self {
            vpn_gateway: vpn_gateway.parse().unwrap(),
            vpn_server_ip,
            // 50 - обычно ниже, чем метрика основной сетевой карты, что обеспечивает предпочтение
            interface_metric: 50,
            original_default_gateway: None,
        }
    }

    /// Поиск оригинального шлюза по умолчанию путем парсинга вывода 'route print'.
    /// Эта функция нестабильна и может сломаться из-за локализации или версии ОС.
    /// Однако, это лучший способ получить его без WinAPI/iphlpapi.
    fn get_original_default_gateway(&mut self) -> Result<()> {
        let output = Command::new("cmd")
            .args(&["/C", "route print -4"])
            .output()
            .context("Failed to run 'route print -4'")?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut gateway_ip: Option<String> = None;

        // Ищем строку, содержащую Network Destination 0.0.0.0 и Mask 0.0.0.0
        for line in output_str.lines() {
            if line.trim().starts_with("0.0.0.0") && line.contains("0.0.0.0") {
                // Строка обычно выглядит так:
                // 0.0.0.0        0.0.0.0         192.168.1.1        192.168.1.100     35
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    // Gateway IP находится на 3 позиции (индекс 2)
                    let ip = parts[2].trim().to_string();

                    // Убеждаемся, что это не IP localhost и не наш будущий VPN Gateway
                    if ip != "0.0.0.0" && ip != self.vpn_gateway.to_string() {
                        gateway_ip = Some(ip);
                        break;
                    }
                }
            }
        }

        self.original_default_gateway = gateway_ip;

        info!(
            "Original physical gateway detected: {:?}",
            self.original_default_gateway
        );

        if self.original_default_gateway.is_none() {
            warn!(
                "Failed to reliably detect original default gateway. Routing stability may suffer."
            );
        }

        Ok(())
    }

    /// Установка маршрутизации: исключающий маршрут к серверу, затем новый шлюз по умолчанию.
    pub fn setup_vpn_routing(&mut self) -> Result<()> {
        info!("Setting up VPN routing for Windows (requires elevation).");

        // Шаг 0: Получаем оригинальный шлюз (необходим для исключающего маршрута)
        // Нам нужно знать это ДО установки VPN маршрута
        self.get_original_default_gateway()?;

        let server_ip = &self.vpn_server_ip;
        let vpn_gateway = self.vpn_gateway.to_string();

        if let Some(orig_gateway) = &self.original_default_gateway {
            // 1. Устанавливаем исключающий маршрут к серверу (через оригинальный шлюз)
            // Должен иметь низкую метрику (например, 5), чтобы маршрут к серверу был стабилен
            let status = Command::new("route")
                .args(&[
                    "ADD",
                    server_ip,
                    "MASK",
                    "255.255.255.255",
                    orig_gateway,
                    "METRIC",
                    "5",
                ])
                .status();

            match status {
                Ok(exit_status) if exit_status.success() => {
                    info!(
                        "Established exclusion route to server {} via {}.",
                        server_ip, orig_gateway
                    );
                }
                _ => {
                    // Это может случиться, если маршрут уже есть, но лучше предупредить.
                    error!("Failed to add critical exclusion route to VPN server.");
                }
            }
        } else {
            warn!("Cannot create exclusion route: original gateway unknown.");
        }

        // 2. Устанавливаем новый маршрут по умолчанию через наш VPN Gateway (10.X.Y.Z)
        let status = Command::new("route")
            .args(&[
                "ADD",
                "0.0.0.0",
                "MASK",
                "0.0.0.0",
                &vpn_gateway,
                "METRIC",
                &self.interface_metric.to_string(),
            ])
            .status();

        match status {
            Ok(exit_status) if exit_status.success() => {
                info!(
                    "Successfully added new default route via VPN ({})",
                    vpn_gateway
                );
            }
            _ => {
                // Это не критическая ошибка, если QUIC работает, но требует ручного вмешательства/админа.
                error!("Failed to set default route via VPN. (Need admin rights?)");
            }
        }

        Ok(())
    }

    /// Восстановление маршрутизации
    pub fn restore_original_routing(&self) -> Result<()> {
        info!("Restoring original Windows routing...");

        // 1. Удаляем исключающий маршрут к VPN Server
        let _ = Command::new("route")
            .args(&["delete", &self.vpn_server_ip])
            .status();

        // 2. Удаляем маршрут по умолчанию, добавленный нами.
        // Если метрики были верными, Windows автоматически вернет старый.
        let vpn_gateway = self.vpn_gateway.to_string();

        // Удаление может потребовать IP, но не IF, так что используем минимальный набор
        let _ = Command::new("route")
            .args(&["delete", "0.0.0.0", "MASK", "0.0.0.0", &vpn_gateway])
            .status();

        info!("Windows routing cleanup finished.");
        Ok(())
    }
}
