// ./anet-client/src/windows_router.rs
#[cfg(windows)]
use anyhow::{Context, Result};
#[cfg(windows)]
use log::{info, warn, debug};
#[cfg(windows)]
use std::process::Command;

// Используем default-net для получения сетевых интерфейсов
use netdev::interface::get_interfaces;
use netdev::get_default_gateway;

#[cfg(windows)]
pub struct WindowsRouteManager {
    vpn_server_ip: String,
}

#[cfg(windows)]
impl WindowsRouteManager {
    pub fn new(vpn_server_ip: String) -> Self {
        Self {
            vpn_server_ip,
        }
    }

    fn find_physical_interface_and_gateway(&self) -> Result<(String, String, u32)> {
        // Получаем все сетевые интерфейсы
        let interfaces = get_interfaces();

        // Ищем физические интерфейсы с IPv4 адресами
        let mut physical_interfaces: Vec<_> = interfaces
            .iter()
            .filter(|iface| {
                // Фильтруем виртуальные интерфейсы
                !iface.name.to_lowercase().contains("tunnel") &&
                    !iface.name.to_lowercase().contains("virtual") &&
                    !iface.name.to_lowercase().contains("vpn") &&
                    !iface.name.to_lowercase().contains("anet") &&
                    !iface.name.to_lowercase().contains("loopback") &&
                    !iface.name.to_lowercase().contains("teredo") &&
                    // Проверяем что есть IPv4 адрес
                    iface.ipv4.iter().any(|addr| !addr.addr.is_loopback() && !addr.addr.is_unspecified())
            })
            .collect();

        // Сортируем по метрике (приоритету) или просто берем первый
        physical_interfaces.sort_by(|a, b| {
            // Предпочитаем интерфейсы с шлюзом по умолчанию
            let a_has_gateway = a.gateway.is_some();
            let b_has_gateway = b.gateway.is_some();
            b_has_gateway.cmp(&a_has_gateway)
        });

        if physical_interfaces.is_empty() {
            return Err(anyhow::anyhow!("No physical network interfaces found"));
        }

        let primary_interface = &physical_interfaces[0];
        info!("Selected physical interface: {} (index: {})",
              primary_interface.name, primary_interface.index);

        // Получаем шлюз по умолчанию для системы
        let default_gateway = match get_default_gateway() {
            Ok(gateway) => {
                info!("Found system default gateway: {}", gateway.ip_addr);
                gateway.ip_addr.to_string()
            }
            Err(e) => {
                // Если не можем получить системный шлюз, используем шлюз интерфейса
                if let Some(iface_gateway) = &primary_interface.gateway {
                    warn!("Could not get system default gateway: {}. Using interface gateway: {}",
                          e, iface_gateway.ip_addr);
                    iface_gateway.ip_addr.to_string()
                } else {
                    return Err(anyhow::anyhow!("No gateway found for interface {}: {}",
                                               primary_interface.name, e));
                }
            }
        };

        Ok((default_gateway, primary_interface.name.clone(), primary_interface.index))
    }

    pub fn setup_exclusion_route(&self) -> Result<()> {
        info!("Setting up exclusion route for VPN server {}", self.vpn_server_ip);

        let (gateway, interface_name, interface_index) = self.find_physical_interface_and_gateway()?;

        info!("Using physical interface: {} (index: {}) with gateway: {}",
              interface_name, interface_index, gateway);

        // Удаляем старый маршрут если существует
        let _ = Command::new("route")
            .args(&["delete", self.vpn_server_ip.as_str()])
            .output();

        // Сначала пробуем добавить маршрут с указанием интерфейса
        let add_output = Command::new("route")
            .args(&[
                "add",
                self.vpn_server_ip.as_str(),
                "mask", "255.255.255.255",
                &gateway,
                "if", &interface_index.to_string(),
                "metric", "5"
            ])
            .output()
            .context("Failed to add exclusion route")?;

        if add_output.status.success() {
            info!("Successfully added exclusion route for VPN server via {} on {}", gateway, interface_name);
        } else {
            let error_msg = String::from_utf8_lossy(&add_output.stderr);

            // Пробуем без указания интерфейса
            warn!("Failed to add exclusion route with interface: {}. Trying without interface...", error_msg.trim());

            let add_output = Command::new("route")
                .args(&[
                    "add",
                    self.vpn_server_ip.as_str(),
                    "mask", "255.255.255.255",
                    &gateway,
                    "metric", "5"
                ])
                .output()
                .context("Failed to add exclusion route without interface")?;

            if add_output.status.success() {
                info!("Successfully added exclusion route without interface specification");
            } else {
                let error_msg = String::from_utf8_lossy(&add_output.stderr);
                warn!("Failed to add exclusion route: {}. VPN might work without it.", error_msg.trim());
            }
        }

        Ok(())
    }

    pub fn restore_routing(&self) -> Result<()> {
        info!("Removing exclusion route for VPN server {}", self.vpn_server_ip);

        let output = Command::new("route")
            .args(&["delete", self.vpn_server_ip.as_str()])
            .output()
            .context("Failed to remove exclusion route")?;

        if output.status.success() {
            info!("Successfully removed exclusion route");
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            if error_msg.contains("not found") {
                info!("Exclusion route already removed or never existed");
            } else {
                warn!("Failed to remove exclusion route: {}", error_msg.trim());
            }
        }
        Ok(())
    }
}
