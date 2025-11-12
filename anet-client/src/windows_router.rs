#[cfg(windows)]
use anyhow::{Context, Result};
#[cfg(windows)]
use log::{info, warn, debug};
#[cfg(windows)]
use std::process::Command;

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

    pub fn setup_exclusion_route(&self) -> Result<()> {
        info!("Setting up exclusion route for VPN server {}", self.vpn_server_ip);

        // Сначала проверяем, существует ли уже маршрут
        let check_output = Command::new("route")
            .args(&["print", self.vpn_server_ip.as_str()])
            .output()
            .context("Failed to check existing routes")?;

        if check_output.status.success() {
            let output_str = String::from_utf8_lossy(&check_output.stdout);
            if output_str.contains(&self.vpn_server_ip) {
                info!("Exclusion route already exists");
                return Ok(());
            }
        }

        // Добавляем маршрут через default gateway
        let add_output = Command::new("route")
            .args(&["add", self.vpn_server_ip.as_str(), "mask", "255.255.255.255", "192.168.122.1", "metric", "5"])
            .output()
            .context("Failed to add exclusion route")?;

        if add_output.status.success() {
            info!("Successfully added exclusion route for VPN server");
            Ok(())
        } else {
            let error_msg = String::from_utf8_lossy(&add_output.stderr);
            if error_msg.contains("already exists") {
                info!("Exclusion route already exists");
                Ok(())
            } else {
                warn!("Failed to add exclusion route: {}. VPN might work without it.", error_msg.trim());
                Ok(())
            }
        }
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