#[cfg(windows)]
use anyhow::{Context, Result};
#[cfg(windows)]
use log::{error, info, warn};
#[cfg(windows)]
use std::net::Ipv4Addr;
#[cfg(windows)]
use std::process::Command;

#[cfg(windows)]
pub struct WindowsRouteManager {
    vpn_gateway: String,
    vpn_server_ip: String,
    interface_metric: u32,
    tun_interface_index: u32,
}

#[cfg(windows)]
impl WindowsRouteManager {
    pub fn new(vpn_gateway: &str, vpn_server_ip: String, tun_interface_index: u32) -> Self {
        Self {
            vpn_gateway: vpn_gateway.to_string(),
            vpn_server_ip,
            interface_metric: 50,
            tun_interface_index,
        }
    }

    fn add_route_using_interface(
        &self,
        destination: &str,
        netmask: &str,
        gateway: &str,
        interface_index: u32,
        metric: u32,
    ) -> Result<()> {
        // Используем PowerShell для более надежного добавления маршрута с указанием интерфейса
        let ps_command = format!(
            "New-NetRoute -DestinationPrefix '{}/{}' -NextHop {} -InterfaceIndex {} -RouteMetric {} -Confirm:$false",
            destination,
            self.cidr_from_netmask(netmask)?,
            gateway,
            interface_index,
            metric
        );

        let output = Command::new("powershell")
            .args(&["-Command", &ps_command])
            .output()
            .context("Failed to execute PowerShell command")?;

        if output.status.success() {
            info!("Successfully added route via PowerShell: {}/{} -> {} (interface: {}, metric {})",
                  destination, netmask, gateway, interface_index, metric);
            Ok(())
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            warn!("PowerShell failed: {}, falling back to route command", error_msg);

            // Fallback к традиционной команде route
            self.add_route_cmd(destination, netmask, gateway, metric)
        }
    }

    fn cidr_from_netmask(&self, netmask: &str) -> Result<u8> {
        let ip: Ipv4Addr = netmask.parse().context("Invalid netmask")?;
        let octets = ip.octets();
        let cidr = octets.iter().map(|&o| o.count_ones() as u8).sum();
        Ok(cidr)
    }

    fn add_route_cmd(
        &self,
        destination: &str,
        netmask: &str,
        gateway: &str,
        metric: u32,
    ) -> Result<()> {
        let status = Command::new("route")
            .args(&[
                "ADD",
                destination,
                "MASK",
                netmask,
                gateway,
                "METRIC",
                &metric.to_string(),
                "IF",
                &self.tun_interface_index.to_string(),
            ])
            .status()
            .context("Failed to execute route command")?;

        if status.success() {
            info!("Successfully added route via command: {} -> {} via {} (interface: {}, metric {})",
                  destination, netmask, gateway, self.tun_interface_index, metric);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Command failed to add route, exit status: {:?}", status))
        }
    }

    fn delete_route_using_interface(&self, destination: &str, gateway: &str) -> Result<()> {
        // Попробуем PowerShell сначала
        let ps_command = format!(
            "Remove-NetRoute -DestinationPrefix '{}/32' -NextHop {} -Confirm:$false -ErrorAction SilentlyContinue",
            destination, gateway
        );

        let output = Command::new("powershell")
            .args(&["-Command", &ps_command])
            .output()
            .context("Failed to execute PowerShell command")?;

        if output.status.success() {
            info!("Successfully deleted route via PowerShell: {} via {}", destination, gateway);
            Ok(())
        } else {
            // Fallback к команде route
            self.delete_route_cmd(destination, gateway)
        }
    }

    fn delete_route_cmd(&self, destination: &str, gateway: &str) -> Result<()> {
        let status = Command::new("route")
            .args(&["DELETE", destination, gateway])
            .status()
            .context("Failed to execute route delete command")?;

        if status.success() {
            info!("Successfully deleted route via command: {} via {}", destination, gateway);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Command failed to delete route, exit status: {:?}", status))
        }
    }

    pub fn setup_vpn_routing(&self) -> Result<()> {
        info!("Setting up VPN routing using PowerShell/route commands with interface index {}...",
              self.tun_interface_index);

        // 1. Add exclusion route for VPN server через физический интерфейс
        let original_gateway = self.find_original_gateway()
            .unwrap_or_else(|e| {
                warn!("Could not determine original gateway: {}. Using fallback.", e);
                "192.168.1.1".to_string() // Common home router IP
            });

        let physical_interface_index = self.find_physical_interface_index(&original_gateway)
            .unwrap_or(1); // Fallback к interface 1

        // Добавляем исключающий маршрут через физический интерфейс
        self.add_route_using_interface(
            &self.vpn_server_ip,
            "255.255.255.255",
            &original_gateway,
            physical_interface_index,
            5,
        )?;

        // 2. Add new default route through VPN gateway using TUN interface
        self.add_route_using_interface(
            "0.0.0.0",
            "0.0.0.0",
            &self.vpn_gateway,
            self.tun_interface_index,
            self.interface_metric,
        )?;

        info!("VPN routing setup completed successfully");
        Ok(())
    }

    fn find_original_gateway(&self) -> Result<String> {
        let output = Command::new("cmd")
            .args(&["/C", "route print -4"])
            .output()
            .context("Failed to run 'route print -4'")?;

        let output_str = String::from_utf8_lossy(&output.stdout);

        for line in output_str.lines() {
            if line.trim().starts_with("0.0.0.0") && line.contains("0.0.0.0") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let ip = parts[2].trim();
                    if ip != "0.0.0.0" && ip != &self.vpn_gateway {
                        return Ok(ip.to_string());
                    }
                }
            }
        }

        Err(anyhow::anyhow!("No suitable original gateway found"))
    }

    fn find_physical_interface_index(&self, gateway: &str) -> Result<u32> {
        // Используем PowerShell чтобы найти индекс интерфейса по шлюзу
        let ps_command = format!(
            "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object {{ $_.NextHop -eq '{}' }} | Select-Object -First 1 -ExpandProperty InterfaceIndex",
            gateway
        );

        let output = Command::new("powershell")
            .args(&["-Command", &ps_command])
            .output()
            .context("Failed to execute PowerShell command to find interface index")?;

        if output.status.success() {
            let index_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if let Ok(index) = index_str.parse::<u32>() {
                return Ok(index);
            }
        }

        // Fallback: используем первый доступный интерфейс
        warn!("Could not determine physical interface index for gateway {}, using default", gateway);
        Ok(1)
    }

    pub fn restore_original_routing(&self) {
        info!("Restoring original Windows routing...");

        let mut success_count = 0;
        let mut error_count = 0;

        // Удаляем исключающий маршрут к VPN серверу
        if let Err(e) = self.delete_route_using_interface(&self.vpn_server_ip, &self.vpn_gateway) {
            error!("Failed to delete exclusion route: {}", e);
            error_count += 1;
        } else {
            success_count += 1;
        }

        // Удаляем маршрут по умолчанию через VPN
        if let Err(e) = self.delete_route_using_interface("0.0.0.0", &self.vpn_gateway) {
            error!("Failed to delete default route: {}", e);
            error_count += 1;
        } else {
            success_count += 1;
        }

        info!("Routing cleanup finished: {} successful, {} failed", success_count, error_count);
    }
}
