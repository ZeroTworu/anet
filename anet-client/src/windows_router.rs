#[cfg(windows)]
use anyhow::{Context, Result};
#[cfg(windows)]
use log::{info, warn, debug};
#[cfg(windows)]
use std::net::Ipv4Addr;
#[cfg(windows)]
use std::process::Command;
#[cfg(windows)]
use std::collections::HashSet;

#[cfg(windows)]
pub struct WindowsRouteManager {
    vpn_gateway: String,
    vpn_server_ip: String,
    interface_metric: u32,
    tun_interface_index: u32,
    added_routes: HashSet<String>,
}

#[cfg(windows)]
impl WindowsRouteManager {
    pub fn new(vpn_gateway: &str, vpn_server_ip: String, tun_interface_index: u32) -> Self {
        Self {
            vpn_gateway: vpn_gateway.to_string(),
            vpn_server_ip,
            interface_metric: 1,
            tun_interface_index,
            added_routes: HashSet::new(),
        }
    }

    fn execute_powershell_command(&self, command: &str) -> Result<()> {
        let output = Command::new("powershell")
            .args(&["-Command", command])
            .output()
            .context("Failed to execute PowerShell command")?;

        if output.status.success() {
            Ok(())
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            if error_msg.contains("already exists") || error_msg.contains("object already exists") {
                info!("Route already exists (ignoring): {}", command);
                Ok(())
            } else {
                Err(anyhow::anyhow!("PowerShell command failed: {}", error_msg))
            }
        }
    }

    fn add_route_using_interface(
        &mut self,
        destination: &str,
        netmask: &str,
        gateway: &str,
        interface_index: u32,
        metric: u32,
    ) -> Result<()> {
        let route_key = format!("{}-{}-{}-{}", destination, netmask, gateway, interface_index);

        if self.added_routes.contains(&route_key) {
            info!("Route already tracked, skipping: {}", route_key);
            return Ok(());
        }

        let cidr = self.cidr_from_netmask(netmask)?;

        let check_command = format!(
            "Get-NetRoute -DestinationPrefix '{}/{}' -NextHop {} -InterfaceIndex {} -ErrorAction SilentlyContinue",
            destination, cidr, gateway, interface_index
        );

        let output = Command::new("powershell")
            .args(&["-Command", &check_command])
            .output()
            .context("Failed to check route existence")?;

        if output.status.success() {
            info!("Route already exists in system: {}/{} -> {}", destination, netmask, gateway);
            self.added_routes.insert(route_key);
            return Ok(());
        }

        let create_command = format!(
            "New-NetRoute -DestinationPrefix '{}/{}' -NextHop {} -InterfaceIndex {} -RouteMetric {} -Confirm:$false",
            destination, cidr, gateway, interface_index, metric
        );

        self.execute_powershell_command(&create_command)
            .context("Failed to add route via PowerShell")?;

        info!(
            "Successfully added route via PowerShell: {}/{} -> {} (interface: {}, metric {})",
            destination, netmask, gateway, interface_index, metric
        );

        self.added_routes.insert(route_key);
        Ok(())
    }

    fn cidr_from_netmask(&self, netmask: &str) -> Result<u8> {
        let ip: Ipv4Addr = netmask.parse().context("Invalid netmask")?;
        let octets = ip.octets();
        let cidr = octets.iter().map(|&o| o.count_ones() as u8).sum();
        Ok(cidr)
    }

    fn delete_route(&self, destination: &str, gateway: &str, netmask: Option<&str>) -> Result<()> {
        let prefix = if let Some(mask) = netmask {
            format!("{}/{}", destination, self.cidr_from_netmask(mask)?)
        } else {
            format!("{}/32", destination)
        };

        let ps_command = format!(
            "Remove-NetRoute -DestinationPrefix '{}' -NextHop {} -Confirm:$false -ErrorAction SilentlyContinue",
            prefix, gateway
        );

        if let Err(e) = self.execute_powershell_command(&ps_command) {
            warn!("Failed to delete route (may not exist): {}", e);
        } else {
            info!(
                "Successfully deleted route via PowerShell: {} via {}",
                destination, gateway
            );
        }
        Ok(())
    }

    pub fn setup_vpn_routing(&mut self) -> Result<()> {
        info!(
            "Setting up VPN routing using PowerShell commands with interface index {}...",
            self.tun_interface_index
        );

        self.diagnose_network_issue()?;
        self.log_routing_table("Before ANY VPN routing changes");

        let (original_gateway, physical_interface_index) = self.find_original_gateway_and_interface()
            .unwrap_or_else(|e| {
                warn!(
                    "Could not determine original gateway: {}. Using fallback.",
                    e
                );
                ("192.168.1.1".to_string(), 1)
            });

        info!("Using original gateway: {} (interface: {})", original_gateway, physical_interface_index);

        // Clone values to avoid borrowing issues
        let vpn_server_ip = self.vpn_server_ip.clone();
        let vpn_gateway = self.vpn_gateway.clone();

        info!("Step 1: Adding exclusion route for VPN server...");
        self.add_route_using_interface(
            &vpn_server_ip,
            "255.255.255.255",
            &original_gateway,
            physical_interface_index,
            5,
        )?;

        info!("Step 2: Verifying exclusion route works...");
        self.verify_exclusion_route()?;

        info!("Step 3: Waiting for TUN interface to stabilize...");
        std::thread::sleep(std::time::Duration::from_secs(3));

        info!("Step 4: Verifying TUN interface...");
        self.verify_tun_interface()?;

        info!("Step 5: Adding default route through TUN...");
        self.add_route_using_interface(
            "0.0.0.0",
            "0.0.0.0",
            &vpn_gateway,
            self.tun_interface_index,
            self.interface_metric,
        )?;

        self.log_routing_table("After VPN routing setup");
        self.diagnose_network_issue()?;

        info!("VPN routing setup completed successfully");
        Ok(())
    }

    fn verify_exclusion_route(&self) -> Result<()> {
        let check_command = format!(
            "Test-NetConnection -ComputerName {} -Port {} -InformationLevel Quiet",
            self.vpn_server_ip, 8445
        );

        let output = Command::new("powershell")
            .args(&["-Command", &check_command])
            .output()
            .context("Failed to test VPN server connectivity")?;

        if output.status.success() {
            info!("VPN server is reachable via exclusion route");
            Ok(())
        } else {
            warn!("VPN server is not reachable via exclusion route. This may cause issues.");
            Ok(())
        }
    }

    fn verify_tun_interface(&self) -> Result<()> {
        let check_command = format!(
            "Get-NetAdapter -InterfaceIndex {} | Where-Object {{ $_.Status -eq 'Up' -and $_.InterfaceOperationalStatus -eq 'Up' }}",
            self.tun_interface_index
        );

        let output = Command::new("powershell")
            .args(&["-Command", &check_command])
            .output()
            .context("Failed to check TUN interface status")?;

        if output.status.success() && !output.stdout.is_empty() {
            info!("TUN interface is UP and operational");
            Ok(())
        } else {
            warn!("TUN interface is not ready. Status: Not UP or not operational");
            Ok(())
        }
    }

    fn find_original_gateway_and_interface(&self) -> Result<(String, u32)> {
        let ps_command = r#"
        try {
            $activeAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceOperationalStatus -eq 'Up' }

            foreach ($adapter in $activeAdapters) {
                $routes = Get-NetRoute -InterfaceIndex $adapter.InterfaceIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
                foreach ($route in $routes) {
                    if ($route.NextHop -and $route.NextHop -ne "0.0.0.0" -and $route.NextHop -ne "on-link" -and $route.NextHop -ne $null) {
                        Write-Output "NextHop $($route.NextHop)"
                        Write-Output "InterfaceIndex $($route.InterfaceIndex)"
                        exit 0
                    }
                }
            }

            $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Where-Object { $_.NextHop -ne "0.0.0.0" -and $_.NextHop -ne "on-link" -and $_.NextHop -ne $null } | Select-Object -First 1
            if ($defaultRoute) {
                Write-Output "NextHop $($defaultRoute.NextHop)"
                Write-Output "InterfaceIndex $($defaultRoute.InterfaceIndex)"
                exit 0
            }

            throw "No suitable gateway found"
        } catch {
            Write-Error $_.Exception.Message
            exit 1
        }
        "#;

        let output = Command::new("powershell")
            .args(&["-Command", ps_command])
            .output()
            .context("Failed to execute PowerShell command to find default gateway")?;

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("PowerShell failed: {}", error_msg));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        debug!("Gateway search output:\n{}", output_str);

        let mut gateway = None;
        let mut interface_index = None;

        for line in output_str.lines() {
            let line = line.trim();
            if line.starts_with("NextHop") {
                gateway = line.split_whitespace().nth(1).map(|s| s.to_string());
            } else if line.starts_with("InterfaceIndex") {
                interface_index = line.split_whitespace().nth(1).and_then(|s| s.parse::<u32>().ok());
            }
        }

        match (gateway, interface_index) {
            (Some(gw), Some(idx)) if !gw.is_empty() && gw != self.vpn_gateway => {
                info!("Found original gateway: {} (interface: {})", gw, idx);
                Ok((gw, idx))
            }
            _ => Err(anyhow::anyhow!("No suitable original gateway found"))
        }
    }

    fn log_routing_table(&self, context: &str) {
        let ps_command = "Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -like '0.0.0.0/*' -or $_.DestinationPrefix -like '*/32' } | Sort-Object RouteMetric | Format-Table -AutoSize";

        if let Ok(output) = Command::new("powershell")
            .args(&["-Command", ps_command])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            debug!("{}:\n{}", context, output_str);
        }
    }

    pub fn diagnose_network_issue(&self) -> Result<()> {
        info!("=== NETWORK DIAGNOSIS ===");

        let tun_check = Command::new("powershell")
            .args(&["-Command", &format!(
                "Get-NetAdapter -InterfaceIndex {} | Format-List Name, Status, InterfaceOperationalStatus, DriverDescription",
                self.tun_interface_index
            )])
            .output()
            .context("Failed to check TUN interface")?;

        info!("TUN Interface status:\n{}", String::from_utf8_lossy(&tun_check.stdout));

        let ip_check = Command::new("powershell")
            .args(&["-Command", &format!(
                "Get-NetIPAddress -InterfaceIndex {} | Format-Table IPAddress, PrefixLength, AddressFamily",
                self.tun_interface_index
            )])
            .output()
            .context("Failed to check TUN IP configuration")?;

        info!("TUN IP Configuration:\n{}", String::from_utf8_lossy(&ip_check.stdout));

        let route_check = Command::new("powershell")
            .args(&["-Command", &format!(
                "Get-NetRoute -DestinationPrefix '{}/32' -ErrorAction SilentlyContinue | Format-Table DestinationPrefix, NextHop, InterfaceIndex, RouteMetric",
                self.vpn_server_ip
            )])
            .output()
            .context("Failed to check VPN server route")?;

        info!("VPN Server Route:\n{}", String::from_utf8_lossy(&route_check.stdout));

        let ping_check = Command::new("ping")
            .args(&["-n", "1", "-w", "1000", &self.vpn_server_ip])
            .output()
            .context("Failed to ping VPN server")?;

        info!("Ping to VPN server {}: {}", self.vpn_server_ip,
              if ping_check.status.success() { "SUCCESS" } else { "FAILED" });

        let trace_check = Command::new("tracert")
            .args(&["-d", "-w", "1000", "-h", "3", &self.vpn_server_ip])
            .output()
            .context("Failed to trace route to VPN server")?;

        info!("Traceroute to VPN server:\n{}", String::from_utf8_lossy(&trace_check.stdout));

        Ok(())
    }

    pub fn restore_original_routing(&self) {
        info!("Restoring original Windows routing...");

        self.log_routing_table("Before routing restoration");

        let mut success_count = 0;

        if self.delete_route("0.0.0.0", &self.vpn_gateway, Some("0.0.0.0")).is_ok() {
            success_count += 1;
        }

        if let Ok((original_gateway, _)) = self.find_original_gateway_and_interface() {
            if self.delete_route(&self.vpn_server_ip, &original_gateway, Some("255.255.255.255")).is_ok() {
                success_count += 1;
            } else if self.force_delete_route(&self.vpn_server_ip).is_ok() {
                success_count += 1;
            }
        } else if self.force_delete_route(&self.vpn_server_ip).is_ok() {
            success_count += 1;
        }

        self.log_routing_table("After routing restoration");

        info!("Routing cleanup finished: {} routes removed", success_count);
    }

    fn force_delete_route(&self, destination: &str) -> Result<()> {
        let ps_command = format!(
            "Get-NetRoute -DestinationPrefix '{}/32' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue",
            destination
        );

        self.execute_powershell_command(&ps_command)
            .context("Failed to force delete route")?;

        info!("Successfully force deleted route: {}", destination);
        Ok(())
    }

    pub fn setup_default_route_only(&mut self) -> Result<()> {
        info!("Setting up ONLY default route through TUN...");

        let vpn_gateway = self.vpn_gateway.clone();

        self.add_route_using_interface(
            "0.0.0.0",
            "0.0.0.0",
            &vpn_gateway,
            self.tun_interface_index,
            self.interface_metric,
        )?;

        info!("Default route setup completed");
        Ok(())
    }

    pub fn setup_exclusion_route_only(&mut self) -> Result<()> {
        info!("Setting up ONLY exclusion route for VPN server...");

        let (original_gateway, physical_interface_index) = self.find_original_gateway_and_interface()
            .unwrap_or_else(|e| {
                warn!("Could not determine original gateway: {}. Using fallback.", e);
                ("192.168.1.1".to_string(), 1)
            });

        let vpn_server_ip = self.vpn_server_ip.clone();

        self.add_route_using_interface(
            &vpn_server_ip,
            "255.255.255.255",
            &original_gateway,
            physical_interface_index,
            5,
        )?;

        info!("Exclusion route setup completed");
        Ok(())
    }
}
