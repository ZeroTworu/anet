// ./anet-client/src/windows_router.rs
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

    fn find_physical_interface_gateway(&self) -> Result<(String, String, String)> {
        // Улучшенный PowerShell код для поиска физического интерфейса
        let ps_command = r#"
        try {
            # Получаем физические адаптеры, которые подключены и работают
            $physicalAdapters = Get-NetAdapter -Physical | Where-Object {
                $_.Status -eq 'Up' -and $_.MediaConnectState -eq 'Connected'
            }

            if (-not $physicalAdapters) {
                Write-Output "No connected physical adapters found"
                exit 1
            }

            # Для каждого адаптера получаем сетевую конфигурацию
            foreach ($adapter in $physicalAdapters) {
                $ifIndex = $adapter.ifIndex
                $ifName = $adapter.Name

                # Получаем IP конфигурацию (исключая localhost)
                $ipConfig = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue |
                            Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -ne '0.0.0.0' }

                if (-not $ipConfig) {
                    continue
                }

                # Получаем шлюз по умолчанию для этого интерфейса
                $gateway = Get-NetRoute -InterfaceIndex $ifIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
                           Select-Object -First 1 -ExpandProperty NextHop

                if ($gateway -and $gateway -match '^\d+\.\d+\.\d+\.\d+$') {
                    # Возвращаем объект с нужными свойствами
                    [PSCustomObject]@{
                        Interface = $ifName
                        Gateway = $gateway
                        InterfaceIndex = $ifIndex
                        IPAddress = $ipConfig.IPAddress
                    }
                    break  # Берем первый подходящий
                }
            }
        } catch {
            Write-Error "Error: $_"
            exit 1
        }
        "#;

        let output = Command::new("powershell")
            .args(&["-Command", ps_command])
            .output()
            .context("Failed to execute PowerShell command")?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "PowerShell command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);

        if output_str.trim().is_empty() || output_str.contains("No connected physical adapters found") {
            return Err(anyhow::anyhow!("No connected physical network interfaces found"));
        }

        // Парсим вывод PowerShell
        let mut gateway = None;
        let mut interface = None;
        let mut interface_index = None;

        for line in output_str.lines() {
            let line = line.trim();
            if line.starts_with("Gateway") {
                gateway = line.splitn(2, ':').nth(1).map(|s| s.trim().to_string());
            } else if line.starts_with("Interface") {
                interface = line.splitn(2, ':').nth(1).map(|s| s.trim().to_string());
            } else if line.starts_with("InterfaceIndex") {
                interface_index = line.splitn(2, ':').nth(1).map(|s| s.trim().to_string());
            }
        }

        match (gateway, interface, interface_index) {
            (Some(gw), Some(iface), Some(index)) if !gw.is_empty() => {
                info!("Found physical interface: {} (index: {}) with gateway: {}", iface, index, gw);
                Ok((gw, iface, index))
            }
            _ => {
                debug!("PowerShell output: {}", output_str);
                Err(anyhow::anyhow!("Could not parse physical interface information from PowerShell output"))
            }
        }
    }

    pub fn setup_exclusion_route(&self) -> Result<()> {
        info!("Setting up exclusion route for VPN server {}", self.vpn_server_ip);

        // Находим физический интерфейс и его шлюз
        let (gateway, interface_name, interface_index) = self.find_physical_interface_gateway()?;

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
                "if", &interface_index,
                "metric", "5"
            ])
            .output()
            .context("Failed to add exclusion route")?;

        if add_output.status.success() {
            info!("Successfully added exclusion route for VPN server via {} on {}", gateway, interface_name);
            Ok(())
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
                Ok(())
            } else {
                let error_msg = String::from_utf8_lossy(&add_output.stderr);
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
