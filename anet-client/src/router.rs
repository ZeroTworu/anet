use anyhow::{Context, Result};
use log::{debug, info, warn};
use netdev::{Interface, get_default_gateway, get_interfaces};
use std::net::Ipv4Addr;
use std::process::Command;

pub struct RouteManager {
    vpn_server_ip: String,
    original_gateway: Option<String>,
    original_interface: Option<String>,
}

impl RouteManager {
    pub fn new(vpn_server_ip: String) -> Self {
        Self {
            vpn_server_ip,
            original_gateway: None,
            original_interface: None,
        }
    }

    fn find_default_interface_and_gateway(&self) -> Result<(String, String, u32)> {
        let default_gateway = get_default_gateway()
            .map_err(|e| anyhow::anyhow!("Failed to get default gateway: {}", e))?;
        let gateway_ip = *default_gateway
            .ipv4
            .first()
            .context("Default gateway has no IPv4 address")?;
        info!(
            "System default gateway found: IP={}, MAC={}",
            gateway_ip, default_gateway.mac_addr
        );
        let interfaces = get_interfaces();
        let default_interface = self
            .find_interface_for_gateway(&interfaces, gateway_ip)
            .context("Failed to find a suitable physical interface for the default gateway")?;
        info!(
            "Selected interface: '{}' (index: {}, type: {}) for routing.",
            default_interface
                .friendly_name
                .as_deref()
                .unwrap_or(&default_interface.name),
            default_interface.index,
            default_interface.if_type.name()
        );
        Ok((
            gateway_ip.to_string(),
            default_interface.name.clone(),
            default_interface.index,
        ))
    }

    fn find_interface_for_gateway<'a>(
        &self,
        interfaces: &'a [Interface],
        gateway_ip: Ipv4Addr,
    ) -> Result<&'a Interface> {
        if let Some(iface) = interfaces.iter().find(|i| {
            self.is_suitable_interface(i) && i.ipv4.iter().any(|net| net.contains(&gateway_ip))
        }) {
            debug!(
                "Found interface '{}' because its network contains the gateway IP {}",
                iface.name, gateway_ip
            );
            return Ok(iface);
        }
        warn!(
            "Could not find any suitable interface whose network contains the gateway IP ({}).",
            gateway_ip
        );
        if let Some(iface) = interfaces.iter().find(|i| self.is_suitable_interface(i)) {
            warn!(
                "Falling back to the first available suitable interface: '{}'. This might be incorrect.",
                iface.name
            );
            return Ok(iface);
        }
        Err(anyhow::anyhow!(
            "No suitable physical network interface could be found."
        ))
    }

    fn is_suitable_interface(&self, interface: &Interface) -> bool {
        interface.is_up()
            && interface.is_oper_up()
            && !interface.ipv4.is_empty()
            && !self.is_virtual_interface(interface)
    }

    fn is_virtual_interface(&self, interface: &Interface) -> bool {
        if interface.is_loopback() || interface.is_tun() {
            return true;
        }
        let name_to_check = interface
            .friendly_name
            .as_deref()
            .unwrap_or(&interface.name);
        let lower_name = name_to_check.to_lowercase();
        let virtual_keywords = [
            "vnet",
            "virbr",
            "br-",
            "docker",
            "veth",
            "tunnel",
            "virtual",
            "vpn",
            "anet",
            "loopback",
            "teredo",
            "wsl",
            "tap",
            "radmin",
            "vmware",
            "vbox",
            "host-only",
            "outline",
        ];
        virtual_keywords
            .iter()
            .any(|&kw| lower_name.contains(kw) || interface.name.starts_with(kw))
    }

    pub fn backup_original_routes(&mut self) -> Result<()> {
        let (gateway, interface, _) = self.find_default_interface_and_gateway()?;
        self.original_gateway = Some(gateway);
        self.original_interface = Some(interface);
        info!(
            "Backed up original routes - Gateway: {:?}, Interface: {:?}",
            self.original_gateway, self.original_interface
        );
        Ok(())
    }

    /// Создает маршрут до VPN-сервера в обход будущего туннеля.
    pub fn setup_exclusion_route(&self) -> Result<()> {
        info!("Setting up exclusion route for VPN server...");
        #[cfg(unix)]
        {
            if let (Some(gateway), Some(interface)) =
                (&self.original_gateway, &self.original_interface)
            {
                let status = Command::new("ip")
                    .args([
                        "route",
                        "replace",
                        &self.vpn_server_ip,
                        "via",
                        gateway,
                        "dev",
                        interface,
                    ])
                    .status()?;
                if !status.success() {
                    return Err(anyhow::anyhow!(
                        "Failed to set exclusion route for VPN server"
                    ));
                }
                info!(
                    "Ensured route to VPN server {} via {}",
                    self.vpn_server_ip, gateway
                );
            } else {
                return Err(anyhow::anyhow!(
                    "Original gateway not backed up, cannot create exception route."
                ));
            }
        }
        #[cfg(windows)]
        {
            let (gateway, _, interface_index) = self.find_default_interface_and_gateway()?;
            info!(
                "Using gateway: {} on interface index: {}",
                gateway, interface_index
            );
            let _ = Command::new("route")
                .args(&["delete", &self.vpn_server_ip])
                .output();
            let output = Command::new("route")
                .args([
                    "add",
                    &self.vpn_server_ip,
                    "mask",
                    "255.255.255.255",
                    &gateway,
                    "if",
                    &interface_index.to_string(),
                    "metric",
                    "5",
                ])
                .output()
                .context("Failed to execute 'route add' command")?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow::anyhow!(
                    "Failed to add exclusion route: {}",
                    stderr.trim()
                ));
            }
        }
        Ok(())
    }

    /// Направляет весь трафик через VPN (только для Linux).
    #[cfg(unix)]
    pub fn set_vpn_as_default_gateway(
        &self,
        vpn_tun_gateway: &str,
        vpn_tun_interface: &str,
    ) -> Result<()> {
        info!("Setting VPN as default gateway...");
        let status = Command::new("ip")
            .args([
                "route",
                "replace",
                "default",
                "via",
                vpn_tun_gateway,
                "dev",
                vpn_tun_interface,
            ])
            .status()?;
        if !status.success() {
            return Err(anyhow::anyhow!(
                "Failed to replace default route to point to VPN."
            ));
        }
        info!(
            "Successfully replaced default route to point to VPN via {}",
            vpn_tun_gateway
        );
        Ok(())
    }

    pub fn restore_routing(&self) -> Result<()> {
        info!("Restoring original routing...");
        #[cfg(unix)]
        {
            if let (Some(gateway), Some(interface)) =
                (&self.original_gateway, &self.original_interface)
            {
                let _ = Command::new("ip")
                    .args([
                        "route", "replace", "default", "via", gateway, "dev", interface,
                    ])
                    .status();
                info!("Restored original default route via {}", gateway);
            }
            let _ = Command::new("ip")
                .args(&["route", "del", &self.vpn_server_ip])
                .status();
        }
        #[cfg(windows)]
        {
            let output = Command::new("route")
                .args(&["delete", &self.vpn_server_ip])
                .output()?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("not found") {
                    warn!("Could not remove exclusion route: {}", stderr.trim());
                }
            }
        }
        info!("Original routing restored.");
        Ok(())
    }
}
