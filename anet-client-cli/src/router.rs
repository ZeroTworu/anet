use anet_client_core::traits::RouteManager;
use anyhow::{Context, Result};
use log::{debug, info, warn};
use netdev::{Interface, get_default_gateway, get_interfaces};
use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::Mutex;

/// Внутреннее состояние для хранения оригинальных маршрутов
#[derive(Default)]
struct RouteState {
    original_gateway: Option<String>,
    original_interface: Option<String>,
    #[cfg(windows)]
    original_interface_index: Option<u32>,
    server_ip_cache: Option<String>,
}

pub struct DesktopRouteManager {
    state: Mutex<RouteState>,
}

impl DesktopRouteManager {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(RouteState::default()),
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
            .context("Failed to find a suitable physical interface")?;

        info!(
            "Selected interface: '{}' (index: {}) for routing.",
            default_interface
                .friendly_name
                .as_deref()
                .unwrap_or(&default_interface.name),
            default_interface.index
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
        // 1. Ищем интерфейс, чья подсеть содержит шлюз
        if let Some(iface) = interfaces.iter().find(|i| {
            self.is_suitable_interface(i) && i.ipv4.iter().any(|net| net.contains(&gateway_ip))
        }) {
            debug!("Found interface '{}' via subnet match", iface.name);
            return Ok(iface);
        }

        warn!("Gateway IP {} not found in any local subnet.", gateway_ip);

        // 2. Fallback: берем первый "подходящий"
        if let Some(iface) = interfaces.iter().find(|i| self.is_suitable_interface(i)) {
            warn!("Fallback to interface: '{}'.", iface.name);
            return Ok(iface);
        }

        Err(anyhow::anyhow!("No suitable network interface found."))
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
        let name = interface
            .friendly_name
            .as_deref()
            .unwrap_or(&interface.name)
            .to_lowercase();

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
            .any(|&kw| name.contains(kw) || interface.name.starts_with(kw))
    }
}

impl RouteManager for DesktopRouteManager {
    fn backup_routes(&self) -> Result<()> {
        let (gateway, interface, index) = self.find_default_interface_and_gateway()?;

        let mut state = self.state.lock().unwrap();
        state.original_gateway = Some(gateway);
        state.original_interface = Some(interface);

        #[cfg(windows)]
        {
            state.original_interface_index = Some(index);
        }
        // Чтобы подавить warning unused variable на linux
        let _ = index;

        info!("Routes backed up.");
        Ok(())
    }

    fn add_exclusion_route(&self, server_ip: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        // Кэшируем IP сервера для очистки в restore()
        state.server_ip_cache = Some(server_ip.to_string());

        info!("Setting exclusion route to VPN server: {}", server_ip);

        #[cfg(unix)]
        {
            let gateway = state
                .original_gateway
                .as_ref()
                .context("Gateway not backed up")?;
            let interface = state
                .original_interface
                .as_ref()
                .context("Interface not backed up")?;

            let status = Command::new("ip")
                .args([
                    "route", "replace", server_ip, "via", gateway, "dev", interface,
                ])
                .status()?;

            if !status.success() {
                return Err(anyhow::anyhow!("Failed to set exclusion route"));
            }
        }

        #[cfg(windows)]
        {
            let gateway = state
                .original_gateway
                .as_ref()
                .context("Gateway not backed up")?;
            let index = state
                .original_interface_index
                .context("Interface index not backed up")?;

            // Сначала удаляем старый (на всякий случай)
            let _ = Command::new("route").args(["delete", server_ip]).output();

            let output = Command::new("route")
                .args([
                    "add",
                    server_ip,
                    "mask",
                    "255.255.255.255",
                    gateway,
                    "if",
                    &index.to_string(),
                    "metric",
                    "5",
                ])
                .output()?;

            if !output.status.success() {
                let err = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow::anyhow!("Failed to add route (Win): {}", err.trim()));
            }
        }

        Ok(())
    }

    fn set_default_route(&self, gateway: &str, interface_name: &str) -> Result<()> {
        #[cfg(unix)]
        {
            info!("Replacing default route via VPN ({})", interface_name);
            let status = Command::new("ip")
                .args([
                    "route",
                    "replace",
                    "default",
                    "via",
                    gateway,
                    "dev",
                    interface_name,
                ])
                .status()?;

            if !status.success() {
                return Err(anyhow::anyhow!("Failed to replace default route"));
            }
        }

        #[cfg(windows)]
        {
            // На Windows маршрутизация обычно работает сама, если у TUN метрика ниже.
            // Но если нужно форсировать - тут сложнее (надо менять метрики).
            // Пока оставим warning, так как в старом коде для Win этого метода не было.
            warn!(
                "set_default_route is not strictly implemented for Windows in this CLI yet (relying on interface metrics)."
            );
        }

        Ok(())
    }

    fn restore_routes(&self) -> Result<()> {
        let state = self.state.lock().unwrap();
        info!("Restoring original routing...");

        #[cfg(unix)]
        {
            if let (Some(gw), Some(iface)) = (&state.original_gateway, &state.original_interface) {
                let _ = Command::new("ip")
                    .args(["route", "replace", "default", "via", gw, "dev", iface])
                    .status();
            }

            if let Some(server_ip) = &state.server_ip_cache {
                let _ = Command::new("ip")
                    .args(["route", "del", server_ip])
                    .status();
            }
        }

        #[cfg(windows)]
        {
            if let Some(server_ip) = &state.server_ip_cache {
                let _ = Command::new("route").args(["delete", server_ip]).output();
            }
            // Дефолтный маршрут на винде обычно восстанавливается сам при падении интерфейса
        }

        info!("Routing restored.");
        Ok(())
    }
}
