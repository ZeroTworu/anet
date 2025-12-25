use anet_client_core::traits::RouteManager;
use anyhow::{Context, Result};
use log::{debug, info, warn};
use netdev::{Interface, get_default_gateway, get_interfaces};
use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::Mutex;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

// Флаг создания процесса без окна консоли
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Вспомогательная функция для тихого запуска команд на Windows
fn run_silent_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    // Собираем команду в строку для cmd
    // Например: "route add ..."
    let mut cmd_line = format!("{} ", cmd);
    cmd_line.push_str(&args.join(" "));

    debug!("Running silent via cmd /c: {}", cmd_line);

    let mut command = Command::new("cmd");

    // /C - выполнить и закрыть
    command.args(&["/C", &cmd_line]);

    command.stdout(std::process::Stdio::null());
    command.stderr(std::process::Stdio::null());
    command.stdin(std::process::Stdio::null());

    // Скрываем окно САМОГО cmd.exe
    command.creation_flags(CREATE_NO_WINDOW).spawn().expect("failed to run silent cmd");;;


    Ok(())
}

#[derive(Default)]
struct RouteState {
    original_gateway: Option<String>,
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

    fn find_default_interface_and_gateway(&self) -> Result<(String, u32)> {
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

        Ok((gateway_ip.to_string(), default_interface.index))
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
            "hyper-v",
        ];

        virtual_keywords
            .iter()
            .any(|&kw| name.contains(kw) || interface.name.starts_with(kw))
    }
}

impl RouteManager for DesktopRouteManager {
    fn backup_routes(&self) -> Result<()> {
        let (gateway, index) = self.find_default_interface_and_gateway()?;

        let mut state = self.state.lock().unwrap();
        state.original_gateway = Some(gateway);
        state.original_interface_index = Some(index);

        info!("Routes backed up.");
        Ok(())
    }

    fn add_exclusion_route(&self, server_ip: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        // Кэшируем IP сервера для очистки в restore()
        state.server_ip_cache = Some(server_ip.to_string());

        info!("Setting exclusion route to VPN server: {}", server_ip);

        let gateway = state
            .original_gateway
            .as_ref()
            .context("Gateway not backed up")?;
        let index = state
            .original_interface_index
            .context("Interface index not backed up")?;
        let index_str = index.to_string();

        // 1. Сначала удаляем старый (на всякий случай, игнорируем ошибку)
        let _ = run_silent_cmd("route", &["delete", server_ip]);

        // 2. Добавляем маршрут
        // route add <IP> mask 255.255.255.255 <Gateway> if <Index> metric 5
        run_silent_cmd(
            "route",
            &[
                "add",
                server_ip,
                "mask",
                "255.255.255.255",
                gateway,
                "if",
                &index_str,
                "metric",
                "5",
            ],
        ).context("Failed to add exclusion route via route.exe")?;

        Ok(())
    }

    fn set_default_route(&self, _gateway: &str, _interface_name: &str) -> Result<()> {
        // На Windows при поднятии TUN-интерфейса (Wintun) он сам получает метрику.
        debug!("Windows routing: relying on interface metrics for default route.");
        Ok(())
    }

    fn restore_routes(&self) -> Result<()> {
        let state = self.state.lock().unwrap();
        info!("Restoring original routing...");

        if let Some(server_ip) = &state.server_ip_cache {
            // Тихо удаляем маршрут
            let _ = run_silent_cmd("route", &["delete", server_ip]);
        }

        // Дефолтный маршрут на винде восстанавливается сам при удалении TUN.

        info!("Routing restored.");
        Ok(())
    }
}
