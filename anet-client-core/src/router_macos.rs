//! macOS Route Manager implementation
//!
//! Uses the `route` command-line tool to manage system routing table.
//! Requires root privileges to add/delete routes.

use crate::traits::RouteManager;
use anyhow::{Context, Result};
use async_trait::async_trait;
use log::{debug, error, info, warn};
use std::net::IpAddr;
use std::process::Stdio;
use tokio::process::Command;
use tokio::sync::Mutex;

/// Represents a route added by the VPN for cleanup
#[derive(Clone, Debug)]
struct AddedRoute {
    destination: IpAddr,
    prefix: u8,
    /// Whether this route was added via gateway (bypass) or interface (tunnel)
    #[allow(dead_code)]
    via_gateway: bool,
    /// The gateway IP if via_gateway is true
    #[allow(dead_code)]
    gateway: Option<IpAddr>,
    /// The interface name if via_gateway is false
    #[allow(dead_code)]
    interface: Option<String>,
}

#[derive(Default)]
struct RouteState {
    /// Original default gateway IP
    original_gateway: Option<IpAddr>,
    /// Original default gateway interface (e.g., en0)
    original_interface: Option<String>,
    /// List of routes added by VPN (for cleanup)
    added_routes: Vec<AddedRoute>,
}

pub struct MacOSRouteManager {
    state: Mutex<RouteState>,
}

impl MacOSRouteManager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            state: Mutex::new(RouteState::default()),
        })
    }

    /// Get the default gateway by parsing `route -n get default`
    async fn get_default_gateway() -> Result<(IpAddr, String)> {
        let output = Command::new("route")
            .args(["-n", "get", "default"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("Failed to execute 'route -n get default'")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!(
                "route command failed: {}",
                stderr.trim()
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Self::parse_route_get_output(&stdout)
    }

    /// Parse the output of `route -n get default`
    fn parse_route_get_output(output: &str) -> Result<(IpAddr, String)> {
        let mut gateway: Option<IpAddr> = None;
        let mut interface: Option<String> = None;

        for line in output.lines() {
            let line = line.trim();
            if let Some(gw_str) = line.strip_prefix("gateway:") {
                let gw_str = gw_str.trim();
                // Handle link-local addresses with interface suffix (e.g., "fe80::1%en0")
                let gw_str = gw_str.split('%').next().unwrap_or(gw_str);
                if let Ok(gw) = gw_str.parse() {
                    gateway = Some(gw);
                }
            } else if let Some(iface_str) = line.strip_prefix("interface:") {
                interface = Some(iface_str.trim().to_string());
            }
        }

        match (gateway, interface) {
            (Some(gw), Some(iface)) => Ok((gw, iface)),
            (None, Some(_)) => Err(anyhow::anyhow!(
                "Could not parse gateway from route output"
            )),
            (Some(_), None) => Err(anyhow::anyhow!(
                "Could not parse interface from route output"
            )),
            (None, None) => Err(anyhow::anyhow!(
                "Could not parse gateway or interface from route output: {}",
                output
            )),
        }
    }

    /// Get interface information using netdev crate
    #[allow(dead_code)]
    fn get_interface_info(name: &str) -> Option<netdev::Interface> {
        netdev::get_interfaces()
            .into_iter()
            .find(|i| i.name == name)
    }

    /// Execute a route command and return success status
    async fn run_route_cmd(args: &[&str]) -> Result<bool> {
        debug!("Executing: route {}", args.join(" "));

        let output = Command::new("route")
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("Failed to execute route command")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !output.status.success() {
            // These are not real errors - route already exists or doesn't exist
            let stderr_lower = stderr.to_lowercase();
            if stderr_lower.contains("file exists")
                || stderr_lower.contains("not in table")
                || stderr_lower.contains("no such process")
            {
                debug!("Route command returned expected error: {}", stderr.trim());
                return Ok(true);
            }

            warn!(
                "Route command failed: {} {} (args: {:?})",
                stdout.trim(),
                stderr.trim(),
                args
            );
            return Ok(false);
        }

        debug!("Route command succeeded: {}", stdout.trim());
        Ok(true)
    }

    /// Add a host route (/32) via gateway
    async fn add_host_route_via_gateway(target: IpAddr, gateway: IpAddr) -> Result<()> {
        Self::run_route_cmd(&[
            "add",
            "-host",
            &target.to_string(),
            &gateway.to_string(),
        ])
        .await?;
        Ok(())
    }

    /// Add a network route via gateway
    async fn add_net_route_via_gateway(target: IpAddr, prefix: u8, gateway: IpAddr) -> Result<()> {
        let cidr = format!("{}/{}", target, prefix);
        Self::run_route_cmd(&["add", "-net", &cidr, &gateway.to_string()]).await?;
        Ok(())
    }

    /// Add a host route (/32) via interface
    async fn add_host_route_via_interface(target: IpAddr, interface: &str) -> Result<()> {
        Self::run_route_cmd(&[
            "add",
            "-host",
            &target.to_string(),
            "-interface",
            interface,
        ])
        .await?;
        Ok(())
    }

    /// Add a network route via interface
    async fn add_net_route_via_interface(target: IpAddr, prefix: u8, interface: &str) -> Result<()> {
        let cidr = format!("{}/{}", target, prefix);
        Self::run_route_cmd(&["add", "-net", &cidr, "-interface", interface]).await?;
        Ok(())
    }

    /// Delete a host route
    async fn delete_host_route(target: IpAddr) -> Result<()> {
        Self::run_route_cmd(&["delete", "-host", &target.to_string()]).await?;
        Ok(())
    }

    /// Delete a network route
    async fn delete_net_route(target: IpAddr, prefix: u8) -> Result<()> {
        let cidr = format!("{}/{}", target, prefix);
        Self::run_route_cmd(&["delete", "-net", &cidr]).await?;
        Ok(())
    }
}

#[async_trait]
impl RouteManager for MacOSRouteManager {
    async fn backup_routes(&self) -> Result<()> {
        let (gateway, interface) = Self::get_default_gateway().await?;

        info!(
            "Backed up default route: gateway {} via interface {}",
            gateway, interface
        );

        let mut state = self.state.lock().await;
        state.original_gateway = Some(gateway);
        state.original_interface = Some(interface);

        Ok(())
    }

    async fn add_bypass_route(&self, target: IpAddr, prefix: u8) -> Result<()> {
        let gateway = {
            let state = self.state.lock().await;
            state
                .original_gateway
                .context("Gateway not backed up - call backup_routes() first")?
        };

        info!(
            "Adding BYPASS route: {}/{} via gateway {}",
            target, prefix, gateway
        );

        // Add the route
        if prefix == 32 {
            Self::add_host_route_via_gateway(target, gateway).await?;
        } else {
            Self::add_net_route_via_gateway(target, prefix, gateway).await?;
        }

        // Track the route for cleanup
        let mut state = self.state.lock().await;
        state.added_routes.push(AddedRoute {
            destination: target,
            prefix,
            via_gateway: true,
            gateway: Some(gateway),
            interface: None,
        });

        Ok(())
    }

    async fn set_default_route(&self, _gateway: &str, interface_name: &str) -> Result<()> {
        info!(
            "Redirecting ALL traffic to TUN interface: {}",
            interface_name
        );

        // Use the 0.0.0.0/1 + 128.0.0.0/1 approach instead of replacing default route.
        // This is more robust because:
        // 1. It doesn't remove the original default route
        // 2. These /1 routes are more specific than /0 and will be preferred
        // 3. If VPN crashes, the original default route still works

        let routes_to_add = [
            (IpAddr::from([0, 0, 0, 0]), 1u8),      // 0.0.0.0/1 - covers 0.0.0.0 - 127.255.255.255
            (IpAddr::from([128, 0, 0, 0]), 1u8),   // 128.0.0.0/1 - covers 128.0.0.0 - 255.255.255.255
        ];

        for (dest, prefix) in routes_to_add {
            // Try to delete existing route first (ignore errors)
            let _ = Self::delete_net_route(dest, prefix).await;

            // Add new route via TUN interface
            if let Err(e) = Self::add_net_route_via_interface(dest, prefix, interface_name).await {
                error!("Failed to add route {}/{}: {}", dest, prefix, e);
                // Continue trying to add other routes
            } else {
                let mut state = self.state.lock().await;
                state.added_routes.push(AddedRoute {
                    destination: dest,
                    prefix,
                    via_gateway: false,
                    gateway: None,
                    interface: Some(interface_name.to_string()),
                });
            }
        }

        info!("Default route redirected to {}", interface_name);
        Ok(())
    }

    async fn add_specific_route(
        &self,
        target: IpAddr,
        prefix: u8,
        _gateway: &str,
        interface_name: &str,
    ) -> Result<()> {
        info!(
            "Adding split-tunnel route: {}/{} via interface {}",
            target, prefix, interface_name
        );

        // Try to delete existing route first (ignore errors)
        if prefix == 32 {
            let _ = Self::delete_host_route(target).await;
            Self::add_host_route_via_interface(target, interface_name).await?;
        } else {
            let _ = Self::delete_net_route(target, prefix).await;
            Self::add_net_route_via_interface(target, prefix, interface_name).await?;
        }

        // Track the route for cleanup
        let mut state = self.state.lock().await;
        state.added_routes.push(AddedRoute {
            destination: target,
            prefix,
            via_gateway: false,
            gateway: None,
            interface: Some(interface_name.to_string()),
        });

        Ok(())
    }

    async fn restore_routes(&self) -> Result<()> {
        info!("Restoring original routing table...");

        let mut state = self.state.lock().await;
        let mut errors = Vec::new();

        // Remove all added routes in reverse order (LIFO)
        while let Some(route) = state.added_routes.pop() {
            debug!(
                "Removing route: {}/{} (via_gateway: {})",
                route.destination, route.prefix, route.via_gateway
            );

            let result = if route.prefix == 32 {
                Self::delete_host_route(route.destination).await
            } else {
                Self::delete_net_route(route.destination, route.prefix).await
            };

            if let Err(e) = result {
                errors.push(format!("{}/{}: {}", route.destination, route.prefix, e));
            }
        }

        if !errors.is_empty() {
            warn!("Some routes could not be removed: {:?}", errors);
        }

        info!("Routing table restored.");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_route_get_output() {
        let output = r#"
   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
"#;
        let (gateway, interface) = MacOSRouteManager::parse_route_get_output(output).unwrap();
        assert_eq!(gateway, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(interface, "en0");
    }

    #[test]
    fn test_parse_route_get_output_ipv6_linklocal() {
        let output = r#"
   route to: default
destination: default
       mask: default
    gateway: fe80::1%en0
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
"#;
        let (gateway, interface) = MacOSRouteManager::parse_route_get_output(output).unwrap();
        assert_eq!(gateway, "fe80::1".parse::<IpAddr>().unwrap());
        assert_eq!(interface, "en0");
    }

    #[test]
    fn test_parse_route_get_output_missing_gateway() {
        let output = r#"
   route to: default
destination: default
  interface: en0
"#;
        let result = MacOSRouteManager::parse_route_get_output(output);
        assert!(result.is_err());
    }
}
