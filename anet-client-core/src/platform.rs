//! Platform abstraction helpers
//!
//! This module provides convenient factory functions for creating
//! platform-specific managers (routing, DNS, etc.)

use crate::dns::{DnsManager, create_dns_manager};
#[cfg(any(target_os = "linux", target_os = "windows"))]
use crate::router::desktop::DesktopRouteManager;
#[cfg(target_os = "macos")]
use crate::router::macos::MacOSRouteManager;
use crate::traits::RouteManager;
use anyhow::Result;

pub struct NoOpRouteManager;

#[async_trait::async_trait]
impl RouteManager for NoOpRouteManager {
    async fn backup_routes(&self) -> Result<()> {
        Ok(())
    }

    async fn add_bypass_route(&self, _target: std::net::IpAddr, _prefix: u8) -> Result<()> {
        Ok(())
    }

    async fn set_default_route(&self, _gateway: &str, _interface_name: &str) -> Result<()> {
        Ok(())
    }

    async fn add_specific_route(
        &self,
        _target: std::net::IpAddr,
        _prefix: u8,
        _gateway: &str,
        _interface_name: &str,
    ) -> Result<()> {
        Ok(())
    }

    async fn restore_routes(&self) -> Result<()> {
        Ok(())
    }
}

/// Create a platform-appropriate route manager
///
/// # Platform behavior
/// - **Linux/Windows**: Uses `net-route` crate via `DesktopRouteManager`
/// - **macOS**: Uses shell commands (`route`) via `MacOSRouteManager`
///
/// # Errors
/// Returns an error if the route manager fails to initialize
/// (e.g., insufficient permissions, missing dependencies)
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub fn create_route_manager(manual_routing: bool) -> Result<Box<dyn RouteManager>> {
    use log::info;
    if manual_routing {
        info!("Manual routing enabled");
        return Ok(Box::new(NoOpRouteManager));
    }
    info!("Enabled auto routing");
    Ok(Box::new(DesktopRouteManager::new()?))
}

#[cfg(target_os = "macos")]
pub fn create_route_manager(_manual_routing: bool) -> Result<Box<dyn RouteManager>> {
    Ok(Box::new(MacOSRouteManager::new()?))
}

#[cfg(target_os = "android")]
pub fn create_route_manager(_manual_routing: bool) -> Result<Box<dyn RouteManager>> {
    // Android uses VpnService for routing - return a no-op manager
    Ok(Box::new(NoOpRouteManager))
}

/// Create a platform-appropriate DNS manager
///
/// # Platform behavior
/// - **Linux**: Modifies `/etc/resolv.conf`
/// - **Windows**: Uses `netsh` (typically handled in TUN factory)
/// - **macOS**: Uses `scutil` for System Configuration
/// - **Android**: No-op (VpnService handles DNS)
pub fn create_platform_dns_manager() -> Box<dyn DnsManager> {
    create_dns_manager()
}

/// No-op route manager for platforms that handle routing internally

/// Check if the current platform requires root/admin privileges for VPN
pub fn requires_elevated_privileges() -> bool {
    cfg!(any(target_os = "linux", target_os = "macos"))
}

/// Get the recommended TUN interface name for the current platform
pub fn default_tun_name() -> &'static str {
    #[cfg(target_os = "linux")]
    return "anet0";

    #[cfg(target_os = "windows")]
    return "ANet";

    #[cfg(target_os = "macos")]
    return "utun";

    #[cfg(target_os = "android")]
    return "tun0";

    #[cfg(not(any(
        target_os = "linux",
        target_os = "windows",
        target_os = "macos",
        target_os = "android"
    )))]
    return "tun0";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_tun_name() {
        let name = default_tun_name();
        assert!(!name.is_empty());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_requires_elevated_privileges_macos() {
        assert!(requires_elevated_privileges());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_requires_elevated_privileges_linux() {
        assert!(requires_elevated_privileges());
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_requires_elevated_privileges_windows() {
        assert!(!requires_elevated_privileges());
    }
}
