//! DNS configuration module
//!
//! Provides platform-specific DNS configuration for VPN connections.

use anyhow::Result;

/// Trait for managing system DNS configuration
pub trait DnsManager: Send + Sync {
    /// Configure DNS servers for the VPN connection
    fn set_dns(&self, servers: &[String]) -> Result<()>;

    /// Restore original DNS configuration
    fn restore_dns(&self) -> Result<()>;
}

/// No-op DNS manager for platforms that don't need special handling
/// (e.g., Android handles DNS automatically, Windows handles via netsh in tun_factory)
pub struct NoOpDnsManager;

impl DnsManager for NoOpDnsManager {
    fn set_dns(&self, _servers: &[String]) -> Result<()> {
        Ok(())
    }

    fn restore_dns(&self) -> Result<()> {
        Ok(())
    }
}

// Platform-specific implementations
#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::MacOSDnsManager;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::LinuxDnsManager;

/// Create a platform-appropriate DNS manager
#[cfg(target_os = "macos")]
pub fn create_dns_manager() -> Box<dyn DnsManager> {
    Box::new(MacOSDnsManager::new())
}

#[cfg(target_os = "linux")]
pub fn create_dns_manager() -> Box<dyn DnsManager> {
    Box::new(LinuxDnsManager::new())
}

#[cfg(target_os = "windows")]
pub fn create_dns_manager() -> Box<dyn DnsManager> {
    // Windows DNS is configured via netsh when setting up the interface
    // The GUI's tun_factory already handles DNS for Windows
    Box::new(NoOpDnsManager)
}

#[cfg(target_os = "android")]
pub fn create_dns_manager() -> Box<dyn DnsManager> {
    // Android handles DNS through VpnService
    Box::new(NoOpDnsManager)
}
