//! macOS DNS configuration using scutil
//!
//! Uses the System Configuration framework via scutil to configure DNS.
//! This approach integrates properly with macOS's DNS resolution system.

use super::DnsManager;
use anyhow::{Context, Result};
use log::{debug, info, warn};
use std::io::Write;
use std::process::{Command, Stdio};

/// Service name used for VPN DNS configuration
const DNS_SERVICE_NAME: &str = "ANetVPN";

/// macOS DNS manager using scutil
pub struct MacOSDnsManager {
    /// Whether DNS has been configured (for cleanup tracking)
    configured: std::sync::atomic::AtomicBool,
}

impl MacOSDnsManager {
    pub fn new() -> Self {
        Self {
            configured: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Run scutil with the given commands via stdin
    fn run_scutil(commands: &str) -> Result<()> {
        debug!("Running scutil with commands:\n{}", commands);

        let mut child = Command::new("scutil")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn scutil")?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(commands.as_bytes())
                .context("Failed to write to scutil stdin")?;
        }

        let output = child.wait_with_output().context("Failed to wait for scutil")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            warn!(
                "scutil command may have failed: stdout={}, stderr={}",
                stdout.trim(),
                stderr.trim()
            );
        }

        Ok(())
    }

    /// Build the scutil commands to set DNS servers
    fn build_dns_set_commands(servers: &[String]) -> String {
        // Build the ServerAddresses array
        // Format: d.add ServerAddresses * <ip1> <ip2> ...
        let server_list = servers.join(" ");

        format!(
            r#"d.init
d.add ServerAddresses * {servers}
d.add SupplementalMatchDomains * ""
set State:/Network/Service/{service}/DNS
"#,
            servers = server_list,
            service = DNS_SERVICE_NAME
        )
    }

    /// Build the scutil command to remove DNS configuration
    fn build_dns_remove_command() -> String {
        format!(
            "remove State:/Network/Service/{}/DNS\n",
            DNS_SERVICE_NAME
        )
    }
}

impl DnsManager for MacOSDnsManager {
    fn set_dns(&self, servers: &[String]) -> Result<()> {
        if servers.is_empty() {
            info!("No DNS servers configured, skipping DNS setup");
            return Ok(());
        }

        info!("Configuring DNS servers: {:?}", servers);

        let commands = Self::build_dns_set_commands(servers);
        Self::run_scutil(&commands)?;

        self.configured
            .store(true, std::sync::atomic::Ordering::SeqCst);

        info!("DNS configured successfully via scutil");
        Ok(())
    }

    fn restore_dns(&self) -> Result<()> {
        if !self.configured.load(std::sync::atomic::Ordering::SeqCst) {
            debug!("DNS was not configured, skipping restore");
            return Ok(());
        }

        info!("Restoring original DNS configuration...");

        let command = Self::build_dns_remove_command();
        Self::run_scutil(&command)?;

        self.configured
            .store(false, std::sync::atomic::Ordering::SeqCst);

        info!("DNS configuration restored");
        Ok(())
    }
}

impl Default for MacOSDnsManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_dns_set_commands() {
        let servers = vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()];
        let commands = MacOSDnsManager::build_dns_set_commands(&servers);

        assert!(commands.contains("d.init"));
        assert!(commands.contains("d.add ServerAddresses * 1.1.1.1 8.8.8.8"));
        assert!(commands.contains("d.add SupplementalMatchDomains"));
        assert!(commands.contains("set State:/Network/Service/ANetVPN/DNS"));
    }

    #[test]
    fn test_build_dns_remove_command() {
        let command = MacOSDnsManager::build_dns_remove_command();
        assert!(command.contains("remove State:/Network/Service/ANetVPN/DNS"));
    }
}
