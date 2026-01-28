use crate::AuthResponse;
use std::net::Ipv4Addr;
use tun::Configuration;

#[derive(Clone)]
pub struct TunParams {
    pub address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub name: String,
    pub mtu: u16,

    pub network: Option<Ipv4Addr>,
}

impl TunParams {
    pub fn from_auth_response(auth_response: &AuthResponse, adapter: &str) -> Self {
        Self {
            address: auth_response.ip.parse().unwrap(),
            netmask: auth_response.netmask.parse().unwrap(),
            gateway: auth_response.gateway.parse().unwrap(),
            name: adapter.to_string(),
            mtu: auth_response.mtu as u16,
            network: None,
        }
    }

    /// Create TUN configuration for Linux
    #[cfg(target_os = "linux")]
    pub fn create_config(&self) -> anyhow::Result<Configuration> {
        let mut config = Configuration::default();

        config.up();
        config.tun_name(&self.name);
        config.address(self.address);
        config.netmask(self.netmask);
        config.destination(self.gateway);
        config.mtu(self.mtu);

        Ok(config)
    }

    /// Create TUN configuration for Windows
    #[cfg(windows)]
    pub fn create_config(&self) -> anyhow::Result<Configuration> {
        let mut config = Configuration::default();

        config.up();
        config.tun_name(&self.name);
        config.address(self.address);
        config.netmask(self.netmask);
        config.destination(self.gateway);
        config.mtu(self.mtu);

        Ok(config)
    }

    /// Create TUN configuration for macOS
    ///
    /// macOS utun interfaces have specific behavior:
    /// - Interface names are assigned dynamically (utun0, utun1, etc.)
    /// - Custom names like "myvpn" are NOT supported - must be "utunX" with a number
    /// - If no valid utunX name is provided, we don't set a name and let macOS auto-assign
    /// - We configure address/netmask but skip destination (point-to-point not needed)
    #[cfg(target_os = "macos")]
    pub fn create_config(&self) -> anyhow::Result<Configuration> {
        let mut config = Configuration::default();

        // Bring interface up
        config.up();

        // macOS only supports utun interface names with a number (utun0, utun1, etc.)
        // The tun crate parses the number suffix, so "utun" alone causes an error.
        // Only set the name if it's a valid "utunX" format with a number.
        if self.name.starts_with("utun") && self.name.len() > 4 {
            // Check if the suffix is a valid number
            if self.name[4..].parse::<u32>().is_ok() {
                config.tun_name(&self.name);
            }
            // Otherwise, don't set name - let macOS auto-assign
        }
        // For non-utun names, don't set name - let macOS auto-assign

        // Set IP configuration
        config.address(self.address);
        config.netmask(self.netmask);

        // On macOS, we don't set destination for the utun interface
        // The routing is handled separately via route commands
        // config.destination(self.gateway);  // Skipped for macOS

        // Set MTU
        config.mtu(self.mtu);

        Ok(config)
    }

    pub fn get_info(&self) -> String {
        format!(
            "Address: {}, Netmask: {}, Destination: {}, Name: {}, MTU: {}",
            self.address, self.netmask, self.gateway, self.name, self.mtu
        )
    }
}
