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

    #[cfg(not(windows))]
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

    #[cfg(windows)]
    pub fn create_config(&self) -> anyhow::Result<Configuration> {
        use tun::platform::windows::DeviceConfig;

        let mut config = DeviceConfig::default();

        // Базовые настройки
        config.name(&self.name)
            .address(self.address)
            .netmask(self.netmask)
            .destination(self.gateway)
            .mtu(self.mtu as i32)
            .up();

        // КРИТИЧНО: Отключаем автоматическое обновление DNS и DHCP
        config = config.dns_register(false);  // Отключаем регистрацию в DNS
        config = config.dhcp_register(false); // Отключаем DHCP

        // Устанавливаем метрику (низкая = приоритет выше)
        config = config.metric(500);

        Ok(Configuration::Device(config))
    }

    pub fn get_info(&self) -> String {
        format!(
            "Address: {}, Netmask: {}, Destination: {}, Name: {}, MTU: {}",
            self.address, self.netmask, self.gateway, self.name, self.mtu
        )
    }
}
