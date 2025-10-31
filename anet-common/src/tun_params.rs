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
    pub fn default_server() -> Self {
        Self {
            address: Ipv4Addr::new(10, 0, 0, 2),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            name: "anet-server".to_string(),
            mtu: 1400,
            network: Some(Ipv4Addr::new(10, 0, 0, 0)),
        }
    }

    pub fn default_client() -> Self {
        Self {
            address: Ipv4Addr::new(10, 0, 0, 2),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            name: "anet-client".to_string(),
            mtu: 1400,
            network: None,
        }
    }

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
    pub fn create_config(&self) -> anyhow::Result<Configuration> {
        let mut binding = Configuration::default();
        let config = binding
            .tun_name(&self.name)
            .mtu(self.mtu)
            .up()
            .address(self.address)
            .netmask(self.netmask)
            .destination(self.gateway);
        Ok(config.clone())
    }

    pub fn get_info(&self) -> String {
        format!(
            "Address: {}, Netmask: {}, Destination: {}, Name: {}, MTU: {}",
            self.address, self.netmask, self.gateway, self.name, self.mtu
        )
    }
}
