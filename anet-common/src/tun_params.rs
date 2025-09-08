use std::net::Ipv4Addr;

#[derive(Clone)]
pub struct TunParams {
    pub address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub name: String,
    pub mtu: u16,
}

impl TunParams {
    pub fn default() -> Self {
        Self {
            address: Ipv4Addr::new(10, 0, 0, 2),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            name: "anet-server".to_string(),
            mtu: 1300,
        }
    }

    pub fn default_client() -> Self {
        Self {
            address: Ipv4Addr::new(10, 0, 0, 2),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            name: "anet-client".to_string(),
            mtu: 1300,
        }
    }
}
