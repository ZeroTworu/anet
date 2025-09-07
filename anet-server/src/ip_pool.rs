use std::net::Ipv4Addr;
use std::collections::HashSet;

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct IpPool {
    pub network: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    server: Ipv4Addr,
}

impl IpPool {
    pub fn new(network: Ipv4Addr, netmask: Ipv4Addr, gateway: Ipv4Addr, server: Ipv4Addr) -> Self {
        Self { network, netmask, gateway, server }
    }

    pub fn allocate(&self, used: &HashSet<Ipv4Addr>) -> Option<Ipv4Addr> {
        let net = u32::from(self.network);
        let mask = u32::from(self.netmask);
        let gw = self.gateway;
        let srv = self.server;

        for host in 1..=u32::MAX {
            let candidate = net | host;
            if (candidate & mask) != (net & mask) {
                break;
            }
            let ip = Ipv4Addr::from(candidate);

            if ip == gw || ip == srv {
                continue;
            }
            if used.contains(&ip) {
                continue;
            }
            return Some(ip);
        }
        None
    }
}
