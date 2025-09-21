use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct IpPool {
    pub network: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub server: Ipv4Addr,
    pub mtu: u16,
    used: Arc<Mutex<HashSet<Ipv4Addr>>>,
}

impl IpPool {
    pub fn new(
        network: Ipv4Addr,
        netmask: Ipv4Addr,
        gateway: Ipv4Addr,
        server: Ipv4Addr,
        mtu: u16,
    ) -> Self {
        Self {
            network,
            netmask,
            gateway,
            server,
            mtu,
            used: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn allocate(&self) -> Option<Ipv4Addr> {
        let net = u32::from(self.network);
        let mask = u32::from(self.netmask);
        let gw = self.gateway;
        let srv = self.server;

        let mut used = self.used.lock().unwrap();

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

            used.insert(ip);
            return Some(ip);
        }
        None
    }

    pub fn release(&self, ip: Ipv4Addr) -> bool {
        let mut used = self.used.lock().unwrap();
        used.remove(&ip)
    }
}
