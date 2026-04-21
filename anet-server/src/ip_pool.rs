use crossbeam::queue::SegQueue;
use dashmap::DashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct Lease {
    pub ip: Ipv4Addr,
    pub client_id: String,
    pub expires_at: Instant,
}

#[derive(Clone)]
pub struct IpPool {
    pub network: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub server: Ipv4Addr,
    pub mtu: u16,

    lease_time: Duration,

    client_to_lease: Arc<DashMap<String, Lease>>,
    ip_to_lease: Arc<DashMap<Ipv4Addr, Lease>>,
    free_ips: Arc<SegQueue<Ipv4Addr>>,
}

impl IpPool {
    pub fn new(
        network: Ipv4Addr,
        netmask: Ipv4Addr,
        gateway: Ipv4Addr,
        server: Ipv4Addr,
        mtu: u16,
    ) -> Self {
        let free_ips = Arc::new(SegQueue::new());

        // заполняем пул IP
        let net = u32::from(network);
        let mask = u32::from(netmask);

        for host in 1..=u32::MAX {
            let candidate = net | host;

            if (candidate & mask) != (net & mask) {
                break;
            }

            let ip = Ipv4Addr::from(candidate);

            if ip == gateway || ip == server {
                continue;
            }

            free_ips.push(ip);
        }

        let lease_time = Duration::from_secs(3600);
        Self {
            network,
            netmask,
            gateway,
            server,
            mtu,
            lease_time,
            client_to_lease: Arc::new(DashMap::new()),
            ip_to_lease: Arc::new(DashMap::new()),
            free_ips,
        }
    }

    pub fn allocate(&self, client_id: String) -> Option<Ipv4Addr> {
        // 1. если уже есть lease
        if let Some(entry) = self.client_to_lease.get(&client_id) {
            let lease = entry.value();

            if lease.expires_at > Instant::now() {
                return Some(lease.ip);
            }

            // истёк — освобождаем
            self.release(lease.ip);
        }

        // 2. берём новый IP
        let ip = self.free_ips.pop()?;

        let lease = Lease {
            ip,
            client_id: client_id.clone(),
            expires_at: Instant::now() + self.lease_time,
        };

        // 3. записываем
        self.client_to_lease
            .insert(client_id.clone(), lease.clone());
        self.ip_to_lease.insert(ip, lease);

        Some(ip)
    }

    pub fn release(&self, ip: Ipv4Addr) -> bool {
        if let Some((_, lease)) = self.ip_to_lease.remove(&ip) {
            self.client_to_lease.remove(&lease.client_id);
            self.free_ips.push(ip);
            return true;
        }
        false
    }
}
