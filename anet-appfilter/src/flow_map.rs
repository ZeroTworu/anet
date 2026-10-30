//! Карта соответствия сетевого сокета процессу.

use std::collections::HashSet;
use std::net::IpAddr;
#[cfg(all(windows, feature = "windivert"))]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};

use dashmap::DashMap;
use ipnet::IpNet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub protocol: u8,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
}

impl FlowKey {
    pub fn new(
        protocol: u8,
        local_addr: IpAddr,
        local_port: u16,
        remote_addr: IpAddr,
        remote_port: u16,
    ) -> Self {
        Self {
            protocol,
            local_addr: local_addr.to_canonical(),
            local_port,
            remote_addr: remote_addr.to_canonical(),
            remote_port,
        }
    }
}

/// Сведения о процессе, владеющем сокетом.
#[derive(Clone, Debug)]
pub struct FlowOwner {
    pub process_id: u32,
    pub image_name: Option<Arc<str>>,
}

#[derive(Clone, Default)]
pub struct FlowMap {
    /// 5-tuple карта для TCP и connected UDP
    inner: Arc<DashMap<FlowKey, FlowOwner>>,
    /// Порт-карта для connectionless UDP (sendto без connect) и предсуществующих UDP-сокетов
    udp_ports: Arc<DashMap<u16, FlowOwner>>,
    /// Порт-карта для TCP-сокетов (fallback для сокетов с local_addr = 0.0.0.0/:: при connect и listen-портов)
    tcp_ports: Arc<DashMap<u16, FlowOwner>>,
}

impl FlowMap {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
            udp_ports: Arc::new(DashMap::new()),
            tcp_ports: Arc::new(DashMap::new()),
        }
    }

    pub fn insert(&self, key: FlowKey, owner: FlowOwner) {
        self.inner.insert(key, owner);
    }

    /// Регистрация UDP порта из SocketBind / SocketConnect / начального снимка таблицы сокетов
    pub fn insert_udp_port(&self, port: u16, owner: FlowOwner) {
        if port != 0 {
            self.udp_ports.insert(port, owner);
        }
    }

    /// Регистрация TCP порта из SocketBind / SocketListen / SocketConnect / начального снимка таблицы сокетов
    pub fn insert_tcp_port(&self, port: u16, owner: FlowOwner) {
        if port != 0 {
            self.tcp_ports.insert(port, owner);
        }
    }

    pub fn remove(&self, key: &FlowKey) {
        self.inner.remove(key);
    }

    /// Удаление UDP порта после истечения grace-периода закрытия сокета
    pub fn remove_udp_port(&self, port: u16) {
        self.udp_ports.remove(&port);
    }

    /// Удаление TCP порта после истечения grace-периода закрытия сокета
    pub fn remove_tcp_port(&self, port: u16) {
        self.tcp_ports.remove(&port);
    }

    /// Поиск владельца потока:
    /// 1. Точное совпадение по канонизированному 5-tuple (`FlowKey`).
    /// 2. Fallback по 5-tuple с `0.0.0.0` (если на этапе `SocketConnect` ядро ещё не выбрало исходящий интерфейс).
    /// 3. Fallback по локальному порту (`udp_ports` для UDP, `tcp_ports` для TCP).
    pub fn lookup(&self, key: &FlowKey) -> Option<FlowOwner> {
        if let Some(owner) = self.inner.get(key) {
            return Some(owner.clone());
        }

        if !key.local_addr.is_unspecified() {
            let unspec_local = match key.local_addr {
                IpAddr::V4(_) => IpAddr::V4( std::net::Ipv4Addr::UNSPECIFIED ),
                IpAddr::V6(_) => IpAddr::V6( std::net::Ipv6Addr::UNSPECIFIED ),
            };
            let wildcard_key = FlowKey {
                protocol: key.protocol,
                local_addr: unspec_local,
                local_port: key.local_port,
                remote_addr: key.remote_addr,
                remote_port: key.remote_port,
            };
            if let Some(owner) = self.inner.get(&wildcard_key) {
                return Some(owner.clone());
            }
        }

        if key.protocol == 17 {
            if let Some(owner) = self.udp_ports.get(&key.local_port) {
                return Some(owner.clone());
            }
        } else if key.protocol == 6 {
            if let Some(owner) = self.tcp_ports.get(&key.local_port) {
                return Some(owner.clone());
            }
        }

        None
    }

    pub fn len(&self) -> usize {
        self.inner.len() + self.udp_ports.len() + self.tcp_ports.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty() && self.udp_ports.is_empty() && self.tcp_ports.is_empty()
    }

    /// Заполняет `FlowMap` уже открытыми в ОС TCP и UDP сокетами (IPv4 и IPv6) на момент старта `AppFilter`.
    /// Это критически важно для приложений, запущенных ДО включения VPN (например, BitTorrent-клиентов,
    /// игр, браузеров и мессенджеров), по которым событие `SocketBind`/`SocketConnect` уже произошло в прошлом.
    #[cfg(all(windows, feature = "windivert"))]
    pub fn populate_initial_sockets(&self) {
        let tcp4 = self.scan_tcp_v4();
        let tcp6 = self.scan_tcp_v6();
        let udp4 = self.scan_udp_v4();
        let udp6 = self.scan_udp_v6();
        log::info!(
            "appfilter: Initial socket table snapshot loaded (tcp4={}, tcp6={}, udp4={}, udp6={})",
            tcp4,
            tcp6,
            udp4,
            udp6
        );
    }

    #[cfg(all(windows, feature = "windivert"))]
    fn scan_tcp_v4(&self) -> usize {
        use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
            TCP_TABLE_OWNER_PID_ALL,
        };
        use windows_sys::Win32::Networking::WinSock::AF_INET;

        let mut size: u32 = 0;
        unsafe {
            let ret = GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if ret != ERROR_INSUFFICIENT_BUFFER || size == 0 {
                return 0;
            }

            let mut buf = vec![0u8; size as usize];
            let ret = GetExtendedTcpTable(
                buf.as_mut_ptr() as *mut _,
                &mut size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if ret != NO_ERROR {
                return 0;
            }

            let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            let num_entries = table.dwNumEntries as usize;
            let rows_ptr = table.table.as_ptr();
            let max_rows = (buf.len().saturating_sub(std::mem::size_of::<u32>()))
                / std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
            let count = num_entries.min(max_rows);
            let rows = std::slice::from_raw_parts(rows_ptr, count);

            let mut added = 0;
            for row in rows {
                let pid = row.dwOwningPid;
                if pid == 0 || pid == 4 {
                    continue;
                }
                let local_port = u16::from_be(row.dwLocalPort as u16);
                if local_port == 0 {
                    continue;
                }
                let local_ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwLocalAddr)));
                let remote_ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwRemoteAddr)));
                let remote_port = u16::from_be(row.dwRemotePort as u16);

                let owner = FlowOwner {
                    process_id: pid,
                    image_name: crate::proc_name::image_name_for_pid(pid),
                };

                self.insert_tcp_port(local_port, owner.clone());
                if remote_port != 0 && !remote_ip.is_unspecified() {
                    let key = FlowKey::new(6, local_ip, local_port, remote_ip, remote_port);
                    self.insert(key, owner);
                }
                added += 1;
            }
            added
        }
    }

    #[cfg(all(windows, feature = "windivert"))]
    fn scan_tcp_v6(&self) -> usize {
        use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
            TCP_TABLE_OWNER_PID_ALL,
        };
        use windows_sys::Win32::Networking::WinSock::AF_INET6;

        let mut size: u32 = 0;
        unsafe {
            let ret = GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut size,
                0,
                AF_INET6 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if ret != ERROR_INSUFFICIENT_BUFFER || size == 0 {
                return 0;
            }

            let mut buf = vec![0u8; size as usize];
            let ret = GetExtendedTcpTable(
                buf.as_mut_ptr() as *mut _,
                &mut size,
                0,
                AF_INET6 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if ret != NO_ERROR {
                return 0;
            }

            let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
            let num_entries = table.dwNumEntries as usize;
            let rows_ptr = table.table.as_ptr();
            let max_rows = (buf.len().saturating_sub(std::mem::size_of::<u32>()))
                / std::mem::size_of::<MIB_TCP6ROW_OWNER_PID>();
            let count = num_entries.min(max_rows);
            let rows = std::slice::from_raw_parts(rows_ptr, count);

            let mut added = 0;
            for row in rows {
                let pid = row.dwOwningPid;
                if pid == 0 || pid == 4 {
                    continue;
                }
                let local_port = u16::from_be(row.dwLocalPort as u16);
                if local_port == 0 {
                    continue;
                }
                let local_ip = IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)).to_canonical();
                let remote_ip = IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr)).to_canonical();
                let remote_port = u16::from_be(row.dwRemotePort as u16);

                let owner = FlowOwner {
                    process_id: pid,
                    image_name: crate::proc_name::image_name_for_pid(pid),
                };

                self.insert_tcp_port(local_port, owner.clone());
                if remote_port != 0 && !remote_ip.is_unspecified() {
                    let key = FlowKey::new(6, local_ip, local_port, remote_ip, remote_port);
                    self.insert(key, owner);
                }
                added += 1;
            }
            added
        }
    }

    #[cfg(all(windows, feature = "windivert"))]
    fn scan_udp_v4(&self) -> usize {
        use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GetExtendedUdpTable, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
        };
        use windows_sys::Win32::Networking::WinSock::AF_INET;

        let mut size: u32 = 0;
        unsafe {
            let ret = GetExtendedUdpTable(
                std::ptr::null_mut(),
                &mut size,
                0,
                AF_INET as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
            if ret != ERROR_INSUFFICIENT_BUFFER || size == 0 {
                return 0;
            }

            let mut buf = vec![0u8; size as usize];
            let ret = GetExtendedUdpTable(
                buf.as_mut_ptr() as *mut _,
                &mut size,
                0,
                AF_INET as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
            if ret != NO_ERROR {
                return 0;
            }

            let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
            let num_entries = table.dwNumEntries as usize;
            let rows_ptr = table.table.as_ptr();
            let max_rows = (buf.len().saturating_sub(std::mem::size_of::<u32>()))
                / std::mem::size_of::<MIB_UDPROW_OWNER_PID>();
            let count = num_entries.min(max_rows);
            let rows = std::slice::from_raw_parts(rows_ptr, count);

            let mut added = 0;
            for row in rows {
                let pid = row.dwOwningPid;
                if pid == 0 || pid == 4 {
                    continue;
                }
                let local_port = u16::from_be(row.dwLocalPort as u16);
                if local_port == 0 {
                    continue;
                }
                let owner = FlowOwner {
                    process_id: pid,
                    image_name: crate::proc_name::image_name_for_pid(pid),
                };
                self.insert_udp_port(local_port, owner);
                added += 1;
            }
            added
        }
    }

    #[cfg(all(windows, feature = "windivert"))]
    fn scan_udp_v6(&self) -> usize {
        use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GetExtendedUdpTable, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
            UDP_TABLE_OWNER_PID,
        };
        use windows_sys::Win32::Networking::WinSock::AF_INET6;

        let mut size: u32 = 0;
        unsafe {
            let ret = GetExtendedUdpTable(
                std::ptr::null_mut(),
                &mut size,
                0,
                AF_INET6 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
            if ret != ERROR_INSUFFICIENT_BUFFER || size == 0 {
                return 0;
            }

            let mut buf = vec![0u8; size as usize];
            let ret = GetExtendedUdpTable(
                buf.as_mut_ptr() as *mut _,
                &mut size,
                0,
                AF_INET6 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
            if ret != NO_ERROR {
                return 0;
            }

            let table = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
            let num_entries = table.dwNumEntries as usize;
            let rows_ptr = table.table.as_ptr();
            let max_rows = (buf.len().saturating_sub(std::mem::size_of::<u32>()))
                / std::mem::size_of::<MIB_UDP6ROW_OWNER_PID>();
            let count = num_entries.min(max_rows);
            let rows = std::slice::from_raw_parts(rows_ptr, count);

            let mut added = 0;
            for row in rows {
                let pid = row.dwOwningPid;
                if pid == 0 || pid == 4 {
                    continue;
                }
                let local_port = u16::from_be(row.dwLocalPort as u16);
                if local_port == 0 {
                    continue;
                }
                let owner = FlowOwner {
                    process_id: pid,
                    image_name: crate::proc_name::image_name_for_pid(pid),
                };
                self.insert_udp_port(local_port, owner);
                added += 1;
            }
            added
        }
    }
}

#[derive(Default)]
struct BypassInner {
    ips: HashSet<IpAddr>,
    nets: Vec<IpNet>,
}

#[derive(Clone, Default)]
pub struct BypassSet {
    inner: Arc<RwLock<BypassInner>>,
}

impl BypassSet {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(BypassInner::default())),
        }
    }

    pub fn with_initial(ips: impl IntoIterator<Item = IpAddr>) -> Self {
        let set = ips.into_iter().map(|ip| ip.to_canonical()).collect();
        Self {
            inner: Arc::new(RwLock::new(BypassInner {
                ips: set,
                nets: Vec::new(),
            })),
        }
    }

    pub fn add_sync(&self, ip: IpAddr) {
        if let Ok(mut guard) = self.inner.write() {
            guard.ips.insert(ip.to_canonical());
        }
    }

    pub fn add_net_sync(&self, net: IpNet) {
        let prefix = net.prefix_len();
        if (net.addr().is_ipv4() && prefix == 32) || (net.addr().is_ipv6() && prefix == 128) {
            self.add_sync(net.addr());
            return;
        }
        if let Ok(mut guard) = self.inner.write() {
            if !guard.nets.contains(&net) {
                guard.nets.push(net);
            }
        }
    }

    pub async fn add(&self, ip: IpAddr) {
        self.add_sync(ip);
    }

    pub fn contains_blocking(&self, ip: &IpAddr) -> bool {
        let canon = ip.to_canonical();
        if let Ok(guard) = self.inner.read() {
            if guard.ips.contains(&canon) {
                return true;
            }
            return guard.nets.iter().any(|net| net.contains(&canon));
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn flow_key_canonicalizes_ipv4_mapped_ipv6() {
        let v6_mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0105));
        let v4_plain = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
        let remote = IpAddr::V4(Ipv4Addr::new(91, 184, 242, 63));

        let k1 = FlowKey::new(6, v6_mapped, 63870, remote, 51413);
        let k2 = FlowKey::new(6, v4_plain, 63870, remote, 51413);
        assert_eq!(k1, k2);
    }

    #[test]
    fn flow_map_resolves_wildcard_local_ip_and_port_fallback() {
        let map = FlowMap::new();
        let remote = IpAddr::V4(Ipv4Addr::new(91, 184, 242, 63));
        let unspec = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let phys = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));

        let owner = FlowOwner {
            process_id: 1234,
            image_name: Some(Arc::from("utorrent.exe")),
        };

        // Case 1: SocketConnect registered 0.0.0.0:55000 -> remote:6881
        map.insert(FlowKey::new(6, unspec, 55000, remote, 6881), owner.clone());
        let packet_key = FlowKey::new(6, phys, 55000, remote, 6881);
        assert_eq!(
            map.lookup(&packet_key).and_then(|o| o.image_name),
            Some(Arc::from("utorrent.exe"))
        );

        // Case 2: Bound TCP/UDP port fallback (e.g. seeding port 63870)
        map.insert_tcp_port(63870, owner.clone());
        map.insert_udp_port(63870, owner);
        let tcp_seed = FlowKey::new(6, phys, 63870, remote, 49152);
        let udp_seed = FlowKey::new(17, phys, 63870, remote, 49152);
        assert_eq!(
            map.lookup(&tcp_seed).and_then(|o| o.image_name),
            Some(Arc::from("utorrent.exe"))
        );
        assert_eq!(
            map.lookup(&udp_seed).and_then(|o| o.image_name),
            Some(Arc::from("utorrent.exe"))
        );
    }
}