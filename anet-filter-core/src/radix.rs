//! Таблица маршрутизации IP-сетей и префиксов (Radix LPM — Longest Prefix Match).
//!
//! Реализует поиск наиболее специфичного маршрута (наибольшей длины сетевой маски)
//! для IPv4 и IPv6 адресов без динамических аллокаций памяти.

use bytecheck::CheckBytes;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rkyv::{Archive, Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::model::RuleAction;

/// Элемент таблицы маршрутизации для IPv4 подсети
#[derive(Archive, Deserialize, Serialize, CheckBytes, Debug, Clone, PartialEq)]
#[archive(check_bytes)]
pub struct RadixNodeV4 {
    /// Сетевой адрес (в хостовом порядке байт)
    pub network: u32,
    /// Маска подсети
    pub netmask: u32,
    /// Длина префикса (0..=32)
    pub prefix_len: u8,
    /// Действие для данной подсети
    pub action: RuleAction,
}

impl RadixNodeV4 {
    pub fn new(net: Ipv4Net, action: RuleAction) -> Self {
        let prefix_len = net.prefix_len();
        let netmask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        let network = u32::from(net.network()) & netmask;
        Self {
            network,
            netmask,
            prefix_len,
            action,
        }
    }

    #[inline(always)]
    pub fn matches(&self, ip: u32) -> bool {
        (ip & self.netmask) == self.network
    }
}

/// Элемент таблицы маршрутизации для IPv6 подсети
#[derive(Archive, Deserialize, Serialize, CheckBytes, Debug, Clone, PartialEq)]
#[archive(check_bytes)]
pub struct RadixNodeV6 {
    /// Сетевой адрес (128 бит в Big-Endian)
    pub network: [u8; 16],
    /// Длина префикса (0..=128)
    pub prefix_len: u8,
    /// Действие для данной подсети
    pub action: RuleAction,
}

impl RadixNodeV6 {
    pub fn new(net: Ipv6Net, action: RuleAction) -> Self {
        let prefix_len = net.prefix_len();
        let mut network = net.network().octets();
        mask_ipv6_octets(&mut network, prefix_len);
        Self {
            network,
            prefix_len,
            action,
        }
    }

    #[inline(always)]
    pub fn matches(&self, ip_octets: &[u8; 16]) -> bool {
        let full_bytes = (self.prefix_len / 8) as usize;
        let rem_bits = self.prefix_len % 8;

        if full_bytes > 0 && ip_octets[..full_bytes] != self.network[..full_bytes] {
            return false;
        }

        if rem_bits > 0 && full_bytes < 16 {
            let mask = !0u8 << (8 - rem_bits);
            if (ip_octets[full_bytes] & mask) != (self.network[full_bytes] & mask) {
                return false;
            }
        }

        true
    }
}

/// Таблица маршрутизации сетей с поддержкой Longest Prefix Match
#[derive(Archive, Deserialize, Serialize, CheckBytes, Debug, Clone, PartialEq, Default)]
#[archive(check_bytes)]
pub struct IpRoutingTable {
    /// Узлы IPv4, отсортированные по убыванию prefix_len (от 32 до 0)
    pub ipv4_nodes: Vec<RadixNodeV4>,
    /// Узлы IPv6, отсортированные по убыванию prefix_len (от 128 до 0)
    pub ipv6_nodes: Vec<RadixNodeV6>,
}

impl IpRoutingTable {
    pub fn new() -> Self {
        Self {
            ipv4_nodes: Vec::new(),
            ipv6_nodes: Vec::new(),
        }
    }

    /// Поиск действия по IP адресу (IPv4 или IPv6)
    pub fn lookup(&self, ip: IpAddr) -> Option<RuleAction> {
        match ip {
            IpAddr::V4(v4) => self.lookup_v4(v4),
            IpAddr::V6(v6) => self.lookup_v6(v6),
        }
    }

    /// Longest Prefix Match для IPv4
    pub fn lookup_v4(&self, ip: Ipv4Addr) -> Option<RuleAction> {
        let ip_u32 = u32::from(ip);
        for node in &self.ipv4_nodes {
            if node.matches(ip_u32) {
                return Some(node.action);
            }
        }
        None
    }

    /// Longest Prefix Match для IPv6
    pub fn lookup_v6(&self, ip: Ipv6Addr) -> Option<RuleAction> {
        let octets = ip.octets();
        for node in &self.ipv6_nodes {
            if node.matches(&octets) {
                return Some(node.action);
            }
        }
        None
    }
}

/// Zero-Copy методы поиска по архивированной таблице `ArchivedIpRoutingTable`
impl ArchivedIpRoutingTable {
    pub fn lookup(&self, ip: IpAddr) -> Option<RuleAction> {
        match ip {
            IpAddr::V4(v4) => self.lookup_v4(v4),
            IpAddr::V6(v6) => self.lookup_v6(v6),
        }
    }

    pub fn lookup_v4(&self, ip: Ipv4Addr) -> Option<RuleAction> {
        let ip_u32 = u32::from(ip);
        for node in self.ipv4_nodes.as_slice() {
            if (ip_u32 & node.netmask) == node.network {
                return Some(node.action.deserialize(&mut rkyv::Infallible).unwrap());
            }
        }
        None
    }

    pub fn lookup_v6(&self, ip: Ipv6Addr) -> Option<RuleAction> {
        let octets = ip.octets();
        for node in self.ipv6_nodes.as_slice() {
            let full_bytes = (node.prefix_len / 8) as usize;
            let rem_bits = node.prefix_len % 8;

            let mut matches = true;
            if full_bytes > 0 && octets[..full_bytes] != node.network[..full_bytes] {
                matches = false;
            } else if rem_bits > 0 && full_bytes < 16 {
                let mask = !0u8 << (8 - rem_bits);
                if (octets[full_bytes] & mask) != (node.network[full_bytes] & mask) {
                    matches = false;
                }
            }

            if matches {
                return Some(node.action.deserialize(&mut rkyv::Infallible).unwrap());
            }
        }
        None
    }
}

/// Построитель таблицы сетей с автоматической сортировкой LPM
#[derive(Debug, Default)]
pub struct IpRoutingTableBuilder {
    v4_rules: Vec<RadixNodeV4>,
    v6_rules: Vec<RadixNodeV6>,
}

impl IpRoutingTableBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Добавляет правило для подсети или отдельного IP-адреса
    pub fn insert_net(&mut self, net: IpNet, action: RuleAction) {
        match net {
            IpNet::V4(v4) => self.v4_rules.push(RadixNodeV4::new(v4, action)),
            IpNet::V6(v6) => self.v6_rules.push(RadixNodeV6::new(v6, action)),
        }
    }

    /// Парсит и добавляет строку CIDR или IP
    pub fn insert_str(&mut self, cidr_or_ip: &str, action: RuleAction) -> Result<(), anyhow::Error> {
        let trimmed = cidr_or_ip.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return Ok(());
        }

        if let Ok(net) = trimmed.parse::<IpNet>() {
            self.insert_net(net, action);
            return Ok(());
        }

        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            let net = match ip {
                IpAddr::V4(v4) => IpNet::V4(Ipv4Net::new(v4, 32)?),
                IpAddr::V6(v6) => IpNet::V6(Ipv6Net::new(v6, 128)?),
            };
            self.insert_net(net, action);
            return Ok(());
        }

        anyhow::bail!("Invalid IP or CIDR string: {trimmed}");
    }

    /// Сортирует правила по убыванию `prefix_len` (от наибольшей маски к наименьшей)
    pub fn build(mut self) -> IpRoutingTable {
        self.v4_rules.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));
        self.v6_rules.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));

        IpRoutingTable {
            ipv4_nodes: self.v4_rules,
            ipv6_nodes: self.v6_rules,
        }
    }
}

fn mask_ipv6_octets(octets: &mut [u8; 16], prefix_len: u8) {
    let full_bytes = (prefix_len / 8) as usize;
    let rem_bits = prefix_len % 8;

    if full_bytes < 16 {
        if rem_bits > 0 {
            octets[full_bytes] &= !0u8 << (8 - rem_bits);
            for b in &mut octets[(full_bytes + 1)..] {
                *b = 0;
            }
        } else {
            for b in &mut octets[full_bytes..] {
                *b = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_longest_prefix_match_ipv4() {
        let mut builder = IpRoutingTableBuilder::new();
        // Широкая подсеть: 10.0.0.0/8 -> Proxy
        builder.insert_str("10.0.0.0/8", RuleAction::Proxy).unwrap();
        // Более узкая подсеть: 10.1.0.0/16 -> Direct
        builder.insert_str("10.1.0.0/16", RuleAction::Direct).unwrap();
        // Отдельный IP внутри 10.1.0.0/16: 10.1.2.3/32 -> Block
        builder.insert_str("10.1.2.3", RuleAction::Block).unwrap();

        let table = builder.build();

        // 10.1.2.3 должен соответствовать Block (самый длинный префикс /32)
        assert_eq!(table.lookup("10.1.2.3".parse().unwrap()), Some(RuleAction::Block));
        // 10.1.5.5 должен соответствовать Direct (/16)
        assert_eq!(table.lookup("10.1.5.5".parse().unwrap()), Some(RuleAction::Direct));
        // 10.2.0.1 должен соответствовать Proxy (/8)
        assert_eq!(table.lookup("10.2.0.1".parse().unwrap()), Some(RuleAction::Proxy));
        // 192.168.1.1 не входит ни в одну
        assert_eq!(table.lookup("192.168.1.1".parse().unwrap()), None);
    }
}
