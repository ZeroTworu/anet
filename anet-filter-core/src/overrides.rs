//! Локальные и административные исключения (Custom Overrides).
//!
//! Обеспечивают высший приоритет для правил, заданных конечным пользователем
//! в `client.toml` или администратором в базе данных `anet-auth`.

use ipnet::IpNet;
use std::net::IpAddr;

use crate::model::{RuleAction, MOZILLA_CANARY_DOMAIN};
use crate::radix::{IpRoutingTable, IpRoutingTableBuilder};
use crate::trie::split_domain_to_reversed_labels;

/// Конфигурация локальных правил пользователя из `client.toml`
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct LocalOverridesConfig {
    #[serde(default)]
    pub block: Vec<String>,
    #[serde(default)]
    pub direct: Vec<String>,
    #[serde(default)]
    pub proxy: Vec<String>,
}

/// Скомпилированная в память структура для сверхбыстрой проверки локальных правил пользователя
#[derive(Debug, Clone, Default)]
pub struct LocalOverrides {
    /// Точные совпадения доменов (lowercase)
    exact_domains: ahash::AHashMap<String, RuleAction>,
    /// Поддомены (*.domain / +.domain), разложенные в обратные метки
    wildcard_rules: Vec<(Vec<String>, RuleAction)>,
    /// IP/CIDR правила
    ip_table: IpRoutingTable,
}

impl LocalOverrides {
    /// Создает пустой набор правил
    pub fn new() -> Self {
        Self::default()
    }

    /// Компилирует конфигурацию `LocalOverridesConfig` в поисковые структуры
    pub fn from_config(config: &LocalOverridesConfig) -> Self {
        let mut overrides = Self::new();
        let mut ip_builder = IpRoutingTableBuilder::new();

        let add_entries = |entries: &[String],
                           action: RuleAction,
                           exact_map: &mut ahash::AHashMap<String, RuleAction>,
                           wildcards: &mut Vec<(Vec<String>, RuleAction)>,
                           builder: &mut IpRoutingTableBuilder| {
            for entry in entries {
                let trimmed = entry.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }

                // Проверяем, является ли это CIDR или IP
                if let Ok(net) = trimmed.parse::<IpNet>() {
                    builder.insert_net(net, action);
                    continue;
                }
                if let Ok(ip) = trimmed.parse::<IpAddr>() {
                    let _ = builder.insert_str(&ip.to_string(), action);
                    continue;
                }

                // Доменное правило
                let lower = trimmed.to_ascii_lowercase();
                if lower.starts_with("*.") || lower.starts_with("+.") {
                    let domain = lower[2..].trim_end_matches('.');
                    let reversed: Vec<String> = split_domain_to_reversed_labels(domain)
                        .into_iter()
                        .map(String::from)
                        .collect();
                    if !reversed.is_empty() {
                        wildcards.push((reversed, action));
                    }
                } else if let Some(domain) = lower.strip_prefix("domain:") {
                    let clean = domain.trim_end_matches('.');
                    let reversed: Vec<String> = split_domain_to_reversed_labels(clean)
                        .into_iter()
                        .map(String::from)
                        .collect();
                    if !reversed.is_empty() {
                        wildcards.push((reversed, action));
                    }
                } else {
                    let clean = lower.trim_end_matches('.');
                    exact_map.insert(clean.to_string(), action);
                }
            }
        };

        add_entries(
            &config.block,
            RuleAction::Block,
            &mut overrides.exact_domains,
            &mut overrides.wildcard_rules,
            &mut ip_builder,
        );
        add_entries(
            &config.direct,
            RuleAction::Direct,
            &mut overrides.exact_domains,
            &mut overrides.wildcard_rules,
            &mut ip_builder,
        );
        add_entries(
            &config.proxy,
            RuleAction::Proxy,
            &mut overrides.exact_domains,
            &mut overrides.wildcard_rules,
            &mut ip_builder,
        );

        overrides.ip_table = ip_builder.build();
        overrides
    }

    /// Поиск доменного правила. Проверяет в первую очередь Canary Domain, затем точные совпадения и wildcards.
    pub fn lookup_domain(&self, domain: &str) -> Option<RuleAction> {
        let clean = domain.trim().trim_end_matches('.');
        if clean.is_empty() {
            return None;
        }

        // Служебный канареечный домен Mozilla DoH всегда перехватывается с действием Block (NXDOMAIN)
        if clean.eq_ignore_ascii_case(MOZILLA_CANARY_DOMAIN) {
            return Some(RuleAction::Block);
        }

        let lower = clean.to_ascii_lowercase();

        // 1. Точное совпадение
        if let Some(action) = self.exact_domains.get(&lower) {
            return Some(*action);
        }

        // 2. Wildcard совпадение по суффиксам
        let reversed_labels = split_domain_to_reversed_labels(&lower);
        for (pattern_labels, action) in &self.wildcard_rules {
            if reversed_labels.len() >= pattern_labels.len() {
                let mut matches = true;
                for (i, plabel) in pattern_labels.iter().enumerate() {
                    if reversed_labels[i] != plabel.as_str() {
                        matches = false;
                        break;
                    }
                }
                if matches {
                    return Some(*action);
                }
            }
        }

        None
    }

    /// Поиск правила для IP-адреса
    pub fn lookup_ip(&self, ip: IpAddr) -> Option<RuleAction> {
        self.ip_table.lookup(ip)
    }

    /// Проверяет, пуст ли набор пользовательских правил
    pub fn is_empty(&self) -> bool {
        self.exact_domains.is_empty()
            && self.wildcard_rules.is_empty()
            && self.ip_table.ipv4_nodes.is_empty()
            && self.ip_table.ipv6_nodes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_overrides() {
        let config = LocalOverridesConfig {
            block: vec!["annoying-ad.com".to_string(), "198.51.100.0/24".to_string()],
            direct: vec!["*.banking.local".to_string(), "192.168.1.1".to_string()],
            proxy: vec!["special-vpn.org".to_string()],
        };

        let overrides = LocalOverrides::from_config(&config);

        // Canary check
        assert_eq!(
            overrides.lookup_domain("use-application-dns.net"),
            Some(RuleAction::Block)
        );

        // Exact match
        assert_eq!(
            overrides.lookup_domain("annoying-ad.com"),
            Some(RuleAction::Block)
        );
        assert_eq!(
            overrides.lookup_domain("special-vpn.org"),
            Some(RuleAction::Proxy)
        );

        // Wildcard
        assert_eq!(
            overrides.lookup_domain("app.banking.local"),
            Some(RuleAction::Direct)
        );

        // IP
        assert_eq!(
            overrides.lookup_ip("198.51.100.42".parse().unwrap()),
            Some(RuleAction::Block)
        );
        assert_eq!(
            overrides.lookup_ip("192.168.1.1".parse().unwrap()),
            Some(RuleAction::Direct)
        );
        assert_eq!(overrides.lookup_ip("8.8.8.8".parse().unwrap()), None);
    }
}
