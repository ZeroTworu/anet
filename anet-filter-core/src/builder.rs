//! Компилятор правил маршрутизации и генератор кэша `.abc`.
//!
//! Используется в `anet-auth` для компиляции внешних списков (MetaCubeX, Anti-AD)
//! и администраторских исключений в единый бинарный файл `rules.abc`.

use crate::model::{
    CompiledRoutingCache, RuleAction, CAPTIVE_PORTAL_DOMAINS, DEFAULT_DOH_DOMAINS,
};
use crate::radix::IpRoutingTableBuilder;
use crate::trie::DomainTrieBuilder;

/// Компилятор правил маршрутизации
#[derive(Debug)]
pub struct RoutingCacheCompiler {
    default_action: RuleAction,
    domain_builder: DomainTrieBuilder,
    ip_builder: IpRoutingTableBuilder,
    /// Администраторские правила накладываются во вторую очередь поверх списков
    admin_domain_overrides: Vec<(String, RuleAction)>,
    admin_ip_overrides: Vec<(String, RuleAction)>,
}

impl RoutingCacheCompiler {
    /// Создает новый компилятор с заданным действием по умолчанию
    pub fn new(default_action: RuleAction) -> Self {
        let mut domain_builder = DomainTrieBuilder::new();
        // По умолчанию блокируем публичные DoH-резолверы (п. 5.2 ТЗ), чтобы браузеры откатывались на системный DNS
        for doh in DEFAULT_DOH_DOMAINS {
            domain_builder.insert_rule(doh, RuleAction::Block, false);
        }

        Self {
            default_action,
            domain_builder,
            ip_builder: IpRoutingTableBuilder::new(),
            admin_domain_overrides: Vec::new(),
            admin_ip_overrides: Vec::new(),
        }
    }

    /// Задает действие по умолчанию
    pub fn set_default_action(&mut self, action: RuleAction) {
        self.default_action = action;
    }

    /// Парсит и добавляет сырой текстовый список доменов (MetaCubeX, Anti-AD, plain text)
    pub fn add_provider_domains(&mut self, content: &str, action: RuleAction) -> usize {
        let mut count = 0;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with('#')
                || trimmed.starts_with(';')
                || trimmed.starts_with("//")
            {
                continue;
            }
            if self.domain_builder.insert_rule(trimmed, action, false) {
                count += 1;
            }
        }
        count
    }

    /// Добавляет список уже нормализованных доменов из БД (таблица rule_provider_items)
    pub fn add_provider_domain_items<I, S>(&mut self, items: I, action: RuleAction) -> usize
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut count = 0;
        for item in items {
            let s = item.as_ref().trim();
            if !s.is_empty() && self.domain_builder.insert_rule(s, action, false) {
                count += 1;
            }
        }
        count
    }

    /// Парсит и добавляет сырой текстовый список IP/CIDR сетей
    pub fn add_provider_ips(&mut self, content: &str, action: RuleAction) -> usize {
        let mut count = 0;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with('#')
                || trimmed.starts_with(';')
                || trimmed.starts_with("//")
            {
                continue;
            }
            if self.ip_builder.insert_str(trimmed, action).is_ok() {
                count += 1;
            }
        }
        count
    }

    /// Добавляет список IP/CIDR записей из БД (таблица rule_provider_items)
    pub fn add_provider_ip_items<I, S>(&mut self, items: I, action: RuleAction) -> usize
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut count = 0;
        for item in items {
            let s = item.as_ref().trim();
            if !s.is_empty() && self.ip_builder.insert_str(s, action).is_ok() {
                count += 1;
            }
        }
        count
    }

    /// Регистрирует администраторское исключение для домена (высший серверный приоритет)
    pub fn add_admin_domain_override(&mut self, pattern: &str, action: RuleAction) {
        self.admin_domain_overrides.push((pattern.to_string(), action));
    }

    /// Регистрирует администраторское исключение для IP/CIDR (высший серверный приоритет)
    pub fn add_admin_ip_override(&mut self, pattern: &str, action: RuleAction) {
        self.admin_ip_overrides.push((pattern.to_string(), action));
    }

    /// Выполняет сборку кэша с наложением администраторских исключений
    pub fn compile(mut self) -> CompiledRoutingCache {
        // 0. Защита служебных доменов Captive Portal от случайного попадания в AdBlock-списки провайдеров (п. 5.3 ТЗ)
        let probe_action = if self.default_action == RuleAction::Block {
            RuleAction::Proxy
        } else {
            self.default_action
        };
        for portal in CAPTIVE_PORTAL_DOMAINS {
            self.domain_builder.insert_rule(portal, probe_action, true);
        }

        // 1. Накладываем администраторские доменные исключения (override_existing = true)
        for (pattern, action) in self.admin_domain_overrides {
            self.domain_builder.insert_rule(&pattern, action, true);
        }

        // 2. Накладываем администраторские IP исключения
        for (pattern, action) in self.admin_ip_overrides {
            let _ = self.ip_builder.insert_str(&pattern, action);
        }

        let domain_trie = self.domain_builder.build();
        let ip_table = self.ip_builder.build();

        CompiledRoutingCache::new(self.default_action, domain_trie, ip_table)
    }

    /// Компилирует кэш и сразу сериализует его в бинарные байты .abc
    pub fn compile_to_bytes(self) -> Result<Vec<u8>, anyhow::Error> {
        let cache = self.compile();
        cache.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compiler_roundtrip() {
        let mut compiler = RoutingCacheCompiler::new(RuleAction::Proxy);

        let domain_list = r#"
        # Anti-AD sample list
        ad.doubleclick.net
        +.analytics.google.com
        tracker.badsite.org
        "#;
        compiler.add_provider_domains(domain_list, RuleAction::Block);

        let ip_list = r#"
        # Direct RU CIDRs
        195.208.0.0/16
        77.88.0.0/18
        "#;
        compiler.add_provider_ips(ip_list, RuleAction::Direct);

        // Администратор форсирует разблокировку одного домена (custom_direct)
        compiler.add_admin_domain_override("analytics.google.com", RuleAction::Direct);

        let bytes = compiler.compile_to_bytes().unwrap();
        assert!(!bytes.is_empty());

        // Zero-copy чтение
        let archived = CompiledRoutingCache::from_bytes(&bytes).unwrap();
        assert_eq!(archived.default_action, RuleAction::Proxy);
        assert_eq!(
            archived.domain_trie.lookup("ad.doubleclick.net"),
            Some(RuleAction::Block)
        );
        // Админское переопределение должно сработать
        assert_eq!(
            archived.domain_trie.lookup("analytics.google.com"),
            Some(RuleAction::Direct)
        );
        // IP
        assert_eq!(
            archived.ip_table.lookup("195.208.1.1".parse().unwrap()),
            Some(RuleAction::Direct)
        );
    }
}
