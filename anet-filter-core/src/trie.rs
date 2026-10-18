//! Инвертированное префиксное дерево меток доменов (Domain Trie).
//!
//! Домены разбиваются на метки по точке и обходятся справа налево:
//! `ads.google.com` -> `["com", "google", "ads"]`.
//! Обеспечивает O(K) поиск (где K — количество меток в домене, обычно 2-4)
//! как для несжатых структур, так и в Zero-Copy режиме через `ArchivedDomainTrie`.

use bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};

use crate::model::RuleAction;

/// Узел инвертированного дерева доменов
#[derive(Archive, Deserialize, Serialize, CheckBytes, Debug, Clone, PartialEq)]
#[archive(check_bytes)]
pub struct TrieNode {
    /// Метка доменного уровня в нижнем регистре (например, "com", "google", "ads")
    pub label: String,
    /// Терминальное действие для данного домена (если правило заканчивается на этом уровне)
    pub terminal_action: Option<RuleAction>,
    /// Распространяется ли действие на все поддомены ниже данного уровня (*.domain)
    pub match_subdomains: bool,
    /// Дочерние узлы (следующие метки домена справа налево)
    pub children: Vec<TrieNode>,
}

impl TrieNode {
    pub fn new(label: String) -> Self {
        Self {
            label,
            terminal_action: None,
            match_subdomains: false,
            children: Vec::new(),
        }
    }
}

/// Корневой контейнер инвертированного дерева доменов
#[derive(Archive, Deserialize, Serialize, CheckBytes, Debug, Clone, PartialEq, Default)]
#[archive(check_bytes)]
pub struct DomainTrie {
    /// Корневые узлы первого уровня (TLD домены: "com", "ru", "org", "net" и т.д.)
    pub root_nodes: Vec<TrieNode>,
}

impl DomainTrie {
    pub fn new() -> Self {
        Self {
            root_nodes: Vec::new(),
        }
    }

    /// Поиск правила маршрутизации для заданного доменного имени
    pub fn lookup(&self, domain: &str) -> Option<RuleAction> {
        let labels = split_domain_to_reversed_labels(domain);
        if labels.is_empty() {
            return None;
        }

        let mut current_nodes = &self.root_nodes;
        let mut last_wildcard_action: Option<RuleAction> = None;

        for (idx, label) in labels.iter().enumerate() {
            let matched_node = current_nodes.iter().find(|n| n.label.as_str() == *label)?;

            if matched_node.match_subdomains && matched_node.terminal_action.is_some() {
                last_wildcard_action = matched_node.terminal_action;
            }

            if idx == labels.len() - 1 {
                // Достигли последнего сегмента домена
                if let Some(action) = matched_node.terminal_action {
                    return Some(action);
                }
                return last_wildcard_action;
            }

            current_nodes = &matched_node.children;
        }

        last_wildcard_action
    }
}

/// Zero-Copy методы поиска по архивному дереву `ArchivedDomainTrie`
impl ArchivedDomainTrie {
    /// Высокопроизводительный поиск действия без выделения памяти в куче
    pub fn lookup(&self, domain: &str) -> Option<RuleAction> {
        let labels = split_domain_to_reversed_labels(domain);
        if labels.is_empty() {
            return None;
        }

        let mut current_nodes = self.root_nodes.as_slice();
        let mut last_wildcard_action: Option<RuleAction> = None;

        for (idx, label) in labels.iter().enumerate() {
            let matched_node = current_nodes
                .iter()
                .find(|n| n.label.as_str() == *label)?;

            if matched_node.match_subdomains {
                if let Some(action) = matched_node.terminal_action.as_ref() {
                    last_wildcard_action = Some(action.deserialize(&mut rkyv::Infallible).unwrap());
                }
            }

            if idx == labels.len() - 1 {
                if let Some(action) = matched_node.terminal_action.as_ref() {
                    return Some(action.deserialize(&mut rkyv::Infallible).unwrap());
                }
                return last_wildcard_action;
            }

            current_nodes = matched_node.children.as_slice();
        }

        last_wildcard_action
    }
}

/// Построитель дерева доменов с поддержкой синтаксиса MetaCubeX / V2Ray / AdBlock
#[derive(Debug, Default)]
pub struct DomainTrieBuilder {
    trie: DomainTrie,
}

impl DomainTrieBuilder {
    pub fn new() -> Self {
        Self {
            trie: DomainTrie::new(),
        }
    }

    /// Добавляет правило для домена
    ///
    /// Поддерживаемые форматы `raw_pattern`:
    /// - `example.com` -> точный домен + поддомены
    /// - `+.example.com` -> домен и все поддомены (синтаксис v2ray/clash)
    /// - `domain:example.com` -> домен и все поддомены
    /// - `full:example.com` -> строго точное совпадение
    /// - `*.example.com` -> поддомены
    pub fn insert_rule(
        &mut self,
        raw_pattern: &str,
        action: RuleAction,
        override_existing: bool,
    ) -> bool {
        let trimmed = raw_pattern.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            return false;
        }

        let (domain_str, match_subdomains) = parse_domain_pattern(trimmed);
        let labels = split_domain_to_reversed_labels(&domain_str);
        if labels.is_empty() {
            return false;
        }

        let mut current_nodes = &mut self.trie.root_nodes;

        for (idx, label) in labels.iter().enumerate() {
            let is_last = idx == labels.len() - 1;

            let node_pos = match current_nodes.iter().position(|n| n.label == *label) {
                Some(pos) => pos,
                None => {
                    current_nodes.push(TrieNode::new((*label).to_string()));
                    current_nodes.len() - 1
                }
            };

            let node = &mut current_nodes[node_pos];

            if is_last {
                if node.terminal_action.is_none() || override_existing {
                    node.terminal_action = Some(action);
                    node.match_subdomains = match_subdomains;
                    return true;
                }
                return false;
            }

            current_nodes = &mut node.children;
        }

        false
    }

    /// Завершает построение и возвращает готовое дерево `DomainTrie`
    pub fn build(mut self) -> DomainTrie {
        // Сортируем корневые узлы по убыванию длины метки или алфавиту для стабильности
        self.trie.root_nodes.sort_by(|a, b| a.label.cmp(&b.label));
        self.trie
    }
}

/// Разбивает доменное имя на обратные метки в нижнем регистре
pub fn split_domain_to_reversed_labels(domain: &str) -> Vec<&str> {
    let clean = domain.trim().trim_end_matches('.');
    if clean.is_empty() {
        return Vec::new();
    }
    let mut parts: Vec<&str> = clean.split('.').filter(|s| !s.is_empty()).collect();
    parts.reverse();
    parts
}

/// Разбирает префиксы шаблонов правил
fn parse_domain_pattern(pattern: &str) -> (String, bool) {
    let lower = pattern.to_ascii_lowercase();

    if let Some(rest) = lower.strip_prefix("+.") {
        (rest.to_string(), true)
    } else if let Some(rest) = lower.strip_prefix("*.") {
        (rest.to_string(), true)
    } else if let Some(rest) = lower.strip_prefix("domain:") {
        (rest.to_string(), true)
    } else if let Some(rest) = lower.strip_prefix("full:") {
        (rest.to_string(), false)
    } else {
        // По умолчанию для списков GeoSite правило `example.com` применяется и к поддоменам
        (lower, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_trie_exact_and_subdomain_matching() {
        let mut builder = DomainTrieBuilder::new();
        builder.insert_rule("google.com", RuleAction::Proxy, true);
        builder.insert_rule("+.doubleclick.net", RuleAction::Block, true);
        builder.insert_rule("full:direct-only.ru", RuleAction::Direct, true);

        let trie = builder.build();

        // Проверка exact
        assert_eq!(trie.lookup("google.com"), Some(RuleAction::Proxy));
        assert_eq!(trie.lookup("mail.google.com"), Some(RuleAction::Proxy));

        // Проверка adblock wildcard
        assert_eq!(trie.lookup("doubleclick.net"), Some(RuleAction::Block));
        assert_eq!(trie.lookup("ad.doubleclick.net"), Some(RuleAction::Block));
        assert_eq!(trie.lookup("video.ad.doubleclick.net"), Some(RuleAction::Block));

        // Проверка full: (без поддоменов)
        assert_eq!(trie.lookup("direct-only.ru"), Some(RuleAction::Direct));
        assert_eq!(trie.lookup("sub.direct-only.ru"), None);

        // Не совпавшие
        assert_eq!(trie.lookup("yandex.ru"), None);
        assert_eq!(trie.lookup("net"), None);
    }

    #[test]
    fn test_domain_trie_override() {
        let mut builder = DomainTrieBuilder::new();
        builder.insert_rule("example.com", RuleAction::Proxy, false);
        // Админ переопределяет на Direct
        builder.insert_rule("example.com", RuleAction::Direct, true);

        let trie = builder.build();
        assert_eq!(trie.lookup("example.com"), Some(RuleAction::Direct));
        assert_eq!(trie.lookup("sub.example.com"), Some(RuleAction::Direct));
    }
}
