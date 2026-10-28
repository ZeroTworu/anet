//! Инвертированное префиксное дерево меток доменов (Domain Trie).
//!
//! Домены разбиваются на метки по точке и обходятся справа налево:
//! `ads.google.com` -> `["com", "google", "ads"]`.
//! Обеспечивает O(K) поиск (где K — количество меток в домене, обычно 2-4)
//! как для несжатых структур, так и в Zero-Copy режиме через `ArchivedDomainTrie`.
//!
//! Использует плоскую табличную адресацию (Flattened Arena Layout) на базе индексов:
//! дочерние узлы любого уровня располагаются в непрерывном срезе `nodes[children_start .. children_start + children_count]`,
//! что исключает рекурсивные типы в схеме сериализации и обеспечивает максимальную кэш-локальность.

use bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};

use crate::model::RuleAction;

/// Узел инвертированного дерева доменов с индексной адресацией дочерних элементов
#[derive(Archive, Deserialize, Serialize, CheckBytes, Debug, Clone, PartialEq)]
#[archive(check_bytes)]
pub struct TrieNode {
    /// Метка доменного уровня в нижнем регистре (например, "com", "google", "ads")
    pub label: String,
    /// Терминальное действие для данного домена (если правило заканчивается на этом уровне)
    pub terminal_action: Option<RuleAction>,
    /// Распространяется ли действие на все поддомены ниже данного уровня (*.domain)
    pub match_subdomains: bool,
    /// Начальный индекс дочерних узлов в плоском массиве `nodes`
    pub children_start: u32,
    /// Количество дочерних узлов
    pub children_count: u16,
}

impl TrieNode {
    pub fn new(label: String) -> Self {
        Self {
            label,
            terminal_action: None,
            match_subdomains: false,
            children_start: 0,
            children_count: 0,
        }
    }
}

/// Корневой контейнер инвертированного дерева доменов
#[derive(Archive, Deserialize, Serialize, CheckBytes, Debug, Clone, PartialEq, Default)]
#[archive(check_bytes)]
pub struct DomainTrie {
    /// Непрерывный массив всех узлов дерева (Flattened Arena)
    pub nodes: Vec<TrieNode>,
    /// Начальный индекс корневых узлов (TLD)
    pub root_start: u32,
    /// Количество корневых узлов
    pub root_count: u16,
}

impl DomainTrie {
    pub fn new() -> Self {
        Self::default()
    }

    /// Поиск правила маршрутизации для заданного доменного имени
    pub fn lookup(&self, domain: &str) -> Option<RuleAction> {
        let normalized: std::borrow::Cow<'_, str> =
            if domain.bytes().any(|b| b.is_ascii_uppercase()) {
                std::borrow::Cow::Owned(domain.to_ascii_lowercase())
            } else {
                std::borrow::Cow::Borrowed(domain)
            };
        let labels = split_domain_to_reversed_labels(&normalized);
        if labels.is_empty() || self.root_count == 0 {
            return None;
        }

        let mut current_start = self.root_start as usize;
        let mut current_count = self.root_count as usize;
        let mut last_wildcard_action: Option<RuleAction> = None;

        for (idx, label) in labels.iter().enumerate() {
            if current_start + current_count > self.nodes.len() {
                return last_wildcard_action;
            }
            let current_slice = &self.nodes[current_start..current_start + current_count];
            let Ok(found_idx) =
                current_slice.binary_search_by(|n| n.label.as_str().cmp(*label))
            else {
                return last_wildcard_action;
            };
            let matched_node = &current_slice[found_idx];

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

            if matched_node.children_count == 0 {
                return last_wildcard_action;
            }

            current_start = matched_node.children_start as usize;
            current_count = matched_node.children_count as usize;
        }

        last_wildcard_action
    }

    /// Возвращает все доменные имена (включая wildcard базы) с действием `Direct`
    pub fn collect_direct_domains(&self) -> Vec<String> {
        let mut result = Vec::new();
        if self.nodes.is_empty() || self.root_count == 0 {
            return result;
        }

        let mut stack = Vec::new();
        let root_start = self.root_start as usize;
        let root_count = self.root_count as usize;

        for i in 0..root_count {
            let idx = root_start + i;
            if idx < self.nodes.len() {
                stack.push((idx, Vec::new()));
            }
        }

        while let Some((node_idx, mut labels)) = stack.pop() {
            let node = &self.nodes[node_idx];
            labels.push(node.label.clone());

            if node.terminal_action == Some(RuleAction::Direct) {
                let mut reversed = labels.clone();
                reversed.reverse();
                result.push(reversed.join("."));
            }

            let c_start = node.children_start as usize;
            let c_count = node.children_count as usize;
            for i in 0..c_count {
                let child_idx = c_start + i;
                if child_idx < self.nodes.len() {
                    stack.push((child_idx, labels.clone()));
                }
            }
        }

        result
    }
}

/// Zero-Copy методы поиска по архивному дереву `ArchivedDomainTrie`
impl ArchivedDomainTrie {
    /// Высокопроизводительный поиск действия без выделения памяти в куче
    pub fn lookup(&self, domain: &str) -> Option<RuleAction> {
        let normalized: std::borrow::Cow<'_, str> =
            if domain.bytes().any(|b| b.is_ascii_uppercase()) {
                std::borrow::Cow::Owned(domain.to_ascii_lowercase())
            } else {
                std::borrow::Cow::Borrowed(domain)
            };
        let labels = split_domain_to_reversed_labels(&normalized);
        if labels.is_empty() || self.root_count == 0 {
            return None;
        }

        let nodes = self.nodes.as_slice();
        let mut current_start = self.root_start as usize;
        let mut current_count = self.root_count as usize;
        let mut last_wildcard_action: Option<RuleAction> = None;

        for (idx, label) in labels.iter().enumerate() {
            if current_start + current_count > nodes.len() {
                return last_wildcard_action;
            }
            let current_slice = &nodes[current_start..current_start + current_count];
            let Ok(found_idx) =
                current_slice.binary_search_by(|n| n.label.as_str().cmp(*label))
            else {
                return last_wildcard_action;
            };
            let matched_node = &current_slice[found_idx];

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

            if matched_node.children_count == 0 {
                return last_wildcard_action;
            }

            current_start = matched_node.children_start as usize;
            current_count = matched_node.children_count as usize;
        }

        last_wildcard_action
    }

    /// Возвращает все доменные имена (включая wildcard базы) с действием `Direct` в Zero-Copy режиме
    pub fn collect_direct_domains(&self) -> Vec<String> {
        let mut result = Vec::new();
        let nodes = self.nodes.as_slice();
        if nodes.is_empty() || self.root_count == 0 {
            return result;
        }

        let mut stack = Vec::new();
        let root_start = self.root_start as usize;
        let root_count = self.root_count as usize;

        for i in 0..root_count {
            let idx = root_start + i;
            if idx < nodes.len() {
                stack.push((idx, Vec::new()));
            }
        }

        while let Some((node_idx, mut labels)) = stack.pop() {
            let node = &nodes[node_idx];
            labels.push(node.label.as_str().to_string());

            if let Some(action) = node.terminal_action.as_ref() {
                let rule_action: RuleAction = action.deserialize(&mut rkyv::Infallible).unwrap();
                if rule_action == RuleAction::Direct {
                    let mut reversed = labels.clone();
                    reversed.reverse();
                    result.push(reversed.join("."));
                }
            }

            let c_start = node.children_start as usize;
            let c_count = node.children_count as usize;
            for i in 0..c_count {
                let child_idx = c_start + i;
                if child_idx < nodes.len() {
                    stack.push((child_idx, labels.clone()));
                }
            }
        }

        result
    }
}

/// Промежуточный узел дерева для стадии сборки (без ограничений rkyv)
#[derive(Debug, Default)]
struct BuilderNode {
    label: String,
    terminal_action: Option<RuleAction>,
    match_subdomains: bool,
    children: Vec<BuilderNode>,
}

/// Построитель дерева доменов с поддержкой синтаксиса MetaCubeX / V2Ray / AdBlock
#[derive(Debug, Default)]
pub struct DomainTrieBuilder {
    roots: Vec<BuilderNode>,
}

impl DomainTrieBuilder {
    pub fn new() -> Self {
        Self::default()
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

        let mut current_nodes = &mut self.roots;

        for (idx, label) in labels.iter().enumerate() {
            let is_last = idx == labels.len() - 1;

            let node_pos = match current_nodes.binary_search_by(|n| n.label.as_str().cmp(*label)) {
                Ok(pos) => pos,
                Err(insert_pos) => {
                    current_nodes.insert(
                        insert_pos,
                        BuilderNode {
                            label: (*label).to_string(),
                            terminal_action: None,
                            match_subdomains: false,
                            children: Vec::new(),
                        },
                    );
                    insert_pos
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

    /// Завершает построение и укладывает иерархию в непрерывный массив `nodes` (BFS level-order)
    pub fn build(mut self) -> DomainTrie {
        if self.roots.is_empty() {
            return DomainTrie::default();
        }

        // Сортируем корневые узлы по алфавиту
        self.roots.sort_by(|a, b| a.label.cmp(&b.label));
        if self.roots.len() > u16::MAX as usize {
            self.roots.truncate(u16::MAX as usize);
        }

        let mut flat_nodes: Vec<TrieNode> = Vec::new();
        let mut queue: std::collections::VecDeque<(usize, Vec<BuilderNode>)> =
            std::collections::VecDeque::new();

        let root_start = 0u32;
        let root_count = self.roots.len() as u16;

        for r in &self.roots {
            flat_nodes.push(TrieNode {
                label: r.label.clone(),
                terminal_action: r.terminal_action,
                match_subdomains: r.match_subdomains,
                children_start: 0,
                children_count: 0,
            });
        }

        for (idx, r) in self.roots.into_iter().enumerate() {
            if !r.children.is_empty() {
                queue.push_back((idx, r.children));
            }
        }

        while let Some((parent_idx, mut children)) = queue.pop_front() {
            children.sort_by(|a, b| a.label.cmp(&b.label));
            if children.len() > u16::MAX as usize {
                children.truncate(u16::MAX as usize);
            }
            let children_start = flat_nodes.len() as u32;
            let children_count = children.len() as u16;

            flat_nodes[parent_idx].children_start = children_start;
            flat_nodes[parent_idx].children_count = children_count;

            let base_idx = flat_nodes.len();
            for c in &children {
                flat_nodes.push(TrieNode {
                    label: c.label.clone(),
                    terminal_action: c.terminal_action,
                    match_subdomains: c.match_subdomains,
                    children_start: 0,
                    children_count: 0,
                });
            }

            for (c_idx, c) in children.into_iter().enumerate() {
                if !c.children.is_empty() {
                    queue.push_back((base_idx + c_idx, c.children));
                }
            }
        }

        DomainTrie {
            nodes: flat_nodes,
            root_start,
            root_count,
        }
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
