//! Политика выбора приложений — аналог белого/чёрного списка из Android-версии.

use std::collections::HashSet;
use std::sync::Arc;

use crate::flow_map::FlowOwner;

/// Режим фильтрации по приложениям.
#[derive(Clone, Debug, PartialEq)]
pub enum AppPolicy {
    /// Include-режим: в туннель идут ТОЛЬКО перечисленные процессы, остальные — напрямую.
    Include(HashSet<Arc<str>>),
    /// Exclude-режим: в туннель идёт всё, КРОМЕ перечисленных процессов.
    Exclude(HashSet<Arc<str>>),
    /// Весь трафик в туннель (поведение по умолчанию, как классический VPN).
    All,
}

impl AppPolicy {
    /// Строит include-политику из списка имён (регистр не важен).
    pub fn include<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        AppPolicy::Include(normalize(names))
    }

    /// Строит exclude-политику из списка имён (регистр не важен).
    pub fn exclude<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        AppPolicy::Exclude(normalize(names))
    }

    /// Решение по умолчанию, если владелец сокета пока не определен (рассинхрон или гонка):
    /// - Include: НЕ трогаем (выпускаем напрямую, так как приложения нет в списке доверенных)
    /// - Exclude: ЗАВОРАЧИВАЕМ в туннель (так как процесс не подтвержден как исключенный)
    /// - All: ЗАВОРАЧИВАЕМ в туннель
    #[inline]
    pub fn should_tunnel_unknown(&self) -> bool {
        match self {
            AppPolicy::All => true,
            AppPolicy::Include(_) => false,
            AppPolicy::Exclude(_) => true,
        }
    }

    /// Решение: должен ли поток идти в туннель на основе владельца (если известен).
    pub fn should_tunnel(&self, owner: Option<&FlowOwner>) -> bool {
        let Some(owner) = owner else {
            return self.should_tunnel_unknown();
        };

        match self {
            AppPolicy::All => true,
            AppPolicy::Include(set) => owner
                .image_name
                .as_ref()
                .is_some_and(|name| set.contains(name)),
            AppPolicy::Exclude(set) => owner
                .image_name
                .as_ref()
                .is_none_or(|name| !set.contains(name)),
        }
    }
}

fn normalize<I, S>(names: I) -> HashSet<Arc<str>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    names
        .into_iter()
        .map(|s| {
            let lower = s.as_ref().to_ascii_lowercase();
            Arc::from(lower.as_str())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(name: Option<&str>) -> FlowOwner {
        FlowOwner {
            process_id: 42,
            image_name: name.map(|n| Arc::from(n)),
        }
    }

    #[test]
    fn include_only_listed_apps_tunnel() {
        let p = AppPolicy::include(["Firefox.exe", "Telegram.exe"]);
        assert!(p.should_tunnel(Some(&owner(Some("firefox.exe")))));
        assert!(!p.should_tunnel(Some(&owner(Some("chrome.exe")))));
        assert!(!p.should_tunnel(None));
    }

    #[test]
    fn exclude_listed_apps_bypass() {
        let p = AppPolicy::exclude(["steam.exe"]);
        assert!(!p.should_tunnel(Some(&owner(Some("steam.exe")))));
        assert!(p.should_tunnel(Some(&owner(Some("firefox.exe")))));
        assert!(p.should_tunnel(None));
        assert!(p.should_tunnel(Some(&owner(None))));
    }

    #[test]
    fn all_policy_tunnels_everything() {
        assert!(AppPolicy::All.should_tunnel(None));
        assert!(AppPolicy::All.should_tunnel(Some(&owner(None))));
        assert!(AppPolicy::All.should_tunnel(Some(&owner(Some("anything.exe")))));
    }
}