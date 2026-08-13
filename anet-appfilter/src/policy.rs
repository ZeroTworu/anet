//! Политика выбора приложений — аналог белого/чёрного списка из Android-версии.

use std::collections::HashSet;
use std::sync::Arc;

use crate::flow_map::FlowOwner;

/// Режим фильтрации по приложениям.
#[derive(Clone, Debug)]
pub enum AppPolicy {
    /// Include-режим (как `addAllowedApplication` в Android): в туннель идут
    /// ТОЛЬКО перечисленные процессы, остальные — напрямую.
    Include(HashSet<Arc<str>>),
    /// Exclude-режим (как `addDisallowedApplication`): в туннель идёт всё,
    /// КРОМЕ перечисленных процессов.
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

    /// Решение: должен ли поток этого владельца идти в туннель.
    ///
    /// Если владелец неизвестен (`image_name == None` — процесс уже умер,
    /// либо это системный трафик без процесса), применяем безопасный дефолт:
    /// в include-режиме — НЕ трогаем (выпускаем напрямую), в exclude-режиме —
    /// заворачиваем. То есть неизвестное всегда трактуется как «не в списке».
    pub fn should_tunnel(&self, owner: &FlowOwner) -> bool {
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
        assert!(p.should_tunnel(&owner(Some("firefox.exe")))); // регистр нормализован
        assert!(!p.should_tunnel(&owner(Some("chrome.exe"))));
    }

    #[test]
    fn exclude_listed_apps_bypass() {
        let p = AppPolicy::exclude(["steam.exe"]);
        assert!(!p.should_tunnel(&owner(Some("steam.exe"))));
        assert!(p.should_tunnel(&owner(Some("firefox.exe"))));
    }

    #[test]
    fn unknown_owner_defaults_to_not_in_list() {
        // include: неизвестный -> напрямую (не в списке разрешённых)
        assert!(!AppPolicy::include(["a.exe"]).should_tunnel(&owner(None)));
        // exclude: неизвестный -> в туннель (не в списке исключённых)
        assert!(AppPolicy::exclude(["a.exe"]).should_tunnel(&owner(None)));
    }

    #[test]
    fn all_policy_tunnels_everything() {
        assert!(AppPolicy::All.should_tunnel(&owner(None)));
        assert!(AppPolicy::All.should_tunnel(&owner(Some("anything.exe"))));
    }
}
