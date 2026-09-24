//! Функции модификации TOML файлов конфигураций

use crate::types::FilterMode;

/// Внедрение настроек списка приложений и режима фильтрации в TOML
pub fn inject_per_app_to_toml(content: &str, apps: &[String], mode: FilterMode) -> String {
    if let Ok(mut val) = toml::from_str::<toml::Value>(content) {
        if let Some(main) = val.get_mut("main").and_then(|m| m.as_table_mut()) {
            let apps_val = apps.iter().cloned().map(toml::Value::String).collect();
            main.insert("per_app".to_string(), toml::Value::Array(apps_val));
            let mode_str = match mode {
                FilterMode::All => "all",
                FilterMode::Include => "include",
                FilterMode::Exclude => "exclude",
            };
            main.insert("per_app_mode".to_string(), toml::Value::String(mode_str.to_string()));
            main.remove("per_app_exclude");
            if let Ok(serialized) = toml::to_string_pretty(&val) {
                return serialized;
            }
        }
    }
    content.to_string()
}

/// Внедрение исключённых IP и CIDR маршрутов в TOML
pub fn inject_exclude_route_to_toml(content: &str, routes: &[String]) -> String {
    if let Ok(mut val) = toml::from_str::<toml::Value>(content) {
        if let Some(main) = val.get_mut("main").and_then(|m| m.as_table_mut()) {
            let routes_val = routes.iter().cloned().map(toml::Value::String).collect();
            main.insert("exclude_route_for".to_string(), toml::Value::Array(routes_val));
            if let Ok(serialized) = toml::to_string_pretty(&val) {
                return serialized;
            }
        }
    }
    content.to_string()
}

/// Внедрение настройки tray_mode в TOML
pub fn inject_tray_mode_to_toml(content: &str, tray_mode: bool) -> String {
    if let Ok(mut val) = toml::from_str::<toml::Value>(content) {
        if let Some(main) = val.get_mut("main").and_then(|m| m.as_table_mut()) {
            main.insert("tray_mode".to_string(), toml::Value::Boolean(tray_mode));
            if let Ok(serialized) = toml::to_string_pretty(&val) {
                return serialized;
            }
        }
    }
    content.to_string()
}
