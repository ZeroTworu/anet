use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::config::PerAppMode;

pub const SERVER_CONFIG_ID: &str = "__SERVER_CONFIG__";
pub const SERVER_CONFIG_DISPLAY_NAME: &str = "Server config";

/// Нормализация URL: если протокол не указан, автоматически добавляется https://
pub fn normalize_config_url(url: &str) -> String {
    let trimmed = url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        format!("https://{}", trimmed)
    } else {
        trimmed.to_string()
    }
}

/// Валидация ссылки на конфигурацию (поддерживает ввод с протоколом и без него)
pub fn validate_server_config_url(url: &str) -> Result<String, &'static str> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err("URL не может быть пустым");
    }

    if trimmed.contains(' ') {
        return Err("URL не должен содержать пробелов");
    }

    let normalized = normalize_config_url(trimmed);

    // Валидация через reqwest::Url
    match Url::parse(&normalized) {
        Ok(parsed) if parsed.host_str().is_some() => Ok(normalized),
        _ => Err("Некорректный формат URL"),
    }
}

/// Пользовательские настройки (Overrides), накладываемые поверх серверного конфига
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ServerConfigOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude_route_for: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_server_list: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_app: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_app_mode: Option<PerAppMode>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tray_mode: Option<bool>,
}

impl ServerConfigOverrides {
    pub fn is_empty(&self) -> bool {
        self.exclude_route_for.is_none()
            && self.dns_server_list.is_none()
            && self.per_app.is_none()
            && self.per_app_mode.is_none()
            && self.tray_mode.is_none()
    }
}

/// Кэшированный зашифрованный серверный конфиг с метаданными (Base64)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedServerConfigBundle {
    pub last_updated_at: u64,
    pub ciphertext_b64: String,
    pub nonce_b64: String,
    pub etag: Option<String>,
}

/// Применение Overrides к распарсенному `CoreConfig`
pub fn apply_overrides(mut cfg: crate::config::CoreConfig, overrides: &ServerConfigOverrides) -> crate::config::CoreConfig {
    if let Some(ref excludes) = overrides.exclude_route_for {
        cfg.main.exclude_route_for = excludes.clone();
    }
    if let Some(ref dns) = overrides.dns_server_list {
        cfg.main.dns_server_list = dns.clone();
    }
    if let Some(ref per_app) = overrides.per_app {
        cfg.main.per_app = per_app.clone();
    }
    if let Some(mode) = overrides.per_app_mode {
        cfg.main.per_app_mode = mode;
    }
    cfg
}

pub fn current_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_server_config_url() {
        let valid_https = "https://example.com/api/v1/config/custom-profile";
        assert_eq!(
            validate_server_config_url(valid_https).unwrap(),
            "https://example.com/api/v1/config/custom-profile"
        );

        let valid_no_scheme = "example.com/config.toml";
        assert_eq!(
            validate_server_config_url(valid_no_scheme).unwrap(),
            "https://example.com/config.toml"
        );

        let valid_trailing = "https://example.com/sub/";
        assert_eq!(
            validate_server_config_url(valid_trailing).unwrap(),
            "https://example.com/sub"
        );

        assert!(validate_server_config_url("").is_err());
        assert!(validate_server_config_url("   ").is_err());
        assert!(validate_server_config_url("not a url").is_err());
    }
}