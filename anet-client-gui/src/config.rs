use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;
use anet_client_core::events::AccountInfo;
use anet_client_core::server_config::{
    ServerConfigOverrides, EncryptedServerConfigBundle, SERVER_CONFIG_ID, SERVER_CONFIG_DISPLAY_NAME
};

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigEntry {
    pub id: String,
    pub name: String,
    pub content: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub is_read_only: bool,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct AppSettings {
    pub configs: Vec<ConfigEntry>,
    pub active_config_id: Option<String>,
    #[serde(default)]
    pub config_url: Option<String>, // <-- Убедитесь, что поле присутствует
    #[serde(default)]
    pub server_config_overrides: ServerConfigOverrides,
    #[serde(default)]
    pub cached_server_config: Option<EncryptedServerConfigBundle>,
    #[serde(default)]
    pub disable_notifications: bool,
    #[serde(default)]
    pub selected_servers: HashMap<String, String>,
    #[serde(default)]
    pub cached_accounts: HashMap<String, AccountInfo>,
}

impl AppSettings {
    pub fn data_dir() -> PathBuf {
        #[cfg(target_os = "windows")]
        {
            dirs::data_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("ANet")
        }
        #[cfg(target_os = "macos")]
        {
            dirs::data_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("ANet")
        }
        #[cfg(target_os = "linux")]
        {
            dirs::config_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("anet")
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            PathBuf::from(".")
        }
    }

    pub fn settings_path() -> PathBuf {
        Self::data_dir().join("settings.json")
    }

    pub fn load() -> Self {
        let path = Self::settings_path();
        if let Ok(content) = std::fs::read_to_string(&path) {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            Self::default()
        }
    }

    pub fn save(&self) {
        let dir = Self::data_dir();
        let _ = std::fs::create_dir_all(&dir);
        if let Ok(content) = serde_json::to_string(self) {
            let _ = std::fs::write(Self::settings_path(), content);
        }
    }

    pub fn add_config(&mut self, name: String, content: String) -> String {
        self.add_config_with_url(name, content, None)
    }

    pub fn add_config_with_url(&mut self, name: String, content: String, url: Option<String>) -> String {
        let id = Uuid::new_v4().to_string();
        self.configs.push(ConfigEntry {
            id: id.clone(),
            name,
            content,
            url,
            is_read_only: false,
        });
        self.active_config_id = Some(id.clone()); // <-- Сразу делаем активным
        self.save();
        id
    }

    pub fn update_config_content(&mut self, id: &str, new_content: String) {
        if let Some(c) = self.configs.iter_mut().find(|c| c.id == id) {
            c.content = new_content;
            self.save();
        }
    }

    pub fn remove_config(&mut self, id: &str) {
        self.configs.retain(|c| c.id != id);
        if self.active_config_id.as_deref() == Some(id) {
            self.active_config_id = None;
        }
        self.selected_servers.remove(id);
        self.cached_accounts.remove(id);
        self.save();
    }

    pub fn rename_config(&mut self, id: &str, new_name: String) {
        if let Some(c) = self.configs.iter_mut().find(|c| c.id == id) {
            c.name = new_name;
            self.save();
        }
    }

    pub fn get_active_config(&self) -> Option<ConfigEntry> {
        let active_id = self.active_config_id.as_ref()?;
        self.configs.iter().find(|c| &c.id == active_id).cloned()
    }

    pub fn get_active_config_with_overrides(&self, storage_key: &[u8; 32]) -> Option<ConfigEntry> {
        let active_id = self.active_config_id.as_deref()?;
        if active_id == SERVER_CONFIG_ID {
            if let Some(bundle) = &self.cached_server_config {
                if let Ok(raw_content) = anet_client_core::updater::Updater::decrypt_config(bundle, storage_key) {
                    let merged_toml = apply_overrides_to_toml_str(&raw_content, &self.server_config_overrides);
                    return Some(ConfigEntry {
                        id: SERVER_CONFIG_ID.to_string(),
                        name: SERVER_CONFIG_DISPLAY_NAME.to_string(),
                        content: merged_toml,
                        url: None,
                        is_read_only: true,
                    });
                }
            }
            return None;
        }

        self.get_active_config()
    }

    pub fn set_active(&mut self, id: &str) {
        if id == SERVER_CONFIG_ID || self.configs.iter().any(|c| c.id == id) {
            self.active_config_id = Some(id.to_string());
            self.save();
        }
    }

    pub fn set_config_url(&mut self, url: Option<String>) {
        self.config_url = url;
        self.save();
    }
}

pub fn apply_overrides_to_toml_str(content: &str, overrides: &ServerConfigOverrides) -> String {
    let mut val: toml::Value = match toml::from_str(content) {
        Ok(v) => v,
        Err(_) => return content.to_string(),
    };

    if let Some(main) = val.get_mut("main").and_then(|m| m.as_table_mut()) {
        if let Some(ref excludes) = overrides.exclude_route_for {
            let arr = excludes.iter().cloned().map(toml::Value::String).collect();
            main.insert("exclude_route_for".to_string(), toml::Value::Array(arr));
        }
        if let Some(ref dns) = overrides.dns_server_list {
            let arr = dns.iter().cloned().map(toml::Value::String).collect();
            main.insert("dns_server_list".to_string(), toml::Value::Array(arr));
        }
        if let Some(ref per_app) = overrides.per_app {
            let arr = per_app.iter().cloned().map(toml::Value::String).collect();
            main.insert("per_app".to_string(), toml::Value::Array(arr));
        }
        if let Some(mode) = overrides.per_app_mode {
            let mode_str = match mode {
                anet_client_core::config::PerAppMode::All => "all",
                anet_client_core::config::PerAppMode::Include => "include",
                anet_client_core::config::PerAppMode::Exclude => "exclude",
            };
            main.insert("per_app_mode".to_string(), toml::Value::String(mode_str.to_string()));
        }
        if let Some(tray) = overrides.tray_mode {
            main.insert("tray_mode".to_string(), toml::Value::Boolean(tray));
        }
    }

    toml::to_string_pretty(&val).unwrap_or_else(|_| content.to_string())
}