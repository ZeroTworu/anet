use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigEntry {
    pub id: String,
    pub name: String,
    pub content: String,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct AppSettings {
    pub configs: Vec<ConfigEntry>,
    pub active_config_id: Option<String>,
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
        let id = Uuid::new_v4().to_string();
        self.configs.push(ConfigEntry {
            id: id.clone(),
            name,
            content,
        });
        self.save();
        id
    }

    pub fn remove_config(&mut self, id: &str) {
        self.configs.retain(|c| c.id != id);
        if self.active_config_id.as_deref() == Some(id) {
            self.active_config_id = None;
        }
        self.save();
    }

    pub fn rename_config(&mut self, id: &str, new_name: String) {
        if let Some(c) = self.configs.iter_mut().find(|c| c.id == id) {
            c.name = new_name;
            self.save();
        }
    }

    pub fn get_active_config(&self) -> Option<ConfigEntry> {
        self.active_config_id
            .as_ref()
            .and_then(|id| self.configs.iter().find(|c| &c.id == id).cloned())
    }

    pub fn set_active(&mut self, id: &str) {
        if self.configs.iter().any(|c| c.id == id) {
            self.active_config_id = Some(id.to_string());
            self.save();
        }
    }
}
