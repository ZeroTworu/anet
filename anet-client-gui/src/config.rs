use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct AppSettings {
    pub last_config_path: Option<String>,
}

impl AppSettings {
    pub fn load() -> Self {
        if let Ok(content) = std::fs::read_to_string("anet_settings.json") {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            Self::default()
        }
    }

    pub fn save(&self) {
        if let Ok(content) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write("anet_settings.json", content);
        }
    }
}
