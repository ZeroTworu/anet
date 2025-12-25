use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default)]
struct AppSettings {
    last_config_path: Option<String>,
}

impl AppSettings {
    fn load() -> Self {
        if let Ok(content) = std::fs::read_to_string("anet_settings.json") {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            Self::default()
        }
    }

    fn save(&self) {
        if let Ok(content) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write("anet_settings.json", content);
        }
    }
}
