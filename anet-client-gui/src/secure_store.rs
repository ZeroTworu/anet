// anet-client-gui/src/secure_store.rs
use std::sync::Mutex;
use std::fs;
use crate::config::AppSettings;

static IN_MEMORY_URL: Mutex<Option<String>> = Mutex::new(None);

pub struct DesktopSecureStore;

impl DesktopSecureStore {
    fn key_file_path() -> std::path::PathBuf {
        AppSettings::data_dir().join(".storage_key")
    }

    fn url_file_path() -> std::path::PathBuf {
        AppSettings::data_dir().join(".server_url")
    }

    pub fn get_server_config_url() -> Option<String> {
        if let Ok(guard) = IN_MEMORY_URL.lock() {
            if let Some(ref url) = *guard {
                return Some(url.clone());
            }
        }
        let path = Self::url_file_path();
        if let Ok(content) = fs::read_to_string(path) {
            let trimmed = content.trim().to_string();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
        None
    }

    pub fn set_server_config_url(url: &str) -> anyhow::Result<()> {
        let dir = AppSettings::data_dir();
        let _ = fs::create_dir_all(&dir);
        fs::write(Self::url_file_path(), url.trim())?;
        if let Ok(mut guard) = IN_MEMORY_URL.lock() {
            *guard = Some(url.trim().to_string());
        }
        Ok(())
    }

    pub fn delete_server_config_url() -> anyhow::Result<()> {
        let path = Self::url_file_path();
        if path.exists() {
            let _ = fs::remove_file(path);
        }
        if let Ok(mut guard) = IN_MEMORY_URL.lock() {
            *guard = None;
        }
        Ok(())
    }

    pub fn get_or_create_device_storage_key() -> [u8; 32] {
        let path = Self::key_file_path();
        if let Ok(bytes) = fs::read(&path) {
            if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                return key;
            }
        }

        let dir = AppSettings::data_dir();
        let _ = fs::create_dir_all(&dir);
        let mut key = [0u8; 32];
        let u1 = uuid::Uuid::new_v4();
        let u2 = uuid::Uuid::new_v4();
        key[..16].copy_from_slice(u1.as_bytes());
        key[16..].copy_from_slice(u2.as_bytes());
        let _ = fs::write(path, &key);
        key
    }
}