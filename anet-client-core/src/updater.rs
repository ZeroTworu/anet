use std::env;
use std::fs;
use std::process::Command;
use reqwest::Client;
use log::{info, warn, error};
use std::path::{Path, PathBuf};
use crate::events::update_progress;
use crate::events::{emit, AnetEvent};
use crate::config::CoreConfig;
use std::io::{Cursor, copy, Read};
use serde::Deserialize;
use zip::ZipArchive;
use crate::server_config::{EncryptedServerConfigBundle, current_timestamp_secs};
use anet_common::encryption::Cipher;
use rand::RngCore;
use rand::rngs::OsRng;
use base64::prelude::*;

#[derive(Deserialize, Clone, Debug)]
pub struct GithubRelease {
    pub tag_name: String,
    pub body: Option<String>,
    pub assets: Vec<GithubAsset>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct GithubAsset {
    pub name: String,
    pub browser_download_url: String,
    pub size: u64,
}

pub struct Updater;

pub enum ConfigFetchResult {
    Updated {
        content: String,
        updated_at: u64,
        etag: Option<String>,
    },
    NotModified,
}

impl Updater {
    /// Загружает текст конфигурации по URL, проверяет корректность TOML и валидность нод.
    pub async fn fetch_config_from_url(url: &str) -> anyhow::Result<String> {
        let trimmed_url = url.trim();
        if trimmed_url.is_empty() {
            return Err(anyhow::anyhow!("Ссылка не может быть пустой"));
        }

        // Если схема не указана, по умолчанию используем https://
        let target_url = if !trimmed_url.starts_with("http://") && !trimmed_url.starts_with("https://") {
            format!("https://{}", trimmed_url)
        } else {
            trimmed_url.to_string()
        };

        info!("[UPDATER] Запрос конфигурации по адресу: {}", target_url);

        let client = Client::builder()
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) ANet-Client")
            .timeout(std::time::Duration::from_secs(15))
            .danger_accept_invalid_certs(true) // Обход самоподписанных TLS сертификатов
            .build()
            .map_err(|e| anyhow::anyhow!("Не удалось создать HTTP-клиент: {}", e))?;

        let response = client
            .get(&target_url)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Не удалось подключиться по указанной ссылке: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Сервер вернул ошибку: HTTP {}",
                response.status()
            ));
        }

        let content = response
            .text()
            .await
            .map_err(|e| anyhow::anyhow!("Ошибка чтения ответа от сервера: {}", e))?;

        if content.trim().is_empty() {
            return Err(anyhow::anyhow!("По ссылке получен пустой ответ"));
        }

        // Валидация ТОЛЬКО полученных данных:
        let mut parsed_config: CoreConfig = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Полученные данные не являются валидным TOML-конфигом: {}", e))?;

        parsed_config
            .sanitize()
            .map_err(|e| anyhow::anyhow!("Ошибка в структуре конфигурации (нет серверов или неверный формат): {}", e))?;

        info!(
            "[UPDATER] Конфигурация успешно проверена (найдено серверов: {})",
            parsed_config.servers.len()
        );

        Ok(content)
    }

    /// Загружает и возвращает распарсенную структуру CoreConfig вместе с исходным текстом.
    pub async fn update_config_from_url(url: &str) -> anyhow::Result<(CoreConfig, String)> {
        let content = Self::fetch_config_from_url(url).await?;
        let mut cfg: CoreConfig = toml::from_str(&content)?;
        cfg.sanitize()?;
        Ok((cfg, content))
    }

    pub async fn check_latest(url: &str, current_version: &str) -> anyhow::Result<Option<GithubRelease>> {
        info!("[UPDATER] Checking for updates...");

        let client = Client::builder()
            .user_agent("ANet-Client-GUI")
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build HTTP client: {}", e))?;

        info!("[UPDATER] Requesting URL: {}", url);

        let response = client.get(url).send().await
            .map_err(|e| anyhow::anyhow!("Network error: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Update server returned error: {}", response.status()));
        }

        let release: GithubRelease = response.json().await
            .map_err(|e| anyhow::anyhow!("Failed to parse release JSON: {}", e))?;

        if release.tag_name != current_version {
            info!("[UPDATER] New version available: {}", release.tag_name);
            Ok(Some(release))
        } else {
            info!("[UPDATER] You are on the latest version.");
            Ok(None)
        }
    }

    pub async fn download_apk(release: GithubRelease, target_path: String) -> anyhow::Result<()> {
        let client = Client::builder().user_agent("ANet-Updater").build()?;

        let asset = release.assets.iter()
            .find(|a| a.name.ends_with(".apk"))
            .ok_or_else(|| anyhow::anyhow!("APK не найден в релизе"))?;

        let total_size = asset.size as u64;
        let mut response = client.get(&asset.browser_download_url).send().await?;

        let mut downloaded: u64 = 0;
        let mut file = std::fs::File::create(&target_path)?;

        while let Some(chunk) = response.chunk().await? {
            std::io::Write::write_all(&mut file, &chunk)?;
            downloaded += chunk.len() as u64;

            let progress = downloaded as f32 / total_size as f32;
            update_progress(progress);
        }

        info!("[UPDATER] APK downloaded to {}", target_path);
        emit(AnetEvent::UpdateReady);
        Ok(())
    }

    pub async fn download_and_apply(release: GithubRelease) -> anyhow::Result<()> {
        info!("[UPDATER] Downloading update...");
        let client = Client::builder().user_agent("ANet-Updater").build()?;

        let asset = release.assets.iter()
            .find(|a| a.name.to_lowercase().contains("client-windows") && a.name.ends_with(".zip"))
            .ok_or_else(|| anyhow::anyhow!("Архив не найден"))?;

        let total_size = asset.size as u64;
        let mut response = client.get(&asset.browser_download_url).send().await?;

        let mut downloaded: u64 = 0;
        let mut buffer = Vec::with_capacity(total_size as usize);

        while let Some(chunk) = response.chunk().await? {
            buffer.extend_from_slice(&chunk);
            downloaded += chunk.len() as u64;
            update_progress(downloaded as f32 / total_size as f32);
        }

        let reader = Cursor::new(buffer);
        let mut archive = ZipArchive::new(reader)?;

        let current_exe_path = env::current_exe()?;
        let working_dir = current_exe_path.parent().unwrap();

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let file_name = match Path::new(file.name()).file_name() {
                Some(name) => name.to_string_lossy().to_string(),
                None => continue,
            };

            if file.is_dir() { continue; }
            let target_path = working_dir.join(&file_name);

            match file_name.as_str() {
                "anet-gui.exe" | "anet-client.exe" => {
                    info!("[UPDATER] Replacing binary: {}", file_name);
                    Self::atomic_replace(&target_path, &mut file)?;
                },
                "client.toml" => {
                    let example_path = working_dir.join("client.toml.example");
                    let mut outfile = fs::File::create(&example_path)?;
                    copy(&mut file, &mut outfile)?;
                },
                _ => {
                    warn!("[UPDATER] Skipping file: {}", file_name);
                }
            }
        }

        info!("[UPDATER] Success! Sending UpdateReady event.");
        emit(AnetEvent::UpdateReady);
        Ok(())
    }

    fn atomic_replace(target: &PathBuf, mut source: impl Read) -> anyhow::Result<()> {
        let mut backup_path = target.clone();
        backup_path.set_extension("exe.old");

        if backup_path.exists() { let _ = fs::remove_file(&backup_path); }

        if target.exists() {
            fs::rename(target, &backup_path).map_err(|e| {
                anyhow::anyhow!("Workaround failed for {}: {}", target.display(), e)
            })?;
        }

        let mut outfile = fs::File::create(target)?;
        copy(&mut source, &mut outfile)?;
        Ok(())
    }

    pub fn final_restart() {
        if let Ok(current_exe) = env::current_exe() {
            let _ = Command::new(current_exe).spawn();
            std::process::exit(0);
        }
    }

    pub fn cleanup_old_version() {
        if let Ok(exe_path) = env::current_exe() {
            let mut old_gui = exe_path.clone();
            old_gui.set_extension("exe.old");
            if old_gui.exists() {
                let _ = fs::remove_file(old_gui);
            }
        }
    }

     pub async fn fetch_server_config(
        url: &str,
        current_etag: Option<&str>,
    ) -> anyhow::Result<ConfigFetchResult> {
        info!("[UPDATER] Запрос серверного конфига: {}", url);

        let client = Client::builder()
            .user_agent("ANet-Client-Core")
            .timeout(std::time::Duration::from_secs(12))
            .danger_accept_invalid_certs(true)
            .build()?;

        let mut req = client.get(url);
        if let Some(etag) = current_etag {
            req = req.header(reqwest::header::IF_NONE_MATCH, etag);
        }

        let response = req.send().await.map_err(|e| {
            anyhow::anyhow!("Сетевая ошибка при загрузке серверного конфига: {}", e)
        })?;

        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            info!("[UPDATER] Конфиг на сервере не изменился (HTTP 304).");
            return Ok(ConfigFetchResult::NotModified);
        }

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Сервер конфигураций вернул HTTP статус: {}",
                response.status()
            ));
        }

        let new_etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let content = response.text().await?;
        if content.trim().is_empty() {
            return Err(anyhow::anyhow!("Получен пустой файл конфигурации"));
        }

        // Проверяем валидность полученного TOML
        let mut parsed_config: CoreConfig = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Файл по ссылке не является корректным TOML: {}", e))?;

        parsed_config
            .sanitize()
            .map_err(|e| anyhow::anyhow!("Ошибка валидации структуры конфига: {}", e))?;

        let updated_at = current_timestamp_secs();
        info!(
            "[UPDATER] Серверный конфиг успешно получен (нод: {}, время: {})",
            parsed_config.servers.len(),
            updated_at
        );

        Ok(ConfigFetchResult::Updated {
            content,
            updated_at,
            etag: new_etag,
        })
    }

    /// Шифрование сырого TOML-конфига для сохранения на диск (защита от утечки в открытом виде)
   pub fn encrypt_config(content: &str, storage_key: &[u8; 32], etag: Option<String>) -> anyhow::Result<EncryptedServerConfigBundle> {
        let cipher = Cipher::new(storage_key);
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let ciphertext = cipher.encrypt(&nonce, bytes::Bytes::from(content.as_bytes().to_vec()))?;

        Ok(EncryptedServerConfigBundle {
            last_updated_at: current_timestamp_secs(),
            ciphertext_b64: BASE64_STANDARD.encode(&ciphertext),
            nonce_b64: BASE64_STANDARD.encode(nonce),
            etag,
        })
    }

    /// Дешифрование локально кэшированного конфига
  pub fn decrypt_config(bundle: &EncryptedServerConfigBundle, storage_key: &[u8; 32]) -> anyhow::Result<String> {
        let cipher = Cipher::new(storage_key);
        let nonce_bytes = BASE64_STANDARD
            .decode(&bundle.nonce_b64)
            .map_err(|e| anyhow::anyhow!("Invalid base64 nonce: {}", e))?;
        let ciphertext_bytes = BASE64_STANDARD
            .decode(&bundle.ciphertext_b64)
            .map_err(|e| anyhow::anyhow!("Invalid base64 ciphertext: {}", e))?;

        let nonce: [u8; 12] = nonce_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid nonce length"))?;

        let decrypted = cipher.decrypt(&nonce, bytes::Bytes::from(ciphertext_bytes))?;
        let content = String::from_utf8(decrypted.to_vec())
            .map_err(|e| anyhow::anyhow!("Decrypted config is not UTF-8: {}", e))?;

        Ok(content)
    }
}