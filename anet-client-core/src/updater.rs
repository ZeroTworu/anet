use std::env;
use std::fs;
use std::process::Command;
use reqwest::Client;
use log::{info, warn};
use std::path::{Path, PathBuf};
use crate::events::update_progress;
use crate::events::{emit, AnetEvent};
use std::io::{Cursor, copy, Read};
use serde::Deserialize;
use zip::ZipArchive;


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

impl Updater {

    pub async fn check_latest(url: &str, current_version: &str) -> anyhow::Result<Option<GithubRelease>> {
        info!("[UPDATER] Checking for updates...");

        let client = Client::builder()
            .user_agent("ANet-Client-GUI")
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build HTTP client: {}", e))?; // Тут будет подробная ошибка

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
                // ИГНОРИРУЕМ ВСЁ ОСТАЛЬНОЕ (включая wintun.dll)
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
        // Теперь мы просто копируем из Read в File
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
}