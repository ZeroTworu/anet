//! Фоновый воркер (Fetcher & Compiler) для периодического обновления внешних списков правил
//! и компиляции бинарных кэшей .abc.

use chrono::Utc;
use log::{debug, error, info, warn};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

use crate::entities::rule_providers::{self, ProviderFormat, ProviderType};

/// Директория для хранения сырых текстовых кэшей провайдеров
pub fn get_provider_cache_dir() -> PathBuf {
    let dir = std::env::var("PROVIDER_CACHE_DIR")
        .unwrap_or_else(|_| "/tmp/anet_providers".to_string());
    let path = PathBuf::from(dir);
    let _ = fs::create_dir_all(&path);
    path
}

/// Запуск фонового планировщика обновления списков
pub async fn run_worker(db: DatabaseConnection) {
    info!("[CompilerWorker] Background rule fetcher & compiler started");
    let mut interval = tokio::time::interval(Duration::from_secs(60));

    loop {
        interval.tick().await;

        let providers = match rule_providers::Entity::find()
            .filter(rule_providers::Column::IsActive.eq(true))
            .all(&db)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                error!("[CompilerWorker] Failed to query rule_providers: {e}");
                continue;
            }
        };

        let now = Utc::now().naive_utc();
        for provider in providers {
            let should_fetch = match provider.last_fetched_at {
                None => true,
                Some(last) => {
                    let diff = now.signed_duration_since(last);
                    diff.num_hours() >= provider.update_interval_hours as i64
                }
            };

            if should_fetch {
                if let Err(e) = fetch_and_cache_provider(&db, &provider).await {
                    warn!("[CompilerWorker] Failed to fetch provider '{}': {e}", provider.name);
                }
            }
        }
    }
}

/// Скачивает и обновляет один провайдер (вызывается фоновым таском или вручную через WebUI)
pub async fn fetch_and_cache_provider(
    db: &DatabaseConnection,
    provider: &rule_providers::Model,
) -> anyhow::Result<usize> {
    info!("[CompilerWorker] Fetching rule provider '{}' from {}", provider.name, provider.url);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let mut req = client.get(&provider.url);
    if let Some(etag) = &provider.last_etag {
        req = req.header("If-None-Match", etag.as_str());
    }

    let resp = req.send().await?;

    if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
        debug!("[CompilerWorker] Provider '{}' not modified (304)", provider.name);
        let mut active: rule_providers::ActiveModel = provider.clone().into();
        active.last_fetched_at = Set(Some(Utc::now().naive_utc()));
        active.updated_at = Set(Utc::now().naive_utc());
        active.update(db).await?;
        return Ok(provider.item_count as usize);
    }

    if !resp.status().is_success() {
        anyhow::bail!("Server returned HTTP {}", resp.status());
    }

    let new_etag = resp
        .headers()
        .get("ETag")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let content = resp.text().await?;

    // Подсчитываем валидные строки
    let count = content
        .lines()
        .filter(|line| {
            let t = line.trim();
            !t.is_empty() && !t.starts_with('#') && !t.starts_with(';')
        })
        .count();

    // Сохраняем текстовый кэш на диск
    let cache_dir = get_provider_cache_dir();
    let cache_file = cache_dir.join(format!("{}.txt", provider.id));
    fs::write(&cache_file, content)?;

    // Обновляем запись в БД
    let mut active: rule_providers::ActiveModel = provider.clone().into();
    active.last_fetched_at = Set(Some(Utc::now().naive_utc()));
    active.last_etag = Set(new_etag);
    active.item_count = Set(count as i64);
    active.updated_at = Set(Utc::now().naive_utc());
    active.update(db).await?;

    info!("[CompilerWorker] Provider '{}' updated: {} items cached", provider.name, count);
    Ok(count)
}
