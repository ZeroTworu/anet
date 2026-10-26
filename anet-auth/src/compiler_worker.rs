//! Фоновый воркер (Fetcher & Compiler) для периодического обновления внешних списков правил,
//! сохранения кэша правил в таблицу `rule_provider_items` и управления кэшем `.abc`.

use chrono::Utc;
use log::{debug, error, info, warn};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
    Set, TransactionTrait,
};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{OnceLock, RwLock};
use std::time::Duration;
use uuid::Uuid;

use crate::entities::{rule_provider_items, rule_providers};

/// Скомпилированный артефакт .abc в памяти сервера (ETag + бинарные байты)
#[derive(Clone, Debug)]
pub struct CachedAbcArtifact {
    pub etag: String,
    pub bytes: Vec<u8>,
}

static ABC_CACHE: OnceLock<RwLock<HashMap<Option<Uuid>, CachedAbcArtifact>>> = OnceLock::new();

fn abc_cache() -> &'static RwLock<HashMap<Option<Uuid>, CachedAbcArtifact>> {
    ABC_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Получает закэшированный артефакт .abc для заданного route_map_id (None = дефолтный)
pub fn get_cached_abc(route_map_id: Option<Uuid>) -> Option<CachedAbcArtifact> {
    abc_cache()
        .read()
        .ok()
        .and_then(|map| map.get(&route_map_id).cloned())
}

/// Сохраняет скомпилированный артефакт .abc в память
pub fn put_cached_abc(route_map_id: Option<Uuid>, artifact: CachedAbcArtifact) {
    if let Ok(mut map) = abc_cache().write() {
        map.insert(route_map_id, artifact);
    }
}

/// Сбрасывает кэш скомпилированных .abc при изменении провайдеров, правил или оверрайдов
pub fn invalidate_compiled_rules_cache() {
    if let Ok(mut map) = abc_cache().write() {
        map.clear();
    }
}

/// Директория для резервного хранения сырых текстовых кэшей провайдеров
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
            let db_items_count = rule_provider_items::Entity::find()
                .filter(rule_provider_items::Column::ProviderId.eq(provider.id))
                .count(&db)
                .await
                .unwrap_or(0);

            let should_fetch = match provider.last_fetched_at {
                None => true,
                Some(last) => {
                    let diff = now.signed_duration_since(last);
                    diff.num_hours() >= provider.update_interval_hours as i64
                        || (provider.item_count > 0 && db_items_count == 0)
                }
            };

            if should_fetch {
                if let Err(e) = fetch_and_cache_provider(&db, &provider, false).await {
                    warn!(
                        "[CompilerWorker] Failed to fetch provider '{}': {e}",
                        provider.name
                    );
                }
            }
        }
    }
}

/// Нормализует сырой текстовый список провайдера в вектор очищенных правил
pub fn parse_provider_lines(content: &str) -> Vec<String> {
    let mut items = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with(';')
            || trimmed.starts_with("//")
        {
            continue;
        }
        // Отсекаем inline-комментарии вида "example.com # comment"
        let clean = trimmed
            .split('#')
            .next()
            .unwrap_or(trimmed)
            .trim();
        if !clean.is_empty() {
            items.push(clean.to_string());
        }
    }
    items
}

/// Скачивает и обновляет один провайдер, сохраняя элементы в таблицу `rule_provider_items`.
/// Если `force == true` (вызов из WebUI), игнорирует `If-None-Match` или перезаполняет таблицу БД.
pub async fn fetch_and_cache_provider(
    db: &DatabaseConnection,
    provider: &rule_providers::Model,
    force: bool,
) -> anyhow::Result<usize> {
    info!(
        "[CompilerWorker] Fetching rule provider '{}' from {} (force={})",
        provider.name, provider.url, force
    );

    let db_items_count = rule_provider_items::Entity::find()
        .filter(rule_provider_items::Column::ProviderId.eq(provider.id))
        .count(db)
        .await
        .unwrap_or(0);

    let profile = anet_common::http_help::BrowserProfile::random();
    let client = profile
        .build_reqwest_builder(std::sync::Arc::new(reqwest::cookie::Jar::default()))?
        .timeout(Duration::from_secs(30))
        .build()?;

    let mut req = profile.apply_to_reqwest(client.get(&provider.url), None, None);
    if !force && db_items_count > 0 {
        if let Some(etag) = &provider.last_etag {
            req = req.header("If-None-Match", etag.as_str());
        }
    }

    let resp = req.send().await?;

    if resp.status() == reqwest::StatusCode::NOT_MODIFIED && db_items_count > 0 {
        debug!(
            "[CompilerWorker] Provider '{}' not modified (304)",
            provider.name
        );
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
    let parsed_items = parse_provider_lines(&content);
    let count = parsed_items.len();

    // Резервно сохраняем текстовый кэш на диск
    let cache_dir = get_provider_cache_dir();
    let cache_file = cache_dir.join(format!("{}.txt", provider.id));
    let _ = fs::write(&cache_file, &content);

    // Сохраняем все элементы в таблицу БД `rule_provider_items` внутри транзакции
    let txn = db.begin().await?;
    rule_provider_items::Entity::delete_many()
        .filter(rule_provider_items::Column::ProviderId.eq(provider.id))
        .exec(&txn)
        .await?;

    for chunk in parsed_items.chunks(1000) {
        let models: Vec<rule_provider_items::ActiveModel> = chunk
            .iter()
            .map(|val| rule_provider_items::ActiveModel {
                provider_id: Set(provider.id),
                rule_value: Set(val.clone()),
                ..Default::default()
            })
            .collect();
        rule_provider_items::Entity::insert_many(models)
            .exec(&txn)
            .await?;
    }

    // Обновляем запись провайдера в БД
    let mut active: rule_providers::ActiveModel = provider.clone().into();
    active.last_fetched_at = Set(Some(Utc::now().naive_utc()));
    active.last_etag = Set(new_etag);
    active.item_count = Set(count as i64);
    active.updated_at = Set(Utc::now().naive_utc());
    active.update(&txn).await?;

    txn.commit().await?;

    // Сбрасываем кэш скомпилированных .abc
    invalidate_compiled_rules_cache();

    info!(
        "[CompilerWorker] Provider '{}' updated: {} items stored in DB",
        provider.name, count
    );
    Ok(count)
}
