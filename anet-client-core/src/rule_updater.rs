//! Менеджер загрузки и Zero-Copy отображения правил маршрутизации `rules.abc`.

use anet_filter_core::{CompiledRoutingCache, RuleAction};
use arc_swap::ArcSwap;
use log::{debug, error, info, warn};
use memmap2::Mmap;
use std::fs::{self, File};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

/// Менеджер бинарного кэша правил
#[derive(Clone)]
pub struct RuleCacheManager {
    cache_path: PathBuf,
    current_mmap: Arc<ArcSwap<Option<Arc<Mmap>>>>,
}

impl RuleCacheManager {
    /// Создает новый менеджер кэша для указанного пути к файлу rules.abc
    pub fn new(cache_path: PathBuf) -> Self {
        let manager = Self {
            cache_path,
            current_mmap: Arc::new(ArcSwap::new(Arc::new(None))),
        };
        // Пробуем загрузить локальный кэш с диска при старте
        manager.load_from_disk();
        manager
    }

    /// Загружает локальный файл rules.abc через mmap
    pub fn load_from_disk(&self) -> bool {
        if !self.cache_path.exists() {
            debug!("[RuleCache] Local cache file does not exist: {:?}", self.cache_path);
            return false;
        }

        match File::open(&self.cache_path) {
            Ok(file) => match unsafe { Mmap::map(&file) } {
                Ok(mmap) => {
                    // Валидация Zero-Copy корня
                    if let Err(e) = CompiledRoutingCache::from_bytes(&mmap) {
                        warn!("[RuleCache] Corrupted .abc file on disk: {e}");
                        return false;
                    }
                    info!("[RuleCache] Successfully mapped rules.abc ({} bytes)", mmap.len());
                    self.current_mmap.store(Arc::new(Some(Arc::new(mmap))));
                    true
                }
                Err(e) => {
                    error!("[RuleCache] Failed to mmap {:?}: {e}", self.cache_path);
                    false
                }
            },
            Err(e) => {
                error!("[RuleCache] Failed to open {:?}: {e}", self.cache_path);
                false
            }
        }
    }

    /// Выполняет фоновое обновление правил по HTTP с проверкой ETag
    pub async fn update_from_server(&self, server_url: &str) -> anyhow::Result<()> {
        let endpoint = format!("{}/api/v1/routing/compiled-rules", server_url.trim_end_matches('/'));
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()?;

        let mut req = client.get(&endpoint);

        // Читаем локальный ETag из файла .etag если есть
        let etag_file = self.cache_path.with_extension("etag");
        if let Ok(etag) = fs::read_to_string(&etag_file) {
            let clean_etag = etag.trim();
            if !clean_etag.is_empty() {
                req = req.header("If-None-Match", clean_etag);
            }
        }

        let resp = req.send().await?;

        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            debug!("[RuleCache] Rules are up to date (304 Not Modified)");
            return Ok(());
        }

        if !resp.status().is_success() {
            anyhow::bail!("Server returned error status: {}", resp.status());
        }

        let new_etag = resp
            .headers()
            .get("ETag")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        let bytes = resp.bytes().await?;

        // Проверяем валидность полученного бинарника
        CompiledRoutingCache::from_bytes(&bytes)?;

        // Записываем во временный файл и атомарно переименовываем
        if let Some(parent) = self.cache_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp_path = self.cache_path.with_extension("tmp");
        fs::write(&tmp_path, &bytes)?;
        fs::rename(&tmp_path, &self.cache_path)?;

        if let Some(etag) = new_etag {
            let _ = fs::write(&etag_file, etag);
        }

        info!("[RuleCache] Downloaded and applied new rules.abc ({} bytes)", bytes.len());
        self.load_from_disk();
        Ok(())
    }

    /// Быстрый Zero-Copy поиск по домену
    pub fn lookup_domain(&self, domain: &str) -> Option<RuleAction> {
        let guard = self.current_mmap.load();
        if let Some(mmap) = guard.as_ref() {
            if let Ok(archived) = CompiledRoutingCache::from_bytes(mmap) {
                return archived.domain_trie.lookup(domain);
            }
        }
        None
    }

    /// Быстрый Zero-Copy поиск по IP
    pub fn lookup_ip(&self, ip: IpAddr) -> Option<RuleAction> {
        let guard = self.current_mmap.load();
        if let Some(mmap) = guard.as_ref() {
            if let Ok(archived) = CompiledRoutingCache::from_bytes(mmap) {
                return archived.ip_table.lookup(ip);
            }
        }
        None
    }
}
