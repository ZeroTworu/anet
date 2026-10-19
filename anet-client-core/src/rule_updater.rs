//! Менеджер загрузки и Zero-Copy отображения правил маршрутизации `rules.abc`.

use anet_filter_core::{CompiledRoutingCache, RuleAction};
use arc_swap::ArcSwap;
use log::{error, info, warn};
use memmap2::Mmap;
use std::fs::{self, File};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

fn is_dir_writable(dir: &std::path::Path) -> bool {
    if fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(".anet_write_probe");
    if fs::write(&probe, b"ok").is_ok() {
        let _ = fs::remove_file(&probe);
        true
    } else {
        false
    }
}

/// Возвращает стандартный путь к локальному кэшу `rules.abc`.
/// Единая логика для Linux, Windows, macOS, Android и будущей iOS:
/// 1. Переменная окружения `ANET_RULES_CACHE_PATH` (если задана).
/// 2. Директория рядом с клиентским бинарником (Desktop / CLI / портативный режим).
/// 3. Текущая рабочая директория (если бинарник установлен в системный `/usr/local/bin`).
/// 4. Пользовательский кэш `$HOME/.cache/anet/rules.abc` или `%USERPROFILE%\.cache\anet\rules.abc` (Linux / macOS / Windows / iOS Sandbox).
/// 5. Приватный кэш песочницы Android (`/data/data/<package>/cache/anet/rules.abc`).
/// 6. Системная временная директория `temp_dir()/anet/rules.abc`.
pub fn default_rules_cache_path() -> PathBuf {
    if let Ok(custom) = std::env::var("ANET_RULES_CACHE_PATH") {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let candidate = exe_dir.join("rules.abc");
            if candidate.exists() || is_dir_writable(exe_dir) {
                return candidate;
            }
        }
    }

    if let Ok(cwd) = std::env::current_dir() {
        let candidate = cwd.join("rules.abc");
        if candidate.exists() || is_dir_writable(&cwd) {
            return candidate;
        }
    }

    if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        let trimmed = home.trim();
        if !trimmed.is_empty() && trimmed != "/" {
            let dir = PathBuf::from(trimmed).join(".cache").join("anet");
            if is_dir_writable(&dir) {
                return dir.join("rules.abc");
            }
        }
    }

    // Определение приватного каталога приложения на Android через /proc/self/cmdline
    if let Ok(cmdline) = fs::read_to_string("/proc/self/cmdline") {
        let pkg = cmdline.split('\0').next().unwrap_or("").trim();
        if pkg.contains('.') && !pkg.starts_with('/') {
            for base in ["/data/user/0", "/data/data"] {
                let dir = PathBuf::from(base).join(pkg).join("cache").join("anet");
                if is_dir_writable(&dir) {
                    return dir.join("rules.abc");
                }
            }
        }
    }

    let dir = std::env::temp_dir().join("anet");
    let _ = fs::create_dir_all(&dir);
    dir.join("rules.abc")
}

/// Менеджер бинарного кэша правил
#[derive(Clone)]
pub struct RuleCacheManager {
    cache_path: PathBuf,
    current_mmap: Arc<ArcSwap<Option<Arc<Mmap>>>>,
    update_lock: Arc<tokio::sync::Mutex<()>>,
}

impl RuleCacheManager {
    /// Создает новый менеджер кэша для указанного пути к файлу rules.abc
    pub fn new(cache_path: PathBuf) -> Self {
        let manager = Self {
            cache_path,
            current_mmap: Arc::new(ArcSwap::new(Arc::new(None))),
            update_lock: Arc::new(tokio::sync::Mutex::new(())),
        };
        // Пробуем загрузить локальный кэш с диска при старте (Zero Cold Start)
        manager.load_from_disk();
        manager
    }

    /// Возвращает true, если кэш правил уже отображен в память
    pub fn is_loaded(&self) -> bool {
        self.current_mmap.load().is_some()
    }

    /// Возвращает путь к файлу rules.abc
    pub fn cache_path(&self) -> &std::path::Path {
        &self.cache_path
    }

    /// Загружает локальный файл rules.abc через mmap
    pub fn load_from_disk(&self) -> bool {
        if !self.cache_path.exists() {
            info!(
                "[RuleCache] Local cache file not found at {} (will download from server if rules_url is configured)",
                self.cache_path.display()
            );
            return false;
        }

        match File::open(&self.cache_path) {
            Ok(file) => match unsafe { Mmap::map(&file) } {
                Ok(mmap) => {
                    // Валидация Zero-Copy корня
                    let (domains_cnt, ips_cnt) = match CompiledRoutingCache::from_bytes(&mmap) {
                        Ok(archived) => (
                            archived.domain_trie.nodes.len(),
                            archived.ip_table.ipv4_nodes.len() + archived.ip_table.ipv6_nodes.len(),
                        ),
                        Err(e) => {
                            warn!("[RuleCache] Corrupted .abc file on disk: {e}");
                            crate::events::status(&format!(
                                "[RuleCache] Corrupted rules.abc on disk: {e}"
                            ));
                            return false;
                        }
                    };
                    let msg = format!(
                        "[RuleCache] Loaded rules.abc ({} bytes, {} domain nodes, {} IP nodes) from {}",
                        mmap.len(),
                        domains_cnt,
                        ips_cnt,
                        self.cache_path.display()
                    );
                    info!("{msg}");
                    crate::events::status(&msg);
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

    /// Выполняет обновление правил по HTTP с проверкой ETag
    pub async fn update_from_server(&self, server_url: &str) -> anyhow::Result<()> {
        let _guard = self.update_lock.lock().await;
        let clean = server_url.trim().trim_end_matches('/');
        let endpoint = if clean.contains("/routing/compiled") {
            clean.to_string()
        } else {
            format!("{}/api/v1/routing/compiled-rules", clean)
        };

        let msg = format!("[RuleCache] Checking routing rules at {endpoint} ...");
        info!("{msg}");
        crate::events::status(&msg);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let mut req = client.get(&endpoint);

        // Читаем локальный ETag из файла .etag если есть
        let etag_file = self.cache_path.with_extension("etag");
        if let Ok(etag) = fs::read_to_string(&etag_file) {
            let clean_etag = etag.trim();
            if !clean_etag.is_empty() && self.cache_path.exists() {
                req = req.header("If-None-Match", clean_etag);
            }
        }

        let resp = req.send().await?;

        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            let msg = format!(
                "[RuleCache] rules.abc is up to date (304 Not Modified, {})",
                self.cache_path.display()
            );
            info!("{msg}");
            crate::events::status(&msg);
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

        // Записываем во временный файл, валидируем через выровненный по странице Mmap и атомарно переименовываем
        if let Some(parent) = self.cache_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp_path = self.cache_path.with_extension("tmp");
        fs::write(&tmp_path, &bytes)?;

        {
            let tmp_file = File::open(&tmp_path)?;
            let tmp_mmap = unsafe { Mmap::map(&tmp_file)? };
            if let Err(e) = CompiledRoutingCache::from_bytes(&tmp_mmap) {
                let _ = fs::remove_file(&tmp_path);
                return Err(e);
            }
        }

        fs::rename(&tmp_path, &self.cache_path)?;

        if let Some(etag) = new_etag {
            let _ = fs::write(&etag_file, etag);
        }

        let msg = format!(
            "[RuleCache] Downloaded rules.abc ({} bytes) -> {}",
            bytes.len(),
            self.cache_path.display()
        );
        info!("{msg}");
        crate::events::status(&msg);
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

    /// Возвращает все статические подсети (IP, prefix_len) с действием `Direct` из `rules.abc`
    pub fn collect_direct_routes(&self) -> Vec<(IpAddr, u8)> {
        let guard = self.current_mmap.load();
        if let Some(mmap) = guard.as_ref() {
            if let Ok(archived) = CompiledRoutingCache::from_bytes(mmap) {
                return archived.ip_table.collect_direct_routes();
            }
        }
        Vec::new()
    }
}
