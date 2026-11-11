// anet-server/src/servers/imap.rs
//! Транспорт IMAP на стороне сервера (ASTP over IMAPS:993).
//!
//! Реализует разделы 3, 4, 5, 7.3, 8 и 9 документа `contrib/docs/imap.ru.md`:
//! - Супервизор пула почтовых ящиков из `imap_dsn`;
//! - Архитектура «Cross-Selected Writer» на стороне сервера:
//!   - `SRV_READER[i]` делает `SELECT "Drafts"`, читает Uplink-сообщения клиентов через `wait_idle_or_wake()`
//!     и передает прочитанные UIDs в локальный список очистки ящика `i`;
//!   - `SRV_WRITER[i]` делает `SELECT "Drafts"` один раз при старте, отправляет Downlink-сообщения
//!     через `APPEND "Notes" (\Seen \Draft)`, а в паузах удаляет прочитанные письма в `"Drafts"`
//!     через `UID STORE` + `UID EXPUNGE` без переключения папок;
//! - Динамический пул ящиков клиентской сессии (`SessionMailboxPool`, раздел 9.5):
//!   - При завершении ASTP Handshake первичный ящик `M_primary` автоматически регистрируется в `SessionMailboxPool`;
//!   - При приходе `Mailbox Binding Frame` (пустого зашифрованного батча `wrap_packet_slice(..., &[], 0)`)
//!     или любого валидного Uplink-батча на вторичный ящик `M_i`, сервер мгновенно привязывает `M_i` к `SessionMailboxPool`;
//!   - `run_client_downlink_batcher` распределяет Downlink-батчи по всем активным здоровым ящикам сессии
//!     по алгоритму **Self-Clocking Round-Robin** с автоматическим обходом занятых воркеров и Zero-Loss Retry.

use crate::auth_handler::ServerAuthHandler;
use crate::client_registry::{ClientRegistry, ClientTransportInfo};
use crate::config::Config;
use anet_common::batcher::{unpack_batch, PacketBatcher};
use anet_common::imap_conn::ImapConn;
use anet_common::transport::{unwrap_packet, wrap_packet_slice};
use anyhow::{anyhow, Context, Result};
use base64::prelude::*;
use bytes::Bytes;
use dashmap::DashMap;
use futures::future::BoxFuture;
use log::{debug, info, warn};
use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Mutex, Notify, OwnedSemaphorePermit, RwLock, Semaphore};

const DEFAULT_IMAP_PORT: u16 = 993;

#[inline]
fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Debug, Clone)]
pub struct ImapAccount {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct DownlinkMessage {
    pub subject: String,
    pub payload: Bytes,
}

/// Дескриптор серверного воркера конкретного почтового ящика `mailbox_idx` (раздел 9.5.2 спецификации)
#[derive(Clone)]
pub struct ServerMailboxHandle {
    pub mailbox_idx: usize,
    pub email: String,
    pub notes_data_tx: mpsc::Sender<(DownlinkMessage, OwnedSemaphorePermit)>,
    pub writer_sem: Arc<Semaphore>,
    pub healthy: Arc<AtomicBool>,
    pub inflight: Arc<AtomicUsize>,
}

impl ServerMailboxHandle {
    pub fn new(
        mailbox_idx: usize,
        email: String,
        healthy: bool,
    ) -> (
        Self,
        mpsc::Receiver<(DownlinkMessage, OwnedSemaphorePermit)>,
    ) {
        let (notes_data_tx, notes_data_rx) = mpsc::channel(1);
        let handle = Self {
            mailbox_idx,
            email,
            notes_data_tx,
            writer_sem: Arc::new(Semaphore::new(1)),
            healthy: Arc::new(AtomicBool::new(healthy)),
            inflight: Arc::new(AtomicUsize::new(0)),
        };
        (handle, notes_data_rx)
    }
}

/// Динамический пул подтверждённых ящиков конкретной клиентской сессии `session_id` (раздел 9.5.2)
pub struct SessionMailboxPool {
    /// Список ящиков, с которых данный `session_id` прислал криптографически валидные пакеты или `Mailbox Binding Frame`
    pub active_mailboxes: RwLock<Vec<ServerMailboxHandle>>,
    /// Курсор Round-Robin для балансировки Downlink-батчей этой сессии
    pub rr_cursor: AtomicUsize,
    /// Сигнал о добавлении нового ящика или освобождении слота в пуле сессии
    pub pool_updated: Notify,
}

impl Default for SessionMailboxPool {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionMailboxPool {
    pub fn new() -> Self {
        Self {
            active_mailboxes: RwLock::new(Vec::new()),
            rr_cursor: AtomicUsize::new(0),
            pool_updated: Notify::new(),
        }
    }

    /// Регистрирует почтовый ящик `handle` в активном пуле сессии, если он ещё не был привязан.
    /// Возвращает `true`, если ящик был добавлен впервые.
    pub async fn register_mailbox(&self, handle: ServerMailboxHandle) -> bool {
        {
            let read_guard = self.active_mailboxes.read().await;
            if read_guard
                .iter()
                .any(|h| h.mailbox_idx == handle.mailbox_idx)
            {
                return false;
            }
        }
        let mut write_guard = self.active_mailboxes.write().await;
        if write_guard
            .iter()
            .any(|h| h.mailbox_idx == handle.mailbox_idx)
        {
            return false;
        }
        write_guard.push(handle);
        drop(write_guard);
        self.pool_updated.notify_waiters();
        true
    }

    pub async fn active_count(&self) -> usize {
        self.active_mailboxes.read().await.len()
    }
}

/// Выбирает первый свободный здоровый ящик из `SessionMailboxPool` по алгоритму Self-Clocking Round-Robin (раздел 9.5.3):
/// 1. Fast Path: неблокирующий обход от `rr_cursor` (`try_acquire_owned()`).
/// 2. All-Busy Path: если все активные здоровые ящики сессии заняты выполнением `APPEND "Notes"`,
///    ожидает первого освободившегося через `futures::future::select_all` (параллельно слушая `pool_updated`
///    для мгновенного подхвата только что привязавшегося нового ящика!).
pub async fn acquire_server_slot_self_clocking(
    session_pool: &SessionMailboxPool,
    max_inflight_batches: usize,
) -> Option<(ServerMailboxHandle, OwnedSemaphorePermit)> {
    loop {
        let handles = session_pool.active_mailboxes.read().await.clone();
        if handles.is_empty() {
            tokio::select! {
                _ = session_pool.pool_updated.notified() => {}
                _ = tokio::time::sleep(Duration::from_millis(25)) => {}
            }
            continue;
        }

        if handles.iter().all(|h| h.notes_data_tx.is_closed()) {
            return None;
        }

        let n = handles.len();
        let start_cursor = session_pool.rr_cursor.load(Ordering::Relaxed);

        // Фаза 1: Мгновенный неблокирующий Round-Robin (Fast Path)
        for offset in 0..n {
            let idx = (start_cursor + offset) % n;
            let h = &handles[idx];
            if !h.healthy.load(Ordering::Acquire) || h.notes_data_tx.is_closed() {
                continue;
            }
            if h.inflight.load(Ordering::Relaxed) >= max_inflight_batches {
                continue;
            }
            if let Ok(permit) = h.writer_sem.clone().try_acquire_owned() {
                session_pool
                    .rr_cursor
                    .store((idx + 1) % n, Ordering::Relaxed);
                return Some((h.clone(), permit));
            }
        }

        // Фаза 2: Все здоровые ящики заняты APPEND — ждём первого освободившегося (All-Busy Self-Clocking Path)
        let mut wait_futs: Vec<
            BoxFuture<
                'static,
                (
                    usize,
                    std::result::Result<OwnedSemaphorePermit, tokio::sync::AcquireError>,
                ),
            >,
        > = Vec::new();

        for offset in 0..n {
            let idx = (start_cursor + offset) % n;
            let h = &handles[idx];
            if !h.healthy.load(Ordering::Acquire) || h.notes_data_tx.is_closed() {
                continue;
            }
            if h.inflight.load(Ordering::Relaxed) >= max_inflight_batches {
                continue;
            }
            let sem = h.writer_sem.clone();
            wait_futs.push(Box::pin(async move { (idx, sem.acquire_owned().await) }));
        }

        if wait_futs.is_empty() {
            tokio::select! {
                _ = session_pool.pool_updated.notified() => {}
                _ = tokio::time::sleep(Duration::from_millis(25)) => {
                    for h in &handles {
                        let cur = h.inflight.load(Ordering::Relaxed);
                        if cur >= max_inflight_batches && cur > 0 {
                            h.inflight.fetch_sub(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            continue;
        }

        tokio::select! {
            biased;
            ((idx, Ok(permit)), _, _) = futures::future::select_all(wait_futs) => {
                if handles[idx].healthy.load(Ordering::Acquire) && !handles[idx].notes_data_tx.is_closed() {
                    session_pool.rr_cursor.store((idx + 1) % n, Ordering::Relaxed);
                    return Some((handles[idx].clone(), permit));
                }
                drop(permit);
            }
            _ = session_pool.pool_updated.notified() => {}
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
}

/// Определяет безопасный базовый IP-адрес для виртуальных сокетов,
/// гарантируя отсутствие коллизий с маршрутами внутри VPN-туннеля (раздел 4.1 спецификации).
pub fn get_safe_fake_base(vpn_net_str: &str) -> Ipv4Addr {
    let vpn_ip = Ipv4Addr::from_str(vpn_net_str).unwrap_or(Ipv4Addr::new(10, 0, 0, 0));
    if vpn_ip.octets()[0] == 127 {
        Ipv4Addr::new(198, 18, 0, 0)
    } else {
        Ipv4Addr::new(127, 127, 0, 0)
    }
}

/// Превращает строковый TempID клиента из темы письма в детерминированный виртуальный SocketAddr
/// для использования в качестве ключа во внутреннем temp_dh_map (ServerAuthHandler).
pub fn fake_addr_from_cli_id(cli_id: &str, safe_base: Ipv4Addr) -> SocketAddr {
    let hash = Sha256::digest(cli_id.as_bytes());
    let base = safe_base.octets();
    let ip = Ipv4Addr::new(base[0], base[1], hash[2], hash[3]);
    let port = (u16::from_be_bytes([hash[4], hash[5]]) | 0x8000).max(1024);
    SocketAddr::new(std::net::IpAddr::V4(ip), port)
}

/// Вычисляет 8-символьный hex-идентификатор сервера (первые 4 байта SHA-256 публичного ключа Ed25519)
pub fn compute_hex_id(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        hash[0], hash[1], hash[2], hash[3]
    )
}

/// Извлекает srv_id и cli_token из темы письма формата:
/// `Subject: {Prefix} [ID: <srv_id>:<cli_token>]`
pub fn extract_srv_and_cli_token(subject: &str) -> Option<(&str, &str)> {
    let start_idx = subject.find("[ID:")?;
    let rest = &subject[start_idx + 4..];
    let end_idx = rest.find(']')?;
    let id_content = rest[..end_idx].trim();
    let (srv_id, cli_token) = id_content.split_once(':')?;
    Some((srv_id.trim(), cli_token.trim()))
}

/// Парсит строку DSN и возвращает хост, порт и список аккаунтов
pub fn parse_imap_server_dsn(dsn: &str) -> Result<(String, u16, Vec<ImapAccount>)> {
    let uri: http::Uri = dsn
        .parse()
        .with_context(|| format!("Invalid IMAP DSN: {}", dsn))?;
    let host = uri
        .host()
        .ok_or_else(|| anyhow!("IMAP DSN has no host: {}", dsn))?
        .to_string();

    let scheme = uri.scheme_str().unwrap_or("imap").to_lowercase();
    let port = uri.port_u16().unwrap_or(match scheme.as_str() {
        "imaps" | "imap" => DEFAULT_IMAP_PORT,
        _ => DEFAULT_IMAP_PORT,
    });

    let mut accounts = Vec::new();

    if let Some(query) = uri.query() {
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k.eq_ignore_ascii_case("acc") {
                    let decoded = urlencoding::decode(v).unwrap_or_else(|_| v.into());
                    if let Some((email, pass)) = decoded.split_once(':') {
                        if !email.trim().is_empty() && !pass.trim().is_empty() {
                            accounts.push(ImapAccount {
                                email: email.trim().to_string(),
                                password: pass.trim().to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    if accounts.is_empty() {
        if let Some(authority) = uri.authority() {
            let auth_str = authority.as_str();
            if let Some((user_info, _)) = auth_str.split_once('@') {
                if let Some((user, pass)) = user_info.split_once(':') {
                    let email = urlencoding::decode(user).unwrap_or_else(|_| user.into());
                    let password = urlencoding::decode(pass).unwrap_or_else(|_| pass.into());
                    if !email.trim().is_empty() && !password.trim().is_empty() {
                        accounts.push(ImapAccount {
                            email: email.trim().to_string(),
                            password: password.trim().to_string(),
                        });
                    }
                }
            }
        }
    }

    if accounts.is_empty() {
        return Err(anyhow!(
            "No IMAP credentials found in server DSN '{}'. Expected ?acc=user%40mail.ru:pass",
            dsn
        ));
    }

    Ok((host, port, accounts))
}

/// Главная точка входа супервизора IMAP-сервера
pub async fn run_imap_server(
    config: Arc<Config>,
    registry: Arc<ClientRegistry>,
    tun_tx: mpsc::Sender<Bytes>,
    auth_handler: ServerAuthHandler,
) -> Result<()> {
    let imap_dsn = config
        .server
        .imap_dsn
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            config
                .imap
                .imap_dsn
                .as_deref()
                .filter(|s| !s.trim().is_empty())
        })
        .context("IMAP server DSN is not configured")?;

    let (host, port, accounts) = parse_imap_server_dsn(imap_dsn)?;
    info!(
        "[IMAP Server] Initializing Active-Active IMAP Transport on {}:{} with {} mailbox(es) (Batch: {} KB, ActiveIDLE: {} ms, ExpungeBatch: {})...",
        host,
        port,
        accounts.len(),
        config.imap.max_batch_kb.clamp(8, 512),
        config.imap.idle_active_poll_ms.clamp(150, 5000),
        config.imap.expunge_batch_size.clamp(5, 200)
    );

    let sk_bytes = BASE64_STANDARD.decode(&config.crypto.server_signing_key)?;
    let sign_key = ed25519_dalek::SigningKey::from_bytes(&sk_bytes.try_into().unwrap());
    let srv_id = compute_hex_id(&sign_key.verifying_key().to_bytes());
    let safe_base_ip = get_safe_fake_base(&config.network.net);

    info!(
        "[IMAP Server] Server ID: {} | Virtual socket base: {}",
        srv_id, safe_base_ip
    );

    // Локальная карта активных сессий (session_id -> (ClientTransportInfo, Instant последней активности))
    let local_sessions: Arc<DashMap<String, (Arc<ClientTransportInfo>, Instant)>> =
        Arc::new(DashMap::new());
    // Глобальная карта динамических пулов ящиков для каждой клиентской сессии (session_id -> Arc<SessionMailboxPool>)
    let session_pools: Arc<DashMap<String, Arc<SessionMailboxPool>>> = Arc::new(DashMap::new());

    // Фоновая задача периодической очистки неактивных сессий (cleanup_interval_ms и session_ttl_ms из раздела 7.4)
    let cleanup_interval = Duration::from_millis(config.imap.cleanup_interval_ms.max(5000));
    let session_ttl = Duration::from_millis(config.imap.session_ttl_ms.max(30000));
    let sessions_for_gc = local_sessions.clone();
    let pools_for_gc = session_pools.clone();
    let registry_for_gc = registry.clone();

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(cleanup_interval);
        loop {
            ticker.tick().await;
            let now = Instant::now();
            sessions_for_gc.retain(|sid, (_, last_active)| {
                let alive_in_reg = registry_for_gc.get_by_session(sid).is_some();
                let not_expired = now.saturating_duration_since(*last_active) <= session_ttl;
                let keep = alive_in_reg && not_expired;
                if !keep {
                    pools_for_gc.remove(sid);
                }
                keep
            });
        }
    });

    // Общие для всех N серверных воркеров индикаторы активности и раннего пробуждения SRV_READER[0..N]:
    // когда трафик идёт через ящик #0, следующий батч клиента по Round-Robin придёт на ящик #1,
    // поэтому все SRV_READER должны синхронно переходить в короткий адаптивный опрос (400 мс)!
    let server_last_activity_ms = Arc::new(AtomicU64::new(now_epoch_ms()));
    let server_reader_wake_notify = Arc::new(Notify::new());

    // Запускаем независимую пару воркеров (SRV_READER[i] + SRV_WRITER[i]) для каждого почтового ящика параллельно
    let mut worker_handles = Vec::new();

    for (mailbox_idx, account) in accounts.into_iter().enumerate() {
        let host_c = host.clone();
        let config_c = config.clone();
        let registry_c = registry.clone();
        let tun_tx_c = tun_tx.clone();
        let auth_c = auth_handler.clone();
        let local_sessions_c = local_sessions.clone();
        let session_pools_c = session_pools.clone();
        let srv_id_c = srv_id.clone();
        let srv_act_c = server_last_activity_ms.clone();
        let srv_wake_c = server_reader_wake_notify.clone();

        let handle = tokio::spawn(async move {
            run_mailbox_worker_pair(
                mailbox_idx,
                host_c,
                port,
                account,
                srv_id_c,
                safe_base_ip,
                config_c,
                registry_c,
                tun_tx_c,
                auth_c,
                local_sessions_c,
                session_pools_c,
                srv_act_c,
                srv_wake_c,
            )
            .await;
        });

        worker_handles.push(handle);
    }

    futures::future::join_all(worker_handles).await;
    Ok(())
}

/// Обслуживает один почтовый ящик `mailbox_idx` парой воркеров (`SRV_READER[i]` и `SRV_WRITER[i]`)
#[allow(clippy::too_many_arguments)]
async fn run_mailbox_worker_pair(
    mailbox_idx: usize,
    host: String,
    port: u16,
    account: ImapAccount,
    srv_id: String,
    safe_base_ip: Ipv4Addr,
    config: Arc<Config>,
    registry: Arc<ClientRegistry>,
    tun_tx: mpsc::Sender<Bytes>,
    auth_handler: ServerAuthHandler,
    local_sessions: Arc<DashMap<String, (Arc<ClientTransportInfo>, Instant)>>,
    session_pools: Arc<DashMap<String, Arc<SessionMailboxPool>>>,
    server_last_activity_ms: Arc<AtomicU64>,
    server_reader_wake_notify: Arc<Notify>,
) {
    let email = account.email.clone();
    let command_timeout = Duration::from_millis(config.imap.command_timeout_ms.max(5000));
    let idle_quiet_timeout = Duration::from_millis(config.imap.idle_refresh_interval_ms.max(2000));
    let idle_active_timeout =
        Duration::from_millis(config.imap.idle_active_poll_ms.clamp(150, 5000));
    let idle_active_window_ms = config.imap.idle_active_window_ms.clamp(1000, 60_000);
    let fetch_max_messages = config.imap.fetch_max_messages.min(100);
    let expunge_batch_size = config.imap.expunge_batch_size.clamp(5, 200);
    let expunge_idle_delay =
        Duration::from_millis(config.imap.expunge_idle_delay_ms.clamp(250, 30_000));
    let expunge_idle_delay_ms = expunge_idle_delay.as_millis() as u64;
    let max_inflight_batches = config.imap.max_inflight_batches.clamp(5, 250);
    let tx_queue_capacity = config.imap.tx_queue_capacity.clamp(32, 2048);
    let literal_plus_auto = config.imap.literal_plus_auto;
    let throttle_backoff = Duration::from_millis(config.imap.throttle_backoff_ms.max(5000));
    let tls_cfg = config.stealth.to_tls_client_config();

    info!(
        "[IMAP Mailbox #{}] Starting worker pair for account {}",
        mailbox_idx, email
    );

    // Долговечные каналы и дескриптор ящика создаются ОДИН РАЗ вне цикла реконнекта (разделы 8 п. 11 и 9.5.2),
    // чтобы при переподключении SRV_READER/SRV_WRITER активные клиентские батчеры не теряли маршрутизацию.
    let (notes_auth_tx, notes_auth_rx) = mpsc::channel::<DownlinkMessage>(64);
    let (mailbox_handle, notes_data_rx) =
        ServerMailboxHandle::new(mailbox_idx, email.clone(), false);
    let notes_auth_rx = Arc::new(Mutex::new(notes_auth_rx));
    let notes_data_rx = Arc::new(Mutex::new(notes_data_rx));
    let pending_retry_msg: Arc<Mutex<Option<DownlinkMessage>>> = Arc::new(Mutex::new(None));

    loop {
        // Список UIDs сообщений в папке "Drafts" именно этого ящика, прочитанных SRV_READER и готовых к удалению
        let cleanup_uids: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let was_throttled = Arc::new(AtomicBool::new(false));
        // Метка времени последнего прихода письма именно в папку "Drafts" этого ящика (для expunge_idle_delay)
        let last_rx_ms = Arc::new(AtomicU64::new(now_epoch_ms()));

        // 1. Подключаем SRV_READER (Архитектура Cross-Selected: делает SELECT "Drafts"!)
        let reader_conn_res = ImapConn::connect(
            &host,
            port,
            &account.email,
            &account.password,
            &tls_cfg,
            command_timeout,
        )
        .await;

        let mut srv_reader = match reader_conn_res {
            Ok(mut conn) => {
                conn.set_literal_plus_enabled(literal_plus_auto);
                conn
            }
            Err(e) => {
                warn!(
                    "[IMAP Server][Box #{}] SRV_READER connect failed for {}: {e:#}. Retrying in 2s...",
                    mailbox_idx, email
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };

        if let Err(e) = srv_reader.select("Drafts", command_timeout).await {
            warn!(
                "[IMAP Server][Box #{}] SRV_READER SELECT 'Drafts' failed for {}: {e:#}. Retrying in 2s...",
                mailbox_idx, email
            );
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }

        let initial_max_uid = srv_reader.get_max_uid(command_timeout).await.unwrap_or(0);
        info!(
            "[IMAP Server][Box #{}] SRV_READER initialized for {} (SELECT 'Drafts', baseline UID: {})",
            mailbox_idx, email, initial_max_uid
        );

        // 2. Подключаем SRV_WRITER (Архитектура Cross-Selected: делает SELECT "Drafts" один раз при старте!)
        let writer_conn_res = ImapConn::connect(
            &host,
            port,
            &account.email,
            &account.password,
            &tls_cfg,
            command_timeout,
        )
        .await;

        let mut srv_writer = match writer_conn_res {
            Ok(mut conn) => {
                conn.set_literal_plus_enabled(literal_plus_auto);
                conn
            }
            Err(e) => {
                warn!(
                    "[IMAP Server][Box #{}] SRV_WRITER connect failed for {}: {e:#}. Retrying in 2s...",
                    mailbox_idx, email
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };

        // Гарантируем наличие обеих папок ("Notes" и "Drafts") на свежезарегистрированных ящиках
        let _ = srv_writer.select("Notes", command_timeout).await;
        if let Err(e) = srv_writer.select("Drafts", command_timeout).await {
            warn!(
                "[IMAP Server][Box #{}] SRV_WRITER SELECT 'Drafts' failed for {}: {e:#}. Retrying in 2s...",
                mailbox_idx, email
            );
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }
        info!(
            "[IMAP Server][Box #{}] SRV_WRITER initialized for {} (SELECT 'Drafts')",
            mailbox_idx, email
        );

        let writer_mutex = Arc::new(Mutex::new(srv_writer));

        // Помечаем ящик здоровым и уведомляем все активные клиентские пулы SessionMailboxPool
        mailbox_handle.inflight.store(0, Ordering::Release);
        mailbox_handle.healthy.store(true, Ordering::Release);
        for entry in session_pools.iter() {
            entry.value().pool_updated.notify_waiters();
        }

        // 3. Запуск SRV_WRITER[i] (Downlink APPEND "Notes" + Ленивый пакетный UID EXPUNGE в "Drafts")
        let writer_for_task = writer_mutex.clone();
        let email_writer = email.clone();
        let cleanup_uids_writer = cleanup_uids.clone();
        let handle_for_writer = mailbox_handle.clone();
        let pools_for_writer = session_pools.clone();
        let stop_flag_writer = stop_flag.clone();
        let throttled_for_writer = was_throttled.clone();
        let last_rx_writer = last_rx_ms.clone();
        let srv_act_writer = server_last_activity_ms.clone();
        let srv_wake_writer = server_reader_wake_notify.clone();
        let notes_auth_rx_writer = notes_auth_rx.clone();
        let notes_data_rx_writer = notes_data_rx.clone();
        let pending_retry_writer = pending_retry_msg.clone();

        let writer_task = tokio::spawn(async move {
            let mut auth_rx_guard = notes_auth_rx_writer.lock().await;
            let mut data_rx_guard = notes_data_rx_writer.lock().await;
            info!(
                "[IMAP Server][Box #{}] SRV_WRITER loop active for {} (Expunge batch: {}, idle delay: {:?})",
                mailbox_idx, email_writer, expunge_batch_size, expunge_idle_delay
            );

            while !stop_flag_writer.load(Ordering::Relaxed) {
                // Шаг 1: Сначала досылаем пакет, не ушедший перед прошлым обрывом SRV_WRITER (если есть),
                // затем приоритетно отправляем ответы Auth Handshake, затем батчи Data Plane.
                // Ждем до 40 мс прежде чем проверять неблокирующий EXPUNGE, чтобы не перехватывать
                // writer_sem у run_client_downlink_batcher посреди активной передачи!
                let retry_msg = pending_retry_writer.lock().await.take();
                let item_opt: Option<(DownlinkMessage, Option<OwnedSemaphorePermit>)> =
                    if let Some(m) = retry_msg {
                        Some((m, None))
                    } else {
                        tokio::select! {
                            biased;
                            auth_msg = auth_rx_guard.recv() => auth_msg.map(|m| (m, None)),
                            data_item = data_rx_guard.recv() => data_item.map(|(m, p)| (m, Some(p))),
                            _ = tokio::time::sleep(Duration::from_millis(40)) => None,
                        }
                    };

                if let Some((msg, permit_opt)) = item_opt {
                    handle_for_writer.inflight.fetch_add(1, Ordering::Relaxed);
                    let append_res = {
                        let mut writer_guard = writer_for_task.lock().await;
                        writer_guard
                            .append_message(
                                "Notes",
                                &msg.subject,
                                &msg.payload,
                                &email_writer,
                                command_timeout,
                            )
                            .await
                    };
                    let cur_inf = handle_for_writer.inflight.load(Ordering::Relaxed);
                    if cur_inf > 0 {
                        handle_for_writer.inflight.fetch_sub(1, Ordering::Relaxed);
                    }

                    match append_res {
                        Ok(lat) => {
                            srv_act_writer.store(now_epoch_ms(), Ordering::Relaxed);
                            srv_wake_writer.notify_waiters();
                            debug!(
                                "[IMAP Downlink][Box #{}] APPEND Notes OK in {:.1} ms ({} B)",
                                mailbox_idx,
                                lat.as_secs_f64() * 1000.0,
                                msg.payload.len()
                            );

                            // Попутная пакетная очистка (Piggybacked Expunge): если за время активного потока
                            // накопилось >= expunge_batch_size прочитанных писем в "Drafts", очищаем их прямо сейчас,
                            // пока мы уже владеем `permit_opt` (без риска дедлока и без голодания сборки мусора!).
                            let piggyback_clean = {
                                let mut guard = cleanup_uids_writer.lock().await;
                                if guard.len() >= expunge_batch_size {
                                    std::mem::take(&mut *guard)
                                } else {
                                    Vec::new()
                                }
                            };
                            if !piggyback_clean.is_empty() {
                                let mut writer_guard = writer_for_task.lock().await;
                                if let Err(e) = writer_guard
                                    .expunge_uids(&piggyback_clean, command_timeout)
                                    .await
                                {
                                    warn!(
                                        "[IMAP Cleanup][Box #{}] Piggybacked UID EXPUNGE in Drafts failed for {}: {e:#}",
                                        mailbox_idx, email_writer
                                    );
                                    handle_for_writer.healthy.store(false, Ordering::Release);
                                    drop(permit_opt);
                                    for entry in pools_for_writer.iter() {
                                        entry.value().pool_updated.notify_waiters();
                                    }
                                    stop_flag_writer.store(true, Ordering::SeqCst);
                                    break;
                                } else {
                                    last_rx_writer.store(now_epoch_ms(), Ordering::Relaxed);
                                    debug!(
                                        "[IMAP Cleanup][Box #{}] Piggybacked expunge of {} read UIDs in Drafts for {}",
                                        mailbox_idx,
                                        piggyback_clean.len(),
                                        email_writer
                                    );
                                }
                            }

                            // Освобождаем семафор ТОЛЬКО ПОСЛЕ завершения сетевого APPEND (и попутного EXPUNGE)!
                            drop(permit_opt);
                            for entry in pools_for_writer.iter() {
                                entry.value().pool_updated.notify_waiters();
                            }
                        }
                        Err(e) => {
                            let err_str = format!("{e:#}");
                            warn!(
                                "[IMAP Downlink][Box #{}] APPEND Notes failed for {}: {err_str}",
                                mailbox_idx, email_writer
                            );
                            if err_str.contains("THROTTLED") || err_str.contains("OVERQUOTA") {
                                throttled_for_writer.store(true, Ordering::SeqCst);
                            }
                            handle_for_writer.healthy.store(false, Ordering::Release);
                            *pending_retry_writer.lock().await = Some(msg);
                            drop(permit_opt);
                            for entry in pools_for_writer.iter() {
                                entry.value().pool_updated.notify_waiters();
                            }
                            stop_flag_writer.store(true, Ordering::SeqCst);
                            break;
                        }
                    }
                } else if auth_rx_guard.is_empty() && data_rx_guard.is_empty() {
                    // Шаг 2: Ленивая пакетная сборка мусора в паузах (когда очередь пуста >= 40 мс)
                    if let Ok(expunge_permit) = handle_for_writer.writer_sem.try_acquire() {
                        let to_clean = {
                            let mut guard = cleanup_uids_writer.lock().await;
                            let force_clean = guard.len() >= expunge_batch_size;
                            let last_act = last_rx_writer
                                .load(Ordering::Relaxed)
                                .max(srv_act_writer.load(Ordering::Relaxed));
                            let since_act_ms = now_epoch_ms().saturating_sub(last_act);
                            let idle_clean =
                                !guard.is_empty() && since_act_ms >= expunge_idle_delay_ms;
                            if force_clean || idle_clean {
                                std::mem::take(&mut *guard)
                            } else {
                                Vec::new()
                            }
                        };

                        if !to_clean.is_empty() {
                            let mut writer_guard = writer_for_task.lock().await;
                            if let Err(e) =
                                writer_guard.expunge_uids(&to_clean, command_timeout).await
                            {
                                warn!(
                                    "[IMAP Cleanup][Box #{}] Non-blocking UID EXPUNGE in Drafts failed for {}: {e:#}",
                                    mailbox_idx, email_writer
                                );
                                drop(expunge_permit);
                                stop_flag_writer.store(true, Ordering::SeqCst);
                                break;
                            } else {
                                last_rx_writer.store(now_epoch_ms(), Ordering::Relaxed);
                                debug!(
                                    "[IMAP Cleanup][Box #{}] Expunged {} read UIDs in Drafts for {}",
                                    mailbox_idx,
                                    to_clean.len(),
                                    email_writer
                                );
                                drop(expunge_permit);
                                for entry in pools_for_writer.iter() {
                                    entry.value().pool_updated.notify_waiters();
                                }
                            }
                        } else {
                            drop(expunge_permit);
                        }
                    }
                }
            }
        });

        // 4. Запуск SRV_READER[i] (Adaptive Short-IDLE + Greedy Fetch Drain "Drafts" -> Fast Path & Auth Plane)
        let mut last_seen_uid = initial_max_uid;
        let mut force_immediate_fetch = false;
        let reader_email = email.clone();
        let server_clamp_mtu = (config.network.mtu as usize).clamp(576, 1500);
        info!(
            "[IMAP Server][Box #{}] SRV_READER loop active for {} (Active IDLE: {:?}, Quiet IDLE: {:?}, FetchMax: {})",
            mailbox_idx, reader_email, idle_active_timeout, idle_quiet_timeout, fetch_max_messages
        );

        while !stop_flag.load(Ordering::Relaxed) {
            let since_active_ms =
                now_epoch_ms().saturating_sub(server_last_activity_ms.load(Ordering::Relaxed));
            let is_active = since_active_ms <= idle_active_window_ms;
            let mut got_event = false;
            let was_forced = force_immediate_fetch;

            if !force_immediate_fetch {
                let cur_idle_timeout = if is_active {
                    idle_active_timeout
                } else {
                    idle_quiet_timeout
                };
                let wake_opt = if is_active {
                    None
                } else {
                    Some(server_reader_wake_notify.as_ref())
                };

                match srv_reader.wait_idle_or_wake(cur_idle_timeout, wake_opt).await {
                    Ok(ev) => {
                        got_event = ev;
                    }
                    Err(e) => {
                        warn!(
                            "[IMAP Server][Box #{}] SRV_READER wait_idle_or_wake error for {}: {e:#}",
                            mailbox_idx, reader_email
                        );
                        break;
                    }
                }
            }
            force_immediate_fetch = false;

            if stop_flag.load(Ordering::Relaxed) {
                break;
            }
            let _ = (was_forced, got_event);

            // Двухфазная порционная выборка новых сообщений из папки "Drafts" (Chunked UID Fetch):
            // 1. Запрашивает легковесный индекс `UID FETCH <last_seen_uid + 1>:* (UID)` (~40 байт).
            //    При отсутствии новых писем не перекачивает 175 КБ дубликат `last_seen_uid` по RFC 3501
            //    и гарантированно находит письма, попавшие в «Слепое окно» Mail.ru.
            // 2. Скачивает тела не более `fetch_max_messages` (например, 3 шт.) за раз и сразу отправляет их в TUN.
            let fetch_res = srv_reader
                .fetch_messages_chunked(last_seen_uid, fetch_max_messages, command_timeout)
                .await;
            if srv_reader.pending_exists {
                srv_reader.pending_exists = false;
                force_immediate_fetch = true;
            }

            match fetch_res {
                Ok(res) => {
                    last_seen_uid = res.new_max_uid;
                    if !res.messages.is_empty() {
                        let now = now_epoch_ms();
                        last_rx_ms.store(now, Ordering::Relaxed);
                        server_last_activity_ms.store(now, Ordering::Relaxed);
                        server_reader_wake_notify.notify_waiters();
                    }

                    for msg in res.messages {
                        let Some((msg_srv_id, cli_token)) = extract_srv_and_cli_token(&msg.subject)
                        else {
                            continue;
                        };

                        if msg_srv_id != srv_id {
                            continue;
                        }

                        // Добавляем UID в локальную очередь очистки этого ящика для SRV_WRITER[i]
                        {
                            let mut guard = cleanup_uids.lock().await;
                            guard.push(msg.uid);
                        }

                        // 1. FAST PATH (Установленная сессия Data Plane, cli_token == session_id)
                        let client_info_opt = local_sessions
                            .get_mut(cli_token)
                            .map(|mut entry| {
                                entry.value_mut().1 = Instant::now();
                                entry.value().0.clone()
                            })
                            .or_else(|| {
                                let info = registry.get_by_session(cli_token)?;
                                local_sessions.insert(
                                    cli_token.to_string(),
                                    (info.clone(), Instant::now()),
                                );
                                Some(info)
                            });

                        if let Some(mut client_info) = client_info_opt {
                            let decrypted_res =
                                match unwrap_packet(&client_info.cipher, &msg.payload) {
                                    Ok(batch) => Ok(batch),
                                    Err(first_err) => {
                                        // Если клиент переподключился с resume_session_id через другой воркер и сменил DH-ключ,
                                        // синхронизируем свежий ClientTransportInfo из глобального реестра.
                                        if let Some(fresh_info) = registry.get_by_session(cli_token)
                                        {
                                            if !Arc::ptr_eq(&client_info, &fresh_info) {
                                                local_sessions.insert(
                                                    cli_token.to_string(),
                                                    (fresh_info.clone(), Instant::now()),
                                                );
                                                client_info = fresh_info;
                                                unwrap_packet(&client_info.cipher, &msg.payload)
                                            } else {
                                                Err(first_err)
                                            }
                                        } else {
                                            Err(first_err)
                                        }
                                    }
                                };

                            registry.touch_client(&client_info);

                            if let Ok(decrypted_batch) = decrypted_res {
                                // Динамическая привязка ящика к пулу сессии (раздел 9.5.2):
                                // как только ящик M_i принял валидный зашифрованный пакет или Mailbox Binding Frame,
                                // регистрируем его ServerMailboxHandle в SessionMailboxPool!
                                let pool = session_pools
                                    .entry(cli_token.to_string())
                                    .or_insert_with(|| Arc::new(SessionMailboxPool::new()))
                                    .value()
                                    .clone();
                                if pool.register_mailbox(mailbox_handle.clone()).await {
                                    let active_cnt = pool.active_count().await;
                                    info!(
                                        "[IMAP Server] Dynamically bound mailbox #{} ({}) to session {} (active striping mailboxes: {})",
                                        mailbox_idx, reader_email, cli_token, active_cnt
                                    );
                                }

                                let packets = unpack_batch(&decrypted_batch);
                                if packets.is_empty() {
                                    // Управляющий Mailbox Binding Frame (раздел 9.3.3): привязка выполнена, в TUN ничего не пишем
                                    debug!(
                                        "[IMAP Server][Box #{}] Processed Mailbox Binding Frame for session {}",
                                        mailbox_idx, cli_token
                                    );
                                    continue;
                                }

                                for pkt in packets {
                                    if pkt.len() < 20 {
                                        continue;
                                    }

                                    // Перехватываем внутритуннельный ICMP Echo Request зонд
                                    if let Some(reply) =
                                        anet_common::icmp_probe::handle_in_tunnel_icmp_probe(&pkt)
                                    {
                                        if let Some(dst_ip) = crate::utils::extract_ip_dst(&reply) {
                                            registry.route_packet_to_ipv4(dst_ip, reply).await;
                                        }
                                        continue;
                                    }

                                    let pkt = anet_common::icmp_probe::clamp_tcp_mss_bytes(
                                        pkt,
                                        server_clamp_mtu,
                                    );
                                    let pkt_len = pkt.len();
                                    let sent_ok = match tun_tx.try_send(pkt) {
                                        Ok(()) => true,
                                        Err(mpsc::error::TrySendError::Full(deferred_pkt)) => {
                                            tokio::time::timeout(
                                                Duration::from_millis(150),
                                                tun_tx.send(deferred_pkt),
                                            )
                                            .await
                                            .is_ok_and(|r| r.is_ok())
                                        }
                                        Err(mpsc::error::TrySendError::Closed(_)) => false,
                                    };
                                    if sent_ok {
                                        registry.record_rx(&client_info, pkt_len, "imap");
                                    }
                                }
                            }
                            continue;
                        }

                        // 2. AUTH PLANE (Хендшейк Фазы 1 или Фазы 3, cli_token == Client_TempID)
                        let fake_addr = fake_addr_from_cli_id(cli_token, safe_base_ip);
                        match auth_handler
                            .process_handshake_packet(msg.payload, fake_addr, "imap")
                            .await
                        {
                            Ok((response_opt, auth_tuple_opt)) => {
                                if let Some((client_info, _auth_response)) = auth_tuple_opt {
                                    let assigned_ip = client_info.assigned_ip.clone();
                                    let session_id = client_info.session_id.clone();
                                    local_sessions.insert(
                                        session_id.clone(),
                                        (client_info.clone(), Instant::now()),
                                    );

                                    // Создаём динамический пул ящиков SessionMailboxPool для новой/возобновленной сессии
                                    // и сразу привязываем к нему первичный ящик M_primary (раздел 9.5.2)
                                    let session_pool = Arc::new(SessionMailboxPool::new());
                                    session_pool.register_mailbox(mailbox_handle.clone()).await;
                                    session_pools.insert(session_id.clone(), session_pool.clone());

                                    let (tx_router, rx_router) =
                                        mpsc::channel::<Bytes>(tx_queue_capacity);
                                    registry.finalize_client(&assigned_ip, tx_router);

                                    info!(
                                        "[IMAP Server] Client {} authenticated via Primary Mailbox #{} ({})! Assigned IP: {}, Session: {}",
                                        cli_token, mailbox_idx, reader_email, assigned_ip, session_id
                                    );

                                    // Запускаем фоновую задачу Self-Clocking Round-Robin Downlink-батчера для этого клиента
                                    let c_info = client_info.clone();
                                    let max_batch_bytes =
                                        (config.imap.max_batch_kb.clamp(8, 512)) * 1024;
                                    let coalesce_ms = config.imap.batch_coalesce_ms.clamp(5, 100);

                                    tokio::spawn(async move {
                                        run_client_downlink_batcher(
                                            rx_router,
                                            c_info,
                                            session_pool,
                                            max_batch_bytes,
                                            coalesce_ms,
                                            max_inflight_batches,
                                        )
                                        .await;
                                    });
                                }

                                // Отправляем ответ хендшейка (Фаза 2 или Фаза 4) в папку "Notes"
                                // через приоритетный канал notes_auth_tx:
                                // Тема: Subject: [ID: <Client_TempID>]
                                if let Some(response_bytes) = response_opt {
                                    let reply_subject = format!("[ID: {}]", cli_token);
                                    let _ = notes_auth_tx
                                        .send(DownlinkMessage {
                                            subject: reply_subject,
                                            payload: response_bytes,
                                        })
                                        .await;
                                }
                            }
                            Err(e) => {
                                debug!(
                                    "[IMAP Auth] Handshake packet ignored for {}: {e}",
                                    cli_token
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "[IMAP Server][Box #{}] SRV_READER UID FETCH error for {}: {e:#}",
                        mailbox_idx, reader_email
                    );
                    break;
                }
            }
        }

        mailbox_handle.healthy.store(false, Ordering::Release);
        stop_flag.store(true, Ordering::SeqCst);
        writer_task.abort();
        let _ = writer_task.await;

        {
            let mut rx_guard = notes_data_rx.lock().await;
            if let Ok((queued_msg, queued_permit)) = rx_guard.try_recv() {
                let mut retry_guard = pending_retry_msg.lock().await;
                if retry_guard.is_none() {
                    *retry_guard = Some(queued_msg);
                }
                drop(queued_permit);
            }
        }
        for entry in session_pools.iter() {
            entry.value().pool_updated.notify_waiters();
        }

        let _ = srv_reader.exit_idle(Duration::from_millis(200)).await;
        let _ = srv_reader.send_line("A9999 LOGOUT").await;

        let backoff = if was_throttled.load(Ordering::Relaxed) {
            warn!(
                "[IMAP Server][Box #{}] Worker pair for {} hit THROTTLED/OVERQUOTA. Backing off {:?}...",
                mailbox_idx, email, throttle_backoff
            );
            throttle_backoff
        } else {
            warn!(
                "[IMAP Server][Box #{}] Worker pair for {} ended. Reconnecting in 2s...",
                mailbox_idx, email
            );
            Duration::from_secs(2)
        };
        tokio::time::sleep(backoff).await;
    }
}

/// Фоновая задача Self-Clocking Round-Robin сборки и балансировки Downlink-батчей из `rx_router` (TUN)
/// по всем активным ящикам клиента в `SessionMailboxPool` (раздел 9.5.3 спецификации):
/// 1. Ждет первый пакет из `rx_router` и коалесцирует стартовый бурст за `coalesce_ms`;
/// 2. Выбирает первый свободный здоровый ящик сессии через `acquire_server_slot_self_clocking`
///    (пока все ящики клиента заняты `APPEND "Notes"`, новые пакеты продолжают копиться в `rx_router`);
/// 3. В момент освобождения любого `SRV_WRITER[k]` выгребает все накопившиеся пакеты до `max_batch_bytes`
///    (приоритезируя ICMP/DNS/ACK в начало батча), шифрует одним вызовом `wrap_packet_slice`
///    и отправляет в `SRV_WRITER[k]`.
pub async fn run_client_downlink_batcher(
    mut rx_router: mpsc::Receiver<Bytes>,
    client_info: Arc<ClientTransportInfo>,
    session_pool: Arc<SessionMailboxPool>,
    max_batch_bytes: usize,
    coalesce_ms: u64,
    max_inflight_batches: usize,
) {
    let mut batcher = PacketBatcher::new(max_batch_bytes, coalesce_ms);
    let subject = format!("[ID: {}]", client_info.session_id);

    loop {
        // 1. Сначала выгребаем всё, что уже лежит в rx_router без ожидания
        while let Ok(pkt) = rx_router.try_recv() {
            if pkt.len() >= 20 {
                batcher.push(pkt);
            }
        }

        // Если батчер пуст — ждем первый пакет из rx_router
        if batcher.is_empty() {
            match rx_router.recv().await {
                Some(first_pkt) => {
                    if first_pkt.len() >= 20 {
                        batcher.push(first_pkt);
                    } else {
                        continue;
                    }
                }
                None => break, // Клиент отключен или перерегистрировал rx_router
            }

            // Выгребаем всё, что пришло вместе с первым пакетом
            while let Ok(pkt) = rx_router.try_recv() {
                if pkt.len() >= 20 {
                    batcher.push(pkt);
                }
            }

            // Ждем микро-окно coalesce_ms (10–15 мс) для сбора стартового бурста
            if coalesce_ms > 0 && !batcher.should_flush() {
                let coalesce_deadline = Instant::now() + Duration::from_millis(coalesce_ms);
                loop {
                    if batcher.should_flush() {
                        break;
                    }
                    let rem = coalesce_deadline.saturating_duration_since(Instant::now());
                    if rem.is_zero() {
                        break;
                    }
                    match tokio::time::timeout(rem, rx_router.recv()).await {
                        Ok(Some(pkt)) => {
                            if pkt.len() >= 20 {
                                batcher.push(pkt);
                            }
                            while let Ok(more_pkt) = rx_router.try_recv() {
                                if more_pkt.len() >= 20 {
                                    batcher.push(more_pkt);
                                }
                            }
                        }
                        Ok(None) => break,
                        Err(_) => break,
                    }
                }
            }
        }

        // 2. Ждем готовности первого свободного здорового ящика в SessionMailboxPool (Self-Clocking Round-Robin),
        // НЕПРЕРЫВНО дренируя rx_router в PacketBatcher (с приоритезацией prio_queue и AQM Head-Drop на bulk queue!).
        // Благодаря этому глобальная очередь rx_tun сервера никогда не забивается старыми пакетами Download,
        // а свежие TCP SYN-ACK / ACK для клиентского Upload мгновенно попадают в prio_queue текущего батча!
        let slot_opt = {
            let acquire_fut =
                acquire_server_slot_self_clocking(&session_pool, max_inflight_batches);
            tokio::pin!(acquire_fut);
            let mut rx_closed = false;
            loop {
                tokio::select! {
                    biased;
                    res = &mut acquire_fut => break res,
                    pkt_opt = rx_router.recv(), if !rx_closed => {
                        match pkt_opt {
                            Some(pkt) => {
                                if pkt.len() >= 20 {
                                    batcher.push(pkt);
                                }
                                while let Ok(more_pkt) = rx_router.try_recv() {
                                    if more_pkt.len() >= 20 {
                                        batcher.push(more_pkt);
                                    }
                                }
                            }
                            None => {
                                rx_closed = true;
                            }
                        }
                    }
                }
            }
        };

        let Some((handle, permit)) = slot_opt else {
            break;
        };

        // 3. Как только SRV_WRITER[k] освободился — выгребаем все оставшиеся пакеты из rx_router в батчер!
        while let Ok(pkt) = rx_router.try_recv() {
            if pkt.len() >= 20 {
                batcher.push(pkt);
            }
        }

        // 4. Шифруем собранный батч одним вызовом wrap_packet_slice и отправляем через выбранный SRV_WRITER[k]
        if let Some(raw_batch) = batcher.flush() {
            let seq = client_info.sequence.fetch_add(1, Ordering::Relaxed);
            if let Ok(encrypted_bytes) = wrap_packet_slice(
                &client_info.cipher,
                &client_info.nonce_prefix,
                seq,
                &raw_batch,
                0,
            ) {
                let msg = DownlinkMessage {
                    subject: subject.clone(),
                    payload: encrypted_bytes,
                };
                let _ = handle.notes_data_tx.send((msg, permit)).await;
            } else {
                drop(permit);
            }
        } else {
            drop(permit);
        }
    }

    debug!(
        "[IMAP Downlink Batcher] Exited for client {}",
        client_info.assigned_ip
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use anet_common::encryption::Cipher;
    use arc_swap::{ArcSwap, ArcSwapOption};
    use std::sync::OnceLock;

    fn make_mock_client_info(cipher: Arc<Cipher>, session_id: &str) -> Arc<ClientTransportInfo> {
        Arc::new(ClientTransportInfo {
            cipher,
            sequence: Arc::new(AtomicU64::new(0)),
            assigned_ip: "10.0.0.2".to_string(),
            session_id: session_id.to_string(),
            nonce_prefix: [1, 2, 3, 4],
            remote_addr: ArcSwap::new(Arc::new("127.0.0.1:50000".parse().unwrap())),
            fingerprint: "fp".to_string(),
            user_id: None,
            protocol: "imap".to_string(),
            speed_limit_kbps: None,
            billing_type: None,
            group_name: None,
            traffic_limit: None,
            traffic_consumed: None,
            allowed_sessions: None,
            active_sessions: None,
            expires_at: None,
            last_activity: Arc::new(AtomicU64::new(0)),
            created_at: 0,
            quic_conn: ArcSwapOption::empty(),
            traffic_counters: OnceLock::new(),
        })
    }

    #[test]
    fn test_extract_srv_and_cli_token() {
        let s1 = "ANet-Data [ID: srv01:client123]";
        assert_eq!(extract_srv_and_cli_token(s1), Some(("srv01", "client123")));

        let s2 = "Important Notice [ID: a1b2c3d4:e5f67890]";
        assert_eq!(
            extract_srv_and_cli_token(s2),
            Some(("a1b2c3d4", "e5f67890"))
        );

        let s3 = "[ID: my_server:session_xyz]";
        assert_eq!(
            extract_srv_and_cli_token(s3),
            Some(("my_server", "session_xyz"))
        );

        let s4 = "Regular email without id";
        assert_eq!(extract_srv_and_cli_token(s4), None);
    }

    #[test]
    fn test_get_safe_fake_base() {
        assert_eq!(get_safe_fake_base("10.0.0.0"), Ipv4Addr::new(127, 127, 0, 0));
        assert_eq!(
            get_safe_fake_base("172.16.0.0"),
            Ipv4Addr::new(127, 127, 0, 0)
        );
        assert_eq!(
            get_safe_fake_base("127.0.0.0"),
            Ipv4Addr::new(198, 18, 0, 0)
        );
    }

    #[test]
    fn test_fake_addr_from_cli_id() {
        let base = Ipv4Addr::new(127, 127, 0, 0);
        let addr1 = fake_addr_from_cli_id("client_abc", base);
        let addr2 = fake_addr_from_cli_id("client_abc", base);
        let addr3 = fake_addr_from_cli_id("client_xyz", base);

        assert_eq!(addr1, addr2);
        assert_ne!(addr1, addr3);

        match addr1.ip() {
            std::net::IpAddr::V4(v4) => {
                assert_eq!(v4.octets()[0], 127);
                assert_eq!(v4.octets()[1], 127);
            }
            _ => panic!("Expected IPv4"),
        }
    }

    #[test]
    fn test_parse_imap_server_dsn() {
        let dsn = "imap://imap.mail.ru:993?acc=node1%40mail.ru:srv_pass1&acc=node2%40mail.ru:srv_pass2";
        let (host, port, accounts) = parse_imap_server_dsn(dsn).unwrap();
        assert_eq!(host, "imap.mail.ru");
        assert_eq!(port, 993);
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].email, "node1@mail.ru");
        assert_eq!(accounts[0].password, "srv_pass1");
        assert_eq!(accounts[1].email, "node2@mail.ru");
        assert_eq!(accounts[1].password, "srv_pass2");
    }

    #[tokio::test]
    async fn test_downlink_batcher_survives_worker_reconnect() {
        let (tx_router, rx_router) = mpsc::channel::<Bytes>(64);
        let (handle, notes_data_rx) =
            ServerMailboxHandle::new(0, "node1@mail.ru".to_string(), true);
        let notes_data_rx = Arc::new(Mutex::new(notes_data_rx));

        let session_pool = Arc::new(SessionMailboxPool::new());
        session_pool.register_mailbox(handle.clone()).await;

        let cipher = Arc::new(Cipher::new(&[0x42u8; 32]));
        let client_info = make_mock_client_info(cipher.clone(), "sess_persist");

        let batcher_handle = tokio::spawn(run_client_downlink_batcher(
            rx_router,
            client_info,
            session_pool.clone(),
            131_072,
            5,
            35,
        ));

        // 1. Первая сессия воркера читает первый батч и затем «обрывается»
        let rx_clone1 = notes_data_rx.clone();
        let writer1 = tokio::spawn(async move {
            let mut guard = rx_clone1.lock().await;
            let (msg, permit) = guard.recv().await.expect("first downlink batch");
            drop(permit);
            msg
        });

        let mut pkt1 = vec![0x45u8; 60];
        pkt1[9] = 1; // ICMP
        tx_router.send(Bytes::from(pkt1.clone())).await.unwrap();

        let msg1 = writer1.await.unwrap();
        assert_eq!(msg1.subject, "[ID: sess_persist]");
        let dec1 = unwrap_packet(&cipher, &msg1.payload).unwrap();
        let unpacked1 = unpack_batch(&dec1);
        assert_eq!(unpacked1.len(), 1);
        assert_eq!(unpacked1[0].as_ref(), pkt1.as_slice());

        // Имитируем временный уход воркера на реконнект (healthy = false -> true)
        handle.healthy.store(false, Ordering::Release);
        let mut pkt2 = vec![0x45u8; 80];
        pkt2[9] = 17;
        tx_router.send(Bytes::from(pkt2.clone())).await.unwrap();

        tokio::time::sleep(Duration::from_millis(20)).await;
        handle.healthy.store(true, Ordering::Release);
        session_pool.pool_updated.notify_waiters();

        // 2. Новый воркер после реконнекта подхватывает тот же notes_data_rx и получает второй батч без потерь!
        let rx_clone2 = notes_data_rx.clone();
        let writer2 = tokio::spawn(async move {
            let mut guard = rx_clone2.lock().await;
            let (msg, permit) = guard.recv().await.expect("second downlink batch");
            drop(permit);
            msg
        });

        let msg2 = writer2.await.unwrap();
        let dec2 = unwrap_packet(&cipher, &msg2.payload).unwrap();
        let unpacked2 = unpack_batch(&dec2);
        assert_eq!(unpacked2.len(), 1);
        assert_eq!(unpacked2[0].as_ref(), pkt2.as_slice());

        drop(tx_router);
        let _ = batcher_handle.await;
    }

    /// Тест 4 из Раздела 9.6: Проверяет регистрацию M_0 при хендшейке, динамическое добавление
    /// M_1 и M_2 при приходе Mailbox Binding Frame (`wrap_packet_slice(..., &[], 0)`),
    /// равномерную балансировку Downlink-трафика по всем 3 ящикам и выживание при отключении любого воркера.
    #[tokio::test]
    async fn test_server_session_mailbox_pool_dynamic_binding_and_striping() {
        let (tx_router, rx_router) = mpsc::channel::<Bytes>(64);
        let cipher = Arc::new(Cipher::new(&[0x55u8; 32]));
        let client_info = make_mock_client_info(cipher.clone(), "sess_multi_srv");

        let (h0, mut rx0) = ServerMailboxHandle::new(0, "box0@mail.ru".to_string(), true);
        let (h1, mut rx1) = ServerMailboxHandle::new(1, "box1@mail.ru".to_string(), true);
        let (h2, mut rx2) = ServerMailboxHandle::new(2, "box2@mail.ru".to_string(), true);

        let session_pool = Arc::new(SessionMailboxPool::new());
        // На этапе Фазы 3 хендшейка привязан только первичный ящик M_0
        assert!(session_pool.register_mailbox(h0.clone()).await);
        assert!(!session_pool.register_mailbox(h0.clone()).await); // идемпотентность
        assert_eq!(session_pool.active_count().await, 1);

        let batcher_handle = tokio::spawn(run_client_downlink_batcher(
            rx_router,
            client_info,
            session_pool.clone(),
            1024,
            0,
            35,
        ));

        // Проверяем, что пока привязан только M_0, первый батч уходит строго через M_0
        let pkt = Bytes::from(vec![0x45u8; 800]);
        tx_router.send(pkt.clone()).await.unwrap();
        let (msg_m0, permit0) = tokio::time::timeout(Duration::from_millis(200), rx0.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(msg_m0.subject, "[ID: sess_multi_srv]");
        drop(permit0);

        // Имитируем приход Mailbox Binding Frame (`wrap_packet_slice(..., &[], 0)`) на M_1 и M_2
        let binding_raw = wrap_packet_slice(&cipher, &[1, 2, 3, 4], 1u64 << 63, &[], 0).unwrap();
        let dec_binding = unwrap_packet(&cipher, &binding_raw).expect("valid binding AEAD");
        assert!(unpack_batch(&dec_binding).is_empty());

        assert!(session_pool.register_mailbox(h1.clone()).await);
        assert!(session_pool.register_mailbox(h2.clone()).await);
        assert_eq!(session_pool.active_count().await, 3);

        // Отправляем 3 последовательных батча (каждый освобождает свой слот сразу):
        // они должны распределиться по всем 3 ящикам (Round-Robin)!
        let mut received_per_box = [0usize; 3];
        for _ in 0..3 {
            tx_router.send(pkt.clone()).await.unwrap();
            tokio::select! {
                Some((_, p)) = rx0.recv() => { received_per_box[0] += 1; drop(p); }
                Some((_, p)) = rx1.recv() => { received_per_box[1] += 1; drop(p); }
                Some((_, p)) = rx2.recv() => { received_per_box[2] += 1; drop(p); }
            }
        }
        assert_eq!(
            received_per_box,
            [1, 1, 1],
            "Downlink batches must be striped evenly across all 3 bound mailboxes"
        );

        // Теперь отключаем M_0 и M_1 (`healthy = false`): трафик должен без простоев пойти через оставшийся M_2!
        h0.healthy.store(false, Ordering::Release);
        h1.healthy.store(false, Ordering::Release);
        session_pool.pool_updated.notify_waiters();

        for _ in 0..2 {
            tx_router.send(pkt.clone()).await.unwrap();
            let (_msg, p2) = tokio::time::timeout(Duration::from_millis(200), rx2.recv())
                .await
                .expect("M_2 should immediately handle all downlink batches when M_0 and M_1 are unhealthy")
                .unwrap();
            drop(p2);
        }

        drop(tx_router);
        let _ = batcher_handle.await;
    }

    /// Тест 2 (серверная часть) из Раздела 9.6: Проверяет, что если ящик M_0 заблокирован долгим APPEND (500 мс),
    /// серверный `run_client_downlink_batcher` не ждёт M_0, а прокачивает очередь через быстрые ящики M_1 и M_2.
    #[tokio::test]
    async fn test_server_self_clocking_bypass_slow_worker() {
        let (tx_router, rx_router) = mpsc::channel::<Bytes>(64);
        let cipher = Arc::new(Cipher::new(&[0x66u8; 32]));
        let client_info = make_mock_client_info(cipher, "sess_srv_fast");

        let session_pool = Arc::new(SessionMailboxPool::new());
        let mut rxs = Vec::new();
        for i in 0..3 {
            let (h, rx) = ServerMailboxHandle::new(i, format!("srv{i}@mail.ru"), true);
            session_pool.register_mailbox(h).await;
            rxs.push(rx);
        }

        let counts = Arc::new([
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
        ]);

        let mut worker_tasks = Vec::new();
        for (i, mut rx) in rxs.into_iter().enumerate() {
            let counts_c = counts.clone();
            let pool_c = session_pool.clone();
            let delay = if i == 0 {
                Duration::from_millis(500)
            } else {
                Duration::from_millis(25)
            };
            worker_tasks.push(tokio::spawn(async move {
                while let Some((_msg, permit)) = rx.recv().await {
                    tokio::time::sleep(delay).await;
                    counts_c[i].fetch_add(1, Ordering::Relaxed);
                    drop(permit);
                    pool_c.pool_updated.notify_waiters();
                }
            }));
        }

        let batcher_handle = tokio::spawn(run_client_downlink_batcher(
            rx_router,
            client_info,
            session_pool,
            1024,
            0,
            35,
        ));

        let pkt = Bytes::from(vec![0x45u8; 880]);
        for _ in 0..7 {
            tx_router.send(pkt.clone()).await.unwrap();
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        tokio::time::sleep(Duration::from_millis(160)).await;
        let c1 = counts[1].load(Ordering::Relaxed);
        let c2 = counts[2].load(Ordering::Relaxed);
        assert!(
            c1 + c2 >= 6,
            "Fast server workers #1 and #2 should bypass slow worker #0 and process >= 6 batches (got c1={c1}, c2={c2})"
        );

        drop(tx_router);
        batcher_handle.abort();
        for t in worker_tasks {
            t.abort();
        }
    }

    /// Регрессионный тест: проверяет отсутствие дедлока `writer_sem` в `SRV_WRITER`, когда
    /// `run_client_downlink_batcher` уже захватил `OwnedSemaphorePermit` и положил `(msg, permit)` в `notes_data_rx`
    /// одновременно с накоплением `>= expunge_batch_size` прочитанных UID в `cleanup_uids`.
    #[tokio::test]
    async fn test_srv_writer_piggybacked_and_idle_expunge_never_deadlocks_with_batcher() {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let mock_writer = Arc::new(Mutex::new(ImapConn::new(client_io)));

        let server_task = tokio::spawn(async move {
            let mut s_buf = BufReader::new(server_io);
            let mut line = String::new();

            // 1. Ожидаем APPEND "Notes"
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("APPEND \"Notes\""));
            let lit_start = line.rfind('{').unwrap();
            let lit_end = line[lit_start + 1..].find('}').unwrap() + lit_start + 1;
            let lit_len: usize = line[lit_start + 1..lit_end].parse().unwrap();
            s_buf.get_mut().write_all(b"+ Ready\r\n").await.unwrap();
            let mut body = vec![0u8; lit_len];
            s_buf.read_exact(&mut body).await.unwrap();
            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            s_buf
                .get_mut()
                .write_all(b"A0001 OK [APPENDUID 1 700] APPEND completed\r\n")
                .await
                .unwrap();

            // 2. Ожидаем попутный UID STORE + UID EXPUNGE в "Drafts"
            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("UID STORE 10,11,12 +FLAGS.SILENT (\\Deleted)"));
            s_buf
                .get_mut()
                .write_all(b"A0002 OK STORE completed\r\n")
                .await
                .unwrap();

            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("UID EXPUNGE 10,11,12"));
            s_buf
                .get_mut()
                .write_all(b"A0003 OK EXPUNGE completed\r\n")
                .await
                .unwrap();
        });

        let (handle, mut notes_data_rx) =
            ServerMailboxHandle::new(0, "srv0@mail.ru".to_string(), true);

        // Батчер уже захватил единственное разрешение `writer_sem` и положил `(msg, permit)` в `notes_data_tx`
        let permit = handle
            .writer_sem
            .clone()
            .try_acquire_owned()
            .expect("batcher acquires sole permit");
        handle
            .notes_data_tx
            .send((
                DownlinkMessage {
                    subject: "[ID: sess_123]".to_string(),
                    payload: Bytes::from_static(b"DOWNLINK_DATA"),
                },
                permit,
            ))
            .await
            .unwrap();

        let cleanup_uids = Arc::new(Mutex::new(vec![10u32, 11, 12]));
        let expunge_batch_size = 3usize;
        let command_timeout = Duration::from_secs(2);

        let handle_w = handle.clone();
        let cleanup_w = cleanup_uids.clone();
        let writer_w = mock_writer.clone();

        let writer_step = tokio::time::timeout(Duration::from_secs(2), async move {
            if notes_data_rx.is_empty() {
                if let Ok(_p) = handle_w.writer_sem.try_acquire() {
                    unreachable!("permit is already held by queued downlink message");
                }
            }

            let (msg, held_permit) = notes_data_rx.recv().await.unwrap();
            {
                let mut w_guard = writer_w.lock().await;
                w_guard
                    .append_message(
                        "Notes",
                        &msg.subject,
                        &msg.payload,
                        "srv0@mail.ru",
                        command_timeout,
                    )
                    .await
                    .unwrap();
            }

            let piggyback_clean = {
                let mut guard = cleanup_w.lock().await;
                if guard.len() >= expunge_batch_size {
                    std::mem::take(&mut *guard)
                } else {
                    Vec::new()
                }
            };
            assert_eq!(piggyback_clean, vec![10, 11, 12]);
            {
                let mut w_guard = writer_w.lock().await;
                w_guard
                    .expunge_uids(&piggyback_clean, command_timeout)
                    .await
                    .unwrap();
            }
            drop(held_permit);
        })
        .await;

        assert!(
            writer_step.is_ok(),
            "SRV_WRITER must not deadlock when cleanup_uids >= expunge_batch_size and permit is in notes_data_rx"
        );
        assert!(cleanup_uids.lock().await.is_empty());
        assert_eq!(handle.writer_sem.available_permits(), 1);
        server_task.await.unwrap();
    }
}
