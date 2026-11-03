// anet-server/src/servers/imap.rs
//! Транспорт IMAP на стороне сервера (ASTP over IMAPS:993).
//!
//! Реализует разделы 3, 4, 5, 7.3 и 8 документа `contrib/docs/imap.ru.md`:
//! - Супервизор пула почтовых ящиков из `imap_dsn`;
//! - Архитектура «Cross-Selected Writer» на стороне сервера:
//!   - `SRV_READER` делает `SELECT "Drafts"`, читает Uplink-сообщения клиентов через `wait_idle_or_pending()`
//!     и передает прочитанные UIDs в локальный канал очистки;
//!   - `SRV_WRITER` делает `SELECT "Drafts"` один раз при старте, отправляет Downlink-сообщения
//!     через `APPEND "Notes" (\Seen \Draft)`, а в паузах удаляет прочитанные письма в `"Drafts"`
//!     через `UID STORE` + `UID EXPUNGE` без переключения папок;
//! - Честная Self-Clocking коалесценция Downlink-батчей (раздел 3.3): пока `SRV_WRITER` выполняет сетевой
//!   `APPEND` (~450 мс), пакеты из TUN накапливаются в `rx_router` и сливаются одним вызовом `wrap_packet_slice`
//!   непосредственно в момент освобождения `SRV_WRITER`;
//! - Управление переполнением (Backpressure `MAX_INFLIGHT_DOWNLINK = 15`, раздел 3.7) без риска взаимной блокировки;
//! - Периодическая очистка неактивных сессий (`cleanup_interval_ms` / `session_ttl_ms`, раздел 7.4).

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
use log::{debug, info, warn};
use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Mutex, Notify};

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

pub struct DownlinkMessage {
    pub subject: String,
    pub payload: Bytes,
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
    let uri: http::Uri = dsn.parse().with_context(|| format!("Invalid IMAP DSN: {}", dsn))?;
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
        .as_ref()
        .context("IMAP server DSN is not configured")?;

    let (host, port, accounts) = parse_imap_server_dsn(imap_dsn)?;
    info!(
        "[IMAP Server] Initializing IMAP Transport on {}:{} with {} mailbox(es) (Batch: {} KB, ActiveIDLE: {} ms, ExpungeBatch: {})...",
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

    // Фоновая задача периодической очистки неактивных сессий (cleanup_interval_ms и session_ttl_ms из раздела 7.4)
    let cleanup_interval = Duration::from_millis(config.imap.cleanup_interval_ms.max(5000));
    let session_ttl = Duration::from_millis(config.imap.session_ttl_ms.max(30000));
    let sessions_for_gc = local_sessions.clone();
    let registry_for_gc = registry.clone();

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(cleanup_interval);
        loop {
            ticker.tick().await;
            let now = Instant::now();
            sessions_for_gc.retain(|sid, (_, last_active)| {
                let alive_in_reg = registry_for_gc.get_by_session(sid).is_some();
                let not_expired = now.saturating_duration_since(*last_active) <= session_ttl;
                alive_in_reg && not_expired
            });
        }
    });

    // Запускаем независимую пару воркеров (Reader + Writer) для каждого почтового ящика параллельно
    let mut worker_handles = Vec::new();

    for account in accounts {
        let host_c = host.clone();
        let config_c = config.clone();
        let registry_c = registry.clone();
        let tun_tx_c = tun_tx.clone();
        let auth_c = auth_handler.clone();
        let local_sessions_c = local_sessions.clone();
        let srv_id_c = srv_id.clone();

        let handle = tokio::spawn(async move {
            run_mailbox_worker_pair(
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
            )
            .await;
        });

        worker_handles.push(handle);
    }

    futures::future::join_all(worker_handles).await;
    Ok(())
}

/// Обслуживает один почтовый ящик парой воркеров (SRV_READER и SRV_WRITER)
async fn run_mailbox_worker_pair(
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
) {
    let email = account.email.clone();
    let command_timeout = Duration::from_millis(config.imap.command_timeout_ms.max(5000));
    let idle_quiet_timeout = Duration::from_millis(config.imap.idle_refresh_interval_ms.max(2000));
    let idle_active_timeout = Duration::from_millis(config.imap.idle_active_poll_ms.clamp(150, 5000));
    let idle_active_window_ms = config.imap.idle_active_window_ms.clamp(1000, 60_000);
    let expunge_batch_size = config.imap.expunge_batch_size.clamp(5, 200);
    let expunge_idle_delay = Duration::from_millis(config.imap.expunge_idle_delay_ms.clamp(250, 30_000));
    let max_inflight_batches = config.imap.max_inflight_batches.clamp(5, 250);
    let tx_queue_capacity = config.imap.tx_queue_capacity.clamp(32, 2048);
    let literal_plus_auto = config.imap.literal_plus_auto;
    let throttle_backoff = Duration::from_millis(config.imap.throttle_backoff_ms.max(5000));
    let tls_cfg = config.stealth.to_tls_client_config();

    info!("[IMAP Mailbox] Starting worker pair for account {}", email);

    // Приоритетный канал ответов рукопожатия (Фаза 2 / Фаза 4) и канал Downlink-данных (раздел 3.3)
    // создаются ОДИН РАЗ вне цикла реконнекта, чтобы при переподключении SRV_READER/SRV_WRITER
    // активные клиентские батчеры не теряли Downlink-маршрутизацию.
    let (notes_auth_tx, notes_auth_rx) = mpsc::channel::<DownlinkMessage>(64);
    let (notes_data_tx, notes_data_rx) = mpsc::channel::<DownlinkMessage>(1);
    let notes_auth_rx = Arc::new(Mutex::new(notes_auth_rx));
    let notes_data_rx = Arc::new(Mutex::new(notes_data_rx));
    let pending_retry_msg: Arc<Mutex<Option<DownlinkMessage>>> = Arc::new(Mutex::new(None));

    loop {
        // Список UIDs сообщений в папке "Drafts", прочитанных SRV_READER и готовых к удалению
        let cleanup_uids: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let inflight_downlink = Arc::new(AtomicUsize::new(0));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let last_activity_ms = Arc::new(AtomicU64::new(now_epoch_ms()));
        let reader_wake_notify = Arc::new(Notify::new());

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
                    "[IMAP Server] SRV_READER connect failed for {}: {e:#}. Backing off {:?}...",
                    email, throttle_backoff
                );
                tokio::time::sleep(throttle_backoff).await;
                continue;
            }
        };

        if let Err(e) = srv_reader.select("Drafts", command_timeout).await {
            warn!(
                "[IMAP Server] SRV_READER SELECT 'Drafts' failed for {}: {e:#}. Backing off {:?}...",
                email, throttle_backoff
            );
            tokio::time::sleep(throttle_backoff).await;
            continue;
        }

        let initial_max_uid = srv_reader.get_max_uid(command_timeout).await.unwrap_or(0);
        info!(
            "[IMAP Server] SRV_READER initialized for {} (SELECT 'Drafts', baseline UID: {})",
            email, initial_max_uid
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
                    "[IMAP Server] SRV_WRITER connect failed for {}: {e:#}. Backing off {:?}...",
                    email, throttle_backoff
                );
                tokio::time::sleep(throttle_backoff).await;
                continue;
            }
        };

        // Гарантируем наличие обеих папок ("Notes" и "Drafts") на свежезарегистрированных ящиках
        let _ = srv_writer.select("Notes", command_timeout).await;
        if let Err(e) = srv_writer.select("Drafts", command_timeout).await {
            warn!(
                "[IMAP Server] SRV_WRITER SELECT 'Drafts' failed for {}: {e:#}. Backing off {:?}...",
                email, throttle_backoff
            );
            tokio::time::sleep(throttle_backoff).await;
            continue;
        }
        info!(
            "[IMAP Server] SRV_WRITER initialized for {} (SELECT 'Drafts')",
            email
        );

        let writer_mutex = Arc::new(Mutex::new(srv_writer));

        // 3. Запуск SRV_WRITER (Downlink APPEND "Notes" + Ленивый пакетный UID EXPUNGE в "Drafts")
        let writer_for_task = writer_mutex.clone();
        let email_writer = email.clone();
        let cleanup_uids_writer = cleanup_uids.clone();
        let inflight_writer = inflight_downlink.clone();
        let stop_flag_writer = stop_flag.clone();
        let last_activity_writer = last_activity_ms.clone();
        let reader_wake_writer = reader_wake_notify.clone();
        let notes_auth_rx_writer = notes_auth_rx.clone();
        let notes_data_rx_writer = notes_data_rx.clone();
        let pending_retry_writer = pending_retry_msg.clone();

        let writer_task = tokio::spawn(async move {
            let mut auth_rx_guard = notes_auth_rx_writer.lock().await;
            let mut data_rx_guard = notes_data_rx_writer.lock().await;
            let mut last_tx_instant = Instant::now();
            info!(
                "[IMAP Server] SRV_WRITER loop active for {} (Expunge batch: {}, idle delay: {:?})",
                email_writer, expunge_batch_size, expunge_idle_delay
            );

            while !stop_flag_writer.load(Ordering::Relaxed) {
                // Шаг 1: Ленивая пакетная сборка мусора в текущей выбранной папке "Drafts"
                // Выполняется только при накоплении >= expunge_batch_size писем, достижении max_inflight_batches,
                // ИЛИ после паузы трафика >= expunge_idle_delay (1500 мс)!
                let to_clean = {
                    let mut guard = cleanup_uids_writer.lock().await;
                    let force_clean = guard.len() >= expunge_batch_size
                        || inflight_writer.load(Ordering::Relaxed) >= max_inflight_batches;
                    let idle_clean = auth_rx_guard.is_empty()
                        && data_rx_guard.is_empty()
                        && !guard.is_empty()
                        && last_tx_instant.elapsed() >= expunge_idle_delay;
                    if force_clean || idle_clean {
                        let list = guard.clone();
                        guard.clear();
                        list
                    } else {
                        Vec::new()
                    }
                };

                if !to_clean.is_empty() {
                    let mut writer_guard = writer_for_task.lock().await;
                    if let Err(e) = writer_guard.expunge_uids(&to_clean, command_timeout).await {
                        warn!(
                            "[IMAP Cleanup] Non-blocking UID EXPUNGE in Drafts failed for {}: {e:#}",
                            email_writer
                        );
                        stop_flag_writer.store(true, Ordering::SeqCst);
                        break;
                    } else {
                        debug!(
                            "[IMAP Cleanup] Expunged {} read UIDs in Drafts for {}",
                            to_clean.len(),
                            email_writer
                        );
                        let cur = inflight_writer.load(Ordering::Relaxed);
                        inflight_writer.fetch_sub(to_clean.len().min(cur), Ordering::Relaxed);
                    }
                }

                // Шаг 2: Управление переполнением (Backpressure раздел 3.7):
                if inflight_writer.load(Ordering::Relaxed) >= max_inflight_batches {
                    tokio::time::sleep(Duration::from_millis(40)).await;
                    let cur = inflight_writer.load(Ordering::Relaxed);
                    if cur > 0 {
                        inflight_writer.fetch_sub(1, Ordering::Relaxed);
                    }
                }

                // Шаг 3: Сначала досылаем пакет, не ушедший перед прошлым обрывом SRV_WRITER (если есть),
                // затем приоритетно отправляем ответы Auth Handshake, затем батчи Data Plane
                let retry_msg = pending_retry_writer.lock().await.take();
                let msg_opt = if retry_msg.is_some() {
                    retry_msg
                } else {
                    tokio::select! {
                        biased;
                        auth_msg = auth_rx_guard.recv() => auth_msg,
                        data_msg = data_rx_guard.recv() => data_msg,
                        _ = tokio::time::sleep(Duration::from_millis(40)) => None,
                    }
                };

                if let Some(msg) = msg_opt {
                    inflight_writer.fetch_add(1, Ordering::Relaxed);
                    let mut writer_guard = writer_for_task.lock().await;
                    let append_res = writer_guard
                        .append_message(
                            "Notes",
                            &msg.subject,
                            &msg.payload,
                            &email_writer,
                            command_timeout,
                        )
                        .await;

                    match append_res {
                        Ok(lat) => {
                            last_tx_instant = Instant::now();
                            last_activity_writer.store(now_epoch_ms(), Ordering::Relaxed);
                            reader_wake_writer.notify_one();
                            debug!(
                                "[IMAP Downlink] APPEND Notes OK in {:.1} ms ({} B)",
                                lat.as_secs_f64() * 1000.0,
                                msg.payload.len()
                            );
                        }
                        Err(e) => {
                            warn!(
                                "[IMAP Downlink] APPEND Notes failed for {}: {e:#}",
                                email_writer
                            );
                            *pending_retry_writer.lock().await = Some(msg);
                            stop_flag_writer.store(true, Ordering::SeqCst);
                            break;
                        }
                    }
                }
            }
        });

        // 4. Запуск SRV_READER (Adaptive Short-IDLE + Greedy Fetch Drain "Drafts" -> Fast Path & Auth Plane)
        let mut last_seen_uid = initial_max_uid;
        let mut force_immediate_fetch = false;
        let reader_email = email.clone();
        info!(
            "[IMAP Server] SRV_READER loop active for {} (Active IDLE: {:?}, Quiet IDLE: {:?})",
            reader_email, idle_active_timeout, idle_quiet_timeout
        );

        while !stop_flag.load(Ordering::Relaxed) {
            // Шаг 1: Адаптивное ожидание через IDLE (или мгновенный пропуск при Greedy Drain / pending_exists)
            if !force_immediate_fetch {
                let since_active_ms =
                    now_epoch_ms().saturating_sub(last_activity_ms.load(Ordering::Relaxed));
                let is_active = since_active_ms <= idle_active_window_ms;
                let cur_idle_timeout = if is_active {
                    idle_active_timeout
                } else {
                    idle_quiet_timeout
                };
                let wake_opt = if is_active {
                    None
                } else {
                    Some(reader_wake_notify.as_ref())
                };

                if let Err(e) = srv_reader.wait_idle_or_wake(cur_idle_timeout, wake_opt).await {
                    warn!(
                        "[IMAP Server] SRV_READER wait_idle_or_wake error for {}: {e:#}",
                        reader_email
                    );
                    break;
                }
            }
            force_immediate_fetch = false;

            if stop_flag.load(Ordering::Relaxed) {
                break;
            }

            // Шаг 2: Выборка новых сообщений из папки "Drafts" (Greedy Fetch Drain)
            let fetch_res = srv_reader
                .fetch_messages_robust(last_seen_uid, command_timeout)
                .await;
            if srv_reader.pending_exists {
                srv_reader.pending_exists = false;
                force_immediate_fetch = true;
            }

            match fetch_res {
                Ok(res) => {
                    last_seen_uid = res.new_max_uid;
                    if !res.messages.is_empty() {
                        last_activity_ms.store(now_epoch_ms(), Ordering::Relaxed);
                    }

                    for msg in res.messages {
                        let Some((msg_srv_id, cli_token)) = extract_srv_and_cli_token(&msg.subject)
                        else {
                            continue;
                        };

                        if msg_srv_id != srv_id {
                            continue;
                        }

                        // Добавляем UID в очередь очистки для SRV_WRITER
                        {
                            let mut guard = cleanup_uids.lock().await;
                            guard.push(msg.uid);
                        }

                        // Подтверждение живого входящего трафика от клиента снижает счетчик in-flight Downlink
                        let cur_inf = inflight_downlink.load(Ordering::Relaxed);
                        if cur_inf > 0 {
                            inflight_downlink.fetch_sub(1, Ordering::Relaxed);
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
                            let decrypted_res = match unwrap_packet(&client_info.cipher, &msg.payload) {
                                Ok(batch) => Ok(batch),
                                Err(first_err) => {
                                    // Если клиент переподключился с resume_session_id через другой воркер и сменил DH-ключ,
                                    // синхронизируем свежий ClientTransportInfo из глобального реестра.
                                    if let Some(fresh_info) = registry.get_by_session(cli_token) {
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

                            if let Ok(decrypted_batch) = decrypted_res
                            {
                                for pkt in unpack_batch(&decrypted_batch) {
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

                                    let (tx_router, rx_router) =
                                        mpsc::channel::<Bytes>(tx_queue_capacity);
                                    registry.finalize_client(&assigned_ip, tx_router);

                                    info!(
                                        "[IMAP Server] Client {} authenticated via IMAP! Assigned IP: {}, Session: {}",
                                        cli_token, assigned_ip, session_id
                                    );

                                    // Запускаем фоновую задачу Self-Clocking Downlink-батчера для этого клиента
                                    // (живет до закрытия rx_router при дисконнекте/перерегистрации клиента и переживает реконнекты IMAP-воркера)
                                    let writer_tx = notes_data_tx.clone();
                                    let c_info = client_info.clone();
                                    let max_batch_bytes =
                                        (config.imap.max_batch_kb.clamp(8, 512)) * 1024;
                                    let coalesce_ms = config.imap.batch_coalesce_ms.clamp(5, 100);

                                    tokio::spawn(async move {
                                        run_client_downlink_batcher(
                                            rx_router,
                                            c_info,
                                            writer_tx,
                                            max_batch_bytes,
                                            coalesce_ms,
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
                        "[IMAP Server] SRV_READER UID FETCH error for {}: {e:#}",
                        reader_email
                    );
                    break;
                }
            }
        }

        stop_flag.store(true, Ordering::SeqCst);
        writer_task.abort();
        let _ = writer_task.await;
        let _ = srv_reader.exit_idle(Duration::from_millis(200)).await;
        let _ = srv_reader.send_line("A9999 LOGOUT").await;

        warn!(
            "[IMAP Server] Worker pair for {} ended. Reconnecting in {:?}...",
            email, throttle_backoff
        );
        tokio::time::sleep(throttle_backoff).await;
    }
}

/// Фоновая задача Self-Clocking сборки Downlink-пакетов из `rx_router` (TUN) в `PacketBatcher`
/// (раздел 3.3 спецификации):
/// 1. Ждет первый пакет из `rx_router`;
/// 2. Дожидается освобождения слота `SRV_WRITER` (`notes_data_tx.reserve().await`);
/// 3. Выгребает ВСЕ накопившиеся за время предыдущего `APPEND` (~450 мс) пакеты из `rx_router`
///    до `max_batch_bytes` (включая крупные батчи 128..512 КБ, приоритезируя ICMP/DNS/ACK в начало батча);
/// 4. Шифрует весь буфер одним вызовом `wrap_packet_slice` и передает в `SRV_WRITER`.
async fn run_client_downlink_batcher(
    mut rx_router: mpsc::Receiver<Bytes>,
    client_info: Arc<ClientTransportInfo>,
    notes_data_tx: mpsc::Sender<DownlinkMessage>,
    max_batch_bytes: usize,
    coalesce_ms: u64,
) {
    let mut batcher = PacketBatcher::new(max_batch_bytes, coalesce_ms);
    let subject = format!("[ID: {}]", client_info.session_id);

    loop {
        // 1. Если батчер пуст — ждем первый пакет из rx_router
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

            // Ждем микро-окно coalesce_ms (10–15 мс) для сбора стартового бурста
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
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        }

        // 2. Ждем готовности SRV_WRITER (пока идет текущий APPEND ~450 мс или реконнект воркера, новые пакеты копятся в rx_router!)
        let Ok(permit) = notes_data_tx.reserve().await else {
            break;
        };

        // 3. Как только SRV_WRITER освободился — выгребаем все накопившиеся за эти ~450 мс пакеты до max_batch_bytes!
        while batcher.current_bytes() < max_batch_bytes {
            match rx_router.try_recv() {
                Ok(pkt) => {
                    if pkt.len() >= 20 {
                        batcher.push(pkt);
                    }
                }
                Err(_) => break,
            }
        }

        // 4. Шифруем собранный батч одним вызовом wrap_packet_slice и отправляем через SRV_WRITER
        if let Some(raw_batch) = batcher.flush() {
            let seq = client_info.sequence.fetch_add(1, Ordering::Relaxed);
            if let Ok(encrypted_bytes) = wrap_packet_slice(
                &client_info.cipher,
                &client_info.nonce_prefix,
                seq,
                &raw_batch,
                0,
            ) {
                permit.send(DownlinkMessage {
                    subject: subject.clone(),
                    payload: encrypted_bytes,
                });
            }
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
        use anet_common::encryption::Cipher;
        use arc_swap::{ArcSwap, ArcSwapOption};
        use std::sync::OnceLock;

        let (tx_router, rx_router) = mpsc::channel::<Bytes>(64);
        let (notes_data_tx, notes_data_rx) = mpsc::channel::<DownlinkMessage>(1);
        let notes_data_rx = Arc::new(Mutex::new(notes_data_rx));

        let cipher = Arc::new(Cipher::new(&[0x42u8; 32]));
        let client_info = Arc::new(ClientTransportInfo {
            cipher: cipher.clone(),
            sequence: Arc::new(AtomicU64::new(0)),
            assigned_ip: "10.0.0.2".to_string(),
            session_id: "sess_persist".to_string(),
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
        });

        let batcher_handle = tokio::spawn(run_client_downlink_batcher(
            rx_router,
            client_info,
            notes_data_tx,
            131_072,
            5,
        ));

        // 1. Первая сессия воркера читает первый батч и затем «обрывается» (abort)
        let rx_clone1 = notes_data_rx.clone();
        let writer1 = tokio::spawn(async move {
            let mut guard = rx_clone1.lock().await;
            guard.recv().await.unwrap()
        });

        tx_router.send(Bytes::from(vec![0x45u8; 40])).await.unwrap();
        let msg1 = writer1.await.unwrap();
        assert_eq!(msg1.subject, "[ID: sess_persist]");
        let dec1 = unwrap_packet(&cipher, &msg1.payload).unwrap();
        assert_eq!(unpack_batch(&dec1).len(), 1);

        // 2. Вторая сессия воркера после реконнекта подхватывает тот же notes_data_rx
        // и получает следующий батч от того же клиентского батчера!
        let rx_clone2 = notes_data_rx.clone();
        let writer2 = tokio::spawn(async move {
            let mut guard = rx_clone2.lock().await;
            guard.recv().await.unwrap()
        });

        tx_router.send(Bytes::from(vec![0x45u8; 60])).await.unwrap();
        let msg2 = writer2.await.unwrap();
        assert_eq!(msg2.subject, "[ID: sess_persist]");
        let dec2 = unwrap_packet(&cipher, &msg2.payload).unwrap();
        let unpacked2 = unpack_batch(&dec2);
        assert_eq!(unpacked2.len(), 1);
        assert_eq!(unpacked2[0].len(), 60);

        drop(tx_router);
        batcher_handle.await.unwrap();
    }
}
