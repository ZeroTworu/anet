// anet-server/src/servers/imap.rs
//! Транспорт IMAP на стороне сервера (ASTP over IMAPS:993).
//!
//! Реализует разделы 5 и 7.3 документа `contrib/docs/imap.ru.md`:
//! - Супервизор пула почтовых ящиков из `imap_dsn`;
//! - Архитектура «Cross-Selected Writer» на стороне сервера:
//!   - `SRV_READER` делает `SELECT "Drafts"`, читает Uplink-сообщения клиентов через `wait_idle_or_event()`
//!     и передает прочитанные UIDs в локальный канал очистки;
//!   - `SRV_WRITER` делает `SELECT "Drafts"` один раз при старте, отправляет Downlink-сообщения
//!     через `APPEND "Notes" (\Seen \Draft)`, а в паузах удаляет прочитанные письма в `"Drafts"`
//!     через `UID STORE` + `UID EXPUNGE` без переключения папок;
//! - Виртуальные сокеты через `fake_addr_from_cli_id` для безопасного связывания с `ServerAuthHandler`;
//! - Fast-path для установленных сессий (`session_id`) и Auth-plane для фаз рукопожатия (`Client_TempID`).

use crate::auth_handler::ServerAuthHandler;
use crate::client_registry::{ClientRegistry, ClientTransportInfo};
use crate::config::Config;
use anet_common::batcher::{unpack_batch, PacketBatcher};
use anet_common::consts::CHANNEL_BUFFER_SIZE;
use anet_common::imap_conn::ImapConn;
use anet_common::transport::{unwrap_packet, wrap_packet_slice};
use anyhow::{anyhow, Context, Result};
use base64::prelude::*;
use bytes::Bytes;
use dashmap::DashMap;
use log::{debug, error, info, warn};
use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};

const DEFAULT_IMAP_PORT: u16 = 993;
const MAX_INFLIGHT_DOWNLINK: usize = 15;

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
        "[IMAP Server] Initializing IMAP Transport on {}:{} with {} mailbox(es)...",
        host,
        port,
        accounts.len()
    );

    let sk_bytes = BASE64_STANDARD.decode(&config.crypto.server_signing_key)?;
    let sign_key = ed25519_dalek::SigningKey::from_bytes(&sk_bytes.try_into().unwrap());
    let srv_id = compute_hex_id(&sign_key.verifying_key().to_bytes());
    let safe_base_ip = get_safe_fake_base(&config.network.net);

    info!(
        "[IMAP Server] Server ID: {} | Virtual socket base: {}",
        srv_id, safe_base_ip
    );

    // Локальная карта активных сессий (session_id -> ClientTransportInfo)
    let local_sessions: Arc<DashMap<String, Arc<ClientTransportInfo>>> = Arc::new(DashMap::new());

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
    local_sessions: Arc<DashMap<String, Arc<ClientTransportInfo>>>,
) {
    let email = account.email.clone();
    let command_timeout = Duration::from_millis(config.imap.command_timeout_ms.max(5000));
    let idle_timeout = Duration::from_millis(config.imap.idle_refresh_interval_ms.max(10000));
    let throttle_backoff = Duration::from_millis(config.imap.throttle_backoff_ms.max(5000));
    let tls_cfg = config.stealth.to_tls_client_config();

    info!("[IMAP Mailbox] Starting worker pair for account {}", email);

    loop {
        // Канал очереди сообщений на отправку через SRV_WRITER в папку "Notes"
        let (notes_append_tx, mut notes_append_rx) =
            mpsc::channel::<DownlinkMessage>(CHANNEL_BUFFER_SIZE);

        // Список UIDs сообщений в папке "Drafts", прочитанных SRV_READER и готовых к удалению
        let cleanup_uids: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let stop_flag = Arc::new(AtomicBool::new(false));

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
            Ok(conn) => conn,
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

        let initial_max_uid = srv_reader
            .get_max_uid(command_timeout)
            .await
            .unwrap_or(0);
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
            Ok(conn) => conn,
            Err(e) => {
                warn!(
                    "[IMAP Server] SRV_WRITER connect failed for {}: {e:#}. Backing off {:?}...",
                    email, throttle_backoff
                );
                tokio::time::sleep(throttle_backoff).await;
                continue;
            }
        };

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

        // 3. Запуск SRV_WRITER (Downlink APPEND "Notes" + Неблокирующий UID EXPUNGE в "Drafts")
        let writer_for_task = writer_mutex.clone();
        let email_writer = email.clone();
        let cleanup_uids_writer = cleanup_uids.clone();
        let stop_flag_writer = stop_flag.clone();

        let writer_task = tokio::spawn(async move {
            info!("[IMAP Server] SRV_WRITER loop active for {}", email_writer);

            while !stop_flag_writer.load(Ordering::Relaxed) {
                // 1. Ожидаем очередное сообщение Downlink с таймаутом 20 мс для проверки очереди очистки
                let msg_opt = tokio::select! {
                    msg = notes_append_rx.recv() => msg,
                    _ = tokio::time::sleep(Duration::from_millis(20)) => None,
                };

                if let Some(msg) = msg_opt {
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
                            debug!(
                                "[IMAP Downlink] APPEND Notes OK in {:.1} ms ({} B)",
                                lat.as_secs_f64() * 1000.0,
                                msg.payload.len()
                            );
                        }
                        Err(e) => {
                            warn!("[IMAP Downlink] APPEND Notes failed for {}: {e:#}", email_writer);
                        }
                    }
                }

                // 2. Неблокирующая сборка мусора в паузах:
                // Выполняем точечный UID EXPUNGE в текущей выбранной папке "Drafts",
                // когда очередь отправки пуста, либо накопилось >= 20 прочитанных UIDs
                let to_clean = {
                    let mut guard = cleanup_uids_writer.lock().await;
                    if (notes_append_rx.is_empty() && !guard.is_empty()) || guard.len() >= 20 {
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
                        debug!("[IMAP Cleanup] Non-blocking UID EXPUNGE in Drafts: {e}");
                    } else {
                        debug!(
                            "[IMAP Cleanup] Expunged {} read UIDs in Drafts for {}",
                            to_clean.len(),
                            email_writer
                        );
                    }
                }
            }
        });

        // 4. Запуск SRV_READER (IDLE / FETCH "Drafts" -> Fast Path & Auth Plane)
        let mut last_seen_uid = initial_max_uid;
        let reader_email = email.clone();
        info!("[IMAP Server] SRV_READER loop active for {}", reader_email);

        while !stop_flag.load(Ordering::Relaxed) {
            // Шаг 1: Активное ожидание через IDLE (или мгновенный пропуск, если pending_exists == true)
            if let Err(e) = srv_reader.wait_idle_or_event(idle_timeout).await {
                warn!(
                    "[IMAP Server] SRV_READER wait_idle_or_event error for {}: {e:#}",
                    reader_email
                );
                tokio::time::sleep(Duration::from_millis(200)).await;
            }

            if stop_flag.load(Ordering::Relaxed) {
                break;
            }

            // Шаг 2: Выборка новых сообщений из папки "Drafts"
            let fetch_res = srv_reader
                .fetch_messages_robust(last_seen_uid, command_timeout)
                .await;

            match fetch_res {
                Ok(res) => {
                    last_seen_uid = res.new_max_uid;

                    for msg in res.messages {
                        // Извлекаем srv_id и cli_token из темы:
                        // Subject: {Prefix} [ID: <srv_id>:<cli_token>]
                        let Some((msg_srv_id, cli_token)) = extract_srv_and_cli_token(&msg.subject)
                        else {
                            continue;
                        };

                        if msg_srv_id != srv_id {
                            // Сообщение адресовано другому серверу в общем ящике
                            continue;
                        }

                        // Добавляем UID в очередь очистки для SRV_WRITER
                        {
                            let mut guard = cleanup_uids.lock().await;
                            guard.push(msg.uid);
                        }

                        // 1. FAST PATH (Установленная сессия Data Plane, cli_token == session_id)
                        let client_info_opt = local_sessions
                            .get(cli_token)
                            .map(|e| e.value().clone())
                            .or_else(|| {
                                let info = registry.get_by_session(cli_token)?;
                                local_sessions.insert(cli_token.to_string(), info.clone());
                                Some(info)
                            });

                        if let Some(client_info) = client_info_opt {
                            // Обновляем таймер последней активности для сторожевого таймера
                            registry.touch_client(&client_info);

                            // Дешифруем ASTP батч
                            if let Ok(decrypted_batch) =
                                unwrap_packet(&client_info.cipher, &msg.payload)
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
                                    if tun_tx.try_send(pkt).is_ok() {
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
                                // Если завершилась Фаза 3 (получена регистрация клиента):
                                if let Some((client_info, _auth_response)) = auth_tuple_opt {
                                    let assigned_ip = client_info.assigned_ip.clone();
                                    let session_id = client_info.session_id.clone();
                                    local_sessions
                                        .insert(session_id.clone(), client_info.clone());

                                    let (tx_router, rx_router) =
                                        mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
                                    registry.finalize_client(&assigned_ip, tx_router);

                                    info!(
                                        "[IMAP Server] Client {} authenticated via IMAP! Assigned IP: {}, Session: {}",
                                        cli_token, assigned_ip, session_id
                                    );

                                    // Запускаем фоновую задачу Downlink-батчера для этого клиента
                                    let writer_tx = notes_append_tx.clone();
                                    let c_info = client_info.clone();
                                    let max_batch_bytes =
                                        (config.imap.max_batch_kb.clamp(8, 128)) * 1024;
                                    let coalesce_ms =
                                        config.imap.batch_coalesce_ms.clamp(5, 50);
                                    let stop_flag_client = stop_flag.clone();

                                    tokio::spawn(async move {
                                        run_client_downlink_batcher(
                                            rx_router,
                                            c_info,
                                            writer_tx,
                                            max_batch_bytes,
                                            coalesce_ms,
                                            stop_flag_client,
                                        )
                                        .await;
                                    });
                                }

                                // Отправляем ответ хендшейка (Фаза 2 или Фаза 4) в папку "Notes":
                                // Тема: Subject: [ID: <Client_TempID>]
                                if let Some(response_bytes) = response_opt {
                                    let reply_subject = format!("[ID: {}]", cli_token);
                                    let _ = notes_append_tx
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
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }

        stop_flag.store(true, Ordering::SeqCst);
        writer_task.abort();
        let _ = srv_reader.exit_idle(Duration::from_millis(200)).await;
        let _ = srv_reader.send_line("A9999 LOGOUT").await;

        warn!(
            "[IMAP Server] Worker pair for {} ended. Reconnecting in {:?}...",
            email, throttle_backoff
        );
        tokio::time::sleep(throttle_backoff).await;
    }
}

/// Фоновая задача сборки Downlink-пакетов из `rx_router` (TUN) в `PacketBatcher`
/// и отправка их через `notes_append_tx` в `SRV_WRITER` (APPEND "Notes")
async fn run_client_downlink_batcher(
    mut rx_router: mpsc::Receiver<Bytes>,
    client_info: Arc<ClientTransportInfo>,
    notes_append_tx: mpsc::Sender<DownlinkMessage>,
    max_batch_bytes: usize,
    coalesce_ms: u64,
    stop_flag: Arc<AtomicBool>,
) {
    let mut batcher = PacketBatcher::new(max_batch_bytes, coalesce_ms);
    let mut coalesce_interval = tokio::time::interval(Duration::from_millis(coalesce_ms));
    coalesce_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let subject = format!("[ID: {}]", client_info.session_id);

    while !stop_flag.load(Ordering::Relaxed) {
        tokio::select! {
            biased;
            packet_opt = rx_router.recv() => {
                match packet_opt {
                    Some(packet) => {
                        if packet.len() >= 20 {
                            batcher.push(packet);
                            // Выгребаем все доступные пакеты текущего бурста
                            while let Ok(next_p) = rx_router.try_recv() {
                                if next_p.len() >= 20 {
                                    batcher.push(next_p);
                                }
                                if batcher.should_flush() {
                                    break;
                                }
                            }
                        }
                    }
                    None => break, // Клиент отключен
                }
            }
            _ = coalesce_interval.tick() => {}
        }

        if !batcher.is_empty() {
            if let Some(raw_batch) = batcher.flush() {
                let seq = client_info.sequence.fetch_add(1, Ordering::Relaxed);
                if let Ok(encrypted_bytes) = wrap_packet_slice(
                    &client_info.cipher,
                    &client_info.nonce_prefix,
                    seq,
                    &raw_batch,
                    0,
                ) {
                    if notes_append_tx
                        .send(DownlinkMessage {
                            subject: subject.clone(),
                            payload: encrypted_bytes,
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
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

        // Детерминированность: одинаковый ID дает одинаковый SocketAddr
        assert_eq!(addr1, addr2);
        // Разные ID дают разные адреса
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
}
