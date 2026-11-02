use super::{ClientTransport, ConnectionResult};
use crate::auth::{AuthChannel, AuthHandler};
use crate::config::{CoreConfig, ServerConfig};
use anet_common::batcher::{unpack_batch, PacketBatcher};
use anet_common::consts::{CHANNEL_BUFFER_SIZE, COALESCE_BUDGET_BYTES};
use anet_common::encryption::Cipher;
use anet_common::handshake_fragmentation::FragmentConfig;
use anet_common::imap_conn::{compute_hex_id, ImapConn};
use anet_common::stream_framing::{frame_packet_into, FrameReader};
use anet_common::transport::wrap_packet_slice;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use base64::prelude::*;
use bytes::{Bytes, BytesMut};
use log::{debug, info, warn};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex, RwLock};

const DEFAULT_IMAP_PORT: u16 = 993;
const MAX_INFLIGHT_APPENDS: usize = 15;

/// Декодирование процентного кодирования URL (например %40 -> @) без внешних крейтов
fn percent_decode(input: &str) -> String {
    let mut bytes = Vec::with_capacity(input.len());
    let mut chars = input.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            if let (Some(h1), Some(h2)) = (chars.next(), chars.next()) {
                let hex = [h1, h2];
                if let Ok(s) = std::str::from_utf8(&hex) {
                    if let Ok(byte) = u8::from_str_radix(s, 16) {
                        bytes.push(byte);
                        continue;
                    }
                }
                bytes.push(b'%');
                bytes.push(h1);
                bytes.push(h2);
            } else {
                bytes.push(b'%');
            }
        } else if b == b'+' {
            bytes.push(b' ');
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8_lossy(&bytes).to_string()
}

#[derive(Debug, Clone)]
pub struct ImapAccount {
    pub email: String,
    pub password: String,
}

/// Активное криптографическое состояние сессии (обновляется атомарно при бесшовном Failover ящика)
struct ActiveImapSessionState {
    pub session_id: String,
    pub cipher: Arc<Cipher>,
    pub nonce_prefix: [u8; 4],
}

pub struct ImapTransport {
    config: CoreConfig,
    server: ServerConfig,
}

impl ImapTransport {
    pub fn new(config: CoreConfig, server: ServerConfig) -> Self {
        Self { config, server }
    }

    /// Парсит список аккаунтов из DSN:
    /// 1. Query-параметры `?acc=email1:pass1&acc=email2:pass2`
    /// 2. Имя пользователя и пароль из URI: `imap://user:pass@host:993`
    fn parse_accounts(&self) -> Result<Vec<ImapAccount>> {
        let mut accounts = Vec::new();
        let uri: http::Uri = self
            .server
            .dsn
            .parse()
            .with_context(|| format!("Invalid IMAP DSN: {}", self.server.dsn))?;

        // 1. Проверяем query-параметры
        if let Some(query) = uri.query() {
            for pair in query.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    if k.eq_ignore_ascii_case("acc") {
                        let decoded = percent_decode(v);
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

        // 2. Если в query аккаунты не найдены, извлекаем authority (user:pass)
        if accounts.is_empty() {
            if let Some(authority) = uri.authority() {
                let auth_str = authority.as_str();
                if let Some((user_info, _host_part)) = auth_str.split_once('@') {
                    if let Some((user, pass)) = user_info.split_once(':') {
                        let email = percent_decode(user);
                        let password = percent_decode(pass);
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
                "No IMAP credentials found in DSN '{}'. Expected ?acc=user%40mail.ru:pass or imap://user:pass@host",
                self.server.dsn
            ));
        }

        Ok(accounts)
    }

    /// Резолвит хост IMAP-сервера и возвращает основной `SocketAddr` + полный список всех IP для `bypass_ips` (раздел 7.2 п. 1).
    fn resolve_target_addresses(&self) -> Result<(String, u16, SocketAddr, Vec<IpAddr>)> {
        let (host, port) = self.server.host_port()?;
        let port = if port == 0 { DEFAULT_IMAP_PORT } else { port };

        let addrs: Vec<SocketAddr> = format!("{}:{}", host, port)
            .to_socket_addrs()
            .with_context(|| format!("Failed to resolve IMAP host {}:{}", host, port))?
            .collect();

        let primary = *addrs
            .first()
            .ok_or_else(|| anyhow!("No IP addresses found for {}:{}", host, port))?;

        let mut bypass_ips = Vec::with_capacity(addrs.len());
        for a in addrs {
            if !bypass_ips.contains(&a.ip()) {
                bypass_ips.push(a.ip());
            }
        }

        Ok((host, port, primary, bypass_ips))
    }
}

/// Адаптер `AuthChannel` для выполнения ASTP Handshake через IMAP (Фазы 1–4)
struct ImapAuthChannel {
    writer: Arc<Mutex<ImapConn>>,
    reader: Arc<Mutex<ImapConn>>,
    account_email: String,
    srv_id: String,
    client_temp_id: String,
    timeout_dur: Duration,
    last_reader_uid: Arc<Mutex<u32>>,
}

#[async_trait]
impl AuthChannel for ImapAuthChannel {
    async fn send(&self, data: Bytes, _frag: &FragmentConfig) -> Result<()> {
        let subject = format!("ANet-Data [ID: {}:{}]", self.srv_id, self.client_temp_id);
        let mut writer_guard = self.writer.lock().await;

        writer_guard
            .append_message(
                "Drafts",
                &subject,
                &data,
                &self.account_email,
                self.timeout_dur,
            )
            .await
            .context("Failed to send ASTP handshake message via APPEND Drafts")?;

        info!("[IMAP Auth] Sent handshake burst ({}) to Drafts", subject);
        Ok(())
    }

    async fn recv(&self, timeout: Duration) -> Result<Bytes> {
        let deadline = Instant::now() + timeout;
        let expected_tag = format!("[ID: {}]", self.client_temp_id);

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(anyhow!("Timeout waiting for ASTP handshake response in Notes"));
            }

            let mut reader_guard = self.reader.lock().await;
            let last_uid = *self.last_reader_uid.lock().await;

            // Проверяем новые сообщения
            let fetch_res = reader_guard
                .fetch_messages_robust(last_uid, self.timeout_dur.min(remaining))
                .await?;

            *self.last_reader_uid.lock().await = fetch_res.new_max_uid;

            for msg in fetch_res.messages {
                if msg.subject.contains(&expected_tag) {
                    info!(
                        "[IMAP Auth] Received matching handshake response (UID: {}, len: {} B)",
                        msg.uid,
                        msg.payload.len()
                    );
                    return Ok(msg.payload);
                }
            }

            // Ждем следующее событие через IDLE
            let wait_dur = remaining.min(Duration::from_secs(5));
            let _ = reader_guard.wait_idle_or_pending(wait_dur).await;
        }
    }
}

/// Устанавливает пару соединений `CLI_WRITER` + `CLI_READER` (Cross-Selected на папку `"Notes"`)
/// и выполняет ASTP-рукопожатие (с поддержкой `resume_session_id` при бесшовном Failover ящика).
async fn establish_mailbox_session(
    host: &str,
    port: u16,
    account: &ImapAccount,
    tls_cfg: &anet_common::boring_tls::TlsClientConfig,
    command_timeout: Duration,
    srv_id: &str,
    client_temp_id: &str,
    core_cfg: &CoreConfig,
    server_pub_key_override: Option<&str>,
    resume_session_id: Option<String>,
) -> Result<(
    ImapConn,
    ImapConn,
    u32,
    anet_common::protocol::AuthResponse,
    [u8; 32],
)> {
    // 1. Подключаем CLI_WRITER (Архитектура Cross-Selected: делает SELECT "Notes" один раз!)
    let mut cli_writer = ImapConn::connect(
        host,
        port,
        &account.email,
        &account.password,
        tls_cfg,
        command_timeout,
    )
    .await
    .with_context(|| format!("Failed to connect CLI_WRITER for {}", account.email))?;

    cli_writer
        .select("Notes", command_timeout)
        .await
        .with_context(|| format!("CLI_WRITER failed to SELECT 'Notes' for {}", account.email))?;

    // 2. Подключаем CLI_READER (делает SELECT "Notes" и замеряет baseline max_uid через UID FETCH * (UID))
    let mut cli_reader = ImapConn::connect(
        host,
        port,
        &account.email,
        &account.password,
        tls_cfg,
        command_timeout,
    )
    .await
    .with_context(|| format!("Failed to connect CLI_READER for {}", account.email))?;

    cli_reader
        .select("Notes", command_timeout)
        .await
        .with_context(|| format!("CLI_READER failed to SELECT 'Notes' for {}", account.email))?;

    let initial_max_uid = cli_reader.get_max_uid(command_timeout).await.unwrap_or(0);
    info!(
        "[IMAP Client] CLI_WRITER & CLI_READER initialized for {} (SELECT 'Notes', baseline UID: {})",
        account.email, initial_max_uid
    );

    let writer_mutex = Arc::new(Mutex::new(cli_writer));
    let reader_mutex = Arc::new(Mutex::new(cli_reader));
    let last_uid_mutex = Arc::new(Mutex::new(initial_max_uid));

    let auth_channel = ImapAuthChannel {
        writer: writer_mutex.clone(),
        reader: reader_mutex.clone(),
        account_email: account.email.clone(),
        srv_id: srv_id.to_string(),
        client_temp_id: client_temp_id.to_string(),
        timeout_dur: command_timeout,
        last_reader_uid: last_uid_mutex.clone(),
    };

    let auth_handler = AuthHandler::new_with_resume(core_cfg, server_pub_key_override, resume_session_id)?;
    let (auth_response, shared_key) = auth_handler.authenticate_once(&auth_channel).await?;
    let final_uid = *last_uid_mutex.lock().await;

    let cli_writer = Arc::try_unwrap(writer_mutex)
        .map_err(|_| anyhow!("Writer mutex still referenced"))?
        .into_inner();
    let cli_reader = Arc::try_unwrap(reader_mutex)
        .map_err(|_| anyhow!("Reader mutex still referenced"))?
        .into_inner();

    Ok((cli_writer, cli_reader, final_uid, auth_response, shared_key))
}

#[async_trait]
impl ClientTransport for ImapTransport {
    async fn connect(&self) -> Result<ConnectionResult> {
        let accounts = self.parse_accounts()?;
        let (host, port, target_addr, bypass_ips) = self.resolve_target_addresses()?;

        let tls_cfg = self.server.effective_tls_config(&self.config.stealth);
        let command_timeout = Duration::from_millis(self.config.imap.command_timeout_ms.max(5000));
        let idle_timeout = Duration::from_millis(self.config.imap.idle_refresh_interval_ms.max(10000));
        let coalesce_ms = self.config.imap.batch_coalesce_ms.clamp(5, 50);
        let max_batch_bytes = (self.config.imap.max_batch_kb.clamp(8, 128)) * 1024;
        let throttle_backoff = Duration::from_millis(self.config.imap.throttle_backoff_ms.max(5000));

        // Вычисляем SRV_ID и Client_TempID для хендшейка (раздел 4 спецификации)
        let server_pub_key_str = self
            .server
            .server_pub_key
            .as_deref()
            .unwrap_or(&self.config.keys.server_pub_key);
        let server_pub_bytes = BASE64_STANDARD
            .decode(server_pub_key_str.trim())
            .context("Failed to decode server_pub_key")?;
        let srv_id = compute_hex_id(&server_pub_bytes);

        let client_priv_bytes = BASE64_STANDARD
            .decode(&self.config.keys.private_key)
            .context("Failed to decode client private_key")?;
        let client_temp_id = compute_hex_id(&client_priv_bytes);

        info!(
            "[IMAP Client] Handshake IDs: SRV_ID={}, Client_TempID={} | Pool accounts: {}",
            srv_id,
            client_temp_id,
            accounts.len()
        );

        // Первичное подключение с перебором ящиков при ошибке авторизации/соединения (Failover раздел 8 п. 8)
        let mut active_idx = 0usize;
        let mut initial_session = None;
        let mut last_err = None;

        for idx in 0..accounts.len() {
            let acc = &accounts[idx];
            info!(
                "[IMAP Client] Connecting to {}:{} via BoringSSL Email Mimicry (Account [{}/{}]: {})",
                host,
                port,
                idx + 1,
                accounts.len(),
                acc.email
            );
            match establish_mailbox_session(
                &host,
                port,
                acc,
                &tls_cfg,
                command_timeout,
                &srv_id,
                &client_temp_id,
                &self.config,
                self.server.server_pub_key.as_deref(),
                None,
            )
            .await
            {
                Ok(res) => {
                    active_idx = idx;
                    initial_session = Some(res);
                    break;
                }
                Err(e) => {
                    warn!(
                        "[IMAP Client] Account {} failed during initial connect/auth: {e:#}. Trying next mailbox...",
                        acc.email
                    );
                    last_err = Some(e);
                }
            }
        }

        let (cli_writer, cli_reader, initial_max_uid, auth_response, shared_key) =
            match initial_session {
                Some(s) => s,
                None => {
                    return Err(last_err.unwrap_or_else(|| {
                        anyhow!("All IMAP mailboxes failed during initial connect")
                    }))
                }
            };

        let session_id = auth_response.session_id.clone();
        info!(
            "[IMAP Client] ASTP Authentication successful on {}! Assigned IP: {}, Session: {}",
            accounts[active_idx].email, auth_response.ip, session_id
        );

        // Создаем локальный дуплексный канал связи с VPN TUN-стеком (раздел 7.2 п. 4)
        let (client_stream, internal_router) = tokio::io::duplex(512 * 1024);
        let (mut tunnel_read, mut tunnel_write) = tokio::io::split(internal_router);

        let nonce_prefix: [u8; 4] = auth_response
            .nonce_prefix
            .as_slice()
            .try_into()
            .context("Invalid nonce prefix in AuthResponse")?;

        let session_state = Arc::new(RwLock::new(ActiveImapSessionState {
            session_id: session_id.clone(),
            cipher: Arc::new(Cipher::new(&shared_key)),
            nonce_prefix,
        }));

        let writer_mutex = Arc::new(Mutex::new(cli_writer));
        let reader_mutex = Arc::new(Mutex::new(cli_reader));
        let active_email = Arc::new(RwLock::new(accounts[active_idx].email.clone()));
        let last_seen_uid_shared = Arc::new(AtomicU64::new(initial_max_uid as u64));

        let sequence = Arc::new(AtomicU64::new(0));
        let cleanup_uids = Arc::new(Mutex::new(Vec::<u32>::new()));
        let inflight_count = Arc::new(AtomicUsize::new(0));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let failover_needed = Arc::new(AtomicBool::new(false));
        let rate_limited_flag = Arc::new(AtomicBool::new(false));

        // Очередь пакетов из TUN для честной Self-Clocking коалесценции (раздел 3.3):
        // пока CLI_WRITER занят выполнением APPEND (~320 мс), задача tun_reader_task
        // непрерывно вычитывает пакеты из tunnel_read в tx_queue.
        let (tx_queue_sender, mut tx_queue) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
        let stop_tun_reader = stop_flag.clone();

        let tun_reader_task = tokio::spawn(async move {
            let mut frame_reader = FrameReader::new();
            while !stop_tun_reader.load(Ordering::Relaxed) {
                match frame_reader.read_next_packet(&mut tunnel_read).await {
                    Ok(Some(packet)) => {
                        if packet.len() >= 20 && tx_queue_sender.send(packet).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        info!("[IMAP Uplink] TUN stream closed (EOF)");
                        break;
                    }
                    Err(e) => {
                        warn!("[IMAP Uplink] Error reading from TUN stream: {e}");
                        break;
                    }
                }
            }
            stop_tun_reader.store(true, Ordering::SeqCst);
        });

        // Фоновый супервизор бесшовного Failover ящиков (раздел 8 п. 8)
        let failover_flag_sup = failover_needed.clone();
        let rate_limit_sup = rate_limited_flag.clone();
        let stop_sup = stop_flag.clone();
        let writer_sup = writer_mutex.clone();
        let reader_sup = reader_mutex.clone();
        let email_sup = active_email.clone();
        let uid_sup = last_seen_uid_shared.clone();
        let cleanup_sup = cleanup_uids.clone();
        let inflight_sup = inflight_count.clone();
        let session_state_sup = session_state.clone();
        let accounts_sup = accounts.clone();
        let host_sup = host.clone();
        let tls_cfg_sup = tls_cfg.clone();
        let srv_id_sup = srv_id.clone();
        let client_temp_id_sup = client_temp_id.clone();
        let core_cfg_sup = self.config.clone();
        let srv_pub_override_sup = self.server.server_pub_key.clone();

        let failover_task = tokio::spawn(async move {
            let mut current_idx = active_idx;
            while !stop_sup.load(Ordering::Relaxed) {
                if !failover_flag_sup.load(Ordering::Acquire) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }

                let was_throttled = rate_limit_sup.swap(false, Ordering::SeqCst);
                if was_throttled && accounts_sup.len() == 1 {
                    warn!(
                        "[IMAP Failover] THROTTLED/OVERQUOTA on single mailbox, backing off {:?}...",
                        throttle_backoff
                    );
                    tokio::time::sleep(throttle_backoff).await;
                }

                let resume_sid = session_state_sup.read().await.session_id.clone();
                let mut reconnected = false;

                for step in 1..=accounts_sup.len() {
                    if stop_sup.load(Ordering::Relaxed) {
                        return;
                    }
                    let next_idx = (current_idx + step) % accounts_sup.len();
                    let next_acc = &accounts_sup[next_idx];
                    info!(
                        "[IMAP Failover] Switching to mailbox [{}/{}]: {} (resume_session_id: {})",
                        next_idx + 1,
                        accounts_sup.len(),
                        next_acc.email,
                        resume_sid
                    );

                    match establish_mailbox_session(
                        &host_sup,
                        port,
                        next_acc,
                        &tls_cfg_sup,
                        command_timeout,
                        &srv_id_sup,
                        &client_temp_id_sup,
                        &core_cfg_sup,
                        srv_pub_override_sup.as_deref(),
                        Some(resume_sid.clone()),
                    )
                    .await
                    {
                        Ok((new_w, new_r, new_uid, new_auth, new_key)) => {
                            if let Ok(new_prefix) = new_auth.nonce_prefix.as_slice().try_into() {
                                {
                                    let mut st = session_state_sup.write().await;
                                    st.session_id = new_auth.session_id;
                                    st.cipher = Arc::new(Cipher::new(&new_key));
                                    st.nonce_prefix = new_prefix;
                                }
                                *writer_sup.lock().await = new_w;
                                *reader_sup.lock().await = new_r;
                                *email_sup.write().await = next_acc.email.clone();
                                uid_sup.store(new_uid as u64, Ordering::SeqCst);
                                cleanup_sup.lock().await.clear();
                                inflight_sup.store(0, Ordering::SeqCst);
                                current_idx = next_idx;
                                failover_flag_sup.store(false, Ordering::Release);
                                info!(
                                    "[IMAP Failover] Seamlessly switched active mailbox to {}",
                                    next_acc.email
                                );
                                reconnected = true;
                                break;
                            }
                        }
                        Err(e) => {
                            warn!(
                                "[IMAP Failover] Failed to switch to mailbox {}: {e:#}",
                                next_acc.email
                            );
                        }
                    }
                }

                if !reconnected {
                    warn!(
                        "[IMAP Failover] All mailboxes failed during failover. Backing off {:?}...",
                        throttle_backoff
                    );
                    tokio::time::sleep(throttle_backoff).await;
                }
            }
        });

        // 6. UPLINK WORKER (CLI_WRITER: tx_queue -> Self-Clocking PacketBatcher -> APPEND "Drafts" + UID EXPUNGE in "Notes")
        let writer_for_uplink = writer_mutex.clone();
        let session_state_ul = session_state.clone();
        let srv_id_ul = srv_id.clone();
        let email_ul = active_email.clone();
        let cleanup_uids_ul = cleanup_uids.clone();
        let inflight_ul = inflight_count.clone();
        let stop_ul = stop_flag.clone();
        let failover_ul = failover_needed.clone();
        let rate_limit_ul = rate_limited_flag.clone();
        let seq_ul = sequence.clone();

        let uplink_task = tokio::spawn(async move {
            let mut batcher = PacketBatcher::new(max_batch_bytes, coalesce_ms);

            info!(
                "[IMAP Uplink] Started Self-Clocking Writer (Batch limit: {} B, Micro-coalesce: {} ms)",
                max_batch_bytes, coalesce_ms
            );

            while !stop_ul.load(Ordering::Relaxed) {
                if failover_ul.load(Ordering::Acquire) {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }

                // Шаг 1: Неблокирующая сборка мусора ВСЕГДА проверяется ДО Backpressure,
                // чтобы исключить взаимную блокировку (Deadlock) при достижении MAX_INFLIGHT_APPENDS!
                let to_clean = {
                    let mut guard = cleanup_uids_ul.lock().await;
                    let force_clean = guard.len() >= 20
                        || inflight_ul.load(Ordering::Relaxed) >= MAX_INFLIGHT_APPENDS;
                    let idle_clean = tx_queue.is_empty() && batcher.is_empty() && !guard.is_empty();
                    if force_clean || idle_clean {
                        let list = guard.clone();
                        guard.clear();
                        list
                    } else {
                        Vec::new()
                    }
                };

                if !to_clean.is_empty() {
                    let mut writer_guard = writer_for_uplink.lock().await;
                    if let Err(e) = writer_guard.expunge_uids(&to_clean, command_timeout).await {
                        debug!("[IMAP Uplink] Non-blocking UID EXPUNGE in Notes error: {e}");
                        failover_ul.store(true, Ordering::Release);
                        continue;
                    } else {
                        debug!("[IMAP Uplink] Cleaned up {} UIDs in Notes", to_clean.len());
                        let cur = inflight_ul.load(Ordering::Relaxed);
                        inflight_ul.fetch_sub(to_clean.len().min(cur), Ordering::Relaxed);
                    }
                }

                // Шаг 2: Управление переполнением (Backpressure раздел 3.7):
                // При достижении 15 in-flight пакетов даем паузу 50 мс для завершения очистки
                // и освобождаем слот скользящего окна, чтобы не блокировать односторонний Upload.
                if inflight_ul.load(Ordering::Relaxed) >= MAX_INFLIGHT_APPENDS {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    let cur = inflight_ul.load(Ordering::Relaxed);
                    if cur > 0 {
                        inflight_ul.fetch_sub(1, Ordering::Relaxed);
                    }
                }

                // Шаг 3: Self-Clocking коалесценция (раздел 3.3 спецификации):
                // Если в tx_queue уже накопились пакеты за время предыдущего APPEND (~320 мс),
                // мгновенно выгребаем их все в батчер до max_batch_bytes!
                while batcher.current_bytes() < max_batch_bytes {
                    match tx_queue.try_recv() {
                        Ok(pkt) => batcher.push(pkt),
                        Err(_) => break,
                    }
                }

                // Если батчер пуст — ждем первый пакет из tx_queue (с коротким таймаутом 25 мс для очистки в паузах)
                if batcher.is_empty() {
                    match tokio::time::timeout(Duration::from_millis(25), tx_queue.recv()).await {
                        Ok(Some(first_pkt)) => {
                            batcher.push(first_pkt);
                        }
                        Ok(None) => break, // Канал закрыт
                        Err(_) => continue, // Пауза трафика — проверим очередь очистки на следующей итерации
                    }
                }

                // Если батчер еще не набрал полный размер, ждем микро-окно coalesce_ms (10–15 мс),
                // добирая текущий бурст пакетов перед отправкой APPEND
                if !batcher.should_flush() {
                    let coalesce_deadline = Instant::now() + Duration::from_millis(coalesce_ms);
                    loop {
                        if batcher.should_flush() {
                            break;
                        }
                        let rem = coalesce_deadline.saturating_duration_since(Instant::now());
                        if rem.is_zero() {
                            break;
                        }
                        match tokio::time::timeout(rem, tx_queue.recv()).await {
                            Ok(Some(pkt)) => batcher.push(pkt),
                            Ok(None) => break,
                            Err(_) => break,
                        }
                    }
                }

                // Шаг 4: Шифруем весь собранный батч ОДНИМ вызовом wrap_packet_slice и выполняем APPEND
                if let Some(raw_batch) = batcher.flush() {
                    let seq = seq_ul.fetch_add(1, Ordering::Relaxed);
                    let (sess_id, cipher_cur, nonce_cur) = {
                        let st = session_state_ul.read().await;
                        (st.session_id.clone(), st.cipher.clone(), st.nonce_prefix)
                    };

                    match wrap_packet_slice(&cipher_cur, &nonce_cur, seq, &raw_batch, 0) {
                        Ok(encrypted_bytes) => {
                            let subject = format!("ANet-Data [ID: {}:{}]", srv_id_ul, sess_id);
                            let email_cur = email_ul.read().await.clone();
                            inflight_ul.fetch_add(1, Ordering::Relaxed);

                            let mut writer_guard = writer_for_uplink.lock().await;
                            let res = writer_guard
                                .append_message(
                                    "Drafts",
                                    &subject,
                                    &encrypted_bytes,
                                    &email_cur,
                                    command_timeout,
                                )
                                .await;

                            match res {
                                Ok(lat) => {
                                    debug!(
                                        "[IMAP Uplink] APPEND Drafts OK in {:.1} ms ({} B)",
                                        lat.as_secs_f64() * 1000.0,
                                        encrypted_bytes.len()
                                    );
                                }
                                Err(e) => {
                                    let err_str = format!("{e:#}");
                                    warn!("[IMAP Uplink] APPEND Drafts failed: {err_str}");
                                    if err_str.contains("THROTTLED") || err_str.contains("OVERQUOTA") {
                                        rate_limit_ul.store(true, Ordering::SeqCst);
                                    }
                                    failover_ul.store(true, Ordering::Release);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("[IMAP Uplink] wrap_packet_slice encryption error: {e}");
                        }
                    }
                }
            }
        });

        // 7. DOWNLINK WORKER (CLI_READER: IDLE/FETCH "Notes" -> unpack_batch -> TUN)
        let reader_for_downlink = reader_mutex.clone();
        let session_state_dl = session_state.clone();
        let cleanup_uids_dl = cleanup_uids.clone();
        let inflight_dl = inflight_count.clone();
        let stop_dl = stop_flag.clone();
        let failover_dl = failover_needed.clone();
        let uid_dl = last_seen_uid_shared.clone();

        let downlink_task = tokio::spawn(async move {
            let mut write_buf = BytesMut::with_capacity(COALESCE_BUDGET_BYTES);

            info!("[IMAP Downlink] Started Reader loop on folder 'Notes'...");

            while !stop_dl.load(Ordering::Relaxed) {
                if failover_dl.load(Ordering::Acquire) {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }

                // 1. Активное ожидание через IDLE (или мгновенный пропуск, если pending_exists == true)
                {
                    let mut reader_guard = reader_for_downlink.lock().await;
                    if let Err(e) = reader_guard.wait_idle_or_pending(idle_timeout).await {
                        warn!("[IMAP Downlink] wait_idle_or_pending error: {e:#}");
                        failover_dl.store(true, Ordering::Release);
                        continue;
                    }
                }

                if stop_dl.load(Ordering::Relaxed) || failover_dl.load(Ordering::Acquire) {
                    continue;
                }

                // 2. Выборка новых сообщений
                let cur_last_uid = uid_dl.load(Ordering::SeqCst) as u32;
                let fetch_res = {
                    let mut reader_guard = reader_for_downlink.lock().await;
                    reader_guard
                        .fetch_messages_robust(cur_last_uid, command_timeout)
                        .await
                };

                match fetch_res {
                    Ok(res) => {
                        uid_dl.store(res.new_max_uid as u64, Ordering::SeqCst);

                        let (expected_sess_tag, cipher_cur) = {
                            let st = session_state_dl.read().await;
                            (format!("[ID: {}]", st.session_id), st.cipher.clone())
                        };

                        for msg in res.messages {
                            if !msg.subject.contains(&expected_sess_tag) {
                                continue;
                            }

                            // Добавляем UID в очередь сборки мусора для CLI_WRITER
                            {
                                let mut guard = cleanup_uids_dl.lock().await;
                                guard.push(msg.uid);
                            }

                            // Подтверждение живого обмена снижает счетчик in-flight
                            let cur_inf = inflight_dl.load(Ordering::Relaxed);
                            if cur_inf > 0 {
                                inflight_dl.fetch_sub(1, Ordering::Relaxed);
                            }

                            // Дешифруем ASTP батч
                            match anet_common::transport::unwrap_packet(&cipher_cur, &msg.payload) {
                                Ok(decrypted_batch) => {
                                    let packets = unpack_batch(&decrypted_batch);
                                    write_buf.clear();

                                    for pkt in packets {
                                        if pkt.len() >= 20 {
                                            frame_packet_into(&mut write_buf, &pkt);
                                        }
                                    }

                                    if !write_buf.is_empty() {
                                        if let Err(e) = tunnel_write.write_all(&write_buf).await {
                                            warn!(
                                                "[IMAP Downlink] Failed to write packets to TUN: {e}"
                                            );
                                            return;
                                        }
                                    }
                                }
                                Err(e) => {
                                    debug!(
                                        "[IMAP Downlink] unwrap_packet error on UID {}: {e}",
                                        msg.uid
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("[IMAP Downlink] UID FETCH failed: {e:#}");
                        failover_dl.store(true, Ordering::Release);
                    }
                }
            }
        });

        // 8. Регистрация shutdown_hook для корректного освобождения сокетов
        let tun_reader_abort = tun_reader_task.abort_handle();
        let failover_abort = failover_task.abort_handle();
        let uplink_abort = uplink_task.abort_handle();
        let downlink_abort = downlink_task.abort_handle();
        let stop_flag_hook = stop_flag.clone();
        let writer_hook = writer_mutex.clone();
        let reader_hook = reader_mutex.clone();

        let shutdown_hook: super::ShutdownHook = Box::pin(async move {
            stop_flag_hook.store(true, Ordering::SeqCst);
            tun_reader_abort.abort();
            failover_abort.abort();
            uplink_abort.abort();
            downlink_abort.abort();

            let _ = tokio::time::timeout(Duration::from_millis(300), async {
                let mut r = reader_hook.lock().await;
                let _ = r.exit_idle(Duration::from_millis(200)).await;
            })
            .await;

            let _ = tokio::time::timeout(Duration::from_millis(300), async {
                let mut w = writer_hook.lock().await;
                let _ = w.send_line("A9999 LOGOUT").await;
            })
            .await;
        });

        Ok(ConnectionResult {
            auth_response,
            vpn_stream: Box::new(client_stream),
            endpoint: None,
            connection: None,
            health_pause: None,
            remote_ip: Some(target_addr.ip()),
            bypass_ips,
            effective_mode: Some("IMAP".to_string()),
            shutdown_hook: Some(shutdown_hook),
        })
    }
}
