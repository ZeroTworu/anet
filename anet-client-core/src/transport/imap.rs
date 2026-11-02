use super::{ClientTransport, ConnectionResult};
use crate::auth::{AuthChannel, AuthHandler};
use crate::config::{CoreConfig, ServerConfig};
use anet_common::batcher::{unpack_batch, PacketBatcher};
use anet_common::consts::{COALESCE_BUDGET_BYTES, NONCE_LEN, PADDING_MTU};
use anet_common::encryption::Cipher;
use anet_common::handshake_fragmentation::FragmentConfig;
use anet_common::imap_conn::{compute_hex_id, ImapConn};
use anet_common::stream_framing::{frame_packet_into, FrameReader};
use anet_common::transport::wrap_packet_slice;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use base64::prelude::*;
use bytes::{Bytes, BytesMut};
use log::{debug, error, info, warn};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

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
        let uri: http::Uri = self.server.dsn.parse()
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

    fn resolve_target_address(&self) -> Result<(String, u16, SocketAddr)> {
        let (host, port) = self.server.host_port()?;
        let port = if port == 0 { DEFAULT_IMAP_PORT } else { port };

        let addr = format!("{}:{}", host, port)
            .to_socket_addrs()
            .with_context(|| format!("Failed to resolve IMAP host {}:{}", host, port))?
            .next()
            .ok_or_else(|| anyhow!("No IP addresses found for {}:{}", host, port))?;

        Ok((host, port, addr))
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
            let mut last_uid = *self.last_reader_uid.lock().await;

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
            let _ = reader_guard.wait_idle_or_event(wait_dur).await;
        }
    }
}

#[async_trait]
impl ClientTransport for ImapTransport {
    async fn connect(&self) -> Result<ConnectionResult> {
        let accounts = self.parse_accounts()?;
        let account = &accounts[0]; // Первичный аккаунт пула

        let (host, port, target_addr) = self.resolve_target_address()?;
        info!(
            "[IMAP Client] Connecting to {}:{} via BoringSSL Email Mimicry (Account: {})",
            host, port, account.email
        );

        let tls_cfg = self.server.effective_tls_config(&self.config.stealth);
        let command_timeout = Duration::from_millis(self.config.imap.command_timeout_ms.max(5000));
        let idle_timeout = Duration::from_millis(self.config.imap.idle_refresh_interval_ms.max(10000));
        let coalesce_ms = self.config.imap.batch_coalesce_ms.clamp(5, 50);
        let max_batch_bytes = (self.config.imap.max_batch_kb.clamp(8, 128)) * 1024;

        // 1. Подключаем CLI_WRITER (Архитектура Cross-Selected: делает SELECT "Notes" один раз!)
        let mut cli_writer = ImapConn::connect(&host, port, &account.email, &account.password, &tls_cfg, command_timeout)
            .await
            .context("Failed to connect CLI_WRITER to IMAP server")?;

        cli_writer
            .select("Notes", command_timeout)
            .await
            .context("CLI_WRITER failed to SELECT 'Notes'")?;
        info!("[IMAP Client] CLI_WRITER initialized (SELECT 'Notes')");

        // 2. Подключаем CLI_READER (делает SELECT "Notes" и замеряет baseline max_uid)
        let mut cli_reader = ImapConn::connect(&host, port, &account.email, &account.password, &tls_cfg, command_timeout)
            .await
            .context("Failed to connect CLI_READER to IMAP server")?;

        cli_reader
            .select("Notes", command_timeout)
            .await
            .context("CLI_READER failed to SELECT 'Notes'")?;

        let initial_max_uid = cli_reader
            .get_max_uid(command_timeout)
            .await
            .unwrap_or(0);
        info!(
            "[IMAP Client] CLI_READER initialized (SELECT 'Notes', baseline UID: {})",
            initial_max_uid
        );

        // 3. Вычисляем SRV_ID и Client_TempID для хендшейка (раздел 4 спецификации)
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
            "[IMAP Client] Handshake IDs: SRV_ID={}, Client_TempID={}",
            srv_id, client_temp_id
        );

        let writer_mutex = Arc::new(Mutex::new(cli_writer));
        let reader_mutex = Arc::new(Mutex::new(cli_reader));
        let last_uid_atomic = Arc::new(Mutex::new(initial_max_uid));

        // 4. Выполняем ASTP Handshake (Фазы 1–4) через IMAP
        let auth_channel = ImapAuthChannel {
            writer: writer_mutex.clone(),
            reader: reader_mutex.clone(),
            account_email: account.email.clone(),
            srv_id: srv_id.clone(),
            client_temp_id: client_temp_id.clone(),
            timeout_dur: command_timeout,
            last_reader_uid: last_uid_atomic.clone(),
        };

        let auth_handler = AuthHandler::new(&self.config, self.server.server_pub_key.as_deref())?;
        info!("[IMAP Client] Initiating ASTP authentication over IMAP...");
        let (auth_response, shared_key) = auth_handler.authenticate_once(&auth_channel).await?;

        let session_id = auth_response.session_id.clone();
        info!(
            "[IMAP Client] ASTP Authentication successful! Assigned IP: {}, Session: {}",
            auth_response.ip, session_id
        );

        // 5. Создаем локальный дуплексный канал связи с VPN TUN-стеком
        let (client_stream, internal_router) = tokio::io::duplex(512 * 1024);
        let (mut tunnel_read, mut tunnel_write) = tokio::io::split(internal_router);

        let cipher = Arc::new(Cipher::new(&shared_key));
        let nonce_prefix: [u8; 4] = auth_response.nonce_prefix.as_slice().try_into()
            .context("Invalid nonce prefix in AuthResponse")?;

        let sequence = Arc::new(AtomicU64::new(0));
        let cleanup_uids = Arc::new(Mutex::new(Vec::<u32>::new()));
        let inflight_count = Arc::new(AtomicUsize::new(0));
        let stop_flag = Arc::new(AtomicBool::new(false));

        // 6. UPLINK WORKER (CLI_WRITER: TUN -> PacketBatcher -> APPEND "Drafts" -> UID EXPUNGE in "Notes")
        let writer_for_uplink = writer_mutex.clone();
        let cipher_ul = cipher.clone();
        let srv_id_ul = srv_id.clone();
        let session_id_ul = session_id.clone();
        let email_ul = account.email.clone();
        let cleanup_uids_ul = cleanup_uids.clone();
        let inflight_ul = inflight_count.clone();
        let stop_ul = stop_flag.clone();
        let seq_ul = sequence.clone();

        let uplink_task = tokio::spawn(async move {
            let mut frame_reader = FrameReader::new();
            let mut batcher = PacketBatcher::new(max_batch_bytes, coalesce_ms);
            let mut coalesce_interval = tokio::time::interval(Duration::from_millis(coalesce_ms));
            coalesce_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            info!(
                "[IMAP Uplink] Started Self-Clocking Writer (Batch limit: {} B, Micro-coalesce: {} ms)",
                max_batch_bytes, coalesce_ms
            );

            while !stop_ul.load(Ordering::Relaxed) {
                // Flow Control / Backpressure: ограничиваем in-flight аппенды (макс. 15),
                // чтобы не переполнять ящик и не ловить сетевой бан по IP
                if inflight_ul.load(Ordering::Relaxed) >= MAX_INFLIGHT_APPENDS {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }

                tokio::select! {
                    biased;
                    // Прием пакетов из TUN-интерфейса
                    pkt_res = frame_reader.read_next_packet(&mut tunnel_read) => {
                        match pkt_res {
                            Ok(Some(packet)) => {
                                if packet.len() >= 20 {
                                    batcher.push(packet);
                                    // Выгребаем все, что уже лежит в буфере
                                    while let Ok(Some(next_p)) = frame_reader.try_next_packet() {
                                        if next_p.len() >= 20 {
                                            batcher.push(next_p);
                                        }
                                        if batcher.should_flush() {
                                            break;
                                        }
                                    }
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
                    _ = coalesce_interval.tick() => {}
                }

                // Отправляем накопленный батч
                if !batcher.is_empty() {
                    if let Some(raw_batch) = batcher.flush() {
                        let seq = seq_ul.fetch_add(1, Ordering::Relaxed);
                        match wrap_packet_slice(&cipher_ul, &nonce_prefix, seq, &raw_batch, 0) {
                            Ok(encrypted_bytes) => {
                                let subject = format!("ANet-Data [ID: {}:{}]", srv_id_ul, session_id_ul);
                                inflight_ul.fetch_add(1, Ordering::Relaxed);

                                let mut writer_guard = writer_for_uplink.lock().await;
                                let res = writer_guard.append_message(
                                    "Drafts",
                                    &subject,
                                    &encrypted_bytes,
                                    &email_ul,
                                    command_timeout,
                                ).await;

                                match res {
                                    Ok(lat) => {
                                        debug!("[IMAP Uplink] APPEND Drafts OK in {:.1} ms ({} B)", lat.as_secs_f64() * 1000.0, encrypted_bytes.len());
                                    }
                                    Err(e) => {
                                        warn!("[IMAP Uplink] APPEND Drafts failed: {e:#}");
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("[IMAP Uplink] wrap_packet_slice encryption error: {e}");
                            }
                        }
                    }
                }

                // Неблокирующая сборка мусора в паузах:
                // Выполняем UID EXPUNGE в текущей выбранной папке "Notes",
                // когда очередь отправки пуста, либо накопилось >= 20 прочитанных UIDs
                let to_clean = {
                    let mut guard = cleanup_uids_ul.lock().await;
                    if (batcher.is_empty() && !guard.is_empty()) || guard.len() >= 20 {
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
                        debug!("[IMAP Uplink] Non-blocking UID EXPUNGE in Notes: {e}");
                    } else {
                        debug!("[IMAP Uplink] Cleaned up {} UIDs in Notes", to_clean.len());
                        inflight_ul.fetch_sub(to_clean.len().min(inflight_ul.load(Ordering::Relaxed)), Ordering::Relaxed);
                    }
                }
            }
        });

        // 7. DOWNLINK WORKER (CLI_READER: IDLE/FETCH "Notes" -> unpack_batch -> TUN)
        let reader_for_downlink = reader_mutex.clone();
        let cipher_dl = cipher.clone();
        let session_id_dl = session_id.clone();
        let cleanup_uids_dl = cleanup_uids.clone();
        let stop_dl = stop_flag.clone();
        let mut last_seen_uid = initial_max_uid;

        let downlink_task = tokio::spawn(async move {
            let mut write_buf = BytesMut::with_capacity(COALESCE_BUDGET_BYTES);
            let expected_sess_tag = format!("[ID: {}]", session_id_dl);

            info!("[IMAP Downlink] Started Reader loop on folder 'Notes'...");

            while !stop_dl.load(Ordering::Relaxed) {
                // 1. Активное ожидание через IDLE (или мгновенный пропуск, если pending_exists == true)
                {
                    let mut reader_guard = reader_for_downlink.lock().await;
                    if let Err(e) = reader_guard.wait_idle_or_event(idle_timeout).await {
                        warn!("[IMAP Downlink] wait_idle_or_event warning: {e}");
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }

                if stop_dl.load(Ordering::Relaxed) {
                    break;
                }

                // 2. Выборка новых сообщений
                let fetch_res = {
                    let mut reader_guard = reader_for_downlink.lock().await;
                    reader_guard.fetch_messages_robust(last_seen_uid, command_timeout).await
                };

                match fetch_res {
                    Ok(res) => {
                        last_seen_uid = res.new_max_uid;

                        for msg in res.messages {
                            // Проверяем, что письмо адресовано нашей текущей сессии
                            if !msg.subject.contains(&expected_sess_tag) {
                                continue;
                            }

                            // Добавляем UID в очередь сборки мусора для CLI_WRITER
                            {
                                let mut guard = cleanup_uids_dl.lock().await;
                                guard.push(msg.uid);
                            }

                            // Дешифруем ASTP батч
                            match anet_common::transport::unwrap_packet(&cipher_dl, &msg.payload) {
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
                                            warn!("[IMAP Downlink] Failed to write packets to TUN: {e}");
                                            return;
                                        }
                                    }
                                }
                                Err(e) => {
                                    debug!("[IMAP Downlink] unwrap_packet error on UID {}: {e}", msg.uid);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("[IMAP Downlink] UID FETCH failed: {e:#}");
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            }
        });

        // 8. Регистрация shutdown_hook для корректного освобождения сокетов
        let uplink_abort = uplink_task.abort_handle();
        let downlink_abort = downlink_task.abort_handle();
        let stop_flag_hook = stop_flag.clone();
        let writer_hook = writer_mutex.clone();
        let reader_hook = reader_mutex.clone();

        let shutdown_hook: super::ShutdownHook = Box::pin(async move {
            stop_flag_hook.store(true, Ordering::SeqCst);
            uplink_abort.abort();
            downlink_abort.abort();

            // Корректно отправляем DONE и закрываем сокеты
            let _ = tokio::time::timeout(Duration::from_millis(300), async {
                let mut r = reader_hook.lock().await;
                let _ = r.exit_idle(Duration::from_millis(200)).await;
            }).await;

            let _ = tokio::time::timeout(Duration::from_millis(300), async {
                let mut w = writer_hook.lock().await;
                let _ = w.send_line("A9999 LOGOUT").await;
            }).await;
        });

        Ok(ConnectionResult {
            auth_response,
            vpn_stream: Box::new(client_stream),
            endpoint: None,
            connection: None,
            health_pause: None,
            remote_ip: Some(target_addr.ip()), // Прямой IP сервера Mail.ru для bypass-маршрутизации
            bypass_ips: vec![target_addr.ip()],
            effective_mode: Some("IMAP".to_string()),
            shutdown_hook: Some(shutdown_hook),
        })
    }
}
