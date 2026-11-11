use super::{ClientTransport, ConnectionResult};
use crate::auth::{AuthChannel, AuthHandler};
use crate::config::{CoreConfig, ImapConfig, ServerConfig};
use anet_common::batcher::{is_priority_ip_packet, unpack_batch, PacketBatcher};
use anet_common::consts::{CLIENT_SEQUENCE_START, COALESCE_BUDGET_BYTES};
use anet_common::encryption::Cipher;
use anet_common::handshake_fragmentation::FragmentConfig;
use anet_common::imap_conn::{compute_hex_id, ImapConn};
use anet_common::stream_framing::{frame_packet_into, FrameReader};
use anet_common::transport::wrap_packet_slice;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use base64::prelude::*;
use bytes::{Bytes, BytesMut};
use futures::future::BoxFuture;
use log::{debug, info, warn};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex, Notify, OwnedSemaphorePermit, RwLock, Semaphore};

const DEFAULT_IMAP_PORT: u16 = 993;

#[inline]
fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImapAccount {
    pub email: String,
    pub password: String,
}

/// Активное криптографическое состояние сессии (единое для всех N почтовых ящиков в пуле)
pub struct ActiveImapSessionState {
    pub session_id: String,
    pub cipher: Arc<Cipher>,
    pub nonce_prefix: [u8; 4],
}

/// Готовый к отправке зашифрованный батч Uplink (раздел 9.4.1 спецификации)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedUplinkBatch {
    pub subject: String,
    pub encrypted_payload: Bytes,
}

/// Дескриптор клиентского воркера конкретного почтового ящика в Active-Active пуле (раздел 9.4.1)
#[derive(Clone)]
pub struct ClientMailboxSlot {
    pub index: usize,
    pub account: ImapAccount,
    /// Канал ёмкостью 1 для передачи зашифрованного батча и разрешения семафора конкретному CLI_WRITER[i]
    pub uplink_tx: mpsc::Sender<(EncryptedUplinkBatch, OwnedSemaphorePermit)>,
    /// Семафор занятости CLI_WRITER[i] (1 разрешение: удерживается на всё время сетевого APPEND или UID EXPUNGE)
    pub writer_sem: Arc<Semaphore>,
    /// Флаг готовности и здоровья пары (CLI_WRITER[i] + CLI_READER[i])
    pub healthy: Arc<AtomicBool>,
    /// Локальный счётчик неподтверждённых батчей именно этого ящика
    pub inflight: Arc<AtomicUsize>,
}

impl ClientMailboxSlot {
    pub fn new(
        index: usize,
        account: ImapAccount,
        healthy: bool,
    ) -> (
        Self,
        mpsc::Receiver<(EncryptedUplinkBatch, OwnedSemaphorePermit)>,
    ) {
        let (uplink_tx, uplink_rx) = mpsc::channel(1);
        let slot = Self {
            index,
            account,
            uplink_tx,
            writer_sem: Arc::new(Semaphore::new(1)),
            healthy: Arc::new(AtomicBool::new(healthy)),
            inflight: Arc::new(AtomicUsize::new(0)),
        };
        (slot, uplink_rx)
    }
}

/// Формирует легковесный управляющий `Mailbox Binding Frame` (раздел 9.3.3 спецификации) —
/// пустой зашифрованный ASTP-батч (`wrap_packet_slice(..., &[], 0)`), позволяющий серверу
/// криптографически верифицировать и мгновенно зарегистрировать вторичный ящик `i` в `SessionMailboxPool`.
pub fn build_mailbox_binding_frame(
    cipher: &Cipher,
    nonce_prefix: &[u8; 4],
    sequence: &AtomicU64,
    srv_id: &str,
    session_id: &str,
) -> Result<EncryptedUplinkBatch> {
    let seq = sequence.fetch_add(1, Ordering::Relaxed);
    let binding_payload = wrap_packet_slice(cipher, nonce_prefix, seq, &[], 0)
        .map_err(|e| anyhow!("Failed to encrypt Mailbox Binding Frame: {e}"))?;
    let subject = format!("ANet-Data [ID: {}:{}]", srv_id, session_id);
    Ok(EncryptedUplinkBatch {
        subject,
        encrypted_payload: binding_payload,
    })
}

/// Выбирает первый свободный здоровый слот по алгоритму Self-Clocking Round-Robin (раздел 9.4.2):
/// 1. Fast Path: неблокирующий обход слотов от `*rr_cursor` (`try_acquire_owned()`).
/// 2. All-Busy Path: если все здоровые ящики сейчас заняты выполнением `APPEND` в сети,
///    ожидает ПЕРВОГО освободившегося воркера через `futures::future::select_all`.
pub async fn acquire_client_slot_self_clocking(
    slots: &[ClientMailboxSlot],
    rr_cursor: &mut usize,
    max_inflight_batches: usize,
    stop_flag: &AtomicBool,
    pool_wake_notify: &Notify,
) -> Option<(usize, OwnedSemaphorePermit)> {
    if slots.is_empty() {
        return None;
    }

    while !stop_flag.load(Ordering::Relaxed) {
        // Фаза 1: Мгновенный неблокирующий Round-Robin (Fast Path)
        for offset in 0..slots.len() {
            let idx = (*rr_cursor + offset) % slots.len();
            let slot = &slots[idx];
            if !slot.healthy.load(Ordering::Acquire) {
                continue;
            }
            if slot.inflight.load(Ordering::Relaxed) >= max_inflight_batches {
                continue;
            }
            if let Ok(permit) = slot.writer_sem.clone().try_acquire_owned() {
                *rr_cursor = (idx + 1) % slots.len();
                return Some((idx, permit));
            }
        }

        // Фаза 2: Все здоровые воркеры заняты APPEND — ждём первого освободившегося (All-Busy Self-Clocking Path)
        let mut wait_futs: Vec<
            BoxFuture<'static, (usize, std::result::Result<OwnedSemaphorePermit, tokio::sync::AcquireError>)>,
        > = Vec::new();

        for offset in 0..slots.len() {
            let idx = (*rr_cursor + offset) % slots.len();
            let slot = &slots[idx];
            if !slot.healthy.load(Ordering::Acquire) {
                continue;
            }
            if slot.inflight.load(Ordering::Relaxed) >= max_inflight_batches {
                continue;
            }
            let sem = slot.writer_sem.clone();
            wait_futs.push(Box::pin(async move { (idx, sem.acquire_owned().await) }));
        }

        if wait_futs.is_empty() {
            // Либо все слоты временно на реконнекте, либо у всех исчерпан лимит inflight (Backpressure)
            tokio::select! {
                _ = pool_wake_notify.notified() => {}
                _ = tokio::time::sleep(Duration::from_millis(25)) => {
                    // Плавное списание inflight при длительном ожидании (защита от deadlock при потере ответов)
                    for slot in slots {
                        let cur = slot.inflight.load(Ordering::Relaxed);
                        if cur >= max_inflight_batches && cur > 0 {
                            slot.inflight.fetch_sub(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            continue;
        }

        tokio::select! {
            biased;
            ((idx, Ok(permit)), _, _) = futures::future::select_all(wait_futs) => {
                if slots[idx].healthy.load(Ordering::Acquire) {
                    *rr_cursor = (idx + 1) % slots.len();
                    return Some((idx, permit));
                }
                // Если слот стал нездоровым ровно в момент освобождения — отпускаем permit и повторяем цикл
                drop(permit);
            }
            _ = pool_wake_notify.notified() => {}
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }

    None
}

/// Центральный диспетчер Uplink (`Self-Clocking Round-Robin Uplink Dispatcher`, раздел 9.4.2):
/// Владеет `prio_rx`, `bulk_rx`, `retry_uplink_rx` и единым `PacketBatcher`, распределяя
/// зашифрованные батчи по всем $N$ здоровым ящикам без Head-of-Line блокировки.
pub async fn run_client_uplink_dispatcher(
    mut prio_rx: mpsc::Receiver<Bytes>,
    mut bulk_rx: mpsc::Receiver<Bytes>,
    mut retry_uplink_rx: mpsc::UnboundedReceiver<EncryptedUplinkBatch>,
    slots: Vec<ClientMailboxSlot>,
    session_state: Arc<RwLock<ActiveImapSessionState>>,
    sequence: Arc<AtomicU64>,
    srv_id: String,
    max_batch_bytes: usize,
    coalesce_ms: u64,
    max_inflight_batches: usize,
    stop_flag: Arc<AtomicBool>,
    pool_wake_notify: Arc<Notify>,
) {
    let mut batcher = PacketBatcher::new(max_batch_bytes, coalesce_ms);
    let mut rr_cursor = 0usize;

    info!(
        "[IMAP Uplink] Started Self-Clocking Multi-Mailbox Dispatcher (Pool size: {}, Batch limit: {} B, Micro-coalesce: {} ms)",
        slots.len(),
        max_batch_bytes,
        coalesce_ms
    );

    while !stop_flag.load(Ordering::Relaxed) {
        // Приоритет №1: Zero-Loss Retry — если какой-либо CLI_WRITER[i] вернул неотправленный батч
        // из-за сетевого сбоя во время APPEND, мгновенно перенаправляем его через другой живой ящик!
        if let Ok(retry_batch) = retry_uplink_rx.try_recv() {
            let Some((slot_idx, permit)) = acquire_client_slot_self_clocking(
                &slots,
                &mut rr_cursor,
                max_inflight_batches,
                &stop_flag,
                &pool_wake_notify,
            )
            .await
            else {
                break;
            };
            if slots[slot_idx]
                .uplink_tx
                .send((retry_batch, permit))
                .await
                .is_err()
            {
                continue;
            }
            continue;
        }

        // Выгребаем ВСЕ доступные пакеты из каналов (сначала приоритетные Fast-Lane, затем bulk с Head-Drop AQM внутри батчера),
        // чтобы tun_reader_task и задача t1 никогда не блокировались на переполнении буферов.
        while let Ok(pkt) = prio_rx.try_recv() {
            batcher.push_priority(pkt);
        }
        while let Ok(pkt) = bulk_rx.try_recv() {
            batcher.push_bulk(pkt);
        }

        // Если батчер пуст — ждём первый пакет (или возврат батча из retry_uplink_rx)
        if batcher.is_empty() {
            tokio::select! {
                biased;
                Some(retry_batch) = retry_uplink_rx.recv() => {
                    let Some((slot_idx, permit)) = acquire_client_slot_self_clocking(
                        &slots,
                        &mut rr_cursor,
                        max_inflight_batches,
                        &stop_flag,
                        &pool_wake_notify,
                    )
                    .await
                    else {
                        break;
                    };
                    let _ = slots[slot_idx].uplink_tx.send((retry_batch, permit)).await;
                    continue;
                }
                res = prio_rx.recv() => {
                    match res {
                        Some(pkt) => batcher.push_priority(pkt),
                        None => break,
                    }
                }
                res = bulk_rx.recv() => {
                    match res {
                        Some(pkt) => batcher.push_bulk(pkt),
                        None => break,
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(50)) => {
                    continue;
                }
            }
        }

        // Микро-коалесценция стартового бурста (coalesce_ms, по умолчанию 15 мс)
        if !batcher.should_flush() && coalesce_ms > 0 {
            let coalesce_deadline = Instant::now() + Duration::from_millis(coalesce_ms);
            loop {
                while let Ok(pkt) = prio_rx.try_recv() {
                    batcher.push_priority(pkt);
                }
                while let Ok(pkt) = bulk_rx.try_recv() {
                    batcher.push_bulk(pkt);
                }
                if batcher.should_flush() {
                    break;
                }
                let rem = coalesce_deadline.saturating_duration_since(Instant::now());
                if rem.is_zero() {
                    break;
                }
                tokio::select! {
                    biased;
                    res = prio_rx.recv() => {
                        match res {
                            Some(pkt) => batcher.push_priority(pkt),
                            None => break,
                        }
                    }
                    res = bulk_rx.recv() => {
                        match res {
                            Some(pkt) => batcher.push_bulk(pkt),
                            None => break,
                        }
                    }
                    _ = tokio::time::sleep(rem) => {
                        break;
                    }
                }
            }
        }

        // Ждём освобождения первого доступного здорового ящика по алгоритму Self-Clocking Round-Robin,
        // непрерывно выгребая новые пакеты из prio_rx и bulk_rx в batcher (с Head-Drop AQM для bulk),
        // чтобы каналы TUN никогда не переполнялись и не задерживали приоритетный трафик.
        let slot_permit_opt = {
            let acquire_fut = acquire_client_slot_self_clocking(
                &slots,
                &mut rr_cursor,
                max_inflight_batches,
                &stop_flag,
                &pool_wake_notify,
            );
            tokio::pin!(acquire_fut);

            loop {
                tokio::select! {
                    biased;
                    res = &mut acquire_fut => break res,
                    Some(pkt) = prio_rx.recv() => {
                        batcher.push_priority(pkt);
                        while let Ok(more) = prio_rx.try_recv() {
                            batcher.push_priority(more);
                        }
                    }
                    Some(pkt) = bulk_rx.recv() => {
                        batcher.push_bulk(pkt);
                        while let Ok(more) = prio_rx.try_recv() {
                            batcher.push_priority(more);
                        }
                        while let Ok(more) = bulk_rx.try_recv() {
                            batcher.push_bulk(more);
                        }
                    }
                }
            }
        };

        let Some((slot_idx, permit)) = slot_permit_opt else {
            break;
        };

        // Повторно проверяем retry_uplink_rx: если во время ожидания освобождения слота соседний воркер
        // уронил соединение и вернул готовый зашифрованный батч, отправляем сначала его!
        if let Ok(retry_batch) = retry_uplink_rx.try_recv() {
            let _ = slots[slot_idx].uplink_tx.send((retry_batch, permit)).await;
            continue;
        }

        // Добираем ВСЕ накопившиеся к моменту пробуждения пакеты (приоритетные ICMP/DNS/ACK всегда встают в начало батча,
        // а избыток bulk-трафика свыше окна BDP автоматически регулируется Head-Drop AQM внутри батчера).
        while let Ok(pkt) = prio_rx.try_recv() {
            batcher.push_priority(pkt);
        }
        while let Ok(pkt) = bulk_rx.try_recv() {
            batcher.push_bulk(pkt);
        }

        if let Some(raw_batch) = batcher.flush() {
            let seq = sequence.fetch_add(1, Ordering::Relaxed);
            let (sess_id, cipher_cur, nonce_cur) = {
                let st = session_state.read().await;
                (st.session_id.clone(), st.cipher.clone(), st.nonce_prefix)
            };

            match wrap_packet_slice(&cipher_cur, &nonce_cur, seq, &raw_batch, 0) {
                Ok(encrypted_payload) => {
                    let subject = format!("ANet-Data [ID: {}:{}]", srv_id, sess_id);
                    let batch = EncryptedUplinkBatch {
                        subject,
                        encrypted_payload,
                    };
                    let _ = slots[slot_idx].uplink_tx.send((batch, permit)).await;
                }
                Err(e) => {
                    warn!("[IMAP Uplink] wrap_packet_slice encryption error: {e}");
                    drop(permit);
                }
            }
        } else {
            drop(permit);
        }
    }
}

pub struct ImapTransport {
    config: CoreConfig,
    server: ServerConfig,
}

impl ImapTransport {
    pub fn new(config: CoreConfig, server: ServerConfig) -> Self {
        Self { config, server }
    }

    /// Возвращает результирующий `ImapConfig` с учётом query-параметров в DSN сервера
    /// (например `?acc=...&max_batch_kb=128&idle_active_poll_ms=400&expunge_batch_size=25`).
    fn effective_imap_config(&self) -> ImapConfig {
        let mut cfg = self.config.imap.clone();
        if let Ok(uri) = self.server.dsn.parse::<http::Uri>() {
            if let Some(query) = uri.query() {
                for pair in query.split('&') {
                    let Some((k, v)) = pair.split_once('=') else {
                        continue;
                    };
                    let v = v.trim();
                    match k.trim().to_ascii_lowercase().as_str() {
                        "max_batch_kb" | "batch_kb" => {
                            if let Ok(val) = v.parse::<usize>() {
                                cfg.max_batch_kb = val;
                            }
                        }
                        "batch_coalesce_ms" | "coalesce_ms" | "batch_ms" => {
                            if let Ok(val) = v.parse::<u64>() {
                                cfg.batch_coalesce_ms = val;
                            }
                        }
                        "fetch_max_messages" | "fetch_max" => {
                            if let Ok(val) = v.parse::<usize>() {
                                cfg.fetch_max_messages = val;
                            }
                        }
                        "idle_active_poll_ms" | "idle_active_ms" => {
                            if let Ok(val) = v.parse::<u64>() {
                                cfg.idle_active_poll_ms = val;
                            }
                        }
                        "idle_active_window_ms" => {
                            if let Ok(val) = v.parse::<u64>() {
                                cfg.idle_active_window_ms = val;
                            }
                        }
                        "idle_refresh_interval_ms" | "idle_ms" => {
                            if let Ok(val) = v.parse::<u64>() {
                                cfg.idle_refresh_interval_ms = val;
                            }
                        }
                        "expunge_batch_size" => {
                            if let Ok(val) = v.parse::<usize>() {
                                cfg.expunge_batch_size = val;
                            }
                        }
                        "expunge_idle_delay_ms" => {
                            if let Ok(val) = v.parse::<u64>() {
                                cfg.expunge_idle_delay_ms = val;
                            }
                        }
                        "max_inflight_batches" | "max_inflight" => {
                            if let Ok(val) = v.parse::<usize>() {
                                cfg.max_inflight_batches = val;
                            }
                        }
                        "tx_queue_capacity" => {
                            if let Ok(val) = v.parse::<usize>() {
                                cfg.tx_queue_capacity = val;
                            }
                        }
                        "literal_plus_auto" | "literal_plus" => {
                            cfg.literal_plus_auto = !matches!(
                                v.to_ascii_lowercase().as_str(),
                                "0" | "false" | "no" | "off"
                            );
                        }
                        _ => {}
                    }
                }
            }
        }
        cfg
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

    /// Резолвит хост IMAP-сервера и возвращает основной `SocketAddr`, список `SocketAddr` и полный список всех IP для `bypass_ips` (раздел 7.2 п. 1).
    /// Для `imap.mail.ru` гарантированно включает оба балансировочных IPv4-адреса Mail.ru (`94.100.180.90` и `217.69.139.90`),
    /// чтобы исключить петлю маршрутизации при Round-Robin DNS и работу Failover без обращения к DNS внутри TUN.
    fn resolve_target_addresses(
        &self,
    ) -> Result<(String, u16, SocketAddr, Vec<SocketAddr>, Vec<IpAddr>)> {
        let (host, port) = self.server.host_port()?;
        let port = if port == 0 { DEFAULT_IMAP_PORT } else { port };

        let mut addrs: Vec<SocketAddr> = format!("{}:{}", host, port)
            .to_socket_addrs()
            .with_context(|| format!("Failed to resolve IMAP host {}:{}", host, port))?
            .collect();

        if host.eq_ignore_ascii_case("imap.mail.ru") {
            for known_ip in [
                IpAddr::V4(std::net::Ipv4Addr::new(94, 100, 180, 90)),
                IpAddr::V4(std::net::Ipv4Addr::new(217, 69, 139, 90)),
            ] {
                let sa = SocketAddr::new(known_ip, port);
                if !addrs.contains(&sa) {
                    addrs.push(sa);
                }
            }
        }

        let primary = *addrs
            .first()
            .ok_or_else(|| anyhow!("No IP addresses found for {}:{}", host, port))?;

        let mut bypass_ips = Vec::with_capacity(addrs.len());
        for a in &addrs {
            if !bypass_ips.contains(&a.ip()) {
                bypass_ips.push(a.ip());
            }
        }

        Ok((host, port, primary, addrs, bypass_ips))
    }
}

/// Адаптер `AuthChannel` для выполнения ASTP Handshake через IMAP (Фазы 1–4)
struct ImapAuthChannel {
    writer: Mutex<ImapConn>,
    reader: Mutex<ImapConn>,
    account_email: String,
    srv_id: String,
    client_temp_id: String,
    timeout_dur: Duration,
    last_reader_uid: Mutex<u32>,
    handshake_uids: Mutex<Vec<u32>>,
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
                    self.handshake_uids.lock().await.push(msg.uid);
                    return Ok(msg.payload);
                }
            }

            // Короткий адаптивный IDLE во время рукопожатия (400 мс), чтобы не ждать 5 с при слепом окне
            let wait_dur = remaining.min(Duration::from_millis(450));
            let _ = reader_guard.wait_idle_or_pending(wait_dur).await;
        }
    }
}

/// Подключает одно IMAP-соединение напрямую по заранее разрешенным адресам `target_addrs` (с фолбэком по списку IP)
async fn connect_imap_with_addrs(
    target_addrs: &[SocketAddr],
    host: &str,
    port: u16,
    email: &str,
    password: &str,
    tls_cfg: &anet_common::boring_tls::TlsClientConfig,
    command_timeout: Duration,
    literal_plus_auto: bool,
) -> Result<ImapConn> {
    let mut last_err = None;
    for &addr in target_addrs {
        match ImapConn::connect_addr(addr, host, email, password, tls_cfg, command_timeout).await {
            Ok(mut conn) => {
                conn.set_literal_plus_enabled(literal_plus_auto);
                return Ok(conn);
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
    }
    if let Some(e) = last_err {
        Err(e)
    } else {
        let mut conn =
            ImapConn::connect(host, port, email, password, tls_cfg, command_timeout).await?;
        conn.set_literal_plus_enabled(literal_plus_auto);
        Ok(conn)
    }
}

/// Подключает вторичную пару `CLI_WRITER[i]` + `CLI_READER[i]` для Data Plane без повторного ASTP-хендшейка (раздел 9.3.3).
async fn connect_data_only_mailbox_pair(
    target_addrs: &[SocketAddr],
    host: &str,
    port: u16,
    account: &ImapAccount,
    tls_cfg: &anet_common::boring_tls::TlsClientConfig,
    command_timeout: Duration,
    literal_plus_auto: bool,
) -> Result<(ImapConn, ImapConn, u32)> {
    let mut cli_writer = connect_imap_with_addrs(
        target_addrs,
        host,
        port,
        &account.email,
        &account.password,
        tls_cfg,
        command_timeout,
        literal_plus_auto,
    )
    .await
    .with_context(|| format!("Failed to connect CLI_WRITER for {}", account.email))?;

    // Гарантируем наличие обеих папок ("Drafts" и "Notes") на свежезарегистрированных ящиках
    let _ = cli_writer.select("Drafts", command_timeout).await;
    cli_writer
        .select("Notes", command_timeout)
        .await
        .with_context(|| format!("CLI_WRITER failed to SELECT 'Notes' for {}", account.email))?;

    let writer_addrs: Vec<SocketAddr> = if let Some(ip) = cli_writer.peer_ip() {
        vec![SocketAddr::new(ip, port)]
    } else {
        target_addrs.to_vec()
    };

    let mut cli_reader = connect_imap_with_addrs(
        &writer_addrs,
        host,
        port,
        &account.email,
        &account.password,
        tls_cfg,
        command_timeout,
        literal_plus_auto,
    )
    .await
    .with_context(|| format!("Failed to connect CLI_READER for {}", account.email))?;

    cli_reader
        .select("Notes", command_timeout)
        .await
        .with_context(|| format!("CLI_READER failed to SELECT 'Notes' for {}", account.email))?;

    let initial_max_uid = cli_reader.get_max_uid(command_timeout).await.unwrap_or(0);
    info!(
        "[IMAP Client] Data-Plane pair CLI_WRITER & CLI_READER initialized for {} (SELECT 'Notes', baseline UID: {})",
        account.email, initial_max_uid
    );

    Ok((cli_writer, cli_reader, initial_max_uid))
}

/// Устанавливает пару соединений `CLI_WRITER` + `CLI_READER` (Cross-Selected на папку `"Notes"`)
/// и выполняет ASTP-рукопожатие (с поддержкой `resume_session_id` при полном восстановлении сессии).
async fn establish_mailbox_session(
    target_addrs: &[SocketAddr],
    host: &str,
    port: u16,
    account: &ImapAccount,
    tls_cfg: &anet_common::boring_tls::TlsClientConfig,
    command_timeout: Duration,
    literal_plus_auto: bool,
    srv_id: &str,
    client_temp_id: &str,
    core_cfg: &CoreConfig,
    server_pub_key_override: Option<&str>,
    resume_session_id: Option<String>,
) -> Result<(
    ImapConn,
    ImapConn,
    u32,
    Vec<u32>,
    anet_common::protocol::AuthResponse,
    [u8; 32],
)> {
    let (cli_writer, cli_reader, initial_max_uid) = connect_data_only_mailbox_pair(
        target_addrs,
        host,
        port,
        account,
        tls_cfg,
        command_timeout,
        literal_plus_auto,
    )
    .await?;

    let auth_channel = ImapAuthChannel {
        writer: Mutex::new(cli_writer),
        reader: Mutex::new(cli_reader),
        account_email: account.email.clone(),
        srv_id: srv_id.to_string(),
        client_temp_id: client_temp_id.to_string(),
        timeout_dur: command_timeout,
        last_reader_uid: Mutex::new(initial_max_uid),
        handshake_uids: Mutex::new(Vec::with_capacity(2)),
    };

    let auth_handler =
        AuthHandler::new_with_resume(core_cfg, server_pub_key_override, resume_session_id)?;
    let (auth_response, shared_key) = auth_handler.authenticate_once(&auth_channel).await?;

    let final_uid = auth_channel.last_reader_uid.into_inner();
    let hs_uids = auth_channel.handshake_uids.into_inner();
    let cli_writer = auth_channel.writer.into_inner();
    let cli_reader = auth_channel.reader.into_inner();

    Ok((
        cli_writer,
        cli_reader,
        final_uid,
        hs_uids,
        auth_response,
        shared_key,
    ))
}

/// Изолированный жизненный цикл клиентской пары воркеров (`CLI_WRITER[i]` + `CLI_READER[i]`) для одного ящика `slot.index`
/// (разделы 9.3.3, 9.4.1, 9.4.3 спецификации):
/// - Хранит строго локальные `last_seen_uid` и `cleanup_uids` папки `"Notes"` своего ящика;
/// - Для вторичных ящиков (и после переподключения) отправляет `Mailbox Binding Frame`;
/// - При обрыве `APPEND` возвращает батч в `retry_uplink_tx` для мгновенной досылки через соседний живой ящик (Zero-Loss Retry);
/// - Самостоятельно переподключается в фоне без прерывания туннеля, пока хотя бы один другой ящик здоров.
#[allow(clippy::too_many_arguments)]
async fn run_client_mailbox_worker(
    slot: ClientMailboxSlot,
    all_slots: Vec<ClientMailboxSlot>,
    uplink_rx: mpsc::Receiver<(EncryptedUplinkBatch, OwnedSemaphorePermit)>,
    retry_uplink_tx: mpsc::UnboundedSender<EncryptedUplinkBatch>,
    downlink_tun_tx: mpsc::Sender<Bytes>,
    initial_conn: Option<(ImapConn, ImapConn, u32, Vec<u32>)>,
    target_addrs: Vec<SocketAddr>,
    host: String,
    port: u16,
    tls_cfg: anet_common::boring_tls::TlsClientConfig,
    srv_id: String,
    client_temp_id: String,
    core_cfg: CoreConfig,
    server_pub_key_override: Option<String>,
    session_state: Arc<RwLock<ActiveImapSessionState>>,
    sequence: Arc<AtomicU64>,
    full_resume_mutex: Arc<Mutex<()>>,
    command_timeout: Duration,
    idle_quiet_timeout: Duration,
    idle_active_timeout: Duration,
    idle_active_window_ms: u64,
    fetch_max_messages: usize,
    expunge_batch_size: usize,
    expunge_idle_delay: Duration,
    _max_inflight_batches: usize,
    literal_plus_auto: bool,
    throttle_backoff: Duration,
    stop_flag: Arc<AtomicBool>,
    pool_wake_notify: Arc<Notify>,
    tunnel_last_activity_ms: Arc<AtomicU64>,
    tunnel_reader_wake_notify: Arc<Notify>,
) {
    let idx = slot.index;
    let email = slot.account.email.clone();
    let mut preconnected = initial_conn;
    let uplink_rx = Arc::new(Mutex::new(uplink_rx));
    let expunge_idle_delay_ms = expunge_idle_delay.as_millis() as u64;

    while !stop_flag.load(Ordering::Relaxed) {
        let mut send_binding_frame = false;

        let (cli_writer, mut cli_reader, initial_max_uid, initial_cleanup) =
            if let Some(conn_tuple) = preconnected.take() {
                conn_tuple
            } else {
                // Проверяем, есть ли в пуле хотя бы один другой здоровый ящик
                let any_other_healthy = all_slots
                    .iter()
                    .any(|s| s.index != idx && s.healthy.load(Ordering::Acquire));

                if any_other_healthy || all_slots.len() > 1 {
                    match connect_data_only_mailbox_pair(
                        &target_addrs,
                        &host,
                        port,
                        &slot.account,
                        &tls_cfg,
                        command_timeout,
                        literal_plus_auto,
                    )
                    .await
                    {
                        Ok((w, r, max_uid)) => {
                            send_binding_frame = true;
                            (w, r, max_uid, Vec::new())
                        }
                        Err(e) => {
                            warn!(
                                "[IMAP Client][Box #{} ({})] Data-plane connect failed: {e:#}. Retrying in 2s...",
                                idx, email
                            );
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            continue;
                        }
                    }
                } else {
                    // Все ящики были недоступны (или N == 1): координируем полное возобновление сессии с resume_session_id
                    let _resume_guard = full_resume_mutex.lock().await;
                    if stop_flag.load(Ordering::Relaxed) {
                        break;
                    }
                    // Повторно проверяем под локом: возможно, соседний воркер только что поднял сессию
                    let other_recovered = all_slots
                        .iter()
                        .any(|s| s.index != idx && s.healthy.load(Ordering::Acquire));

                    if other_recovered {
                        continue;
                    }

                    let resume_sid = session_state.read().await.session_id.clone();
                    info!(
                        "[IMAP Client][Box #{} ({})] Performing full session resume (resume_session_id: {})...",
                        idx, email, resume_sid
                    );
                    match establish_mailbox_session(
                        &target_addrs,
                        &host,
                        port,
                        &slot.account,
                        &tls_cfg,
                        command_timeout,
                        literal_plus_auto,
                        &srv_id,
                        &client_temp_id,
                        &core_cfg,
                        server_pub_key_override.as_deref(),
                        Some(resume_sid),
                    )
                    .await
                    {
                        Ok((w, r, max_uid, hs_uids, new_auth, new_key)) => {
                            if let Ok(new_prefix) = new_auth.nonce_prefix.as_slice().try_into() {
                                {
                                    let mut st = session_state.write().await;
                                    st.session_id = new_auth.session_id;
                                    st.cipher = Arc::new(Cipher::new(&new_key));
                                    st.nonce_prefix = new_prefix;
                                }
                                sequence.store(CLIENT_SEQUENCE_START, Ordering::SeqCst);
                                (w, r, max_uid, hs_uids)
                            } else {
                                tokio::time::sleep(Duration::from_secs(2)).await;
                                continue;
                            }
                        }
                        Err(e) => {
                            warn!(
                                "[IMAP Client][Box #{} ({})] Full session resume failed: {e:#}. Backing off {:?}...",
                                idx, email, throttle_backoff
                            );
                            tokio::time::sleep(throttle_backoff).await;
                            continue;
                        }
                    }
                }
            };

        let mut cli_writer = cli_writer;

        // Для вторичных ящиков (и после переподключения) отправляем Mailbox Binding Frame (раздел 9.3.3),
        // чтобы сервер мгновенно привязал этот ящик к SessionMailboxPool клиента!
        if send_binding_frame {
            let binding_res = {
                let st = session_state.read().await;
                build_mailbox_binding_frame(
                    &st.cipher,
                    &st.nonce_prefix,
                    &sequence,
                    &srv_id,
                    &st.session_id,
                )
            };
            match binding_res {
                Ok(binding) => {
                    if let Err(e) = cli_writer
                        .append_message(
                            "Drafts",
                            &binding.subject,
                            &binding.encrypted_payload,
                            &email,
                            command_timeout,
                        )
                        .await
                    {
                        warn!(
                            "[IMAP Client][Box #{} ({})] Failed to send Mailbox Binding Frame: {e:#}. Reconnecting...",
                            idx, email
                        );
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        continue;
                    }
                    info!(
                        "[IMAP Client][Box #{} ({})] Sent Mailbox Binding Frame ({})",
                        idx, email, binding.subject
                    );
                }
                Err(e) => {
                    warn!(
                        "[IMAP Client][Box #{} ({})] Binding frame build error: {e:#}",
                        idx, email
                    );
                }
            }
        }

        let writer_mutex = Arc::new(Mutex::new(cli_writer));
        let cleanup_uids = Arc::new(Mutex::new(initial_cleanup));
        let worker_stop = Arc::new(AtomicBool::new(false));
        let was_throttled = Arc::new(AtomicBool::new(false));
        // Метка времени последнего прихода письма именно в папку "Notes" этого ящика (для expunge_idle_delay)
        let last_rx_ms = Arc::new(AtomicU64::new(now_epoch_ms()));

        slot.inflight.store(0, Ordering::Release);
        slot.healthy.store(true, Ordering::Release);
        pool_wake_notify.notify_waiters();
        info!(
            "[IMAP Client][Box #{} ({})] Mailbox slot marked HEALTHY & active in striping pool",
            idx, email
        );

        let mut last_seen_uid = initial_max_uid;
        let mut force_immediate_fetch = false;
        let mut write_buf = BytesMut::with_capacity(COALESCE_BUDGET_BYTES);

        // Запускаем параллельную задачу CLI_WRITER[i]
        let writer_for_task = writer_mutex.clone();
        let uplink_rx_for_writer = uplink_rx.clone();
        let cleanup_for_writer = cleanup_uids.clone();
        let slot_for_writer = slot.clone();
        let retry_tx_for_writer = retry_uplink_tx.clone();
        let worker_stop_for_writer = worker_stop.clone();
        let global_stop_for_writer = stop_flag.clone();
        let throttled_for_writer = was_throttled.clone();
        let last_rx_for_writer = last_rx_ms.clone();
        let tunnel_act_for_writer = tunnel_last_activity_ms.clone();
        let tunnel_wake_for_writer = tunnel_reader_wake_notify.clone();
        let pool_wake_for_writer = pool_wake_notify.clone();
        let email_for_writer = email.clone();

        let writer_handle = tokio::spawn(async move {
            let mut uplink_rx_guard = uplink_rx_for_writer.lock().await;

            while !worker_stop_for_writer.load(Ordering::Relaxed)
                && !global_stop_for_writer.load(Ordering::Relaxed)
            {
                // 1. Сначала ожидаем следующий батч от центрального диспетчера (чтобы не перехватывать
                //    writer_sem на микросекундном стыке между drop(permit) и пробуждением диспетчера!).
                let next_item = tokio::select! {
                    biased;
                    item = uplink_rx_guard.recv() => item,
                    _ = tokio::time::sleep(Duration::from_millis(40)) => None,
                };

                let Some((batch, permit)) = next_item else {
                    // 2. Ленивая пакетная очистка строго в реальных паузах (когда очередь пуста >= 40 мс
                    //    и весь туннель неактивен >= expunge_idle_delay_ms, либо накопился полный батч).
                    if uplink_rx_guard.is_empty() {
                        if let Ok(expunge_permit) = slot_for_writer.writer_sem.try_acquire() {
                            let to_clean = {
                                let mut guard = cleanup_for_writer.lock().await;
                                let force_clean = guard.len() >= expunge_batch_size;
                                let last_act = last_rx_for_writer
                                    .load(Ordering::Relaxed)
                                    .max(tunnel_act_for_writer.load(Ordering::Relaxed));
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
                                let mut w_guard = writer_for_task.lock().await;
                                if let Err(e) =
                                    w_guard.expunge_uids(&to_clean, command_timeout).await
                                {
                                    debug!(
                                        "[IMAP Uplink][Box #{} ({})] UID EXPUNGE in Notes failed: {e}",
                                        idx, email_for_writer
                                    );
                                    drop(expunge_permit);
                                    worker_stop_for_writer.store(true, Ordering::SeqCst);
                                    break;
                                } else {
                                    last_rx_for_writer.store(now_epoch_ms(), Ordering::Relaxed);
                                    debug!(
                                        "[IMAP Uplink][Box #{} ({})] Cleaned up {} UIDs in Notes",
                                        idx,
                                        email_for_writer,
                                        to_clean.len()
                                    );
                                    drop(expunge_permit);
                                    pool_wake_for_writer.notify_waiters();
                                }
                            } else {
                                drop(expunge_permit);
                            }
                        }
                    }
                    continue;
                };

                slot_for_writer.inflight.fetch_add(1, Ordering::Relaxed);
                let append_res = {
                    let mut w_guard = writer_for_task.lock().await;
                    w_guard
                        .append_message(
                            "Drafts",
                            &batch.subject,
                            &batch.encrypted_payload,
                            &email_for_writer,
                            command_timeout,
                        )
                        .await
                };
                let cur_inf = slot_for_writer.inflight.load(Ordering::Relaxed);
                if cur_inf > 0 {
                    slot_for_writer.inflight.fetch_sub(1, Ordering::Relaxed);
                }

                match append_res {
                    Ok(lat) => {
                        tunnel_act_for_writer.store(now_epoch_ms(), Ordering::Relaxed);
                        tunnel_wake_for_writer.notify_waiters();
                        if crate::connectivity_monitor::ConnectivityMonitor::get_tunnel_rtt_ms()
                            .is_none()
                        {
                            let est_rtt = (lat.as_millis() as u64).clamp(1, 30_000);
                            crate::connectivity_monitor::ConnectivityMonitor::update_tunnel_rtt_ms(
                                Some(est_rtt),
                            );
                        }
                        debug!(
                            "[IMAP Uplink][Box #{} ({})] APPEND Drafts OK in {:.1} ms ({} B)",
                            idx,
                            email_for_writer,
                            lat.as_secs_f64() * 1000.0,
                            batch.encrypted_payload.len()
                        );

                        // Попутная пакетная очистка (Piggybacked Expunge): если за время активного потока
                        // накопилось >= expunge_batch_size прочитанных писем в "Notes", очищаем их прямо сейчас,
                        // пока мы уже владеем `permit` (без риска дедлока и без голодания сборки мусора!).
                        let piggyback_clean = {
                            let mut guard = cleanup_for_writer.lock().await;
                            if guard.len() >= expunge_batch_size {
                                std::mem::take(&mut *guard)
                            } else {
                                Vec::new()
                            }
                        };
                        if !piggyback_clean.is_empty() {
                            let mut w_guard = writer_for_task.lock().await;
                            if let Err(e) =
                                w_guard.expunge_uids(&piggyback_clean, command_timeout).await
                            {
                                debug!(
                                    "[IMAP Uplink][Box #{} ({})] Piggybacked UID EXPUNGE in Notes failed: {e}",
                                    idx, email_for_writer
                                );
                                slot_for_writer.healthy.store(false, Ordering::Release);
                                drop(permit);
                                pool_wake_for_writer.notify_waiters();
                                worker_stop_for_writer.store(true, Ordering::SeqCst);
                                break;
                            } else {
                                last_rx_for_writer.store(now_epoch_ms(), Ordering::Relaxed);
                                debug!(
                                    "[IMAP Uplink][Box #{} ({})] Piggybacked cleanup of {} UIDs in Notes",
                                    idx,
                                    email_for_writer,
                                    piggyback_clean.len()
                                );
                            }
                        }

                        // Освобождаем разрешение семафора ТОЛЬКО ПОСЛЕ завершения сетевого APPEND (и попутного EXPUNGE)!
                        drop(permit);
                        pool_wake_for_writer.notify_waiters();
                    }
                    Err(e) => {
                        let err_str = format!("{e:#}");
                        warn!(
                            "[IMAP Uplink][Box #{} ({})] APPEND Drafts failed, returning batch to retry queue: {err_str}",
                            idx, email_for_writer
                        );
                        if err_str.contains("THROTTLED") || err_str.contains("OVERQUOTA") {
                            throttled_for_writer.store(true, Ordering::SeqCst);
                        }
                        slot_for_writer.healthy.store(false, Ordering::Release);
                        // Zero-Loss Retry: возвращаем батч центральному диспетчеру!
                        let _ = retry_tx_for_writer.send(batch);
                        drop(permit);
                        pool_wake_for_writer.notify_waiters();
                        worker_stop_for_writer.store(true, Ordering::SeqCst);
                        break;
                    }
                }
            }
        });

        // Цикл CLI_READER[i]: Adaptive Short-IDLE + Greedy Fetch Drain "Notes" -> unpack_batch -> downlink_tun_tx
        while !worker_stop.load(Ordering::Relaxed) && !stop_flag.load(Ordering::Relaxed) {
            let since_active_ms =
                now_epoch_ms().saturating_sub(tunnel_last_activity_ms.load(Ordering::Relaxed));
            let is_active = since_active_ms <= idle_active_window_ms;
            let mut got_event = true;

            if !force_immediate_fetch {
                let cur_idle_timeout = if is_active {
                    idle_active_timeout
                } else {
                    idle_quiet_timeout
                };
                let wake_opt = if is_active {
                    None
                } else {
                    Some(tunnel_reader_wake_notify.as_ref())
                };

                match cli_reader.wait_idle_or_wake(cur_idle_timeout, wake_opt).await {
                    Ok(ev) => got_event = ev,
                    Err(e) => {
                        warn!(
                            "[IMAP Downlink][Box #{} ({})] wait_idle_or_wake error: {e:#}",
                            idx, email
                        );
                        worker_stop.store(true, Ordering::SeqCst);
                        break;
                    }
                }
            }
            let _ = got_event;
            force_immediate_fetch = false;

            if worker_stop.load(Ordering::Relaxed) || stop_flag.load(Ordering::Relaxed) {
                break;
            }

            // Двухфазный порционный опрос (Chunked UID Fetch):
            // 1. Запрашивает легковесный индекс `UID FETCH <last_seen_uid + 1>:* (UID)` (~40 байт).
            //    Если новых писем нет (включая выход из 400ms/10s IDLE по тайм-ауту), не качает 175 КБ дубликат
            //    и на 100% закрывает «Слепое окно» Mail.ru.
            // 2. Если писем накопилось много, скачивает тела не более `fetch_max_messages` (например, 3 шт.) за шаг,
            //    сразу сбрасывает их в TUN и мгновенно (без входа в IDLE) переходит к следующей порции.
            let fetch_res = cli_reader
                .fetch_messages_chunked(last_seen_uid, fetch_max_messages, command_timeout)
                .await;
            if cli_reader.pending_exists {
                cli_reader.pending_exists = false;
                force_immediate_fetch = true;
            }

            match fetch_res {
                Ok(res) => {
                    last_seen_uid = res.new_max_uid;
                    if !res.messages.is_empty() {
                        let now = now_epoch_ms();
                        last_rx_ms.store(now, Ordering::Relaxed);
                        tunnel_last_activity_ms.store(now, Ordering::Relaxed);
                        tunnel_reader_wake_notify.notify_waiters();
                    }

                    let (expected_sess_tag, cipher_cur) = {
                        let st = session_state.read().await;
                        (format!("[ID: {}]", st.session_id), st.cipher.clone())
                    };

                    for msg in res.messages {
                        if !msg.subject.contains(&expected_sess_tag) {
                            continue;
                        }

                        {
                            let mut guard = cleanup_uids.lock().await;
                            guard.push(msg.uid);
                        }

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
                                    let framed_chunk = write_buf.split().freeze();
                                    if downlink_tun_tx.send(framed_chunk).await.is_err() {
                                        stop_flag.store(true, Ordering::SeqCst);
                                        worker_stop.store(true, Ordering::SeqCst);
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                debug!(
                                    "[IMAP Downlink][Box #{} ({})] unwrap_packet error on UID {}: {e}",
                                    idx, email, msg.uid
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "[IMAP Downlink][Box #{} ({})] UID FETCH failed: {e:#}",
                        idx, email
                    );
                    worker_stop.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }

        // Помечаем слот нездоровым на время переподключения
        slot.healthy.store(false, Ordering::Release);
        worker_stop.store(true, Ordering::SeqCst);
        pool_wake_notify.notify_waiters();

        writer_handle.abort();
        let _ = writer_handle.await;

        // Если в буфере канала этого воркера остался неотправленный батч — возвращаем его диспетчеру без потерь!
        {
            let mut rx_guard = uplink_rx.lock().await;
            while let Ok((pending_batch, permit)) = rx_guard.try_recv() {
                let _ = retry_uplink_tx.send(pending_batch);
                drop(permit);
            }
        }
        pool_wake_notify.notify_waiters();

        let _ = tokio::time::timeout(Duration::from_millis(250), async {
            let _ = cli_reader.exit_idle(Duration::from_millis(200)).await;
            let _ = cli_reader.send_line("A9999 LOGOUT").await;
        })
        .await;
        let _ = tokio::time::timeout(Duration::from_millis(250), async {
            let mut w = writer_mutex.lock().await;
            let _ = w.send_line("A9999 LOGOUT").await;
        })
        .await;

        if stop_flag.load(Ordering::Relaxed) {
            break;
        }

        let backoff = if was_throttled.load(Ordering::Relaxed) {
            warn!(
                "[IMAP Client][Box #{} ({})] THROTTLED/OVERQUOTA hit, backing off {:?}...",
                idx, email, throttle_backoff
            );
            throttle_backoff
        } else {
            Duration::from_secs(2)
        };
        tokio::time::sleep(backoff).await;
    }
}

#[async_trait]
impl ClientTransport for ImapTransport {
    async fn connect(&self) -> Result<ConnectionResult> {
        let accounts = self.parse_accounts()?;
        let (host, port, target_addr, target_addrs, mut bypass_ips) =
            self.resolve_target_addresses()?;

        let tls_cfg = self.server.effective_tls_config(&self.config.stealth);
        let imap_cfg = self.effective_imap_config();

        let command_timeout = Duration::from_millis(imap_cfg.command_timeout_ms.max(5000));
        let idle_quiet_timeout = Duration::from_millis(imap_cfg.idle_refresh_interval_ms.max(2000));
        let idle_active_timeout =
            Duration::from_millis(imap_cfg.idle_active_poll_ms.clamp(150, 5000));
        let idle_active_window_ms = imap_cfg.idle_active_window_ms.clamp(1000, 60_000);
        let coalesce_ms = imap_cfg.batch_coalesce_ms.clamp(5, 100);
        let max_batch_bytes = (imap_cfg.max_batch_kb.clamp(8, 512)) * 1024;
        let fetch_max_messages = imap_cfg.fetch_max_messages.min(100);
        let expunge_batch_size = imap_cfg.expunge_batch_size.clamp(5, 200);
        let expunge_idle_delay =
            Duration::from_millis(imap_cfg.expunge_idle_delay_ms.clamp(250, 30_000));
        let max_inflight_batches = imap_cfg.max_inflight_batches.clamp(5, 250);
        let tx_queue_capacity = imap_cfg.tx_queue_capacity.clamp(32, 2048);
        let literal_plus_auto = imap_cfg.literal_plus_auto;
        let throttle_backoff = Duration::from_millis(imap_cfg.throttle_backoff_ms.max(5000));

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
            "[IMAP Client] Handshake IDs: SRV_ID={}, Client_TempID={} | Active-Active Pool accounts: {} | Batch: {} KB, FetchMax: {}, ActiveIDLE: {} ms, ExpungeBatch: {}",
            srv_id,
            client_temp_id,
            accounts.len(),
            max_batch_bytes / 1024,
            fetch_max_messages,
            idle_active_timeout.as_millis(),
            expunge_batch_size
        );

        // 1. Первичный ASTP-хендшейк через первый доступный ящик (Primary Mailbox, раздел 9.3.1)
        let mut primary_idx = 0usize;
        let mut initial_session = None;
        let mut last_err = None;

        for (idx, acc) in accounts.iter().enumerate() {
            info!(
                "[IMAP Client] Connecting Primary Mailbox to {}:{} via BoringSSL Email Mimicry (Account [{}/{}]: {})",
                host,
                port,
                idx + 1,
                accounts.len(),
                acc.email
            );
            match establish_mailbox_session(
                &target_addrs,
                &host,
                port,
                acc,
                &tls_cfg,
                command_timeout,
                literal_plus_auto,
                &srv_id,
                &client_temp_id,
                &self.config,
                self.server.server_pub_key.as_deref(),
                None,
            )
            .await
            {
                Ok(res) => {
                    primary_idx = idx;
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

        let (
            primary_writer,
            primary_reader,
            initial_max_uid,
            initial_hs_uids,
            auth_response,
            shared_key,
        ) = match initial_session {
            Some(s) => s,
            None => {
                return Err(last_err.unwrap_or_else(|| {
                    anyhow!("All IMAP mailboxes failed during initial connect")
                }))
            }
        };

        let pinned_ip = primary_writer.peer_ip().unwrap_or(target_addr.ip());
        if !bypass_ips.contains(&pinned_ip) {
            bypass_ips.push(pinned_ip);
        }
        if let Some(r_ip) = primary_reader.peer_ip() {
            if !bypass_ips.contains(&r_ip) {
                bypass_ips.push(r_ip);
            }
        }

        let session_id = auth_response.session_id.clone();
        info!(
            "[IMAP Client] ASTP Authentication successful on Primary Mailbox {}! Assigned IP: {}, Session: {} (Spawning {} Active-Active striping worker pair(s))",
            accounts[primary_idx].email,
            auth_response.ip,
            session_id,
            accounts.len()
        );

        // Создаем локальный дуплексный канал связи с VPN TUN-стеком (раздел 7.2 п. 4)
        let (client_stream, internal_router) = tokio::io::duplex(256 * 1024);
        let (mut tunnel_read, mut tunnel_write) = tokio::io::split(internal_router);

        let nonce_prefix: [u8; 4] = auth_response
            .nonce_prefix
            .as_slice()
            .try_into()
            .context("Invalid nonce prefix in AuthResponse")?;

        let session_state = Arc::new(RwLock::new(ActiveImapSessionState {
            session_id,
            cipher: Arc::new(Cipher::new(&shared_key)),
            nonce_prefix,
        }));

        let sequence = Arc::new(AtomicU64::new(CLIENT_SEQUENCE_START));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let pool_wake_notify = Arc::new(Notify::new());
        let full_resume_mutex = Arc::new(Mutex::new(()));
        // Общие для всех N ящиков индикаторы активности туннеля и раннего пробуждения CLI_READER[0..N]:
        // когда пакет уходит через ящик #0, ответ сервера может прийти через ящик #1, поэтому все ридеры
        // должны синхронно переходить в короткий адаптивный опрос (400 мс)!
        let tunnel_last_activity_ms = Arc::new(AtomicU64::new(now_epoch_ms()));
        let tunnel_reader_wake_notify = Arc::new(Notify::new());

        // 2. Двухполосная очередь пакетов из TUN (Fast-Lane Priority + Bounded Bulk).
        // Важно: tun_reader_task никогда не блокируется надолго на bulk_tx, чтобы не останавливать
        // чтение приоритетных пакетов (ICMP-зондов, DNS, TCP SYN/ACK) и не замораживать задачу t1.
        let (prio_tx, prio_rx) = mpsc::channel::<Bytes>(512);
        let (bulk_tx, bulk_rx) = mpsc::channel::<Bytes>(tx_queue_capacity);
        let stop_tun_reader = stop_flag.clone();

        let tun_reader_task = tokio::spawn(async move {
            let mut frame_reader = FrameReader::new();
            while !stop_tun_reader.load(Ordering::Relaxed) {
                match frame_reader.read_next_packet(&mut tunnel_read).await {
                    Ok(Some(packet)) => {
                        if packet.len() < 20 {
                            continue;
                        }
                        if is_priority_ip_packet(&packet) {
                            match prio_tx.try_send(packet) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(pkt)) => {
                                    let _ = bulk_tx.try_send(pkt);
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => break,
                            }
                        } else {
                            match bulk_tx.try_send(packet) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {}
                                Err(mpsc::error::TrySendError::Closed(_)) => break,
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
            stop_tun_reader.store(true, Ordering::SeqCst);
        });

        // 3. Общий канал записи расфреймированных Downlink-пакетов от всех N CLI_READER[i] в TUN
        let (downlink_tun_tx, mut downlink_tun_rx) =
            mpsc::channel::<Bytes>((tx_queue_capacity * 2).max(128));
        let stop_tun_writer = stop_flag.clone();
        let tun_writer_task = tokio::spawn(async move {
            while let Some(chunk) = downlink_tun_rx.recv().await {
                if let Err(e) = tunnel_write.write_all(&chunk).await {
                    warn!("[IMAP Downlink] Failed to write packets to TUN: {e}");
                    stop_tun_writer.store(true, Ordering::SeqCst);
                    break;
                }
            }
        });

        // 4. Создаем N слотов ClientMailboxSlot и запускаем N изолированных пар воркеров (CLI_WRITER[i] + CLI_READER[i])
        let (retry_uplink_tx, retry_uplink_rx) = mpsc::unbounded_channel::<EncryptedUplinkBatch>();
        let mut slots = Vec::with_capacity(accounts.len());
        let mut slot_receivers = Vec::with_capacity(accounts.len());

        for (idx, acc) in accounts.iter().cloned().enumerate() {
            let is_primary = idx == primary_idx;
            let (slot, rx) = ClientMailboxSlot::new(idx, acc, is_primary);
            slots.push(slot);
            slot_receivers.push(rx);
        }

        let mut primary_conn_opt = Some((
            primary_writer,
            primary_reader,
            initial_max_uid,
            initial_hs_uids,
        ));
        let mut worker_aborts = Vec::with_capacity(slots.len());

        for (idx, uplink_rx) in slot_receivers.into_iter().enumerate() {
            let init_conn = if idx == primary_idx {
                primary_conn_opt.take()
            } else {
                None
            };
            let slot_c = slots[idx].clone();
            let all_slots_c = slots.clone();
            let retry_tx_c = retry_uplink_tx.clone();
            let dl_tun_tx_c = downlink_tun_tx.clone();
            let target_addrs_c = target_addrs.clone();
            let host_c = host.clone();
            let tls_cfg_c = tls_cfg.clone();
            let srv_id_c = srv_id.clone();
            let cli_temp_c = client_temp_id.clone();
            let core_cfg_c = self.config.clone();
            let srv_pub_c = self.server.server_pub_key.clone();
            let sess_state_c = session_state.clone();
            let seq_c = sequence.clone();
            let resume_mtx_c = full_resume_mutex.clone();
            let stop_c = stop_flag.clone();
            let wake_c = pool_wake_notify.clone();
            let tun_act_c = tunnel_last_activity_ms.clone();
            let tun_wake_c = tunnel_reader_wake_notify.clone();

            let worker_task = tokio::spawn(async move {
                run_client_mailbox_worker(
                    slot_c,
                    all_slots_c,
                    uplink_rx,
                    retry_tx_c,
                    dl_tun_tx_c,
                    init_conn,
                    target_addrs_c,
                    host_c,
                    port,
                    tls_cfg_c,
                    srv_id_c,
                    cli_temp_c,
                    core_cfg_c,
                    srv_pub_c,
                    sess_state_c,
                    seq_c,
                    resume_mtx_c,
                    command_timeout,
                    idle_quiet_timeout,
                    idle_active_timeout,
                    idle_active_window_ms,
                    fetch_max_messages,
                    expunge_batch_size,
                    expunge_idle_delay,
                    max_inflight_batches,
                    literal_plus_auto,
                    throttle_backoff,
                    stop_c,
                    wake_c,
                    tun_act_c,
                    tun_wake_c,
                )
                .await;
            });
            worker_aborts.push(worker_task.abort_handle());
        }

        // 5. Запускаем центральный Self-Clocking Round-Robin Uplink Dispatcher (раздел 9.4.2)
        let slots_for_disp = slots.clone();
        let sess_state_disp = session_state.clone();
        let seq_disp = sequence.clone();
        let srv_id_disp = srv_id.clone();
        let stop_disp = stop_flag.clone();
        let wake_disp = pool_wake_notify.clone();

        let dispatcher_task = tokio::spawn(async move {
            run_client_uplink_dispatcher(
                prio_rx,
                bulk_rx,
                retry_uplink_rx,
                slots_for_disp,
                sess_state_disp,
                seq_disp,
                srv_id_disp,
                max_batch_bytes,
                coalesce_ms,
                max_inflight_batches,
                stop_disp,
                wake_disp,
            )
            .await;
        });

        // 6. Регистрация shutdown_hook для корректного освобождения всех N пар сокетов
        let tun_reader_abort = tun_reader_task.abort_handle();
        let tun_writer_abort = tun_writer_task.abort_handle();
        let dispatcher_abort = dispatcher_task.abort_handle();
        let stop_flag_hook = stop_flag.clone();
        let wake_hook = pool_wake_notify.clone();

        let shutdown_hook: super::ShutdownHook = Box::pin(async move {
            stop_flag_hook.store(true, Ordering::SeqCst);
            wake_hook.notify_waiters();
            tun_reader_abort.abort();
            tun_writer_abort.abort();
            dispatcher_abort.abort();
            for abort_handle in worker_aborts {
                abort_handle.abort();
            }
        });

        Ok(ConnectionResult {
            auth_response,
            vpn_stream: Box::new(client_stream),
            endpoint: None,
            connection: None,
            health_pause: None,
            remote_ip: Some(pinned_ip),
            bypass_ips,
            effective_mode: Some("IMAP".to_string()),
            shutdown_hook: Some(shutdown_hook),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anet_common::transport::unwrap_packet;

    fn make_ipv4_packet(payload_size: usize, tag_byte: u8) -> Bytes {
        let total_len = (20 + payload_size).max(20);
        let mut buf = vec![0u8; total_len];
        buf[0] = 0x45; // IPv4, IHL=5 (20 bytes)
        buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        buf[9] = 17; // UDP
        buf[12..16].copy_from_slice(&[10, 0, 0, 2]);
        buf[16..20].copy_from_slice(&[8, 8, 8, 8]);
        for b in &mut buf[20..] {
            *b = tag_byte;
        }
        Bytes::from(buf)
    }

    #[test]
    fn test_parse_multi_mailbox_accounts_and_percent_decode() {
        let cfg = CoreConfig::default();
        let srv = ServerConfig {
            dsn: "imap://imap.mail.ru:993?acc=furude.hanyuu%40mail.ru:pass_one&acc=zero.two.00.02%40mail.ru:pass_two&max_batch_kb=256".to_string(),
            ..Default::default()
        };
        let transport = ImapTransport::new(cfg, srv);
        let accounts = transport.parse_accounts().expect("parse accounts");
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].email, "furude.hanyuu@mail.ru");
        assert_eq!(accounts[0].password, "pass_one");
        assert_eq!(accounts[1].email, "zero.two.00.02@mail.ru");
        assert_eq!(accounts[1].password, "pass_two");

        let eff = transport.effective_imap_config();
        assert_eq!(eff.max_batch_kb, 256);
    }

    #[test]
    fn test_build_mailbox_binding_frame_roundtrip() {
        let key = [0x33u8; 32];
        let cipher = Cipher::new(&key);
        let nonce_prefix = [0x11, 0x22, 0x33, 0x44];
        let seq = AtomicU64::new(CLIENT_SEQUENCE_START);

        let frame =
            build_mailbox_binding_frame(&cipher, &nonce_prefix, &seq, "a1b2c3d4", "sess_777")
                .expect("build binding frame");
        assert_eq!(frame.subject, "ANet-Data [ID: a1b2c3d4:sess_777]");
        assert_eq!(seq.load(Ordering::Relaxed), CLIENT_SEQUENCE_START + 1);

        // На стороне сервера unwrap_packet успешно верифицирует тег Poly1305, а unpack_batch возвращает 0 IP-пакетов
        let decrypted = unwrap_packet(&cipher, &frame.encrypted_payload).expect("unwrap binding");
        assert!(decrypted.is_empty());
        assert!(unpack_batch(&decrypted).is_empty());
    }

    /// Тест 1 из Раздела 9.6: Проверяет, что при наличии N = 3 здоровых слотов `ClientMailboxSlot`
    /// последовательные батчи распределяются диспетчером равномерно (`0 -> 1 -> 2 -> 0 -> 1 -> 2`).
    #[tokio::test]
    async fn test_multi_mailbox_uplink_round_robin_distribution() {
        let mut slots = Vec::new();
        let mut rxs = Vec::new();
        for i in 0..3 {
            let (slot, rx) = ClientMailboxSlot::new(
                i,
                ImapAccount {
                    email: format!("box{i}@mail.ru"),
                    password: "pass".to_string(),
                },
                true,
            );
            slots.push(slot);
            rxs.push(rx);
        }

        let stop_flag = AtomicBool::new(false);
        let wake_notify = Notify::new();
        let mut rr_cursor = 0usize;
        let mut chosen_order = Vec::new();

        for _ in 0..6 {
            let (idx, permit) = acquire_client_slot_self_clocking(
                &slots,
                &mut rr_cursor,
                35,
                &stop_flag,
                &wake_notify,
            )
            .await
            .expect("should acquire slot");
            chosen_order.push(idx);
            // Освобождаем permit сразу (имитируем мгновенное завершение APPEND перед следующим шагом)
            drop(permit);
        }

        assert_eq!(chosen_order, vec![0, 1, 2, 0, 1, 2]);
        drop(rxs);
    }

    /// Тест 2 из Раздела 9.6: Имитирует ситуацию, когда ящик #0 заблокирован долгим APPEND (500 мс),
    /// а ящики #1 и #2 освобождаются каждые 30 мс. Проверяет, что диспетчер не блокируется на ящике #0
    /// (отсутствие Head-of-Line блокировки), а прокачивает всю очередь через ящики #1 и #2.
    #[tokio::test]
    async fn test_multi_mailbox_self_clocking_bypass_slow_worker() {
        let (prio_tx, prio_rx) = mpsc::channel::<Bytes>(64);
        let (bulk_tx, bulk_rx) = mpsc::channel::<Bytes>(64);
        let (_retry_tx, retry_rx) = mpsc::unbounded_channel::<EncryptedUplinkBatch>();

        let mut slots = Vec::new();
        let mut rxs = Vec::new();
        for i in 0..3 {
            let (slot, rx) = ClientMailboxSlot::new(
                i,
                ImapAccount {
                    email: format!("box{i}@mail.ru"),
                    password: "pass".to_string(),
                },
                true,
            );
            slots.push(slot);
            rxs.push(rx);
        }

        let key = [0x42u8; 32];
        let session_state = Arc::new(RwLock::new(ActiveImapSessionState {
            session_id: "sess_stripe".to_string(),
            cipher: Arc::new(Cipher::new(&key)),
            nonce_prefix: [1, 2, 3, 4],
        }));
        let sequence = Arc::new(AtomicU64::new(CLIENT_SEQUENCE_START));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let wake_notify = Arc::new(Notify::new());

        let counts = Arc::new([
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
        ]);

        // Запускаем 3 мок-воркера: воркер #0 спит 500 мс на APPEND, а воркеры #1 и #2 — всего 25 мс
        let mut worker_handles = Vec::new();
        for (i, mut rx) in rxs.into_iter().enumerate() {
            let counts_c = counts.clone();
            let wake_c = wake_notify.clone();
            let delay = if i == 0 {
                Duration::from_millis(500)
            } else {
                Duration::from_millis(25)
            };
            worker_handles.push(tokio::spawn(async move {
                while let Some((_batch, permit)) = rx.recv().await {
                    tokio::time::sleep(delay).await;
                    counts_c[i].fetch_add(1, Ordering::Relaxed);
                    drop(permit);
                    wake_c.notify_waiters();
                }
            }));
        }

        let disp_handle = tokio::spawn(run_client_uplink_dispatcher(
            prio_rx,
            bulk_rx,
            retry_rx,
            slots,
            session_state,
            sequence,
            "srv01".to_string(),
            1024, // 1 КБ макс батч, чтобы каждый пакет 900 Б уходил отдельным батчем
            0,
            35,
            stop_flag.clone(),
            wake_notify.clone(),
        ));

        // Отправляем 7 крупных пакетов по 900 байт (каждый формирует отдельный батч)
        for tag in 0..7u8 {
            bulk_tx.send(make_ipv4_packet(880, tag)).await.unwrap();
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        // Ждём ~160 мс: за это время медленный ящик #0 ещё даже не закончил первый APPEND (500 мс),
        // но быстрые ящики #1 и #2 уже должны были прокачать все остальные 6 батчей!
        tokio::time::sleep(Duration::from_millis(160)).await;
        let c1 = counts[1].load(Ordering::Relaxed);
        let c2 = counts[2].load(Ordering::Relaxed);
        assert!(
            c1 + c2 >= 6,
            "Fast workers #1 and #2 should bypass slow worker #0 and process >= 6 batches (got c1={c1}, c2={c2})"
        );

        stop_flag.store(true, Ordering::SeqCst);
        drop(prio_tx);
        drop(bulk_tx);
        disp_handle.abort();
        for h in worker_handles {
            h.abort();
        }
    }

    /// Тест 3 из Раздела 9.6: Имитирует обрыв APPEND на ящике #1 во время передачи батча.
    /// Проверяет, что `EncryptedUplinkBatch` возвращается через `retry_uplink_tx` и мгновенно
    /// доставляется через ящик #2 без потерь и без разрыва VPN-сессии.
    #[tokio::test]
    async fn test_multi_mailbox_zero_loss_on_single_worker_failure() {
        let (_prio_tx, prio_rx) = mpsc::channel::<Bytes>(64);
        let (bulk_tx, bulk_rx) = mpsc::channel::<Bytes>(64);
        let (retry_tx, retry_rx) = mpsc::unbounded_channel::<EncryptedUplinkBatch>();

        let mut slots = Vec::new();
        let mut rxs = Vec::new();
        for i in 0..2 {
            let (slot, rx) = ClientMailboxSlot::new(
                i,
                ImapAccount {
                    email: format!("box{i}@mail.ru"),
                    password: "pass".to_string(),
                },
                true,
            );
            slots.push(slot);
            rxs.push(rx);
        }

        let key = [0x77u8; 32];
        let cipher = Arc::new(Cipher::new(&key));
        let session_state = Arc::new(RwLock::new(ActiveImapSessionState {
            session_id: "sess_zero_loss".to_string(),
            cipher: cipher.clone(),
            nonce_prefix: [9, 8, 7, 6],
        }));
        let sequence = Arc::new(AtomicU64::new(CLIENT_SEQUENCE_START));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let wake_notify = Arc::new(Notify::new());

        let delivered_batches = Arc::new(Mutex::new(Vec::<Bytes>::new()));

        let mut rx0 = rxs.remove(0);
        let mut rx1 = rxs.remove(0);

        // Воркер #0: симулирует ошибку APPEND на первом же батче, помечает себя healthy = false
        // и возвращает батч в retry_tx!
        let slot0 = slots[0].clone();
        let retry_tx_0 = retry_tx.clone();
        let wake_0 = wake_notify.clone();
        let w0 = tokio::spawn(async move {
            if let Some((batch, permit)) = rx0.recv().await {
                slot0.healthy.store(false, Ordering::Release);
                let _ = retry_tx_0.send(batch);
                drop(permit);
                wake_0.notify_waiters();
            }
        });

        // Воркер #1: здоровый, принимает все батчи и складывает расшифрованные данные в delivered_batches
        let delivered_1 = delivered_batches.clone();
        let cipher_1 = cipher.clone();
        let wake_1 = wake_notify.clone();
        let w1 = tokio::spawn(async move {
            while let Some((batch, permit)) = rx1.recv().await {
                let dec = unwrap_packet(&cipher_1, &batch.encrypted_payload).expect("decrypt");
                for pkt in unpack_batch(&dec) {
                    delivered_1.lock().await.push(pkt);
                }
                drop(permit);
                wake_1.notify_waiters();
            }
        });

        let disp_handle = tokio::spawn(run_client_uplink_dispatcher(
            prio_rx,
            bulk_rx,
            retry_rx,
            slots,
            session_state,
            sequence,
            "srv01".to_string(),
            1024,
            0,
            35,
            stop_flag.clone(),
            wake_notify.clone(),
        ));

        let pkt_a = make_ipv4_packet(800, 0xAA);
        let pkt_b = make_ipv4_packet(800, 0xBB);
        bulk_tx.send(pkt_a.clone()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        bulk_tx.send(pkt_b.clone()).await.unwrap();

        tokio::time::sleep(Duration::from_millis(80)).await;

        let received = delivered_batches.lock().await.clone();
        assert_eq!(
            received.len(),
            2,
            "Both packets must be delivered without loss despite worker #0 failure"
        );
        assert!(received.contains(&pkt_a));
        assert!(received.contains(&pkt_b));

        stop_flag.store(true, Ordering::SeqCst);
        disp_handle.abort();
        w0.abort();
        w1.abort();
    }

    /// Регрессионный тест: проверяет отсутствие дедлока `writer_sem` в `CLI_WRITER`, когда
    /// диспетчер уже захватил `OwnedSemaphorePermit` и положил `(batch, permit)` в `uplink_rx`
    /// одновременно с накоплением `>= expunge_batch_size` прочитанных UID в `cleanup_uids`.
    #[tokio::test]
    async fn test_writer_piggybacked_and_idle_expunge_never_deadlocks_with_dispatcher() {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let mock_writer = Arc::new(Mutex::new(ImapConn::new(client_io)));

        // Мок IMAP-сервера, который принимает APPEND "Drafts", а сразу следом — попутный UID STORE + UID EXPUNGE
        let server_task = tokio::spawn(async move {
            let mut s_buf = BufReader::new(server_io);
            let mut line = String::new();

            // 1. Ожидаем APPEND "Drafts"
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("APPEND \"Drafts\""));
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
                .write_all(b"A0001 OK [APPENDUID 1 500] APPEND completed\r\n")
                .await
                .unwrap();

            // 2. Ожидаем попутный UID STORE + UID EXPUNGE (Piggybacked Expunge)
            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("UID STORE 1,2,3 +FLAGS.SILENT (\\Deleted)"));
            s_buf
                .get_mut()
                .write_all(b"A0002 OK STORE completed\r\n")
                .await
                .unwrap();

            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("UID EXPUNGE 1,2,3"));
            s_buf
                .get_mut()
                .write_all(b"A0003 OK EXPUNGE completed\r\n")
                .await
                .unwrap();
        });

        let (slot, mut uplink_rx) = ClientMailboxSlot::new(
            0,
            ImapAccount {
                email: "box0@mail.ru".to_string(),
                password: "pass".to_string(),
            },
            true,
        );

        // Имитируем ситуацию: диспетчер УЖЕ захватил единственное разрешение `writer_sem`
        // и положил `(batch, permit)` в канал `uplink_tx` ДО того, как воркер проверил `cleanup_uids`!
        let permit = slot
            .writer_sem
            .clone()
            .try_acquire_owned()
            .expect("dispatcher acquires sole permit");
        slot.uplink_tx
            .send((
                EncryptedUplinkBatch {
                    subject: "ANet-Data [ID: srv:sess]".to_string(),
                    encrypted_payload: Bytes::from_static(b"PAYLOAD"),
                },
                permit,
            ))
            .await
            .unwrap();

        // Одновременно в cleanup_uids уже лежит >= expunge_batch_size (3) UID
        let cleanup_uids = Arc::new(Mutex::new(vec![1u32, 2, 3]));
        let expunge_batch_size = 3usize;
        let command_timeout = Duration::from_secs(2);

        // Запускаем итерацию логики CLI_WRITER: она не должна заблокироваться на writer_sem,
        // а должна вычитать (batch, permit), выполнить APPEND и попутный EXPUNGE!
        let slot_w = slot.clone();
        let cleanup_w = cleanup_uids.clone();
        let writer_w = mock_writer.clone();

        let writer_step = tokio::time::timeout(Duration::from_secs(2), async move {
            // Шаг 1: в очереди uplink_rx уже лежит батч, поэтому try_acquire() вернет Err и не создаст дедлок
            if uplink_rx.is_empty() {
                if let Ok(_p) = slot_w.writer_sem.try_acquire() {
                     unreachable!("permit is already held by queued batch");
                }
            }

            // Шаг 2: забираем (batch, permit) и выполняем APPEND + попутный EXPUNGE под тем же permit
            let (batch, held_permit) = uplink_rx.recv().await.unwrap();
            {
                let mut w_guard = writer_w.lock().await;
                w_guard
                    .append_message(
                        "Drafts",
                        &batch.subject,
                        &batch.encrypted_payload,
                        "box0@mail.ru",
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
            assert_eq!(piggyback_clean, vec![1, 2, 3]);
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
            "CLI_WRITER must not deadlock when cleanup_uids >= expunge_batch_size and permit is in uplink_rx"
        );
        assert!(cleanup_uids.lock().await.is_empty());
        assert_eq!(slot.writer_sem.available_permits(), 1);
        server_task.await.unwrap();
    }
}
