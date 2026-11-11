// anet-common/src/imap_conn.rs
//! Высокопроизводительный асинхронный IMAP-клиент `ImapConn` для транспорта `imap` (ASTP over IMAPS:993).
//!
//! Разработан строго по спецификации `contrib/docs/imap.ru.md` и верифицирован эталоном
//! `contrib/scripts/imap_soak_test.py`:
//! - Работает напрямую поверх `tokio::io::BufReader<tokio_boring::SslStream<TcpStream>>` (BoringSSL Email TLS Mimicry, без `tokio::io::split` / `BiLock`);
//! - Отслеживает нетегированные ответы `* <N> EXISTS` в реальном времени (`pending_exists`),
//!   устраняя проблему «Слепого окна» (Blind Window);
//! - Побайтово считывает литералы RFC 3501 через `read_exact(len)` и корректно парсит постфиксный
//!   UID Mail.ru (`... {len}\r\n<bytes> UID <id>\r\n`);
//! - Бинарно извлекает зашифрованный ASTP Base64-пейлоуд без промежуточного преобразования в UTF-8;
//! - Фильтрует дубликаты `UID FETCH <last+1>:*` при `uid <= last_seen_uid`;
//! - Выполняет неблокирующий `UID EXPUNGE` (RFC 4315) с фолбэком на `EXPUNGE`.

use anyhow::{anyhow, Context, Result};
use base64::prelude::*;
use bytes::Bytes;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Максимально допустимый размер одного литерала сообщения при `UID FETCH` (2 МиБ).
/// Защищает парсер от OOM-аллокаций и зависания при попадании в почтовый ящик стороннего
/// письма с крупным вложением (максимальный легитимный ASTP-батч 512 КБ в Base64 занимает ~700 КБ).
pub const MAX_IMAP_LITERAL_BYTES: usize = 2 * 1024 * 1024;

/// Вычисляет 8-символьный hex-идентификатор узла (первые 4 байта SHA-256)
pub fn compute_hex_id(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        hash[0], hash[1], hash[2], hash[3]
    )
}

/// Форматирует текущее системное время в валидную строку RFC 2822 / RFC 5322 (`Mon, 02 Nov 2026 22:26:14 +0000`)
/// без внешних зависимостей для заголовка `Date:` письма.
pub fn format_rfc2822_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;

    // 1970-01-01 — четверг (4)
    const WDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    let wday = WDAYS[(days + 4).rem_euclid(7) as usize];

    // Алгоритм Howard Hinnant (civil_from_days)
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let mon_str = MONTHS[(m as usize).saturating_sub(1).min(11)];

    format!("{wday}, {d:02} {mon_str} {year:04} {hour:02}:{min:02}:{sec:02} +0000")
}

/// Генерирует 16-символьный случайный hex для `Message-ID`
fn random_message_id_hex() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut s = String::with_capacity(16);
    for b in bytes {
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

/// Результат выборки сообщений из папки
#[derive(Debug, Clone)]
pub struct FetchedMessage {
    pub uid: u32,
    pub subject: String,
    pub payload: Bytes,
}

/// Результат выполнения UID FETCH
#[derive(Debug, Clone)]
pub struct FetchResult {
    pub messages: Vec<FetchedMessage>,
    pub new_max_uid: u32,
    pub latency_ms: f64,
}

/// Проверяет, является ли строка нетегированным уведомлением о новых письмах (`* <N> EXISTS`).
#[inline]
pub fn is_exists_line(line: &str) -> bool {
    let trimmed = line.trim();
    if !trimmed.starts_with('*') {
        return false;
    }
    let mut parts = trimmed.split_whitespace();
    match (parts.next(), parts.next(), parts.next()) {
        (Some("*"), Some(num), Some(kw)) if kw.eq_ignore_ascii_case("EXISTS") => {
            num.chars().all(|c| c.is_ascii_digit())
        }
        _ => false,
    }
}

/// Извлекает числовой размер литерала `{<len>}` из заголовка IMAP-ответа (например, `* 1 FETCH (... {1234}`).
#[inline]
pub fn parse_literal_length(line: &str) -> Option<usize> {
    let start = line.rfind('{')?;
    let end = line[start + 1..].find('}')? + start + 1;
    let len_str = &line[start + 1..end];
    len_str.trim().parse::<usize>().ok()
}

/// Извлекает UID из метаданных строки FETCH (поддерживает как префиксное `(UID 123 ...)`, так и постфиксное `(... UID 123)` расположение).
pub fn extract_uid_from_fetch_meta(meta: &str) -> Option<u32> {
    let mut iter = meta.split_whitespace();
    while let Some(token) = iter.next() {
        let clean = token.trim_matches(|c: char| !c.is_ascii_alphanumeric());
        if clean.eq_ignore_ascii_case("UID") {
            if let Some(num_str) = iter.next() {
                let clean_num = num_str.trim_matches(|c: char| !c.is_ascii_digit());
                if let Ok(uid) = clean_num.parse::<u32>() {
                    return Some(uid);
                }
            }
        }
    }
    None
}

/// Извлекает заголовок Subject и чистое тело сообщения из сырых байтов RFC 5322,
/// после чего напрямую декодирует Base64 без промежуточного UTF-8.
pub fn parse_rfc822_message(raw_bytes: &[u8]) -> Result<(String, Bytes)> {
    // 1. Ищем границу заголовков и тела (\r\n\r\n или \n\n)
    let (header_bytes, body_bytes) =
        if let Some(pos) = raw_bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            (&raw_bytes[..pos], &raw_bytes[pos + 4..])
        } else if let Some(pos) = raw_bytes.windows(2).position(|w| w == b"\n\n") {
            (&raw_bytes[..pos], &raw_bytes[pos + 2..])
        } else {
            (&raw_bytes[..], &[][..])
        };

    // 2. Извлекаем Subject из заголовков (латинский безопасный поиск)
    let header_str = String::from_utf8_lossy(header_bytes);
    let mut subject = String::new();
    for line in header_str.lines() {
        if let Some(idx) = line.find(':') {
            let key = line[..idx].trim();
            if key.eq_ignore_ascii_case("Subject") {
                subject = line[idx + 1..].trim().to_string();
                break;
            }
        }
    }

    // 3. Бинарно очищаем Base64-тело от пробелов, \r и \n
    let mut clean_b64 = Vec::with_capacity(body_bytes.len());
    for &b in body_bytes {
        if !b.is_ascii_whitespace() {
            clean_b64.push(b);
        }
    }

    let decoded = BASE64_STANDARD
        .decode(&clean_b64)
        .map_err(|e| anyhow!("Base64 payload decoding failed: {e}"))?;

    Ok((subject, Bytes::from(decoded)))
}

/// Проверяет наличие токенов `LITERAL+` и `LITERAL-` в строке ответа `CAPABILITY`.
pub fn parse_capability_flags(line: &str) -> (bool, bool) {
    let upper = line.to_ascii_uppercase();
    if !upper.contains("CAPABILITY") {
        return (false, false);
    }
    let mut lit_plus = false;
    let mut lit_minus = false;
    for raw_tok in upper.split(|c: char| c.is_ascii_whitespace() || c == '[' || c == ']') {
        if raw_tok == "LITERAL+" {
            lit_plus = true;
        } else if raw_tok == "LITERAL-" {
            lit_minus = true;
        }
    }
    (lit_plus, lit_minus)
}

/// Асинхронное IMAP-соединение напрямую поверх `tokio::io::BufReader<S>` (раздел 3.1 / 7.1 спецификации).
pub struct ImapConn<S = tokio_boring::SslStream<TcpStream>> {
    stream: BufReader<S>,
    tag_counter: u64,
    /// Флаг «Слепого окна»: взводится при получении `* <N> EXISTS` вне или внутри IDLE.
    pub pending_exists: bool,
    /// Находится ли соединение в состоянии IMAP IDLE в данный момент.
    pub in_idle: bool,
    /// Обнаружена ли поддержка RFC 2088 / 7888 `LITERAL+` у сервера.
    pub supports_literal_plus: bool,
    /// Обнаружена ли поддержка RFC 7888 `LITERAL-` (несессионные литералы <= 4096 байт).
    pub supports_literal_minus: bool,
    /// Разрешено ли использование `LITERAL+` / `LITERAL-` конфигурацией (`literal_plus_auto`).
    pub use_literal_plus: bool,
    capabilities_received: bool,
    idle_tag: String,
    line_buf: String,
}

impl<S> ImapConn<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: S) -> Self {
        Self {
            stream: BufReader::with_capacity(64 * 1024, stream),
            tag_counter: 0,
            pending_exists: false,
            in_idle: false,
            supports_literal_plus: false,
            supports_literal_minus: false,
            use_literal_plus: true,
            capabilities_received: false,
            idle_tag: String::new(),
            line_buf: String::with_capacity(1024),
        }
    }

    pub fn set_literal_plus_enabled(&mut self, enabled: bool) {
        self.use_literal_plus = enabled;
    }

    pub fn next_tag(&mut self) -> String {
        self.tag_counter += 1;
        format!("A{:04}", self.tag_counter)
    }

    /// Отправляет сырую строку в сокет с добавлением `\r\n` и выполняет `flush()`.
    pub async fn send_line(&mut self, line: &str) -> Result<()> {
        let inner = self.stream.get_mut();
        inner.write_all(line.as_bytes()).await?;
        inner.write_all(b"\r\n").await?;
        inner.flush().await?;
        Ok(())
    }

    /// Считывает одну строку ответа от IMAP-сервера с автоматической фиксацией `* <N> EXISTS` и `CAPABILITY`.
    pub async fn read_line(&mut self) -> Result<String> {
        self.line_buf.clear();
        let bytes_read = self.stream.read_line(&mut self.line_buf).await?;
        if bytes_read == 0 {
            return Err(anyhow!("Connection closed by IMAP server (Unexpected EOF)"));
        }

        let line = self.line_buf.clone();
        if is_exists_line(&line) {
            self.pending_exists = true;
        }
        if line.contains("CAPABILITY") || line.contains("capability") {
            let (lp, lm) = parse_capability_flags(&line);
            if lp {
                self.supports_literal_plus = true;
            }
            if lm {
                self.supports_literal_minus = true;
            }
            self.capabilities_received = true;
        }

        Ok(line)
    }

    /// Считывает ответы от сервера до получения тегированной строки `tag OK / NO / BAD`.
    pub async fn read_until_tagged(&mut self, tag: &str, timeout_dur: Duration) -> Result<Vec<String>> {
        let mut lines = Vec::new();
        let deadline = Instant::now() + timeout_dur;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(anyhow!("Timeout waiting for tagged IMAP response '{tag}'"));
            }

            let line = tokio::time::timeout(remaining, self.read_line())
                .await
                .context("Timeout reading line from IMAP socket")??;

            let is_tagged_done = line.starts_with(&format!("{tag} OK"))
                || line.starts_with(&format!("{tag} NO"))
                || line.starts_with(&format!("{tag} BAD"));

            lines.push(line);

            if is_tagged_done {
                break;
            }
        }

        Ok(lines)
    }

    /// Выполняет команду LOGIN.
    pub async fn login(&mut self, email: &str, pass: &str, timeout_dur: Duration) -> Result<()> {
        // Сбрасываем pre-auth флаг, чтобы проверить post-login CAPABILITY
        self.capabilities_received = false;
        let tag = self.next_tag();
        self.send_line(&format!("{tag} LOGIN \"{email}\" \"{pass}\"")).await?;
        let resp = self.read_until_tagged(&tag, timeout_dur).await?;

        let last_line = resp.last().ok_or_else(|| anyhow!("Empty LOGIN response"))?;
        if !last_line.starts_with(&format!("{tag} OK")) {
            return Err(anyhow!("IMAP LOGIN failed: {}", last_line.trim()));
        }
        Ok(())
    }

    /// Запрашивает `CAPABILITY` у сервера после `LOGIN` (если сервер не прислал их автоматически в `OK [CAPABILITY ...]`),
    /// чтобы определить поддержку `LITERAL+` / `LITERAL-`.
    pub async fn detect_capabilities(&mut self, timeout_dur: Duration) -> Result<()> {
        if !self.capabilities_received {
            let tag = self.next_tag();
            self.send_line(&format!("{tag} CAPABILITY")).await?;
            let _ = self.read_until_tagged(&tag, timeout_dur).await?;
        }
        Ok(())
    }

    /// Создает почтовую папку (`CREATE "<folder>"`), если она еще не существует на свежезарегистрированном ящике.
    pub async fn create_folder(&mut self, folder: &str, timeout_dur: Duration) -> Result<()> {
        let tag = self.next_tag();
        self.send_line(&format!("{tag} CREATE \"{folder}\"")).await?;
        let resp = self.read_until_tagged(&tag, timeout_dur).await?;
        if let Some(last_line) = resp.last() {
            if last_line.starts_with(&format!("{tag} OK")) {
                log::info!("[IMAP] Created missing folder '{folder}'");
            }
        }
        Ok(())
    }

    /// Выполняет команду SELECT "<folder>".
    /// Если на новом почтовом ящике (например, в русскоязычной локали Mail.ru, где системная папка
    /// черновиков закодирована в modified UTF-7, а папка "Notes" еще не создана) папка отсутствует (`tag NO`),
    /// автоматически выполняет `CREATE "<folder>"` и повторяет `SELECT "<folder>"`.
    pub async fn select(&mut self, folder: &str, timeout_dur: Duration) -> Result<()> {
        let tag = self.next_tag();
        self.send_line(&format!("{tag} SELECT \"{folder}\"")).await?;
        let resp = self.read_until_tagged(&tag, timeout_dur).await?;

        let last_line = resp.last().ok_or_else(|| anyhow!("Empty SELECT response"))?;
        if !last_line.starts_with(&format!("{tag} OK")) {
            log::warn!(
                "[IMAP] SELECT '{}' returned '{}' — attempting CREATE \"{}\"...",
                folder,
                last_line.trim(),
                folder
            );
            let _ = self.create_folder(folder, timeout_dur).await;

            let tag2 = self.next_tag();
            self.send_line(&format!("{tag2} SELECT \"{folder}\"")).await?;
            let resp2 = self.read_until_tagged(&tag2, timeout_dur).await?;
            let last_line2 = resp2.last().ok_or_else(|| anyhow!("Empty SELECT retry response"))?;
            if !last_line2.starts_with(&format!("{tag2} OK")) {
                return Err(anyhow!(
                    "IMAP SELECT '{folder}' failed after CREATE: {}",
                    last_line2.trim()
                ));
            }
        }
        // Сбрасываем статический счетчик EXISTS, возвращаемый сервером при начальном SELECT
        self.pending_exists = false;
        Ok(())
    }

    /// Определяет максимальный существующий UID в выбранной папке без скачивания сообщений.
    pub async fn get_max_uid(&mut self, timeout_dur: Duration) -> Result<u32> {
        let tag = self.next_tag();
        self.send_line(&format!("{tag} UID FETCH * (UID)")).await?;
        let resp = self.read_until_tagged(&tag, timeout_dur).await?;

        let mut max_uid = 0u32;
        for line in resp {
            if let Some(uid) = extract_uid_from_fetch_meta(&line) {
                max_uid = max_uid.max(uid);
            }
        }
        Ok(max_uid)
    }

    /// Отправляет сообщение в указанную папку через APPEND с флагами `(\Seen \Draft)`:
    /// - Если сервер поддерживает `LITERAL+` (или `LITERAL-` при `msg_len <= 4096`) и `use_literal_plus == true`,
    ///   отправляет команду `{size+}\r\n` и тело письма в одном буфере за **1 RTT** без ожидания `+`;
    /// - В противном случае выполняет классический 2-шаговый `APPEND` с ожиданием `+`.
    pub async fn append_message(
        &mut self,
        folder: &str,
        subject: &str,
        payload_bytes: &[u8],
        account_email: &str,
        timeout_dur: Duration,
    ) -> Result<Duration> {
        let t0 = Instant::now();

        // 1. Формируем Base64 с разбивкой по 76 символов
        let b64_raw = BASE64_STANDARD.encode(payload_bytes);
        let mut b64_chunked = String::with_capacity(b64_raw.len() + (b64_raw.len() / 76) * 2 + 16);
        for chunk in b64_raw.as_bytes().chunks(76) {
            b64_chunked.push_str(std::str::from_utf8(chunk)?);
            b64_chunked.push_str("\r\n");
        }

        let rfc2822_date = format_rfc2822_now();
        let domain = account_email
            .split_once('@')
            .map(|(_, d)| d)
            .unwrap_or("mail.ru");
        let msg_id_hex = random_message_id_hex();

        // Формируем строго валидное RFC 5322 тело черновика (раздел 3.5 спецификации)
        let msg_raw = format!(
            "From: <{account_email}>\r\n\
             To: <{account_email}>\r\n\
             Subject: {subject}\r\n\
             Date: {rfc2822_date}\r\n\
             Message-ID: <{msg_id_hex}@{domain}>\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n\
             {b64_chunked}\r\n"
        );

        let msg_len = msg_raw.len();
        let tag = self.next_tag();

        let can_non_sync_literal = self.use_literal_plus
            && (self.supports_literal_plus || (self.supports_literal_minus && msg_len <= 4096));

        if can_non_sync_literal {
            // 1-RTT Non-Synchronizing Literal (RFC 2088 / RFC 7888):
            // отправляем заголовок команды с `{msg_len+}` и тело письма одним TCP/TLS-буфером
            let cmd_header = format!("{tag} APPEND \"{folder}\" (\\Seen \\Draft) {{{msg_len}+}}\r\n");
            let inner = self.stream.get_mut();
            inner.write_all(cmd_header.as_bytes()).await?;
            inner.write_all(msg_raw.as_bytes()).await?;
            inner.write_all(b"\r\n").await?;
            inner.flush().await?;
        } else {
            // Классический 2-шаговый APPEND с синхронизирующим литералом
            self.send_line(&format!("{tag} APPEND \"{folder}\" (\\Seen \\Draft) {{{msg_len}}}")).await?;

            // Ожидаем строку продолжения '+' от сервера
            let deadline = Instant::now() + timeout_dur;
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(anyhow!("Timeout waiting for '+' continuation prompt in APPEND"));
                }

                let line = tokio::time::timeout(remaining, self.read_line())
                    .await
                    .context("Timeout reading APPEND prompt line")??;

                if line.starts_with('+') {
                    break;
                }
                if line.starts_with(&format!("{tag} NO")) || line.starts_with(&format!("{tag} BAD")) {
                    if line.contains("THROTTLED") {
                        return Err(anyhow!("IMAP APPEND rejected: THROTTLED rate-limit hit"));
                    }
                    if line.contains("OVERQUOTA") {
                        return Err(anyhow!("IMAP APPEND rejected: OVERQUOTA storage limit hit"));
                    }
                    return Err(anyhow!("IMAP APPEND step 1 rejected: {}", line.trim()));
                }
            }

            // Шаг 2: передаем тело литерала + \r\n
            {
                let inner = self.stream.get_mut();
                inner.write_all(msg_raw.as_bytes()).await?;
                inner.write_all(b"\r\n").await?;
                inner.flush().await?;
            }
        }

        let resp = self.read_until_tagged(&tag, timeout_dur).await?;
        let last_line = resp.last().ok_or_else(|| anyhow!("Empty APPEND response"))?;
        if !last_line.starts_with(&format!("{tag} OK")) {
            if last_line.contains("THROTTLED") {
                return Err(anyhow!("IMAP APPEND rejected: THROTTLED rate-limit hit"));
            }
            if last_line.contains("OVERQUOTA") {
                return Err(anyhow!("IMAP APPEND rejected: OVERQUOTA storage limit hit"));
            }
            return Err(anyhow!("IMAP APPEND step 2 failed: {}", last_line.trim()));
        }

        Ok(t0.elapsed())
    }

    /// Входит в режим ожидания IMAP IDLE.
    pub async fn enter_idle(&mut self, timeout_dur: Duration) -> Result<()> {
        if self.in_idle {
            return Ok(());
        }
        let tag = self.next_tag();
        self.idle_tag = tag.clone();
        self.send_line(&format!("{tag} IDLE")).await?;

        let deadline = Instant::now() + timeout_dur;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(anyhow!("Timeout waiting for '+' in enter_idle"));
            }
            let line = tokio::time::timeout(remaining, self.read_line())
                .await
                .context("Timeout waiting for IDLE '+'")??;

            if line.starts_with('+') {
                self.in_idle = true;
                break;
            }
            if line.starts_with(&format!("{tag} NO")) || line.starts_with(&format!("{tag} BAD")) {
                return Err(anyhow!("IMAP IDLE rejected: {}", line.trim()));
            }
        }
        Ok(())
    }

    /// Выходит из режима IMAP IDLE отправкой `DONE`.
    pub async fn exit_idle(&mut self, timeout_dur: Duration) -> Result<()> {
        if !self.in_idle {
            return Ok(());
        }
        self.send_line("DONE").await?;
        let _ = self.read_until_tagged(&self.idle_tag.clone(), timeout_dur).await?;
        self.in_idle = false;
        Ok(())
    }

    /// Активное ожидание новых писем в IDLE с проверкой `pending_exists` ДО входа в IDLE
    /// и СРАЗУ ПОСЛЕ выхода из IDLE (раздел 3.1 и раздел 8 п. 3 спецификации),
    /// а также с опциональным сигналом раннего пробуждения `wake_notify` (например, при отправке Uplink-пакета).
    pub async fn wait_idle_or_wake(
        &mut self,
        timeout_dur: Duration,
        wake_notify: Option<&tokio::sync::Notify>,
    ) -> Result<bool> {
        // 1. Проверяем флаг «Слепого окна» ДО входа в IDLE
        if self.pending_exists {
            self.pending_exists = false;
            return Ok(true);
        }

        // 2. Входим в IDLE
        self.enter_idle(Duration::from_secs(5)).await?;

        // Если `* <N> EXISTS` пришло между отправкой `IDLE` и ответом `+ idling`
        if self.pending_exists {
            self.pending_exists = false;
            self.exit_idle(Duration::from_secs(5)).await?;
            return Ok(true);
        }

        let mut got_event = false;
        let deadline = Instant::now() + timeout_dur;

        while self.in_idle {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }

            let step_wait = remaining.min(Duration::from_secs(5));
            if let Some(notify) = wake_notify {
                tokio::select! {
                    biased;
                    res = tokio::time::timeout(step_wait, self.read_line()) => {
                        match res {
                            Ok(Ok(line)) => {
                                if is_exists_line(&line) {
                                    self.pending_exists = false;
                                    got_event = true;
                                    break;
                                }
                            }
                            Ok(Err(e)) => {
                                self.in_idle = false;
                                return Err(e);
                            }
                            Err(_) => continue,
                        }
                    }
                    _ = notify.notified() => {
                        // Локальный Writer отправил пакет во время долгого IDLE — просыпаемся,
                        // чтобы переключиться на короткий адаптивный цикл опроса!
                        break;
                    }
                }
            } else {
                match tokio::time::timeout(step_wait, self.read_line()).await {
                    Ok(Ok(line)) => {
                        if is_exists_line(&line) {
                            self.pending_exists = false;
                            got_event = true;
                            break;
                        }
                    }
                    Ok(Err(e)) => {
                        self.in_idle = false;
                        return Err(e);
                    }
                    Err(_) => {
                        continue;
                    }
                }
            }
        }

        // 3. Выходим из IDLE
        self.exit_idle(Duration::from_secs(5)).await?;

        // 4. Проверяем флаг «Слепого окна» ПОСЛЕ выхода из IDLE (на случай прихода EXISTS во время DONE)
        if self.pending_exists {
            self.pending_exists = false;
            got_event = true;
        }

        Ok(got_event)
    }

    /// Активное ожидание новых писем в IDLE с проверкой `pending_exists` ДО входа в IDLE
    /// и СРАЗУ ПОСЛЕ выхода из IDLE (раздел 3.1 и раздел 8 п. 3 спецификации).
    pub async fn wait_idle_or_pending(&mut self, timeout_dur: Duration) -> Result<bool> {
        self.wait_idle_or_wake(timeout_dur, None).await
    }

    /// Синоним `wait_idle_or_pending` (раздел 3.8 спецификации).
    #[inline]
    pub async fn wait_idle_or_event(&mut self, timeout_dur: Duration) -> Result<bool> {
        self.wait_idle_or_wake(timeout_dur, None).await
    }

    /// Универсальный побайтовый парсер `UID FETCH <last_uid + 1>:* (UID BODY.PEEK[])`:
    /// - Читает ровно `{len}` байт сообщения через `read_exact`;
    /// - Дочитывает остаток строки `rest_line` и извлекает постфиксный UID Mail.ru;
    /// - Игнорирует дубликаты `uid <= last_seen_uid`;
    /// - Бинарно декодирует Base64.
    pub async fn fetch_messages_robust(
        &mut self,
        last_seen_uid: u32,
        timeout_dur: Duration,
    ) -> Result<FetchResult> {
        let start_uid = last_seen_uid.saturating_add(1);
        let cmd_target = format!("{start_uid}:*");
        self.fetch_messages_by_uid_set(&cmd_target, last_seen_uid, timeout_dur)
            .await
    }

    /// Одношаговая (1-RTT) потоковая выборка новых сообщений
    /// `UID FETCH <last_seen_uid + 1>:4294967295 (UID BODY.PEEK[])`:
    /// - Использует явную верхнюю границу `4294967295` (`u32::MAX`) вместо символа `*`:
    ///   1) На `imap.mail.ru` при отсутствии новых писем сервер мгновенно возвращает `OK` (0 байт),
    ///      не перекачивая 175 КБ дубликат `last_seen_uid` по правилу раскрытия `*` в RFC 3501;
    ///   2) Полностью обходит кэширование устаревшего `*` на `imap.mail.ru` в «Слепом окне»
    ///      (когда письмо пришло вне `IDLE` и запрос `UID FETCH <start>:*` возвращает старый `last_seen_uid`);
    ///   3) Выполняется за **1 RTT** без предварительного индексного запроса `UID FETCH (UID)`.
    /// - Вызывает `on_message(&msg)` **немедленно** после вычитывания каждого литерала `read_exact`,
    ///   чтобы воркер сразу расшифровывал и отправлял пакеты каждого письма в `TUN`, не дожидаясь
    ///   скачивания остальных писем пачки и финального `tag OK`.
    pub async fn fetch_messages_streaming<F>(
        &mut self,
        last_seen_uid: u32,
        timeout_dur: Duration,
        on_message: F,
    ) -> Result<FetchResult>
    where
        F: FnMut(&FetchedMessage),
    {
        let start_uid = last_seen_uid.saturating_add(1);
        let cmd_target = format!("{start_uid}:{}", u32::MAX);
        self.fetch_messages_by_uid_set_streaming(&cmd_target, last_seen_uid, timeout_dur, on_message)
            .await
    }

    /// Выборка тел конкретной порции UID (`UID FETCH u1,u2,u3 (UID BODY.PEEK[])`).
    pub async fn fetch_uids_body(
        &mut self,
        uids: &[u32],
        last_seen_uid: u32,
        timeout_dur: Duration,
    ) -> Result<FetchResult> {
        if uids.is_empty() {
            return Ok(FetchResult {
                messages: Vec::new(),
                new_max_uid: last_seen_uid,
                latency_ms: 0.0,
            });
        }

        let mut uid_set = String::new();
        for (i, &u) in uids.iter().enumerate() {
            if i > 0 {
                uid_set.push(',');
            }
            let _ = write!(&mut uid_set, "{u}");
        }

        let mut res = self
            .fetch_messages_by_uid_set(&uid_set, last_seen_uid, timeout_dur)
            .await?;
        if let Some(&max_requested) = uids.iter().max() {
            res.new_max_uid = res.new_max_uid.max(max_requested);
        }
        Ok(res)
    }

    /// Двухфазная порционная выборка новых сообщений (`Chunked UID Fetch`).
    pub async fn fetch_messages_chunked(
        &mut self,
        last_seen_uid: u32,
        fetch_max_messages: usize,
        timeout_dur: Duration,
    ) -> Result<FetchResult> {
        if fetch_max_messages == 0 {
            return self.fetch_messages_robust(last_seen_uid, timeout_dur).await;
        }

        let t0 = Instant::now();
        let deadline = t0 + timeout_dur;
        let start_uid = last_seen_uid.saturating_add(1);

        self.pending_exists = false;

        let tag1 = self.next_tag();
        self.send_line(&format!("{tag1} UID FETCH {start_uid}:* (UID)"))
            .await?;
        let idx_lines = self.read_until_tagged(&tag1, timeout_dur).await?;

        if let Some(last) = idx_lines.last() {
            if last.starts_with(&format!("{tag1} NO"))
                || last.starts_with(&format!("{tag1} BAD"))
            {
                return Err(anyhow!("IMAP UID FETCH index failed: {}", last.trim()));
            }
        }

        let mut new_uids = Vec::new();
        for line in &idx_lines {
            if let Some(uid) = extract_uid_from_fetch_meta(line) {
                if uid > last_seen_uid {
                    new_uids.push(uid);
                }
            }
        }
        new_uids.sort_unstable();
        new_uids.dedup();

        if new_uids.is_empty() {
            return Ok(FetchResult {
                messages: Vec::new(),
                new_max_uid: last_seen_uid,
                latency_ms: t0.elapsed().as_secs_f64() * 1000.0,
            });
        }

        let take_count = new_uids.len().min(fetch_max_messages);
        let chunk = &new_uids[..take_count];
        let has_more_in_folder = new_uids.len() > take_count;

        let rem_timeout = deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_secs(5));
        let exists_during_index = self.pending_exists;
        let mut res = self.fetch_uids_body(chunk, last_seen_uid, rem_timeout).await?;
        res.latency_ms = t0.elapsed().as_secs_f64() * 1000.0;

        if has_more_in_folder || exists_during_index {
            self.pending_exists = true;
        }

        Ok(res)
    }

    async fn fetch_messages_by_uid_set(
        &mut self,
        uid_set: &str,
        last_seen_uid: u32,
        timeout_dur: Duration,
    ) -> Result<FetchResult> {
        self.fetch_messages_by_uid_set_streaming(uid_set, last_seen_uid, timeout_dur, |_| {})
            .await
    }

    async fn fetch_messages_by_uid_set_streaming<F>(
        &mut self,
        uid_set: &str,
        last_seen_uid: u32,
        timeout_dur: Duration,
        mut on_message: F,
    ) -> Result<FetchResult>
    where
        F: FnMut(&FetchedMessage),
    {
        let t0 = Instant::now();
        let tag = self.next_tag();

        // Сбрасываем pending_exists до отправки команды UID FETCH:
        // если новое уведомление `* <N> EXISTS` придет во время вычитывания ответа, `read_line()` снова взведет его.
        self.pending_exists = false;

        self.send_line(&format!("{tag} UID FETCH {uid_set} (UID BODY.PEEK[])")).await?;

        let mut messages = Vec::new();
        let mut new_max_uid = last_seen_uid;
        let mut deadline = Instant::now() + timeout_dur;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(anyhow!("Timeout waiting for UID FETCH response"));
            }

            let line = tokio::time::timeout(remaining, self.read_line())
                .await
                .context("Timeout reading FETCH line")??;

            if line.starts_with(&format!("{tag} OK")) {
                break;
            }
            if line.starts_with(&format!("{tag} NO"))
                || line.starts_with(&format!("{tag} BAD"))
            {
                return Err(anyhow!("IMAP UID FETCH failed: {}", line.trim()));
            }

            // Ищем размер литерала `{<len>}`
            let Some(literal_len) = parse_literal_length(&line) else {
                continue;
            };

            if literal_len > MAX_IMAP_LITERAL_BYTES {
                return Err(anyhow!(
                    "IMAP FETCH literal size {} exceeds safety cap {} bytes",
                    literal_len,
                    MAX_IMAP_LITERAL_BYTES
                ));
            }

            // Продлеваем дедлайн на каждое активно скачиваемое сообщение пачки
            deadline = Instant::now() + timeout_dur;

            // 1. Считываем ровно literal_len байт тела сообщения с контролем дедлайна
            let rem_body = deadline.saturating_duration_since(Instant::now());
            if rem_body.is_zero() {
                return Err(anyhow!("Timeout waiting for UID FETCH literal body"));
            }
            let mut msg_bytes = vec![0u8; literal_len];
            tokio::time::timeout(rem_body, self.stream.read_exact(&mut msg_bytes))
                .await
                .context("Timeout reading FETCH literal body")??;

            // 2. Считываем остаток строки ответа сервера (закрывающая скобка и UID) с контролем дедлайна
            let rem_tail = deadline.saturating_duration_since(Instant::now());
            if rem_tail.is_zero() {
                return Err(anyhow!("Timeout waiting for UID FETCH trailing line"));
            }
            let rest_line = tokio::time::timeout(rem_tail, self.read_line())
                .await
                .context("Timeout reading FETCH trailing line")??;

            // 3. Извлекаем UID из объединенной строки метаданных
            let full_meta = format!("{line} {rest_line}");
            let Some(uid) = extract_uid_from_fetch_meta(&full_meta) else {
                log::warn!("[IMAP] Failed to extract UID from FETCH meta: {}", full_meta.trim());
                continue;
            };

            // Защита от дублей RFC 3501 (при запросе <last+1>:* сервер может вернуть last_seen_uid)
            if uid <= last_seen_uid {
                continue;
            }
            new_max_uid = new_max_uid.max(uid);

            // 4. Парсим RFC 5322 сообщение и МГНОВЕННО передаем его в потоковый обработчик `on_message`
            // еще до чтения следующего литерала из сокета!
            match parse_rfc822_message(&msg_bytes) {
                Ok((subject, payload)) => {
                    let fetched = FetchedMessage {
                        uid,
                        subject,
                        payload,
                    };
                    on_message(&fetched);
                    messages.push(fetched);
                }
                Err(e) => {
                    log::warn!("[IMAP] Failed to parse message UID {uid}: {e}");
                }
            }
        }

        let latency_ms = t0.elapsed().as_secs_f64() * 1000.0;
        Ok(FetchResult {
            messages,
            new_max_uid,
            latency_ms,
        })
    }

    /// Удаляет прочитанные UIDs за 1 RTT через конвейерный `NOOP` + `UID STORE` + `UID EXPUNGE` (RFC 4315)
    /// с фолбэком на классический `EXPUNGE`.
    /// Команда `NOOP` перед `UID STORE` обязательна для `imap.mail.ru`: поскольку соединение `WRITER`
    /// выполняет только `APPEND` в противоположную папку, без `NOOP` его снимок выбранной папки устаревает,
    /// и `imap.mail.ru` молча игнорирует `UID STORE` / `UID EXPUNGE` для всех новых писем.
    pub async fn expunge_uids(&mut self, uids: &[u32], timeout_dur: Duration) -> Result<()> {
        if uids.is_empty() {
            return Ok(());
        }

        let mut uid_str = String::new();
        for (i, &u) in uids.iter().enumerate() {
            if i > 0 {
                uid_str.push(',');
            }
            let _ = write!(&mut uid_str, "{u}");
        }

        let tag1 = self.next_tag();
        let tag2 = self.next_tag();
        let tag3 = self.next_tag();
        let pipelined_cmd = format!(
            "{tag1} NOOP\r\n{tag2} UID STORE {uid_str} +FLAGS.SILENT (\\Deleted)\r\n{tag3} UID EXPUNGE {uid_str}\r\n"
        );

        let prev_pending = self.pending_exists;
        {
            let inner = self.stream.get_mut();
            inner.write_all(pipelined_cmd.as_bytes()).await?;
            inner.flush().await?;
        }

        // 1. Читаем ответ на NOOP (обновляет снимок UID в выбранной папке на Mail.ru)
        let _ = self.read_until_tagged(&tag1, timeout_dur).await?;
        self.pending_exists = prev_pending;

        // 2. Читаем ответ на UID STORE (\Deleted)
        let resp2 = self.read_until_tagged(&tag2, timeout_dur).await?;
        if !resp2.last().is_some_and(|l| l.starts_with(&format!("{tag2} OK"))) {
            return Err(anyhow!(
                "IMAP UID STORE \\Deleted failed: {}",
                resp2.last().map(|s| s.trim()).unwrap_or_default()
            ));
        }

        // 3. Читаем ответ на UID EXPUNGE (RFC 4315)
        let resp3 = self.read_until_tagged(&tag3, timeout_dur).await?;
        let ok = resp3.last().is_some_and(|l| l.starts_with(&format!("{tag3} OK")));
        if !ok {
            // Фолбэк на стандартный EXPUNGE
            let tag4 = self.next_tag();
            self.send_line(&format!("{tag4} EXPUNGE")).await?;
            let resp4 = self.read_until_tagged(&tag4, timeout_dur).await?;
            if !resp4.last().is_some_and(|l| l.starts_with(&format!("{tag4} OK"))) {
                return Err(anyhow!(
                    "IMAP fallback EXPUNGE failed: {}",
                    resp4.last().map(|s| s.trim()).unwrap_or_default()
                ));
            }
        }

        Ok(())
    }

    /// Пакетно удаляет все сообщения с `UID 1:<max_uid>` в текущей выбранной папке за 1 RTT
    /// (`NOOP` + `UID STORE 1:<max_uid> +FLAGS.SILENT (\Deleted)` + `UID EXPUNGE 1:<max_uid>`).
    /// Используется при холодном старте клиента и сервера для очистки старых писем от прерванных сессий.
    pub async fn expunge_all_up_to(&mut self, max_uid: u32, timeout_dur: Duration) -> Result<()> {
        if max_uid == 0 {
            return Ok(());
        }

        let tag1 = self.next_tag();
        let tag2 = self.next_tag();
        let tag3 = self.next_tag();
        let pipelined_cmd = format!(
            "{tag1} NOOP\r\n{tag2} UID STORE 1:{max_uid} +FLAGS.SILENT (\\Deleted)\r\n{tag3} UID EXPUNGE 1:{max_uid}\r\n"
        );

        let prev_pending = self.pending_exists;
        {
            let inner = self.stream.get_mut();
            inner.write_all(pipelined_cmd.as_bytes()).await?;
            inner.flush().await?;
        }

        let _ = self.read_until_tagged(&tag1, timeout_dur).await?;
        self.pending_exists = prev_pending;

        let resp2 = self.read_until_tagged(&tag2, timeout_dur).await?;
        if !resp2.last().is_some_and(|l| l.starts_with(&format!("{tag2} OK"))) {
            return Err(anyhow!(
                "IMAP UID STORE 1:{max_uid} \\Deleted failed: {}",
                resp2.last().map(|s| s.trim()).unwrap_or_default()
            ));
        }

        let resp3 = self.read_until_tagged(&tag3, timeout_dur).await?;
        let ok = resp3.last().is_some_and(|l| l.starts_with(&format!("{tag3} OK")));
        if !ok {
            let tag4 = self.next_tag();
            self.send_line(&format!("{tag4} EXPUNGE")).await?;
            let resp4 = self.read_until_tagged(&tag4, timeout_dur).await?;
            if !resp4.last().is_some_and(|l| l.starts_with(&format!("{tag4} OK"))) {
                return Err(anyhow!(
                    "IMAP fallback EXPUNGE 1:{max_uid} failed: {}",
                    resp4.last().map(|s| s.trim()).unwrap_or_default()
                ));
            }
        }

        Ok(())
    }
}

impl ImapConn<tokio_boring::SslStream<TcpStream>> {
    /// Возвращает фактический удаленный IP-адрес открытого TCP-соединения.
    pub fn peer_ip(&self) -> Option<std::net::IpAddr> {
        self.stream
            .get_ref()
            .get_ref()
            .peer_addr()
            .ok()
            .map(|a| a.ip())
    }

    /// Устанавливает защищенное IMAPS-соединение напрямую по заранее разрешенному `target_addr` (без повторного DNS-запроса)
    /// с использованием `host` в качестве TLS SNI и профиля BoringSSL Email Mimicry (KMail / OpenSSL 3.x).
    /// Исключает рассинхронизацию Round-Robin DNS с `bypass_ips` и зависание DNS внутри TUN при Failover.
    pub async fn connect_addr(
        target_addr: std::net::SocketAddr,
        host: &str,
        email: &str,
        password: &str,
        tls_cfg: &crate::boring_tls::TlsClientConfig,
        timeout_dur: Duration,
    ) -> Result<Self> {
        let tcp = tokio::time::timeout(timeout_dur, TcpStream::connect(target_addr))
            .await
            .context("TCP connect timeout to IMAP server")?
            .with_context(|| {
                format!("Failed to connect to IMAP TCP socket at {target_addr} ({host})")
            })?;

        let _ = tcp.set_nodelay(true);

        let tls_stream = tokio::time::timeout(
            timeout_dur,
            crate::boring_tls::connect_email_tls_with_config(host, tcp, tls_cfg),
        )
        .await
        .context("TLS handshake timeout to IMAP server")?
        .with_context(|| {
            format!("TLS handshake failed with IMAP server {host} ({target_addr})")
        })?;

        let mut conn = Self::new(tls_stream);

        // Считываем приветственный баннер сервера: "* OK ..."
        let banner = tokio::time::timeout(timeout_dur, conn.read_line())
            .await
            .context("Timeout waiting for IMAP banner")??;
        log::info!(
            "[IMAP] Connected to {host} ({target_addr}), banner: {}",
            banner.trim()
        );

        // Выполняем LOGIN и авто-детект CAPABILITY (LITERAL+ / LITERAL-)
        conn.login(email, password, timeout_dur).await?;
        let _ = conn.detect_capabilities(timeout_dur).await;
        log::info!(
            "[IMAP] Logged in successfully as {email} (LITERAL+: {}, LITERAL-: {})",
            conn.supports_literal_plus,
            conn.supports_literal_minus
        );

        Ok(conn)
    }

    /// Устанавливает защищенное IMAPS-соединение на порт 993 с использованием профиля
    /// BoringSSL Email Mimicry (KMail / OpenSSL 3.x).
    pub async fn connect(
        host: &str,
        port: u16,
        email: &str,
        password: &str,
        tls_cfg: &crate::boring_tls::TlsClientConfig,
        timeout_dur: Duration,
    ) -> Result<Self> {
        let addr_str = format!("{host}:{port}");
        let tcp = tokio::time::timeout(timeout_dur, TcpStream::connect(&addr_str))
            .await
            .context("TCP connect timeout to IMAP server")?
            .with_context(|| format!("Failed to connect to IMAP TCP socket at {addr_str}"))?;

        let _ = tcp.set_nodelay(true);

        let tls_stream = tokio::time::timeout(
            timeout_dur,
            crate::boring_tls::connect_email_tls_with_config(host, tcp, tls_cfg),
        )
        .await
        .context("TLS handshake timeout to IMAP server")?
        .with_context(|| format!("TLS handshake failed with IMAP server {host}:{port}"))?;

        let mut conn = Self::new(tls_stream);

        // Считываем приветственный баннер сервера: "* OK ..."
        let banner = tokio::time::timeout(timeout_dur, conn.read_line())
            .await
            .context("Timeout waiting for IMAP banner")??;
        log::info!("[IMAP] Connected to {host}:{port}, banner: {}", banner.trim());

        // Выполняем LOGIN и авто-детект CAPABILITY (LITERAL+ / LITERAL-)
        conn.login(email, password, timeout_dur).await?;
        let _ = conn.detect_capabilities(timeout_dur).await;
        log::info!(
            "[IMAP] Logged in successfully as {email} (LITERAL+: {}, LITERAL-: {})",
            conn.supports_literal_plus,
            conn.supports_literal_minus
        );

        Ok(conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_exists_line_detection() {
        assert!(is_exists_line("* 12 EXISTS\r\n"));
        assert!(is_exists_line("* 1 EXISTS\n"));
        assert!(is_exists_line("* 99999 EXISTS"));
        assert!(!is_exists_line("* 12 RECENT\r\n"));
        assert!(!is_exists_line("* 12 EXPUNGE\r\n"));
        assert!(!is_exists_line("A0001 OK IDLE completed\r\n"));
        assert!(!is_exists_line("+ idling\r\n"));
    }

    #[test]
    fn test_parse_capability_flags() {
        assert_eq!(
            parse_capability_flags("* CAPABILITY IMAP4rev1 LITERAL+ IDLE UIDPLUS\r\n"),
            (true, false)
        );
        assert_eq!(
            parse_capability_flags("A0001 OK [CAPABILITY IMAP4rev1 LITERAL- IDLE] Logged in\r\n"),
            (false, true)
        );
        assert_eq!(
            parse_capability_flags("* CAPABILITY IMAP4rev1 ID XLIST UIDPLUS UNSELECT MOVE LIST-STATUS IDLE\r\n"),
            (false, false)
        );
    }

    #[test]
    fn test_rfc2822_date_format() {
        let date = format_rfc2822_now();
        assert!(date.ends_with(" +0000"), "Invalid RFC2822 date: {date}");
        assert!(date.contains(", "), "Missing weekday comma: {date}");
    }

    #[test]
    fn test_parse_literal_length() {
        assert_eq!(
            parse_literal_length("* 1 FETCH (BODY[] {1024}\r\n"),
            Some(1024)
        );
        assert_eq!(
            parse_literal_length("* 42 FETCH (FLAGS (\\Draft) BODY.PEEK[] {45}\r\n"),
            Some(45)
        );
        assert_eq!(parse_literal_length("* 1 FETCH (UID 123)\r\n"), None);
    }

    #[test]
    fn test_extract_trailing_and_prefix_uid() {
        assert_eq!(
            extract_uid_from_fetch_meta("* 1 FETCH (BODY[] {50} UID 88412)\r\n"),
            Some(88412)
        );
        assert_eq!(
            extract_uid_from_fetch_meta("* 2 FETCH (UID 5510 BODY[] {100})\r\n"),
            Some(5510)
        );
        assert_eq!(
            extract_uid_from_fetch_meta("* 5 FETCH (UID 105)\r\n"),
            Some(105)
        );
        assert_eq!(
            extract_uid_from_fetch_meta("* 1 FETCH (FLAGS (\\Seen) UID 42 BODY[] {10})\r\n"),
            Some(42)
        );
    }

    #[test]
    fn test_rfc822_binary_payload_extraction() {
        let original_data = b"HELLO_ASTP_ENCRYPTED_PACKET_BYTES_123456789";
        let b64 = BASE64_STANDARD.encode(original_data);

        let email_raw = format!(
            "From: <node@mail.ru>\r\n\
             To: <node@mail.ru>\r\n\
             Subject: ANet-Data [ID: srv01:sess_abc123]\r\n\
             Date: Mon, 02 Nov 2026 22:26:14 +0000\r\n\
             Message-ID: <0123456789abcdef@mail.ru>\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n\
             {b64}\r\n"
        );

        let (subj, payload) = parse_rfc822_message(email_raw.as_bytes()).expect("parse message");
        assert_eq!(subj, "ANet-Data [ID: srv01:sess_abc123]");
        assert_eq!(payload.as_ref(), original_data);
    }

    #[tokio::test]
    async fn test_mock_imap_protocol_exchange() {
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let mut conn = ImapConn::new(client_io);

        let server_task = tokio::spawn(async move {
            server_io.write_all(b"* OK Mock IMAP Server ready\r\n").await.unwrap();

            let mut line = String::new();
            let mut s_buf = BufReader::new(server_io);
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("LOGIN \"user@example.com\" \"pass123\""));
            s_buf.get_mut().write_all(b"A0001 OK LOGIN completed\r\n").await.unwrap();

            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("SELECT \"Drafts\""));
            s_buf.get_mut().write_all(b"* 5 EXISTS\r\n* 0 RECENT\r\nA0002 OK [READ-WRITE] SELECT completed\r\n").await.unwrap();

            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("UID FETCH * (UID)"));
            s_buf.get_mut().write_all(b"* 5 FETCH (UID 105)\r\nA0003 OK UID FETCH completed\r\n").await.unwrap();

            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("APPEND \"Drafts\" (\\Seen \\Draft)"));
            let literal_len = parse_literal_length(&line).expect("APPEND literal length");
            s_buf.get_mut().write_all(b"+ Ready for literal data\r\n").await.unwrap();

            let mut msg_body = vec![0u8; literal_len];
            s_buf.read_exact(&mut msg_body).await.unwrap();
            let msg_body_str = String::from_utf8_lossy(&msg_body);
            assert!(msg_body_str.contains("Message-ID: <"));
            assert!(msg_body_str.contains("+0000\r\n"));

            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            s_buf.get_mut().write_all(b"A0004 OK [APPENDUID 1 106] APPEND completed\r\n").await.unwrap();

            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("IDLE"));
            s_buf.get_mut().write_all(b"+ idling\r\n").await.unwrap();

            tokio::time::sleep(Duration::from_millis(50)).await;
            s_buf.get_mut().write_all(b"* 6 EXISTS\r\n").await.unwrap();

            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert_eq!(line.trim(), "DONE");
            s_buf.get_mut().write_all(b"A0005 OK IDLE completed\r\n").await.unwrap();

            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("UID FETCH 106:* (UID BODY.PEEK[])"));

            let test_payload = b"ASTP_DOWNLINK_PACKET";
            let b64 = BASE64_STANDARD.encode(test_payload);
            let test_rfc822 = format!(
                "From: <u@e.com>\r\nSubject: [ID: sess_999]\r\n\r\n{}\r\n",
                b64
            );
            let fetch_resp = format!(
                "* 6 FETCH (BODY[] {{{}}}\r\n{} UID 106)\r\nA0006 OK UID FETCH completed\r\n",
                test_rfc822.len(),
                test_rfc822
            );
            s_buf.get_mut().write_all(fetch_resp.as_bytes()).await.unwrap();

            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("NOOP"));
            s_buf.get_mut().write_all(b"A0007 OK NOOP completed\r\n").await.unwrap();

            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("UID STORE 106 +FLAGS.SILENT (\\Deleted)"));
            s_buf.get_mut().write_all(b"A0008 OK STORE completed\r\n").await.unwrap();

            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("UID EXPUNGE 106"));
            s_buf.get_mut().write_all(b"A0009 OK UID EXPUNGE completed\r\n").await.unwrap();
        });

        let banner = conn.read_line().await.unwrap();
        assert!(banner.contains("Mock IMAP Server ready"));

        conn.login("user@example.com", "pass123", Duration::from_secs(2)).await.unwrap();
        conn.select("Drafts", Duration::from_secs(2)).await.unwrap();

        let max_uid = conn.get_max_uid(Duration::from_secs(2)).await.unwrap();
        assert_eq!(max_uid, 105);

        let append_lat = conn
            .append_message(
                "Drafts",
                "ANet-Data [ID: srv01:sess_106]",
                b"ASTP_TEST_PACKET",
                "user@example.com",
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert!(append_lat.as_millis() < 500);

        let event = conn.wait_idle_or_pending(Duration::from_secs(2)).await.unwrap();
        assert!(event);

        let fetch_res = conn.fetch_messages_robust(105, Duration::from_secs(2)).await.unwrap();
        assert_eq!(fetch_res.messages.len(), 1);
        assert_eq!(fetch_res.messages[0].uid, 106);
        assert_eq!(fetch_res.messages[0].subject, "[ID: sess_999]");
        assert_eq!(fetch_res.messages[0].payload.as_ref(), b"ASTP_DOWNLINK_PACKET");
        assert_eq!(fetch_res.new_max_uid, 106);

        conn.expunge_uids(&[106], Duration::from_secs(2)).await.unwrap();

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_literal_plus_auto_detect_and_1rtt_append() {
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let mut conn = ImapConn::new(client_io);

        let server_task = tokio::spawn(async move {
            server_io.write_all(b"* OK Dovecot ready\r\n").await.unwrap();
            let mut s_buf = BufReader::new(server_io);
            let mut line = String::new();

            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("LOGIN"));
            s_buf.get_mut().write_all(b"A0001 OK Logged in\r\n").await.unwrap();

            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("CAPABILITY"));
            s_buf
                .get_mut()
                .write_all(b"* CAPABILITY IMAP4rev1 LITERAL+ UIDPLUS IDLE\r\nA0002 OK CAPABILITY completed\r\n")
                .await
                .unwrap();

            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("+}\r\n"), "Expected non-synchronizing literal {{N+}}, got: {line}");
            let start = line.rfind('{').unwrap();
            let end = line[start + 1..].find('+').unwrap() + start + 1;
            let lit_len: usize = line[start + 1..end].parse().unwrap();

            let mut msg_body = vec![0u8; lit_len];
            s_buf.read_exact(&mut msg_body).await.unwrap();
            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            s_buf
                .get_mut()
                .write_all(b"A0003 OK [APPENDUID 1 200] APPEND completed\r\n")
                .await
                .unwrap();
        });

        let _ = conn.read_line().await.unwrap();
        conn.login("u@e.com", "p", Duration::from_secs(2)).await.unwrap();
        conn.detect_capabilities(Duration::from_secs(2)).await.unwrap();
        assert!(conn.supports_literal_plus);

        conn.append_message("Notes", "Subj", b"1RTT_DATA", "u@e.com", Duration::from_secs(2))
            .await
            .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_fetch_messages_robust_rejects_tagged_no_and_bad() {
        let (client_io, mut server_io) = tokio::io::duplex(16 * 1024);
        let mut conn = ImapConn::new(client_io);

        let server_task = tokio::spawn(async move {
            let mut s_buf = BufReader::new(&mut server_io);
            let mut line = String::new();

            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("UID FETCH 11:*"));
            s_buf
                .get_mut()
                .write_all(b"A0001 NO [CANNOT] Temporary mailbox storage error\r\n")
                .await
                .unwrap();

            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("UID FETCH 11:*"));
            s_buf
                .get_mut()
                .write_all(b"A0002 BAD Command syntax error\r\n")
                .await
                .unwrap();
        });

        let err_no = conn
            .fetch_messages_robust(10, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(format!("{err_no:#}").contains("A0001 NO"));

        let err_bad = conn
            .fetch_messages_robust(10, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(format!("{err_bad:#}").contains("A0002 BAD"));

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_fetch_messages_robust_rejects_oversized_literal() {
        let (client_io, mut server_io) = tokio::io::duplex(16 * 1024);
        let mut conn = ImapConn::new(client_io);

        let server_task = tokio::spawn(async move {
            let mut s_buf = BufReader::new(&mut server_io);
            let mut line = String::new();
            s_buf.read_line(&mut line).await.unwrap();
            let oversized = MAX_IMAP_LITERAL_BYTES + 1024;
            let resp = format!("* 1 FETCH (UID 50 BODY[] {{{oversized}}}\r\n");
            s_buf.get_mut().write_all(resp.as_bytes()).await.unwrap();
        });

        let err = conn
            .fetch_messages_robust(10, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("exceeds safety cap"));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_fetch_messages_robust_times_out_on_stalled_literal_body() {
        let (client_io, mut server_io) = tokio::io::duplex(16 * 1024);
        let mut conn = ImapConn::new(client_io);

        let server_task = tokio::spawn(async move {
            let mut s_buf = BufReader::new(&mut server_io);
            let mut line = String::new();
            s_buf.read_line(&mut line).await.unwrap();
            // Объявляем литерал в 256 байт, но отправляем только 10 байт и замолкаем
            s_buf
                .get_mut()
                .write_all(b"* 1 FETCH (UID 50 BODY[] {256}\r\n0123456789")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
        });

        let err = conn
            .fetch_messages_robust(10, Duration::from_millis(120))
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("Timeout"));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_select_auto_creates_missing_folder_on_new_mailbox() {
        let (client_io, mut server_io) = tokio::io::duplex(16 * 1024);
        let mut conn = ImapConn::new(client_io);

        let server_task = tokio::spawn(async move {
            let mut s_buf = BufReader::new(&mut server_io);
            let mut line = String::new();

            // 1. Первая попытка SELECT "Notes" на свежем ящике возвращает NO [NONEXISTENT]
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("SELECT \"Notes\""));
            s_buf
                .get_mut()
                .write_all(b"A0001 NO [NONEXISTENT] Unknown Mailbox: Notes\r\n")
                .await
                .unwrap();

            // 2. Клиент автоматически отправляет CREATE "Notes"
            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("CREATE \"Notes\""));
            s_buf
                .get_mut()
                .write_all(b"A0002 OK CREATE completed\r\n")
                .await
                .unwrap();

            // 3. Повторный SELECT "Notes" проходит успешно
            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("SELECT \"Notes\""));
            s_buf
                .get_mut()
                .write_all(b"* 0 EXISTS\r\nA0003 OK [READ-WRITE] SELECT completed\r\n")
                .await
                .unwrap();
        });

        conn.select("Notes", Duration::from_secs(1))
            .await
            .expect("select should auto-create missing folder");
        assert!(!conn.pending_exists);
        server_task.await.unwrap();
    }

    fn build_test_rfc822(email: &str, subject: &str, payload: &[u8]) -> Vec<u8> {
        let b64 = BASE64_STANDARD.encode(payload);
        format!("From: <{email}>\r\nTo: <{email}>\r\nSubject: {subject}\r\n\r\n{b64}\r\n")
            .into_bytes()
    }

    #[tokio::test]
    async fn test_fetch_messages_chunked_splits_backlog_and_sets_pending_exists() {
        let (client_io, mut server_io) = tokio::io::duplex(32 * 1024);
        let mut conn = ImapConn::new(client_io);

        let raw_m1 = build_test_rfc822("a@b.c", "[ID: s1]", b"pkt1");
        let raw_m2 = build_test_rfc822("a@b.c", "[ID: s1]", b"pkt2");
        let raw_m3 = build_test_rfc822("a@b.c", "[ID: s1]", b"pkt3");

        let server_task = tokio::spawn(async move {
            let mut s_buf = BufReader::new(&mut server_io);
            let mut line = String::new();

            // Чанк 1 (fetch_max_messages = 2):
            // 1. Клиент запрашивает индекс `A0001 UID FETCH 11:* (UID)`
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("UID FETCH 11:* (UID)"));
            s_buf
                .get_mut()
                .write_all(
                    b"* 1 FETCH (UID 10)\r\n* 2 FETCH (UID 12)\r\n* 3 FETCH (UID 15)\r\n* 4 FETCH (UID 19)\r\nA0001 OK UID FETCH completed\r\n",
                )
                .await
                .unwrap();

            // 2. Клиент запрашивает тела только первых 2 новых UID (12,15): `A0002 UID FETCH 12,15 (UID BODY.PEEK[])`
            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("UID FETCH 12,15 (UID BODY.PEEK[])"));
            let mut resp1 = Vec::new();
            resp1.extend_from_slice(
                format!("* 2 FETCH (BODY[] {{{}}}\r\n", raw_m1.len()).as_bytes(),
            );
            resp1.extend_from_slice(&raw_m1);
            resp1.extend_from_slice(b" UID 12)\r\n");
            resp1.extend_from_slice(
                format!("* 3 FETCH (BODY[] {{{}}}\r\n", raw_m2.len()).as_bytes(),
            );
            resp1.extend_from_slice(&raw_m2);
            resp1.extend_from_slice(b" UID 15)\r\nA0002 OK UID FETCH completed\r\n");
            s_buf.get_mut().write_all(&resp1).await.unwrap();

            // Чанк 2 (оставшийся UID 19):
            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("UID FETCH 16:* (UID)"));
            s_buf
                .get_mut()
                .write_all(b"* 4 FETCH (UID 19)\r\nA0003 OK UID FETCH completed\r\n")
                .await
                .unwrap();

            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("UID FETCH 19 (UID BODY.PEEK[])"));
            let mut resp2 = Vec::new();
            resp2.extend_from_slice(
                format!("* 4 FETCH (BODY[] {{{}}}\r\n", raw_m3.len()).as_bytes(),
            );
            resp2.extend_from_slice(&raw_m3);
            resp2.extend_from_slice(b" UID 19)\r\nA0004 OK UID FETCH completed\r\n");
            s_buf.get_mut().write_all(&resp2).await.unwrap();
        });

        let res1 = conn
            .fetch_messages_chunked(10, 2, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(res1.new_max_uid, 15);
        assert_eq!(res1.messages.len(), 2);
        assert_eq!(res1.messages[0].payload.as_ref(), b"pkt1");
        assert_eq!(res1.messages[1].payload.as_ref(), b"pkt2");
        // В папке остался еще UID 19, поэтому pending_exists должен быть взведен!
        assert!(conn.pending_exists);

        let res2 = conn
            .fetch_messages_chunked(res1.new_max_uid, 2, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(res2.new_max_uid, 19);
        assert_eq!(res2.messages.len(), 1);
        assert_eq!(res2.messages[0].payload.as_ref(), b"pkt3");
        assert!(!conn.pending_exists);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_fetch_messages_streaming_upper_bound_and_callback() {
        let (client_io, mut server_io) = tokio::io::duplex(32 * 1024);
        let mut conn = ImapConn::new(client_io);

        let raw_m1 = build_test_rfc822("a@b.c", "[ID: s1]", b"stream_pkt_1");
        let raw_m2 = build_test_rfc822("a@b.c", "[ID: s1]", b"stream_pkt_2");

        let server_task = tokio::spawn(async move {
            let mut s_buf = BufReader::new(&mut server_io);
            let mut line = String::new();

            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("UID FETCH 101:4294967295 (UID BODY.PEEK[])"));

            let mut resp = Vec::new();
            resp.extend_from_slice(
                format!("* 1 FETCH (BODY[] {{{}}}\r\n", raw_m1.len()).as_bytes(),
            );
            resp.extend_from_slice(&raw_m1);
            resp.extend_from_slice(b" UID 101)\r\n");
            resp.extend_from_slice(
                format!("* 2 FETCH (BODY[] {{{}}}\r\n", raw_m2.len()).as_bytes(),
            );
            resp.extend_from_slice(&raw_m2);
            resp.extend_from_slice(b" UID 105)\r\nA0001 OK UID FETCH completed\r\n");
            s_buf.get_mut().write_all(&resp).await.unwrap();
        });

        let mut callback_uids = Vec::new();
        let res = conn
            .fetch_messages_streaming(100, Duration::from_secs(1), |msg| {
                callback_uids.push((msg.uid, msg.payload.clone()));
            })
            .await
            .unwrap();

        assert_eq!(res.new_max_uid, 105);
        assert_eq!(res.messages.len(), 2);
        assert_eq!(callback_uids.len(), 2);
        assert_eq!(callback_uids[0].0, 101);
        assert_eq!(callback_uids[0].1.as_ref(), b"stream_pkt_1");
        assert_eq!(callback_uids[1].0, 105);
        assert_eq!(callback_uids[1].1.as_ref(), b"stream_pkt_2");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_pipelined_expunge_uids_and_expunge_all_up_to() {
        let (client_io, mut server_io) = tokio::io::duplex(32 * 1024);
        let mut conn = ImapConn::new(client_io);

        let server_task = tokio::spawn(async move {
            let mut s_buf = BufReader::new(&mut server_io);
            let mut l1 = String::new();
            let mut l2 = String::new();
            let mut l3 = String::new();

            // 1. expunge_uids(&[10, 12])
            s_buf.read_line(&mut l1).await.unwrap();
            s_buf.read_line(&mut l2).await.unwrap();
            s_buf.read_line(&mut l3).await.unwrap();
            assert_eq!(l1.trim(), "A0001 NOOP");
            assert_eq!(l2.trim(), "A0002 UID STORE 10,12 +FLAGS.SILENT (\\Deleted)");
            assert_eq!(l3.trim(), "A0003 UID EXPUNGE 10,12");
            s_buf
                .get_mut()
                .write_all(
                    b"* 12 EXISTS\r\nA0001 OK NOOP completed\r\nA0002 OK UID STORE completed\r\n* 10 EXPUNGE\r\n* 11 EXPUNGE\r\nA0003 OK UID EXPUNGE completed\r\n",
                )
                .await
                .unwrap();

            // 2. expunge_all_up_to(50)
            l1.clear();
            l2.clear();
            l3.clear();
            s_buf.read_line(&mut l1).await.unwrap();
            s_buf.read_line(&mut l2).await.unwrap();
            s_buf.read_line(&mut l3).await.unwrap();
            assert_eq!(l1.trim(), "A0004 NOOP");
            assert_eq!(l2.trim(), "A0005 UID STORE 1:50 +FLAGS.SILENT (\\Deleted)");
            assert_eq!(l3.trim(), "A0006 UID EXPUNGE 1:50");
            s_buf
                .get_mut()
                .write_all(
                    b"A0004 OK NOOP completed\r\nA0005 OK UID STORE completed\r\nA0006 OK UID EXPUNGE completed\r\n",
                )
                .await
                .unwrap();
        });

        conn.expunge_uids(&[10, 12], Duration::from_secs(1))
            .await
            .unwrap();
        conn.expunge_all_up_to(50, Duration::from_secs(1))
            .await
            .unwrap();

        server_task.await.unwrap();
    }
}

