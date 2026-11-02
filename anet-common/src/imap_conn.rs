// anet-common/src/imap_conn.rs
//! Высокопроизводительный асинхронный IMAP-клиент `ImapConn` для транспорта `imap` (ASTP over IMAPS:993).
//!
//! Разработан строго по спецификации `contrib/docs/imap.ru.md` и верифицирован эталоном
//! `contrib/scripts/imap_soak_test.py`:
//! - Работает напрямую поверх `tokio` и `tokio_boring::SslStream` (BoringSSL Email TLS Mimicry);
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
use std::fmt::Write as _;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadHalf,
    WriteHalf,
};
use tokio::net::TcpStream;
use sha2::{Digest, Sha256};

/// Вычисляет 8-символьный hex-идентификатор узла (первые 4 байта SHA-256)
pub fn compute_hex_id(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        hash[0], hash[1], hash[2], hash[3]
    )
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
    // Ожидаемый формат: ["*", "<number>", "EXISTS"]
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
                // Очищаем от возможных завершающих скобок: "123)" -> "123"
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
    let (header_bytes, body_bytes) = if let Some(pos) = raw_bytes.windows(4).position(|w| w == b"\r\n\r\n") {
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

/// Асинхронное IMAP-соединение с разделенным вводом-выводом для высокой производительности.
pub struct ImapConn<R = ReadHalf<tokio_boring::SslStream<TcpStream>>, W = WriteHalf<tokio_boring::SslStream<TcpStream>>> {
    reader: BufReader<R>,
    writer: W,
    tag_counter: u64,
    /// Флаг «Слепого окна»: взводится при получении `* <N> EXISTS` вне или внутри IDLE.
    pub pending_exists: bool,
    /// Находится ли соединение в состоянии IMAP IDLE в данный момент.
    pub in_idle: bool,
    idle_tag: String,
    line_buf: String,
}

impl<R, W> ImapConn<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: BufReader::with_capacity(64 * 1024, reader),
            writer,
            tag_counter: 0,
            pending_exists: false,
            in_idle: false,
            idle_tag: String::new(),
            line_buf: String::with_capacity(1024),
        }
    }

    pub fn next_tag(&mut self) -> String {
        self.tag_counter += 1;
        format!("A{:04}", self.tag_counter)
    }

    /// Отправляет сырую строку в сокет с добавлением `\r\n` и выполняет `flush()`.
    pub async fn send_line(&mut self, line: &str) -> Result<()> {
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.write_all(b"\r\n").await?;
        self.writer.flush().await?;
        Ok(())
    }

    /// Считывает одну строку ответа от IMAP-сервера с автоматической фиксацией `* <N> EXISTS`.
    pub async fn read_line(&mut self) -> Result<String> {
        self.line_buf.clear();
        let bytes_read = self.reader.read_line(&mut self.line_buf).await?;
        if bytes_read == 0 {
            return Err(anyhow!("Connection closed by IMAP server (Unexpected EOF)"));
        }

        let line = self.line_buf.clone();
        if is_exists_line(&line) {
            self.pending_exists = true;
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
        let tag = self.next_tag();
        self.send_line(&format!("{tag} LOGIN \"{email}\" \"{pass}\"")).await?;
        let resp = self.read_until_tagged(&tag, timeout_dur).await?;

        let last_line = resp.last().ok_or_else(|| anyhow!("Empty LOGIN response"))?;
        if !last_line.starts_with(&format!("{tag} OK")) {
            return Err(anyhow!("IMAP LOGIN failed: {}", last_line.trim()));
        }
        Ok(())
    }

    /// Выполняет команду SELECT "<folder>".
    pub async fn select(&mut self, folder: &str, timeout_dur: Duration) -> Result<()> {
        let tag = self.next_tag();
        self.send_line(&format!("{tag} SELECT \"{folder}\"")).await?;
        let resp = self.read_until_tagged(&tag, timeout_dur).await?;

        let last_line = resp.last().ok_or_else(|| anyhow!("Empty SELECT response"))?;
        if !last_line.starts_with(&format!("{tag} OK")) {
            return Err(anyhow!("IMAP SELECT '{folder}' failed: {}", last_line.trim()));
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

    /// Отправляет сообщение в указанную папку через 2-шаговый APPEND с флагами `(\Seen \Draft)`.
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

        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Формируем RFC 5322 тело черновика
        let msg_raw = format!(
            "From: <{account_email}>\r\n\
             To: <{account_email}>\r\n\
             Subject: {subject}\r\n\
             Date: {now_sec}\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n\
             {b64_chunked}\r\n"
        );

        let msg_len = msg_raw.len();
        let tag = self.next_tag();

        // Шаг 1: отправляем заголовок APPEND с размером литерала
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
        self.writer.write_all(msg_raw.as_bytes()).await?;
        self.writer.write_all(b"\r\n").await?;
        self.writer.flush().await?;

        let resp = self.read_until_tagged(&tag, timeout_dur).await?;
        let last_line = resp.last().ok_or_else(|| anyhow!("Empty APPEND response"))?;
        if !last_line.starts_with(&format!("{tag} OK")) {
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

    /// Активное ожидание новых писем в IDLE.
    /// Если `pending_exists` уже взведён (событие пришло во время FETCH), мгновенно возвращает `true`
    /// без входа в IDLE, экономя ~250 мс задержки!
    pub async fn wait_idle_or_event(&mut self, timeout_dur: Duration) -> Result<bool> {
        // 1. Проверяем флаг «Слепого окна»
        if self.pending_exists {
            self.pending_exists = false;
            return Ok(true);
        }

        // 2. Входим в IDLE
        self.enter_idle(Duration::from_secs(5)).await?;
        let mut got_event = false;
        let deadline = Instant::now() + timeout_dur;

        while self.in_idle {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }

            match tokio::time::timeout(remaining.min(Duration::from_secs(5)), self.read_line()).await {
                Ok(Ok(line)) => {
                    if is_exists_line(&line) {
                        got_event = true;
                        break;
                    }
                }
                Ok(Err(e)) => {
                    self.in_idle = false;
                    return Err(e);
                }
                Err(_) => {
                    // Короткий таймаут тика: продолжаем ждать до общего дедлайна
                    continue;
                }
            }
        }

        // 3. Выходим из IDLE
        self.exit_idle(Duration::from_secs(5)).await?;
        Ok(got_event)
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
        let t0 = Instant::now();
        let tag = self.next_tag();
        let start_uid = last_seen_uid + 1;

        self.send_line(&format!("{tag} UID FETCH {start_uid}:* (UID BODY.PEEK[])")).await?;

        let mut messages = Vec::new();
        let mut new_max_uid = last_seen_uid;
        let deadline = Instant::now() + timeout_dur;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(anyhow!("Timeout waiting for UID FETCH response"));
            }

            let line = tokio::time::timeout(remaining, self.read_line())
                .await
                .context("Timeout reading FETCH line")??;

            if line.starts_with(&format!("{tag} OK"))
                || line.starts_with(&format!("{tag} NO"))
                || line.starts_with(&format!("{tag} BAD"))
            {
                break;
            }

            // Ищем размер литерала `{<len>}`
            let Some(literal_len) = parse_literal_length(&line) else {
                continue;
            };

            // 1. Считываем ровно literal_len байт тела сообщения
            let mut msg_bytes = vec![0u8; literal_len];
            self.reader.read_exact(&mut msg_bytes).await?;

            // 2. Считываем остаток строки ответа сервера (закрывающая скобка и UID)
            let rest_line = self.read_line().await?;

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

            // 4. Парсим RFC 5322 сообщение
            match parse_rfc822_message(&msg_bytes) {
                Ok((subject, payload)) => {
                    messages.push(FetchedMessage {
                        uid,
                        subject,
                        payload,
                    });
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

    /// Удаляет прочитанные UIDs через `UID EXPUNGE` (RFC 4315) с фолбэком на классический `EXPUNGE`.
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

        // Шаг 1: помечаем письма удаленными (\Deleted)
        let tag1 = self.next_tag();
        self.send_line(&format!("{tag1} UID STORE {uid_str} +FLAGS.SILENT (\\Deleted)")).await?;
        let _ = self.read_until_tagged(&tag1, timeout_dur).await?;

        // Шаг 2: точечное удаление через UID EXPUNGE (RFC 4315)
        let tag2 = self.next_tag();
        self.send_line(&format!("{tag2} UID EXPUNGE {uid_str}")).await?;
        let resp2 = self.read_until_tagged(&tag2, timeout_dur).await?;

        let ok = resp2.last().is_some_and(|l| l.starts_with(&format!("{tag2} OK")));
        if !ok {
            // Фолбэк на стандартный EXPUNGE
            let tag3 = self.next_tag();
            self.send_line(&format!("{tag3} EXPUNGE")).await?;
            let _ = self.read_until_tagged(&tag3, timeout_dur).await?;
        }

        Ok(())
    }
}

impl ImapConn<ReadHalf<tokio_boring::SslStream<TcpStream>>, WriteHalf<tokio_boring::SslStream<TcpStream>>> {
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

        let (reader, writer) = tokio::io::split(tls_stream);
        let mut conn = Self::new(reader, writer);

        // Считываем приветственный баннер сервера: "* OK ..."
        let banner = tokio::time::timeout(timeout_dur, conn.read_line())
            .await
            .context("Timeout waiting for IMAP banner")??;
        log::info!("[IMAP] Connected to {host}:{port}, banner: {}", banner.trim());

        // Выполняем LOGIN
        conn.login(email, password, timeout_dur).await?;
        log::info!("[IMAP] Logged in successfully as {email}");

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
        // Формат Mail.ru (UID в хвосте после литерала):
        assert_eq!(
            extract_uid_from_fetch_meta("* 1 FETCH (BODY[] {50} UID 88412)\r\n"),
            Some(88412)
        );
        // Стандартный формат RFC 3501 (UID в заголовке):
        assert_eq!(
            extract_uid_from_fetch_meta("* 2 FETCH (UID 5510 BODY[] {100})\r\n"),
            Some(5510)
        );
        // Одиночный UID из get_max_uid:
        assert_eq!(
            extract_uid_from_fetch_meta("* 5 FETCH (UID 105)\r\n"),
            Some(105)
        );
        // С флагами:
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
        let (c_reader, c_writer) = tokio::io::split(client_io);
        let mut conn = ImapConn::new(c_reader, c_writer);

        let server_task = tokio::spawn(async move {
            // 1. Отправляем приветственный баннер
            server_io.write_all(b"* OK Mock IMAP Server ready\r\n").await.unwrap();

            // 2. Читаем LOGIN
            let mut line = String::new();
            let mut s_buf = BufReader::new(server_io);
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("LOGIN \"user@example.com\" \"pass123\""));
            s_buf.get_mut().write_all(b"A0001 OK LOGIN completed\r\n").await.unwrap();

            // 3. Читаем SELECT
            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("SELECT \"Drafts\""));
            s_buf.get_mut().write_all(b"* 5 EXISTS\r\n* 0 RECENT\r\nA0002 OK [READ-WRITE] SELECT completed\r\n").await.unwrap();

            // 4. get_max_uid: UID FETCH * (UID)
            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("UID FETCH * (UID)"));
            s_buf.get_mut().write_all(b"* 5 FETCH (UID 105)\r\nA0003 OK UID FETCH completed\r\n").await.unwrap();

            // 5. APPEND
            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("APPEND \"Drafts\" (\\Seen \\Draft)"));
            let literal_len = parse_literal_length(&line).expect("APPEND literal length");
            s_buf.get_mut().write_all(b"+ Ready for literal data\r\n").await.unwrap();

            // Читаем тело черновика ровно literal_len байт
            let mut msg_body = vec![0u8; literal_len];
            s_buf.read_exact(&mut msg_body).await.unwrap();

            // Читаем завершающий CRLF строки команды APPEND
            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            s_buf.get_mut().write_all(b"A0004 OK [APPENDUID 1 106] APPEND completed\r\n").await.unwrap();

            // 6. IDLE с активным пробуждением через * EXISTS
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

            // 7. UID FETCH (с постфиксным UID в стиле Mail.ru)
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

            // 8. UID EXPUNGE
            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("UID STORE 106 +FLAGS.SILENT (\\Deleted)"));
            s_buf.get_mut().write_all(b"A0007 OK STORE completed\r\n").await.unwrap();

            line.clear();
            s_buf.read_line(&mut line).await.unwrap();
            assert!(line.contains("UID EXPUNGE 106"));
            s_buf.get_mut().write_all(b"A0008 OK UID EXPUNGE completed\r\n").await.unwrap();
        });

        // Тестируем клиентские вызовы:
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

        let event = conn.wait_idle_or_event(Duration::from_secs(2)).await.unwrap();
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
}
