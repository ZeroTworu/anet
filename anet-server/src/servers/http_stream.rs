use crate::auth_handler::ServerAuthHandler;
use crate::client_registry::ClientRegistry;
use crate::config::Config;
use anet_common::consts::{CHANNEL_BUFFER_SIZE, CLIENT_SEQUENCE_START};
use anet_common::reassembly::ReassemblyQueue;
use anet_common::stream_framing::read_next_packet;
use anet_common::transport::{unwrap_packet_with_seq, wrap_packet_padded};
use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use httparse::{Request, Status};
use log::{debug, info, warn};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use url::Url;

fn get_real_ip(req: &httparse::Request, fallback: SocketAddr) -> SocketAddr {
    anet_common::http_help::extract_real_ip_from_raw(
        req.headers.iter().map(|h| (h.name, h.value)),
        fallback,
    )
}

/// Отправка базового ответа HTTP/1.1 с таймаутом записи
async fn send_http_response(
    stream: &mut TcpStream,
    status_code: u16,
    status_text: &str,
    content_type: &str,
    body: &[u8],
    keep_alive: bool,
    write_timeout: Duration,
) -> Result<()> {
    let conn_hdr = if keep_alive { "keep-alive" } else { "close" };
    let response = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-cache, no-store\r\n\
         X-Accel-Buffering: no\r\n\
         Connection: {}\r\n\r\n",
        status_code,
        status_text,
        content_type,
        body.len(),
        conn_hdr
    );
    tokio::time::timeout(write_timeout, async {
        stream.write_all(response.as_bytes()).await?;
        if !body.is_empty() {
            stream.write_all(body).await?;
        }
        stream.flush().await?;
        Ok::<(), std::io::Error>(())
    })
    .await
    .context("HTTP response write timed out")??;
    Ok(())
}

fn extract_query_param(path: &str, param: &str) -> Option<String> {
    let base_url = Url::parse("http://localhost").ok()?;
    let url = base_url.join(path).ok()?;

    url.query_pairs()
        .find(|(k, _)| k == param)
        .map(|(_, v)| v.into_owned())
}

#[derive(Debug, PartialEq, Eq)]
enum ChunkedParseError {
    InvalidFormat,
    PayloadTooLarge,
}

/// Инкрементальный парсер `Transfer-Encoding: chunked` (RFC 9112 §7.1).
/// Возвращает `Ok(None)`, если в буфере пока недостаточно байт для полного тела,
/// либо `Ok(Some((decoded_body, total_consumed_bytes)))`.
fn try_parse_chunked_body(
    slice: &[u8],
    max_body_bytes: usize,
    max_trailer_bytes: usize,
) -> std::result::Result<Option<(Bytes, usize)>, ChunkedParseError> {
    let mut pos = 0usize;
    let mut out = BytesMut::new();

    loop {
        let Some(rel_crlf) = slice[pos..].windows(2).position(|w| w == b"\r\n") else {
            if slice.len() - pos > 4096 {
                return Err(ChunkedParseError::InvalidFormat);
            }
            return Ok(None);
        };
        if rel_crlf > 4096 {
            return Err(ChunkedParseError::InvalidFormat);
        }

        let line_bytes = &slice[pos..pos + rel_crlf];
        let line_str = std::str::from_utf8(line_bytes).map_err(|_| ChunkedParseError::InvalidFormat)?;
        let size_hex = line_str.split(';').next().unwrap_or("").trim();
        if size_hex.is_empty() {
            return Err(ChunkedParseError::InvalidFormat);
        }
        let chunk_size =
            usize::from_str_radix(size_hex, 16).map_err(|_| ChunkedParseError::InvalidFormat)?;
        pos += rel_crlf + 2;

        if chunk_size == 0 {
            // Завершающая пустая строка либо секция трейлеров до `\r\n\r\n`
            if slice.len() - pos < 2 {
                return Ok(None);
            }
            if &slice[pos..pos + 2] == b"\r\n" {
                return Ok(Some((out.freeze(), pos + 2)));
            }
            let trailer_start = pos;
            loop {
                let Some(trailer_crlf) = slice[pos..].windows(2).position(|w| w == b"\r\n") else {
                    if slice.len() - trailer_start > max_trailer_bytes {
                        return Err(ChunkedParseError::InvalidFormat);
                    }
                    return Ok(None);
                };
                if trailer_crlf == 0 {
                    return Ok(Some((out.freeze(), pos + 2)));
                }
                pos += trailer_crlf + 2;
                if pos - trailer_start > max_trailer_bytes {
                    return Err(ChunkedParseError::InvalidFormat);
                }
            }
        }

        let new_total = out
            .len()
            .checked_add(chunk_size)
            .ok_or(ChunkedParseError::PayloadTooLarge)?;
        if new_total > max_body_bytes {
            return Err(ChunkedParseError::PayloadTooLarge);
        }

        let Some(needed_end) = pos.checked_add(chunk_size).and_then(|v| v.checked_add(2)) else {
            return Err(ChunkedParseError::PayloadTooLarge);
        };
        if slice.len() < needed_end {
            return Ok(None);
        }
        if &slice[pos + chunk_size..pos + chunk_size + 2] != b"\r\n" {
            return Err(ChunkedParseError::InvalidFormat);
        }

        out.extend_from_slice(&slice[pos..pos + chunk_size]);
        pos += chunk_size + 2;
    }
}

fn format_response_headers(template: &str, body_len: usize) -> String {
    let mut hdr = template
        .replace("\r\n", "\n")
        .replace('\n', "\r\n")
        .replace("{}", &body_len.to_string());
    if !hdr.ends_with("\r\n\r\n") {
        if hdr.ends_with("\r\n") {
            hdr.push_str("\r\n");
        } else {
            hdr.push_str("\r\n\r\n");
        }
    }
    hdr
}

/// Контекст сессии на сервере (Очередь вывода + Скользящее окно ввода)
struct ServerSession {
    nonce_prefix: [u8; 4],
    rx_router: Arc<Mutex<mpsc::Receiver<Bytes>>>,
    // Синхронный Mutex для неблокирующего доступа без .await внутри ресемблера
    reassembler: Arc<StdMutex<ReassemblyQueue>>,
}

pub async fn run_http_stream_server(
    config: Arc<Config>,
    registry: Arc<ClientRegistry>,
    tun_tx: mpsc::Sender<Bytes>,
    auth_handler: ServerAuthHandler,
) -> Result<()> {
    let bind_to = &config.server.ahttp_bind_to;
    info!("[AHTTP-Stream] Initializing XHTTP pipeline on {}", bind_to);

    // Глобальная карта активных сессионных контекстов
    let active_sessions: Arc<DashMap<String, Arc<ServerSession>>> = Arc::new(DashMap::new());

    // Фоновый сборщик мусора удаляет ServerSession для уже выселенных клиентов
    let gc_interval = Duration::from_secs(config.ahttp.session_gc_interval_secs.max(1));
    let gc_sessions = active_sessions.clone();
    let gc_registry = registry.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(gc_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            gc_sessions.retain(|sid, _| gc_registry.get_by_session(sid).is_some());
        }
    });

    let listener = TcpListener::bind(bind_to).await?;
    loop {
        let (stream, remote_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!("[AHTTP-Stream] Accept error: {}", e);
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        if let Err(e) = stream.set_nodelay(true) {
            debug!("[AHTTP-Stream] Failed to set TCP_NODELAY: {}", e);
        }

        let (cfg, rg, tx, auth, sessions) = (
            config.clone(),
            registry.clone(),
            tun_tx.clone(),
            auth_handler.clone(),
            active_sessions.clone(),
        );

        tokio::spawn(async move {
            if let Err(e) =
                handle_http_connection(stream, remote_addr, rg, cfg, tx, auth, sessions).await
            {
                debug!("[AHTTP-Stream] Connection {} closed: {}", remote_addr, e);
            }
        });
    }
}

fn get_or_create_session(
    sessions: &DashMap<String, Arc<ServerSession>>,
    registry: &ClientRegistry,
    session_id: &str,
    assigned_ip: &str,
    nonce_prefix: [u8; 4],
    reassembly_max_size: usize,
    reassembly_gap_timeout: Duration,
) -> Arc<ServerSession> {
    if let Some(existing) = sessions.get(session_id) {
        if existing.nonce_prefix == nonce_prefix {
            return existing.value().clone();
        }
    }

    let (tx_router, rx_router) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
    registry.finalize_client(assigned_ip, tx_router);
    let new_session = Arc::new(ServerSession {
        nonce_prefix,
        rx_router: Arc::new(Mutex::new(rx_router)),
        reassembler: Arc::new(StdMutex::new(ReassemblyQueue::with_config(
            reassembly_max_size.max(1),
            CLIENT_SEQUENCE_START,
            reassembly_gap_timeout,
        ))),
    });
    sessions.insert(session_id.to_string(), new_session.clone());
    new_session
}

async fn handle_http_connection(
    mut stream: TcpStream,
    remote_addr: SocketAddr,
    registry: Arc<ClientRegistry>,
    config: Arc<Config>,
    tun_tx: mpsc::Sender<Bytes>,
    auth_handler: ServerAuthHandler,
    sessions: Arc<DashMap<String, Arc<ServerSession>>>,
) -> Result<()> {
    let mut buffer = BytesMut::with_capacity(65536);

    // Чтение путей из конфигурационного файла [ahttp]
    let path_handshake = format!("{}{}", config.server.ahttp_path, config.ahttp.handshake_path);
    let path_auth = format!("{}{}", config.server.ahttp_path, config.ahttp.auth_path);
    let path_traffic = format!("{}{}", config.server.ahttp_path, config.ahttp.traffic_path);

    let read_timeout = config.ahttp.read_timeout();
    let write_timeout = config.ahttp.write_timeout();
    let idle_keepalive_timeout = config.ahttp.idle_keepalive_timeout();
    let max_body_bytes = config.ahttp.effective_max_body_bytes();
    let session_id_header = config.ahttp.session_id_header.trim();
    let session_id_query_param = config.ahttp.effective_session_id_query_param();

    loop {
        if buffer.is_empty() {
            buffer.reserve(65536);
            let n = match tokio::time::timeout(idle_keepalive_timeout, stream.read_buf(&mut buffer))
                .await
            {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => return Ok(()),
            };
            if n == 0 {
                return Ok(());
            }
        }

        let mut headers = [httparse::EMPTY_HEADER; 128];
        let mut req = Request::new(&mut headers);

        enum ParsedHead {
            Complete {
                header_len: usize,
                path: String,
                real_addr: SocketAddr,
                header_session_id: Option<String>,
                is_chunked: bool,
                content_length: Option<usize>,
                invalid: bool,
            },
            Partial,
        }

        let parsed = match req.parse(&buffer) {
            Ok(Status::Complete(header_len)) => {
                let path = req.path.unwrap_or_default().to_string();
                let real_addr = get_real_ip(&req, remote_addr);
                let mut is_chunked = false;
                let mut content_length: Option<usize> = None;
                let mut invalid = false;
                let mut header_session_id: Option<String> = None;

                for header in req.headers.iter() {
                    if header.name.eq_ignore_ascii_case("transfer-encoding") {
                        if let Ok(val) = std::str::from_utf8(header.value) {
                            if val
                                .split(',')
                                .any(|tok| tok.trim().eq_ignore_ascii_case("chunked"))
                            {
                                is_chunked = true;
                            }
                        } else {
                            invalid = true;
                        }
                    } else if header.name.eq_ignore_ascii_case("content-length") {
                        match std::str::from_utf8(header.value)
                            .ok()
                            .and_then(|s| s.trim().parse::<usize>().ok())
                        {
                            Some(v) => {
                                if let Some(prev) = content_length {
                                    if prev != v {
                                        invalid = true;
                                    }
                                } else {
                                    content_length = Some(v);
                                }
                            }
                            None => {
                                invalid = true;
                            }
                        }
                    } else if !session_id_header.is_empty()
                        && header.name.eq_ignore_ascii_case(session_id_header)
                    {
                        if let Ok(val) = std::str::from_utf8(header.value) {
                            let trimmed = val.trim();
                            if !trimmed.is_empty() {
                                header_session_id = Some(trimmed.to_string());
                            }
                        }
                    }
                }

                ParsedHead::Complete {
                    header_len,
                    path,
                    real_addr,
                    header_session_id,
                    is_chunked,
                    content_length,
                    invalid,
                }
            }
            Ok(Status::Partial) => ParsedHead::Partial,
            Err(_) => {
                let _ = send_http_response(
                    &mut stream,
                    400,
                    "Bad Request",
                    "text/plain",
                    b"Bad Request",
                    false,
                    write_timeout,
                )
                .await;
                return Ok(());
            }
        };

        let (header_len, path, real_addr, header_session_id, is_chunked, content_length, invalid) =
            match parsed {
                ParsedHead::Complete {
                    header_len,
                    path,
                    real_addr,
                    header_session_id,
                    is_chunked,
                    content_length,
                    invalid,
                } => (
                    header_len,
                    path,
                    real_addr,
                    header_session_id,
                    is_chunked,
                    content_length,
                    invalid,
                ),
                ParsedHead::Partial => {
                    if buffer.len() > config.ahttp.max_header_bytes {
                        let _ = send_http_response(
                            &mut stream,
                            431,
                            "Request Header Fields Too Large",
                            "text/plain",
                            b"Header Too Large",
                            false,
                            write_timeout,
                        )
                        .await;
                        return Ok(());
                    }
                    buffer.reserve(8192);
                    let n = tokio::time::timeout(read_timeout, stream.read_buf(&mut buffer))
                        .await
                        .context("Timed out reading HTTP headers")??;
                    if n == 0 {
                        return Ok(());
                    }
                    continue;
                }
            };

        let _ = buffer.split_to(header_len);

        if invalid {
            let _ = send_http_response(
                &mut stream,
                400,
                "Bad Request",
                "text/plain",
                b"Invalid Headers",
                false,
                write_timeout,
            )
            .await;
            return Ok(());
        }

        // Чтение тела запроса (поддерживает и Content-Length, и Transfer-Encoding: chunked от Cloudflare)
        let body: Bytes = if is_chunked {
            loop {
                match try_parse_chunked_body(&buffer, max_body_bytes, config.ahttp.max_header_bytes) {
                    Ok(Some((decoded, consumed))) => {
                        let _ = buffer.split_to(consumed);
                        break decoded;
                    }
                    Ok(None) => {
                        let max_wire_chunked = max_body_bytes
                            .saturating_mul(2)
                            .saturating_add(config.ahttp.max_header_bytes);
                        if buffer.len() > max_wire_chunked {
                            let _ = send_http_response(
                                &mut stream,
                                413,
                                "Payload Too Large",
                                "text/plain",
                                b"Payload Too Large",
                                false,
                                write_timeout,
                            )
                            .await;
                            return Ok(());
                        }
                        buffer.reserve(16384);
                        let n = tokio::time::timeout(read_timeout, stream.read_buf(&mut buffer))
                            .await
                            .context("Timed out reading chunked HTTP body")??;
                        if n == 0 {
                            return Err(anyhow::anyhow!(
                                "Connection closed while reading chunked body"
                            ));
                        }
                    }
                    Err(ChunkedParseError::PayloadTooLarge) => {
                        let _ = send_http_response(
                            &mut stream,
                            413,
                            "Payload Too Large",
                            "text/plain",
                            b"Payload Too Large",
                            false,
                            write_timeout,
                        )
                        .await;
                        return Ok(());
                    }
                    Err(ChunkedParseError::InvalidFormat) => {
                        let _ = send_http_response(
                            &mut stream,
                            400,
                            "Bad Request",
                            "text/plain",
                            b"Malformed Chunked Body",
                            false,
                            write_timeout,
                        )
                        .await;
                        return Ok(());
                    }
                }
            }
        } else {
            let expected_len = content_length.unwrap_or(0);
            if expected_len > max_body_bytes {
                let _ = send_http_response(
                    &mut stream,
                    413,
                    "Payload Too Large",
                    "text/plain",
                    b"Payload Too Large",
                    false,
                    write_timeout,
                )
                .await;
                return Ok(());
            }
            if buffer.len() < expected_len {
                buffer.reserve(expected_len - buffer.len());
                while buffer.len() < expected_len {
                    let n = tokio::time::timeout(read_timeout, stream.read_buf(&mut buffer))
                        .await
                        .context("Timed out reading HTTP body")??;
                    if n == 0 {
                        return Err(anyhow::anyhow!("Connection closed while reading body"));
                    }
                }
            }
            buffer.split_to(expected_len).freeze()
        };

        let base_path = path.split('?').next().unwrap_or(&path);

        match base_path {
            p if p == path_handshake || p == path_auth => {
                match auth_handler
                    .process_handshake_packet(body, real_addr, "ahttp")
                    .await
                {
                    Ok((Some(resp), _)) => {
                        send_http_response(
                            &mut stream,
                            200,
                            "OK",
                            "application/octet-stream",
                            &resp,
                            true,
                            write_timeout,
                        )
                        .await?;
                    }
                    Ok((None, _)) => {
                        send_http_response(
                            &mut stream,
                            204,
                            "No Content",
                            "application/octet-stream",
                            &[],
                            true,
                            write_timeout,
                        )
                        .await?;
                    }
                    Err(e) => {
                        debug!("[AHTTP-Stream] Invalid handshake packet from {}: {}", real_addr, e);
                        let _ = send_http_response(
                            &mut stream,
                            404,
                            "Not Found",
                            "text/plain",
                            b"Not Found",
                            false,
                            write_timeout,
                        )
                        .await;
                        return Ok(());
                    }
                }
            }
            // ЕДИНАЯ ТОЧКА ТРАФИКА ДЛЯ UPLINK И DOWNLINK
            p if p == path_traffic => {
                let Some(session_id) = header_session_id
                    .or_else(|| extract_query_param(&path, session_id_query_param))
                else {
                    let _ = send_http_response(
                        &mut stream,
                        401,
                        "Unauthorized",
                        "text/plain",
                        b"Missing session_id",
                        false,
                        write_timeout,
                    )
                    .await;
                    return Ok(());
                };

                if let Some(client_info) = registry.get_by_session(&session_id) {
                    registry.touch_client(&client_info);

                    // Получаем или переинициализируем контекст сессии (при смене nonce_prefix после resume)
                    let session = get_or_create_session(
                        &sessions,
                        &registry,
                        &session_id,
                        &client_info.assigned_ip,
                        client_info.nonce_prefix,
                        config.ahttp.reassembly_queue_max_size,
                        config.ahttp.effective_reassembly_gap_timeout(),
                    );

                    // 1. Прием Uplink-трафика (батчевая распаковка + окно упорядочивания)
                    let uplink_len = body.len();
                    let mut unpacked_batch = Vec::with_capacity(if uplink_len > 0 { 64 } else { 0 });
                    if !body.is_empty() {
                        let mut cursor = std::io::Cursor::new(&body[..]);
                        while let Ok(Some(encrypted_packet)) = read_next_packet(&mut cursor).await {
                            if let Ok((seq, decrypted)) =
                                unwrap_packet_with_seq(&client_info.cipher, &encrypted_packet)
                            {
                                unpacked_batch.push((seq, decrypted));
                            }
                        }
                    }

                    let to_forward = {
                        let mut reassembler = session.reassembler.lock().unwrap();
                        if !unpacked_batch.is_empty() {
                            reassembler.insert_batch(unpacked_batch)
                        } else if reassembler.gap_remaining().is_some_and(|d| d.is_zero()) {
                            reassembler.flush_expired()
                        } else {
                            Vec::new()
                        }
                    };

                    for packet in to_forward {
                        let packet_len = packet.len();
                        if tun_tx.send(packet).await.is_err() {
                            return Err(anyhow::anyhow!("Server TUN channel closed"));
                        }
                        registry.record_rx(&client_info, packet_len, "ahttp");
                    }

                    // 2. Отдача Downlink-трафика
                    let mut body_buf = BytesMut::new();
                    let padding_step = config.stealth.padding_step;
                    let coalesce_budget = config.ahttp.coalesce_budget_bytes.max(4096);
                    let is_heavy_uplink =
                        uplink_len >= config.ahttp.heavy_uplink_threshold_bytes;
                    let is_empty_poll = uplink_len == 0;

                    // Для тяжёлых Uplink-батчей (>= 8 КБ по умолчанию) не удерживаем запрос на poll-таймаут.
                    // Для пустых idle long-poll запросов держим окно `idle_poll_timeout_ms` (просыпаемся мгновенно при появлении пакета!).
                    // Для мелких пакетов (TCP ACK / DNS) используем короткий `poll_timeout_ms`.
                    let timeout_duration = if is_heavy_uplink {
                        Duration::from_millis(1)
                    } else if is_empty_poll {
                        config.ahttp.effective_idle_poll_timeout()
                    } else {
                        config.ahttp.effective_active_poll_timeout()
                    };
                    let deadline = tokio::time::Instant::now() + timeout_duration;
                    let max_coalesce_window = Duration::from_millis(config.ahttp.coalesce_max_wait_ms);
                    let packet_gap_timeout =
                        Duration::from_micros(config.ahttp.coalesce_gap_timeout_us.max(100));

                    let mut raw_downlink_packets = Vec::new();
                    let mut raw_bytes_accum = 0usize;
                    let mut base_seq = 0u64;

                    if let Ok(mut rx_router) =
                        tokio::time::timeout_at(deadline, session.rx_router.lock()).await
                    {
                        let first_pkt = match rx_router.try_recv() {
                            Ok(pkt) => Some(pkt),
                            Err(_) if is_heavy_uplink => None,
                            Err(_) => {
                                match tokio::time::timeout_at(deadline, rx_router.recv()).await {
                                    Ok(Some(pkt)) => Some(pkt),
                                    _ => None,
                                }
                            }
                        };

                        if let Some(packet) = first_pkt {
                            if packet.len() >= 20 {
                                raw_bytes_accum += packet.len() + 40;
                                raw_downlink_packets.push(packet);
                            }

                            while raw_bytes_accum < coalesce_budget {
                                match rx_router.try_recv() {
                                    Ok(next_packet) => {
                                        if next_packet.len() >= 20 {
                                            raw_bytes_accum += next_packet.len() + 40;
                                            raw_downlink_packets.push(next_packet);
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }

                            // Адаптивная коалесценция Downlink
                            if !max_coalesce_window.is_zero() && raw_bytes_accum < coalesce_budget {
                                let burst_deadline =
                                    tokio::time::Instant::now() + max_coalesce_window;
                                while raw_bytes_accum < coalesce_budget {
                                    let now = tokio::time::Instant::now();
                                    if now >= burst_deadline {
                                        break;
                                    }
                                    let step_deadline =
                                        (now + packet_gap_timeout).min(burst_deadline);
                                    match tokio::time::timeout_at(step_deadline, rx_router.recv())
                                        .await
                                    {
                                        Ok(Some(p)) => {
                                            if p.len() >= 20 {
                                                raw_bytes_accum += p.len() + 40;
                                                raw_downlink_packets.push(p);
                                            }
                                            while raw_bytes_accum < coalesce_budget {
                                                match rx_router.try_recv() {
                                                    Ok(next_packet) => {
                                                        if next_packet.len() >= 20 {
                                                            raw_bytes_accum +=
                                                                next_packet.len() + 40;
                                                            raw_downlink_packets.push(next_packet);
                                                        }
                                                    }
                                                    Err(_) => break,
                                                }
                                            }
                                        }
                                        _ => break,
                                    }
                                }
                            }
                        }

                        // Резервируем sequence строго ВНУТРИ лока rx_router
                        if !raw_downlink_packets.is_empty() {
                            let count = raw_downlink_packets.len() as u64;
                            base_seq = client_info.sequence.fetch_add(count, Ordering::Relaxed);
                        }
                    }

                    if !raw_downlink_packets.is_empty() {
                        body_buf.reserve(
                            raw_bytes_accum
                                + raw_downlink_packets.len() * (padding_step as usize + 32),
                        );

                        for (idx, packet) in raw_downlink_packets.into_iter().enumerate() {
                            let seq = base_seq + idx as u64;
                            if let Ok(encrypted) = wrap_packet_padded(
                                &client_info.cipher,
                                &client_info.nonce_prefix,
                                seq,
                                packet,
                                padding_step,
                            ) {
                                anet_common::stream_framing::frame_packet_into(
                                    &mut body_buf,
                                    &encrypted,
                                );
                            }
                        }
                    }

                    // 3. Отвечаем клиенту с таймаутом записи
                    let response_header =
                        format_response_headers(&config.ahttp.response_headers, body_buf.len());

                    tokio::time::timeout(write_timeout, async {
                        stream.write_all(response_header.as_bytes()).await?;
                        if !body_buf.is_empty() {
                            stream.write_all(&body_buf).await?;
                        }
                        stream.flush().await?;
                        Ok::<(), std::io::Error>(())
                    })
                    .await
                    .context("Timed out writing HTTP traffic response")??;
                } else {
                    sessions.remove(&session_id);
                    let _ = send_http_response(
                        &mut stream,
                        401,
                        "Unauthorized",
                        "text/plain",
                        b"Unauthorized",
                        false,
                        write_timeout,
                    )
                    .await;
                    return Ok(());
                }
            }
            _ => {
                let _ = send_http_response(
                    &mut stream,
                    404,
                    "Not Found",
                    "text/plain",
                    b"Not Found",
                    false,
                    write_timeout,
                )
                .await;
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunked_parser_handles_single_and_multi_chunks_and_trailers() {
        let single = b"5\r\nhello\r\n0\r\n\r\n";
        let (body, consumed) = try_parse_chunked_body(single, 1024, 1024).unwrap().unwrap();
        assert_eq!(body.as_ref(), b"hello");
        assert_eq!(consumed, single.len());

        let multi_with_ext_and_trailers =
            b"4;foo=bar\r\nRust\r\n6\r\n+AHTTP\r\n0\r\nX-Check: 1\r\n\r\n";
        let (body2, consumed2) =
            try_parse_chunked_body(multi_with_ext_and_trailers, 1024, 1024)
                .unwrap()
                .unwrap();
        assert_eq!(body2.as_ref(), b"Rust+AHTTP");
        assert_eq!(consumed2, multi_with_ext_and_trailers.len());

        let empty_chunked = b"0\r\n\r\nEXTRA";
        let (body3, consumed3) = try_parse_chunked_body(empty_chunked, 1024, 1024)
            .unwrap()
            .unwrap();
        assert!(body3.is_empty());
        assert_eq!(consumed3, 5);
    }

    #[test]
    fn chunked_parser_returns_none_on_partial_and_errors_on_oversize_or_corrupt() {
        assert_eq!(try_parse_chunked_body(b"5\r\nhel", 1024, 1024), Ok(None));
        assert_eq!(try_parse_chunked_body(b"0\r\n", 1024, 1024), Ok(None));

        assert_eq!(
            try_parse_chunked_body(b"a\r\n0123456789\r\n0\r\n\r\n", 5, 1024),
            Err(ChunkedParseError::PayloadTooLarge)
        );
        assert_eq!(
            try_parse_chunked_body(b"zzzz\r\n", 1024, 1024),
            Err(ChunkedParseError::InvalidFormat)
        );
        assert_eq!(
            try_parse_chunked_body(b"3\r\nabcXX0\r\n\r\n", 1024, 1024),
            Err(ChunkedParseError::InvalidFormat)
        );
    }

    #[test]
    fn format_response_headers_normalizes_crlf_and_terminator() {
        let out = format_response_headers("HTTP/1.1 200 OK\nContent-Length: {}\nConnection: keep-alive", 42);
        assert_eq!(
            out,
            "HTTP/1.1 200 OK\r\nContent-Length: 42\r\nConnection: keep-alive\r\n\r\n"
        );
    }
}
