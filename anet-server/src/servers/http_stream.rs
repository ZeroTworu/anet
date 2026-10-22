use crate::client_registry::ClientRegistry;
use crate::auth_handler::ServerAuthHandler;
use crate::config::Config;
use anet_common::consts::CHANNEL_BUFFER_SIZE;
use anet_common::transport::wrap_packet_padded;
use anet_common::reassembly::ReassemblyQueue;
use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use httparse::{Request, Status};
use log::{info, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
// Используем синхронный Mutex для быстрых, неблокирующих операций
use std::sync::Mutex as StdMutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use dashmap::DashMap;
use url::Url;
use anet_common::stream_framing::read_next_packet;

fn get_real_ip(req: &httparse::Request, fallback: SocketAddr) -> SocketAddr {
    anet_common::http_help::extract_real_ip_from_raw(
        req.headers.iter().map(|h| (h.name, h.value)),
        fallback,
    )
}

/// Отправка базового ответа HTTP/1.1
async fn send_http_response(
    stream: &mut TcpStream,
    status_code: u16,
    status_text: &str,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let response = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-cache, no-store\r\n\
         X-Accel-Buffering: no\r\n\
         Connection: close\r\n\r\n",
        status_code, status_text, content_type, body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

fn extract_query_param(path: &str, param: &str) -> Option<String> {
    let base_url = Url::parse("http://localhost").ok()?;
    let url = base_url.join(path).ok()?;

    url.query_pairs()
        .find(|(k, _)| k == param)
        .map(|(_, v)| v.into_owned())
}

/// Дешифрует входящий пакет и извлекает из него оригинальный sequence (u64)
fn unwrap_packet_with_seq(cipher: &anet_common::encryption::Cipher, raw_packet: Bytes) -> Result<(u64, Bytes)> {
    let mut buffer = raw_packet
        .try_into_mut()
        .map_err(|_| anyhow::anyhow!("Encrypted packet buffer is unexpectedly shared"))?;

    if buffer.len() < 12 + 16 {
        anyhow::bail!("Packet too short");
    }

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&buffer[..12]);

    let payload_buffer = &mut buffer[12..];
    cipher.decrypt_in_place(&nonce, payload_buffer)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

    let plaintext_len = payload_buffer.len() - 16;
    let plaintext = &payload_buffer[..plaintext_len];

    if plaintext.len() < 10 {
        anyhow::bail!("Payload too short");
    }

    let seq = u64::from_be_bytes(plaintext[0..8].try_into().unwrap());
    let data_len = u16::from_be_bytes([plaintext[8], plaintext[9]]) as usize;

    if 10 + data_len > plaintext.len() {
        anyhow::bail!("Malformed packet length");
    }

    let payload_start = 12 + 10;
    let payload_end = payload_start + data_len;
    buffer.truncate(payload_end);
    let payload_bytes = buffer.freeze().slice(payload_start..payload_end);

    Ok((seq, payload_bytes))
}


/// Контекст сессии на сервере (Очередь вывода + Скользящее окно ввода)
struct ServerSession {
    rx_router: Arc<Mutex<mpsc::Receiver<Bytes>>>,
    // ИСПОЛЬЗУЕМ std::sync::Mutex для синхронных операций без .await
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

    let listener = TcpListener::bind(bind_to).await?;
    loop {
        let (stream, remote_addr) = listener.accept().await?;
        stream.set_nodelay(true)?;

        let (cfg, rg, tx, auth, sessions) = (
            config.clone(),
            registry.clone(),
            tun_tx.clone(),
            auth_handler.clone(),
            active_sessions.clone(),
        );

        tokio::spawn(async move {
            if let Err(_e) = handle_http_connection(stream, remote_addr, rg, cfg, tx, auth, sessions).await {
                // Игнорируем штатные обрывы TCP
            }
        });
    }
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

    loop {
        if buffer.is_empty() {
            buffer.reserve(65536);
            let n = stream.read_buf(&mut buffer).await?;
            if n == 0 { return Ok(()); }
        }

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = Request::new(&mut headers);

        match req.parse(&buffer) {
            Ok(Status::Complete(header_len)) => {
                let path = req.path.unwrap_or_default().to_string();
                let real_addr = get_real_ip(&req, remote_addr);

                let mut content_length = 0usize;
                for header in req.headers.iter() {
                    if header.name.eq_ignore_ascii_case("content-length") {
                        if let Ok(val) = std::str::from_utf8(header.value) {
                            content_length = val.parse().unwrap_or(0);
                        }
                    }
                }

                let total_expected = header_len + content_length;
                if buffer.len() < total_expected {
                    buffer.reserve(total_expected - buffer.len());
                    while buffer.len() < total_expected {
                        let n = stream.read_buf(&mut buffer).await?;
                        if n == 0 { return Err(anyhow::anyhow!("Connection closed while reading body")); }
                    }
                }

                let body = &buffer[header_len..total_expected];
                let base_path = path.split('?').next().unwrap_or(&path);

                match base_path {
                    p if p == path_handshake => {
                        let packet = Bytes::copy_from_slice(body);
                        let (response, _) = auth_handler.process_handshake_packet(packet, real_addr, "ahttp").await?;
                        if let Some(resp) = response {
                            send_http_response(&mut stream, 200, "OK", "application/octet-stream", &resp).await?;
                        }
                    }
                    p if p == path_auth => {
                        let packet = Bytes::copy_from_slice(body);
                        let (response, _) = auth_handler.process_handshake_packet(packet, real_addr, "ahttp").await?;
                        if let Some(resp) = response {
                            send_http_response(&mut stream, 200, "OK", "application/octet-stream", &resp).await?;
                        }
                    }
                    // ЕДИНАЯ ТОЧКА ТРАФИКА ДЛЯ UPLINK И DOWNLINK
                    p if p == path_traffic => {
                        let session_id = extract_query_param(&path, "session_id").context("Missing session_id in query")?;

                        if let Some(client_info) = registry.get_by_session(&session_id) {

                            client_info.last_activity.store(
                                std::time::SystemTime::now()
                                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                                Ordering::Relaxed
                            );

                            // Получаем или инициализируем контекст сессии
                            let session = sessions.entry(session_id.clone()).or_insert_with(|| {
                                let (tx_router, rx_router) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
                                registry.finalize_client(&client_info.assigned_ip, tx_router);
                                Arc::new(ServerSession {
                                    rx_router: Arc::new(Mutex::new(rx_router)),
                                    reassembler: Arc::new(StdMutex::new(ReassemblyQueue::new(config.ahttp.reassembly_queue_max_size))),
                                })
                            }).value().clone();

                            // 1. Прием Uplink-трафика (Батчевая распаковка через окно упорядочивания)
                            if !body.is_empty() {
                                let mut cursor = std::io::Cursor::new(body);
                                let mut unpacked_batch = Vec::with_capacity(64);

                                while let Ok(Some(encrypted_packet)) = read_next_packet(&mut cursor).await {
                                    if let Ok((seq, decrypted)) = unwrap_packet_with_seq(&client_info.cipher, encrypted_packet) {
                                        unpacked_batch.push((seq, decrypted));
                                    }
                                }

                                let to_forward = if !unpacked_batch.is_empty() {
                                    let mut reassembler = session.reassembler.lock().unwrap();
                                    reassembler.insert_batch(unpacked_batch)
                                } else {
                                    Vec::new()
                                };

                                for packet in to_forward {
                                    let packet_len = packet.len();

                                    // BACKPRESSURE
                                    match tun_tx.try_send(packet) {
                                        Ok(_) => {
                                            registry.record_rx(&client_info, packet_len, "ahttp");
                                        }
                                        Err(mpsc::error::TrySendError::Full(_)) => {
                                            warn!("[AHTTP] TUN queue full, dropping uplink packet");
                                        }
                                        Err(mpsc::error::TrySendError::Closed(_)) => {
                                            break;
                                        }
                                    }
                                }
                            }

                            // 2. Отдача Downlink-трафика
                            let mut body_buf = BytesMut::new();
                            let padding_step = config.stealth.padding_step;
                            let coalesce_budget = config.ahttp.coalesce_budget_bytes;
                            let is_heavy_uplink = content_length >= 8192;

                            // Для крупных Uplink-батчей (>= 8 КБ) НЕ блокируем ответ на poll_timeout_ms,
                            // чтобы мгновенно освобождать слот клиента под следующий Upload-батч.
                            // Для пустых poll-запросов и мелких пакетов (TCP ACK / ping) гарантируем
                            // разумное окно ожидания (минимум 20 мс, даже если в старом конфиге стояло 2 мс).
                            let timeout_duration = if is_heavy_uplink {
                                std::time::Duration::from_millis(1)
                            } else {
                                std::time::Duration::from_millis(config.ahttp.poll_timeout_ms.max(20))
                            };
                            let deadline = tokio::time::Instant::now() + timeout_duration;
                            let micro_coalesce = std::time::Duration::from_micros(500);

                            let mut raw_downlink_packets = Vec::new();
                            let mut raw_bytes_accum = 0usize;

                            if let Ok(mut rx_router) = tokio::time::timeout_at(deadline, session.rx_router.lock()).await {
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

                                    // Микро-коалесценция (до 0.5 мс): когда первый пакет пачки из TUN
                                    // разбудил воркер, даем TUN reader'у еще полмиллисекунды дочитать
                                    // остальные пакеты всплеска, чтобы не закрывать HTTP-ответ с 1 пакетом (1.4 КБ).
                                    if raw_bytes_accum < coalesce_budget / 2 {
                                        let coalesce_deadline = tokio::time::Instant::now() + micro_coalesce;
                                        while raw_bytes_accum < coalesce_budget {
                                            match tokio::time::timeout_at(coalesce_deadline, rx_router.recv()).await {
                                                Ok(Some(p)) => {
                                                    if p.len() >= 20 {
                                                        raw_bytes_accum += p.len() + 40;
                                                        raw_downlink_packets.push(p);
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
                                                }
                                                _ => break,
                                            }
                                        }
                                    }
                                }
                            } // <--- Лок rx_router освобождается мгновенно, следующий HTTP-воркер сразу берет следующий батч!

                            if !raw_downlink_packets.is_empty() {
                                body_buf.reserve(raw_bytes_accum + raw_downlink_packets.len() * (padding_step as usize + 32));
                                // Резервируем диапазон sequence номеров атомарно на весь батч,
                                // чтобы параллельные воркеры шифровали свои батчи со строго возрастающими seq
                                let count = raw_downlink_packets.len() as u64;
                                let base_seq = client_info.sequence.fetch_add(count, Ordering::Relaxed);

                                for (idx, packet) in raw_downlink_packets.into_iter().enumerate() {
                                    let seq = base_seq + idx as u64;
                                    if let Ok(encrypted) = wrap_packet_padded(
                                        &client_info.cipher,
                                        &client_info.nonce_prefix,
                                        seq,
                                        packet,
                                        padding_step,
                                    ) {
                                        anet_common::stream_framing::frame_packet_into(&mut body_buf, &encrypted);
                                    }
                                }
                            }

                            // 3. Отвечаем клиенту
                            let response_header = config.ahttp.response_headers
                                .replace("\r\n", "\n")
                                .replace('\n', "\r\n")
                                .replace("{}", &body_buf.len().to_string());

                            stream.write_all(response_header.as_bytes()).await?;
                            if !body_buf.is_empty() {
                                stream.write_all(&body_buf).await?;
                            }
                            stream.flush().await?;

                        } else {
                            sessions.remove(&session_id);
                            send_http_response(&mut stream, 401, "Unauthorized", "text/plain", b"Unauthorized").await?;
                        }
                    }
                    _ => {
                        send_http_response(&mut stream, 404, "Not Found", "text/plain", b"Not Found").await?;
                    }
                }

                let _ = buffer.split_to(total_expected);
            }
            Ok(Status::Partial) => {
                if buffer.len() > config.ahttp.max_header_bytes {
                    return Err(anyhow::anyhow!("HTTP header too large"));
                }
                buffer.reserve(8192);
                let n = stream.read_buf(&mut buffer).await?;
                if n == 0 { return Ok(()); }
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
}
