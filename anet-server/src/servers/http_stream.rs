use crate::client_registry::ClientRegistry;
use crate::auth_handler::ServerAuthHandler;
use crate::config::Config;
use anet_common::consts::{CHANNEL_BUFFER_SIZE, MAX_PACKET_SIZE};
use anet_common::transport::wrap_packet_padded;
use anet_common::reassembly::ReassemblyQueue;
use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use httparse::{Request, Status};
use log::info;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use dashmap::DashMap;
use url::Url;
use anet_common::stream_framing::read_next_packet;

fn get_real_ip(req: &httparse::Request, fallback: SocketAddr) -> SocketAddr {
    for header in req.headers.iter() {
        if header.name.eq_ignore_ascii_case("x-real-ip") || header.name.eq_ignore_ascii_case("x-forwarded-for") {
            if let Ok(ip_str) = std::str::from_utf8(header.value) {
                let first_ip = ip_str.split(',').next().unwrap_or("").trim();
                if let Ok(ip) = first_ip.parse::<std::net::IpAddr>() {
                    return SocketAddr::new(ip, 0);
                }
            }
        }
    }
    SocketAddr::new(fallback.ip(), 0)
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
    reassembler: Arc<Mutex<ReassemblyQueue>>,
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
    let mut buffer = BytesMut::with_capacity(MAX_PACKET_SIZE * 2);

    // Чтение путей из конфигурационного файла [ahttp]
    let path_handshake = format!("{}{}", config.server.ahttp_path, config.ahttp.handshake_path);
    let path_auth = format!("{}{}", config.server.ahttp_path, config.ahttp.auth_path);
    let path_traffic = format!("{}{}", config.server.ahttp_path, config.ahttp.traffic_path);

    loop {
        let mut temp = [0u8; 8192];
        let n = stream.read(&mut temp).await?;
        if n == 0 { return Ok(()); }
        buffer.extend_from_slice(&temp[..n]);

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

                while buffer.len() < header_len + content_length {
                    let mut temp = [0u8; 8192];
                    let n = stream.read(&mut temp).await?;
                    if n == 0 { return Err(anyhow::anyhow!("Connection closed while reading body")); }
                    buffer.extend_from_slice(&temp[..n]);
                }

                let body = &buffer[header_len..header_len + content_length];
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

                            // Получаем или инициализируем контекст сессии (Очередь + Реассемблер)
                            let session = sessions.entry(session_id.clone()).or_insert_with(|| {
                                let (tx_router, rx_router) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
                                registry.finalize_client(&client_info.assigned_ip, tx_router);
                                Arc::new(ServerSession {
                                    rx_router: Arc::new(Mutex::new(rx_router)),
                                    reassembler: Arc::new(Mutex::new(ReassemblyQueue::new(config.ahttp.reassembly_queue_max_size))),
                                })
                            }).value().clone();

                            // 1. Прием Uplink-трафика (Распаковка через окно упорядочивания)
                            if !body.is_empty() {
                                let mut cursor = std::io::Cursor::new(body);
                                let mut reassembler = session.reassembler.lock().await;

                                while let Ok(Some(encrypted_packet)) = read_next_packet(&mut cursor).await {
                                    if let Ok((seq, decrypted)) = unwrap_packet_with_seq(&client_info.cipher, encrypted_packet) {

                                        // Получаем готовые упорядоченные пакеты
                                        let ready_packets = reassembler.insert(seq, decrypted);
                                        for packet in ready_packets {
                                            let packet_len = packet.len();
                                            let _ = tun_tx.send(packet).await;
                                            // Записываем статистику на сервере
                                            registry.record_rx(&client_info, packet_len, "ahttp");
                                        }
                                    }
                                }
                            }

                            // 2. Отдача Downlink-трафика (Short-Polling: ждем до 30мс)
                            let mut rx_router = session.rx_router.lock().await;
                            let mut body_buf = BytesMut::new();
                            let padding_step = config.stealth.padding_step;

                            let timeout_duration = std::time::Duration::from_millis(config.ahttp.poll_timeout_ms);

                            // Инлайним шифрование пакетов и полностью убираем замыкания
                            if let Ok(Some(packet)) = tokio::time::timeout(timeout_duration, rx_router.recv()).await {
                                if packet.len() >= 20 {
                                    let seq = client_info.sequence.fetch_add(1, Ordering::Relaxed);
                                    if let Ok(encrypted) = wrap_packet_padded(
                                        &client_info.cipher,
                                        &client_info.nonce_prefix,
                                        seq,
                                        packet,
                                        padding_step
                                    ) {
                                        let framed = anet_common::stream_framing::frame_packet(encrypted);
                                        body_buf.extend_from_slice(&framed);
                                    }
                                }

                                while let Ok(next_packet) = rx_router.try_recv() {
                                    if next_packet.len() >= 20 {
                                        let seq = client_info.sequence.fetch_add(1, Ordering::Relaxed);
                                        if let Ok(encrypted) = wrap_packet_padded(
                                            &client_info.cipher,
                                            &client_info.nonce_prefix,
                                            seq,
                                            next_packet,
                                            padding_step
                                        ) {
                                            let framed = anet_common::stream_framing::frame_packet(encrypted);
                                            body_buf.extend_from_slice(&framed);
                                        }
                                    }
                                    if body_buf.len() >= config.ahttp.coalesce_budget_bytes {
                                        break;
                                    }
                                }
                            }

                            // 3. Отвечаем клиенту на основе кастомных заголовков
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

                // Очищаем буфер для следующего запроса в рамках Keep-Alive сессии
                let total_consumed = header_len + content_length;
                let _ = buffer.split_to(total_consumed);
            }
            Ok(Status::Partial) => {
                if buffer.len() > config.ahttp.max_header_bytes {
                    return Err(anyhow::anyhow!("HTTP header too large"));
                }
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
}
