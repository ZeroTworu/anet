use crate::client_registry::ClientRegistry;
use crate::auth_handler::ServerAuthHandler;
use crate::config::Config;
use anet_common::consts::{CHANNEL_BUFFER_SIZE, MAX_PACKET_SIZE, COALESCE_BUDGET_BYTES};
use anet_common::transport::unwrap_packet_bytes_in_place;
use base64::Engine as _;
use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use httparse::{Request, Status};
use log::{info, warn, debug, error};
use std::net::SocketAddr;
use std::sync::Arc;
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

pub async fn run_http_stream_server(
    config: Arc<Config>,
    registry: Arc<ClientRegistry>,
    tun_tx: mpsc::Sender<Bytes>,
    auth_handler: ServerAuthHandler,
) -> Result<()> {
    let bind_to = &config.server.ahttp_bind_to;
    info!("[AHTTP-Stream] Initializing XHTTP cloaked pipeline on {}", bind_to);

    let active_sessions: Arc<DashMap<String, Arc<Mutex<mpsc::Receiver<Bytes>>>>> = Arc::new(DashMap::new());

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
            if let Err(e) = handle_http_connection(stream, remote_addr, rg, cfg, tx, auth, sessions).await {
                warn!("[AHTTP-Stream] Session {} stopped: {:#}", remote_addr, e);
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
    sessions: Arc<DashMap<String, Arc<Mutex<mpsc::Receiver<Bytes>>>>>,
) -> Result<()> {
    let mut buffer = BytesMut::with_capacity(65536);

    let path_handshake = format!("{}/handshake", config.server.ahttp_path);
    let path_auth = format!("{}/auth", config.server.ahttp_path);
    let path_traffic = format!("{}/traffic", config.server.ahttp_path);

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
                let method = req.method.unwrap_or_default().to_string();

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

                match (method.as_str(), base_path) {
                    ("POST", p) if p == path_handshake => {
                        let packet = Bytes::copy_from_slice(body);
                        let (response, _) = auth_handler.process_handshake_packet(packet, real_addr, "ahttp").await?;
                        if let Some(resp) = response {
                            send_http_response(&mut stream, 200, "OK", "application/octet-stream", &resp).await?;
                        }
                    }
                    ("POST", p) if p == path_auth => {
                        let packet = Bytes::copy_from_slice(body);
                        let (response, _) = auth_handler.process_handshake_packet(packet, real_addr, "ahttp").await?;
                        if let Some(resp) = response {
                            send_http_response(&mut stream, 200, "OK", "application/octet-stream", &resp).await?;
                        }
                    }
                    (m, p) if p == path_traffic && (m == "POST" || m == "PUT" || m == "OPTIONS" || m == "PATCH" || m == "GET") => {
                        let session_id = extract_query_param(&path, "session_id").context("Missing session_id in query")?;

                        if let Some(client_info) = registry.get_by_session(&session_id) {

                            let receiver_lock = sessions.entry(session_id.clone()).or_insert_with(|| {
                                let (tx_router, rx_router) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
                                registry.finalize_client(&client_info.assigned_ip, tx_router);
                                Arc::new(Mutex::new(rx_router))
                            }).value().clone();

                            // 1. Обрабатываем входящий Uplink-трафик
                            if !body.is_empty() {
                                debug!("[AHTTP Server Debug] <<< Received {} bytes from client", body.len());
                                let mut cursor = std::io::Cursor::new(body);
                                let mut rx_pkts_count = 0;
                                let mut dec_failures = 0;

                                while let Ok(Some(encrypted_packet)) = read_next_packet(&mut cursor).await {
                                    let packet_len = encrypted_packet.len();
                                    match unwrap_packet_bytes_in_place(&client_info.cipher, encrypted_packet) {
                                        Ok(decrypted) => {
                                            rx_pkts_count += 1;
                                            let _ = tun_tx.send(decrypted).await;
                                            registry.record_rx(&client_info, packet_len, "ahttp");
                                        }
                                        Err(e) => {
                                            dec_failures += 1;
                                            error!("[AHTTP Server Debug] Decryption failed for packet: {}", e);
                                        }
                                    }
                                }
                                debug!("[AHTTP Server Debug] <<< Unpacked {} valid packets ({} decryption failures)", rx_pkts_count, dec_failures);
                            }

                            // 2. Опрашиваем Downlink-очередь с микро-таймаутом
                            let mut rx_router = receiver_lock.lock().await;
                            let mut body_buf = BytesMut::new();
                            let mut tx_pkts_count = 0;

                            let timeout_duration = std::time::Duration::from_millis(30);
                            if let Ok(Some(packet)) = tokio::time::timeout(timeout_duration, rx_router.recv()).await {
                                let framed = anet_common::stream_framing::frame_packet(packet);
                                anet_common::stream_framing::frame_packet_into(&mut body_buf, &framed);
                                tx_pkts_count += 1;

                                while let Ok(next_packet) = rx_router.try_recv() {
                                    let framed = anet_common::stream_framing::frame_packet(next_packet);
                                    anet_common::stream_framing::frame_packet_into(&mut body_buf, &framed);
                                    tx_pkts_count += 1;
                                    if body_buf.len() >= COALESCE_BUDGET_BYTES {
                                        break;
                                    }
                                }
                            }

                            if !body_buf.is_empty() {
                                debug!("[AHTTP Server Debug] >>> Sending {} bytes ({} packets) to client", body_buf.len(), tx_pkts_count);
                            }

                            // 3. Отправляем ответ с явным Content-Length без chunked-протокола.
                            let response_header = format!(
                                "HTTP/1.1 200 OK\r\n\
                                 Content-Type: video/mp4\r\n\
                                 Cache-Control: no-cache, no-transform, private, must-revalidate\r\n\
                                 Pragma: no-cache\r\n\
                                 X-Accel-Buffering: no\r\n\
                                 Content-Length: {}\r\n\
                                 Connection: close\r\n\r\n",
                                body_buf.len()
                            );

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
                break;
            }
            Ok(Status::Partial) => {
                if buffer.len() > 16384 {
                    return Err(anyhow::anyhow!("HTTP header too large or malformed"));
                }
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
