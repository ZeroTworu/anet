use super::{ClientTransport, ConnectionResult};
use crate::auth::{AuthChannel, AuthHandler};
use crate::config::{CoreConfig, ServerConfig};
use anet_common::consts::{CHANNEL_BUFFER_SIZE, MAX_PACKET_SIZE};
use anet_common::handshake_fragmentation::FragmentConfig;
use anet_common::http_help::BrowserProfile;
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use httparse::{Response, Status, parse_chunk_size};
use log::{info, warn};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::{TlsConnector, client::TlsStream};

#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self, _end_entity: &CertificateDer<'_>, _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>, _ocsp_response: &[u8], _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::RSA_PSS_SHA256, SignatureScheme::ECDSA_NISTP256_SHA256, SignatureScheme::ED25519]
    }
}

/// Установка TLS-соединения с зафиксированным Anycast IP (DNS Pinning)
async fn connect_tls_pinned(
    resolved_addr: SocketAddr,
    host: &str,
    is_tls: bool,
) -> Result<TlsStream<TcpStream>> {
    let tcp_stream = TcpStream::connect(resolved_addr).await?;
    tcp_stream.set_nodelay(true)?;

    if is_tls {
        let mut tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
            .with_no_client_auth();
        tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let connector = TlsConnector::from(Arc::new(tls_config));
        let server_name = ServerName::try_from(host)?.to_owned();
        let tls_stream = connector.connect(server_name, tcp_stream).await?;
        Ok(tls_stream)
    } else {
        anyhow::bail!("http:// without TLS is not supported for OpSec reasons (use https://)");
    }
}

async fn read_http_response(stream: &mut TlsStream<TcpStream>) -> Result<Bytes> {
    let mut buf = BytesMut::with_capacity(8192);
    loop {
        let mut temp = [0u8; 4096];
        let n = stream.read(&mut temp).await?;
        if n == 0 { anyhow::bail!("Connection closed by server"); }
        buf.extend_from_slice(&temp[..n]);

        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut res = Response::new(&mut headers);

        match res.parse(&buf) {
            Ok(Status::Complete(header_len)) => {
                if res.code != Some(200) {
                    anyhow::bail!("Server rejected request: HTTP {}", res.code.unwrap_or(0));
                }
                let body = buf.split_off(header_len);
                return Ok(body.freeze());
            }
            Ok(Status::Partial) => continue,
            Err(e) => anyhow::bail!("Failed to parse HTTP response: {:?}", e),
        }
    }
}

/// Извлечение хоста для маскировки из query-параметров DSN
fn extract_host_from_query(query: &str) -> Option<String> {
    for part in query.split('&') {
        let mut kv = part.split('=');
        if let Some(k) = kv.next() {
            if k == "host" {
                if let Some(v) = kv.next() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

fn parse_next_http_chunk(buf: &mut BytesMut) -> Result<Option<Bytes>> {
    let s = buf.as_ref();
    match parse_chunk_size(s) {
        Ok(Status::Complete((header_len, size))) => {
            let size = size as usize;
            let chunk_end = header_len + size;
            if s.len() < chunk_end + 2 {
                return Ok(None);
            }
            let packet = buf.split_to(chunk_end).freeze().slice(header_len..chunk_end);
            let _ = buf.split_to(2);
            Ok(Some(packet))
        }
        Ok(Status::Partial) => Ok(None),
        Err(e) => Err(anyhow::anyhow!("Invalid HTTP chunk size: {:?}", e)),
    }
}

struct AHttpAuthChannel {
    stream: Mutex<TlsStream<TcpStream>>,
    host: String,
    path: String,
    profile: BrowserProfile,
    is_auth_phase: tokio::sync::Mutex<bool>,
}

#[async_trait]
impl AuthChannel for AHttpAuthChannel {
    async fn send(&self, data: Bytes, _frag: &FragmentConfig) -> Result<()> {
        let mut is_auth = self.is_auth_phase.lock().await;
        let req_path = if !*is_auth {
            *is_auth = true;
            format!("{}/handshake", self.path)
        } else {
            format!("{}/auth", self.path)
        };

        let headers = self.profile.build_headers("POST", &self.host, &req_path, Some(data.len()), false);
        let mut stream = self.stream.lock().await;
        stream.write_all(headers.as_bytes()).await?;
        stream.write_all(&data).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn recv(&self, timeout: Duration) -> Result<Bytes> {
        let mut stream = self.stream.lock().await;
        tokio::time::timeout(timeout, read_http_response(&mut *stream))
            .await
            .context("HTTP Auth timeout")?
    }
}

pub struct AHttpTransport {
    config: CoreConfig,
    server: ServerConfig,
}

impl AHttpTransport {
    pub fn new(config: CoreConfig, server: ServerConfig) -> Self {
        Self { config, server }
    }
}

#[async_trait]
impl ClientTransport for AHttpTransport {
    async fn connect(&self) -> Result<ConnectionResult> {
        let profile = BrowserProfile::random();

        let uri = self.server.dsn.parse::<http::Uri>()?;
        let query_str = uri.query().unwrap_or("");

        let mut host = uri.host().context("No host in DSN")?.to_string();
        if let Some(h) = extract_host_from_query(query_str) {
            host = h;
        }

        let is_tls = uri.scheme_str() == Some("https");
        let port = uri.port_u16().unwrap_or(if is_tls { 443 } else { 80 });
        let base_path = uri.path().to_string();

        let resolved_addr = format!("{}:{}", uri.host().unwrap_or(""), port)
            .to_socket_addrs()?
            .next()
            .context("DNS resolution failed")?;

        let uplink_method: &'static str = if query_str.contains("method=OPTIONS") {
            "OPTIONS"
        } else if query_str.contains("method=PUT") {
            "PUT"
        } else if query_str.contains("method=PATCH") {
            "PATCH"
        } else {
            "POST"
        };

        info!("[AHTTP] Connecting primary channel to {} (resolved: {})", self.server.dsn, resolved_addr);
        let conn_down = connect_tls_pinned(resolved_addr, &host, is_tls).await?;

        let auth_channel = AHttpAuthChannel {
            stream: Mutex::new(conn_down),
            host: host.clone(),
            path: base_path.clone(),
            profile: profile.clone(),
            is_auth_phase: tokio::sync::Mutex::new(false),
        };

        let auth = AuthHandler::new(&self.config, self.server.server_pub_key.as_deref())?;
        let (auth_response, shared_key) = auth.authenticate_once(&auth_channel).await?;

        let session_id = auth_response.session_id.clone();
        let cipher = Arc::new(anet_common::encryption::Cipher::new(&shared_key));
        let nonce_prefix: [u8; 4] = auth_response.nonce_prefix.as_slice().try_into()?;
        let sequence = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let health_pause = Arc::new(AtomicBool::new(false));

        let (client_stream, internal_router) = tokio::io::duplex(MAX_PACKET_SIZE * 10);
        let (mut tunnel_read, mut tunnel_write) = tokio::io::split(internal_router);
        let (tunnel_packet_tx, mut tunnel_packet_rx) = tokio::sync::mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);

        let tunnel_reader_task = tokio::spawn(async move {
            while let Ok(Some(packet)) = read_next_packet(&mut tunnel_read).await {
                if tunnel_packet_tx.send(packet).await.is_err() { break; }
            }
        });

        let padding_step = self.config.stealth.padding_step;

        let host_ul = host.clone();
        let base_path_ul = base_path.clone();
        let session_id_ul = session_id.clone();
        let profile_ul = profile.clone();
        let cipher_ul = cipher.clone();
        let sequence_ul = sequence.clone();

        tokio::spawn(async move {
            info!("[AHTTP Client Debug] Started Unified XHTTP Traffic Loop using method: {}", uplink_method);
            let traffic_path = format!("{}/traffic?session_id={}", base_path_ul, session_id_ul);
            let mut batch_buf = BytesMut::with_capacity(16384);
            let poll_timeout = Duration::from_millis(50);

            // Инициализируем первое рабочее соединение
            let mut conn = match connect_tls_pinned(resolved_addr, &host_ul, is_tls).await {
                Ok(c) => c,
                Err(e) => {
                    warn!("[AHTTP Client Debug] Initial traffic connection failed: {}", e);
                    return Result::<()>::Err(anyhow::anyhow!("Initial connection failed"));
                }
            };

            loop {
                let packet_opt = tokio::select! {
                    pkt = tunnel_packet_rx.recv() => pkt,
                    _ = tokio::time::sleep(poll_timeout) => None,
                };

                if let Some(packet) = packet_opt {
                    let seq = sequence_ul.fetch_add(1, Ordering::Relaxed);
                    if let Ok(encrypted) = anet_common::transport::wrap_packet_padded(&cipher_ul, &nonce_prefix, seq, packet, padding_step) {
                        anet_common::stream_framing::frame_packet_into(&mut batch_buf, &encrypted);
                    }

                    while batch_buf.len() < 16384 {
                        match tunnel_packet_rx.try_recv() {
                            Ok(p) => {
                                let seq = sequence_ul.fetch_add(1, Ordering::Relaxed);
                                if let Ok(enc) = anet_common::transport::wrap_packet_padded(&cipher_ul, &nonce_prefix, seq, p, padding_step) {
                                    anet_common::stream_framing::frame_packet_into(&mut batch_buf, &enc);
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }

                let payload = batch_buf.split().freeze();
                let mut success = false;
                let mut attempts = 0;

                while attempts < 3 {
                    let req_headers = profile_ul.build_headers(uplink_method, &host_ul, &traffic_path, Some(payload.len()), false);

                    let conn_ref = &mut conn;
                    let exchange_res = async {
                        conn_ref.write_all(req_headers.as_bytes()).await?;
                        conn_ref.write_all(&payload).await?;
                        conn_ref.flush().await?;

                        let mut buf = BytesMut::with_capacity(16384);
                        let mut content_length: Option<usize> = None;
                        let mut is_chunked = false;
                        let mut header_len = 0;

                        // 1. Читаем до конца заголовков
                        loop {
                            let mut temp = [0u8; 4096];
                            let n = conn_ref.read(&mut temp).await?;
                            if n == 0 {
                                return Err(anyhow::anyhow!("Connection closed by server before headers received"));
                            }
                            buf.extend_from_slice(&temp[..n]);

                            let mut headers = [httparse::EMPTY_HEADER; 32];
                            let mut res = Response::new(&mut headers);
                            match res.parse(&buf) {
                                Ok(Status::Complete(len)) => {
                                    if res.code != Some(200) {
                                        return Err(anyhow::anyhow!("Server returned status {:?}", res.code));
                                    }
                                    header_len = len;
                                    for h in res.headers.iter() {
                                        if h.name.eq_ignore_ascii_case("content-length") {
                                            content_length = std::str::from_utf8(h.value).unwrap_or("").parse().ok();
                                        } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
                                            if std::str::from_utf8(h.value).unwrap_or("").contains("chunked") {
                                                is_chunked = true;
                                            }
                                        }
                                    }
                                    break;
                                }
                                Ok(Status::Partial) => continue,
                                Err(e) => return Err(anyhow::anyhow!("Failed to parse response headers: {:?}", e)),
                            }
                        }

                        // 2. Дочитываем тело
                        loop {
                            if let Some(cl) = content_length {
                                if !is_chunked && buf.len() >= header_len + cl {
                                    break;
                                }
                            }
                            let mut temp = [0u8; 4096];
                            let n = conn_ref.read(&mut temp).await?;
                            if n == 0 { break; } // Connection: close или EOF
                            buf.extend_from_slice(&temp[..n]);
                        }

                        let mut body = buf.split_off(header_len);

                        // 3. Распаковываем
                        let mut clean_body = BytesMut::new();
                        if is_chunked {
                            while let Ok(Some(chunk)) = parse_next_http_chunk(&mut body) {
                                clean_body.extend_from_slice(&chunk);
                            }
                        } else {
                            if let Some(cl) = content_length {
                                body.truncate(cl);
                            }
                            clean_body = body;
                        }

                        // 4. Отправляем в TUN
                        if !clean_body.is_empty() {
                            let mut cursor = std::io::Cursor::new(clean_body.freeze());
                            while let Ok(Some(encrypted_packet)) = read_next_packet(&mut cursor).await {
                                if let Ok(decrypted) = anet_common::transport::unwrap_packet_bytes_in_place(&cipher_ul, encrypted_packet) {
                                    let _ = tunnel_write.write_all(&frame_packet(decrypted)).await;
                                }
                            }
                        }

                        Ok(())
                    }.await;

                    if exchange_res.is_ok() {
                        success = true;
                        break;
                    }

                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(50 * attempts)).await;
                    match connect_tls_pinned(resolved_addr, &host_ul, is_tls).await {
                        Ok(new_conn) => {
                            conn = new_conn;
                        }
                        Err(_) => {}
                    }
                }

                if !success {
                    warn!("[AHTTP Client Debug] Traffic exchange transaction failed");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }

                if tunnel_packet_rx.is_closed() {
                    break;
                }
            }

            tunnel_reader_task.abort();
            let _ = tunnel_reader_task.await;
            info!("[AHTTP] Traffic loop exited cleanly.");
            Result::<()>::Ok(())
        });

        info!("[AHTTP] Transport session initialized.");

        Ok(ConnectionResult {
            auth_response,
            vpn_stream: Box::new(client_stream),
            endpoint: None,
            connection: None,
            health_pause: Some(health_pause),
        })
    }
}
