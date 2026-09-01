use super::{ClientTransport, ConnectionResult};
use crate::auth::{AuthChannel, AuthHandler};
use crate::config::{CoreConfig, ServerConfig};
use anet_common::consts::{CHANNEL_BUFFER_SIZE, MAX_PACKET_SIZE};
use anet_common::handshake_fragmentation::FragmentConfig;
use anet_common::http_help::BrowserProfile;
use anet_common::stream_framing::{frame_packet, frame_packet_into, read_next_packet};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use log::{info, warn, debug};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use reqwest::{Client, Method, Url};
use std::net::SocketAddr;
use std::collections::BTreeMap;
use tokio::sync::Mutex;
use anet_common::transport::wrap_packet_padded;

/// Скользящее окно реассемблирования входящих out-of-order пакетов
struct ReassemblyQueue {
    next_seq: u64,
    buffer: BTreeMap<u64, Bytes>,
}

impl ReassemblyQueue {
    fn new() -> Self {
        Self {
            next_seq: 0,
            buffer: BTreeMap::new(),
        }
    }

    async fn insert_and_drain<W: AsyncWriteExt + Unpin>(
        &mut self,
        seq: u64,
        payload: Bytes,
        writer: &mut W,
    ) -> Result<()> {
        if seq < self.next_seq {
            return Ok(()); // Дубликат — игнорируем
        }

        self.buffer.insert(seq, payload);

        // Лимитируем размер буфера для предотвращения утечек памяти при потере пакетов
        if self.buffer.len() > 1024 {
            if let Some(&oldest_seq) = self.buffer.keys().next() {
                self.buffer.remove(&oldest_seq);
                self.next_seq = oldest_seq + 1;
            }
        }

        while let Some(packet) = self.buffer.remove(&self.next_seq) {
            writer.write_all(&frame_packet(packet)).await?;
            self.next_seq += 1;
        }
        Ok(())
    }
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

/// Нативно внедряет маскировку заголовков в запрос reqwest без аллокаций и парсинга строк
fn apply_stealth_headers(
    builder: reqwest::RequestBuilder,
    profile: &BrowserProfile,
    host: &str,
) -> reqwest::RequestBuilder {
    let mut builder = builder
        .header("Host", host)
        .header("User-Agent", profile.user_agent)
        .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
        .header("Accept-Language", profile.accept_language)
        .header("Accept-Encoding", "gzip, deflate, br")
        .header("Connection", "close") // Force Connection: close для CDN
        .header("Sec-Fetch-Dest", "document")
        .header("Sec-Fetch-Mode", "navigate")
        .header("Sec-Fetch-Site", "none")
        .header("Cache-Control", "no-cache")
        .header("Pragma", "no-cache");

    if let Some(index) = profile.chrome_profile {
        use anet_common::http_help::{CHROME_BRANDS, CHROME_PLATFORMS};
        builder = builder
            .header("sec-ch-ua", CHROME_BRANDS[index])
            .header("sec-ch-ua-mobile", "?0")
            .header("sec-ch-ua-platform", CHROME_PLATFORMS[index]);
    }
    builder
}

struct AHttpAuthChannel {
    client: Client,
    base_url: String,
    profile: BrowserProfile,
    is_auth_phase: Mutex<bool>,
    pending_response: Mutex<Option<Bytes>>,
    handshake_path: String,
    auth_path: String,
}

#[async_trait]
impl AuthChannel for AHttpAuthChannel {
    async fn send(&self, data: Bytes, _frag: &FragmentConfig) -> Result<()> {
        let mut is_auth = self.is_auth_phase.lock().await;
        let req_path = if !*is_auth {
            *is_auth = true;
            format!("{}{}", self.base_url, self.handshake_path)
        } else {
            format!("{}{}", self.base_url, self.auth_path)
        };

        // Извлекаем Host из целевого URL
        let parsed_url = Url::parse(&req_path)?;
        let host = parsed_url.host_str().unwrap_or("");

        let mut req = self.client.post(&req_path);
        req = apply_stealth_headers(req, &self.profile, host);

        let resp = req.body(data.to_vec()).send().await?;

        if !resp.status().is_success() {
            bail!("Server returned HTTP {}", resp.status());
        }

        let body = resp.bytes().await?;
        *self.pending_response.lock().await = Some(body);
        Ok(())
    }

    async fn recv(&self, _timeout: Duration) -> Result<Bytes> {
        let mut pending = self.pending_response.lock().await;
        if let Some(body) = pending.take() {
            Ok(body)
        } else {
            bail!("No pending response from server");
        }
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

    /// Резолвит домен напрямую через нативный системный резолвер ОС (getaddrinfo),
    /// гарантируя идеальное совпадение IP с BYPASS-маршрутами ядра.
    async fn resolve_host(&self, host: &str, port: u16) -> Result<SocketAddr> {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }

        let addrs = tokio::net::lookup_host(format!("{}:{}", host, port)).await
            .context(format!("Failed to resolve DNS for {}:{}", host, port))?;

        let addr = addrs.into_iter().next().context("No IP addresses found")?;
        Ok(addr)
    }
}

#[async_trait]
impl ClientTransport for AHttpTransport {
    async fn connect(&self) -> Result<ConnectionResult> {
        let profile = BrowserProfile::random();

        // 1. Парсинг DSN
        let dsn_url = Url::parse(&self.server.dsn)?;
        let scheme = dsn_url.scheme();
        let target_host = dsn_url.host_str().context("No host in DSN")?.to_string();
        let port = dsn_url.port_or_known_default().unwrap_or(if scheme == "https" { 443 } else { 80 });
        let mut base_url = format!("{}://{}{}", scheme, target_host, dsn_url.path());

        // Убираем слэш на конце, если он есть
        if base_url.ends_with('/') {
            base_url.pop();
        }

        let mut uplink_method_str = "POST".to_string();
        for (k, v) in dsn_url.query_pairs() {
            if k == "method" { uplink_method_str = v.into_owned(); }
        }
        let uplink_method = Method::from_bytes(uplink_method_str.as_bytes()).unwrap_or(Method::POST);

        // 2. DNS PINNING: Резолвим физический IP
        let resolved_addr = self.resolve_host(&target_host, port).await?;
        info!("[AHTTP] Initializing XHTTP engine to {} (Pinned IP: {})", base_url, resolved_addr);

        // Настраиваем reqwest с жестким биндингом домена к IP
        let mut builder = Client::builder()
            .resolve(&target_host, resolved_addr)
            .danger_accept_invalid_certs(true)
            .pool_max_idle_per_host(self.config.ahttp.pool_max_idle_per_host)
            .pool_idle_timeout(Some(Duration::from_secs(self.config.ahttp.pool_idle_timeout_secs)))
            .tcp_nodelay(self.config.ahttp.tcp_nodelay)
            .timeout(Duration::from_secs(self.config.ahttp.timeout_secs))
            // 4. Применяем новые H2 оптимизации из конфигурационного файла
            .http2_adaptive_window(self.config.ahttp.http2_adaptive_window);

        if let Some(max_frame) = self.config.ahttp.http2_max_frame_size {
            builder = builder.http2_max_frame_size(max_frame);
        }

        if let Some(max_header) = self.config.ahttp.http2_max_header_list_size {
            builder = builder.http2_max_header_list_size(max_header);
        }

        if let Some(ka_interval) = self.config.ahttp.http2_keep_alive_interval_secs {
            builder = builder.http2_keep_alive_interval(Some(Duration::from_secs(ka_interval)));

            if let Some(ka_timeout) = self.config.ahttp.http2_keep_alive_timeout_secs {
                builder = builder.http2_keep_alive_timeout(Duration::from_secs(ka_timeout));
            }

            builder = builder.http2_keep_alive_while_idle(self.config.ahttp.http2_keep_alive_while_idle);
        }

        let http_client = builder.build();
        let http_client = match  http_client {
            Ok(http_client) => http_client,
            Err(e) => bail!("Cannot build a HTTP client: {}", e),
        };

        // 3. Авторизация
        let auth_channel = AHttpAuthChannel {
            client: http_client.clone(),
            base_url: base_url.clone(),
            profile: profile.clone(),
            is_auth_phase: Mutex::new(false),
            pending_response: Mutex::new(None),
            handshake_path: self.config.ahttp.handshake_path.clone(),
            auth_path: self.config.ahttp.auth_path.clone(),
        };

        let auth = AuthHandler::new(&self.config, self.server.server_pub_key.as_deref())?;
        let (auth_response, shared_key) = auth.authenticate_once(&auth_channel).await?;

        let session_id = auth_response.session_id.clone();
        let cipher = Arc::new(anet_common::encryption::Cipher::new(&shared_key));
        let nonce_prefix: [u8; 4] = auth_response.nonce_prefix.as_slice().try_into()?;
        let sequence = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let health_pause = Arc::new(AtomicBool::new(false));

        let (client_stream, internal_router) = tokio::io::duplex(MAX_PACKET_SIZE * 10);
        let (mut tunnel_read, tunnel_write) = tokio::io::split(internal_router);
        let (tunnel_packet_tx, mut tunnel_packet_rx) = tokio::sync::mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);

        let tunnel_reader_task = tokio::spawn(async move {
            while let Ok(Some(packet)) = read_next_packet(&mut tunnel_read).await {
                if tunnel_packet_tx.send(packet).await.is_err() { break; }
            }
        });

        let padding_step = self.config.stealth.padding_step;
        let config_ahttp = self.config.ahttp.clone();

        // Клонируем переменные для изолированного фонового воркера
        let host_ul = target_host.clone();
        let profile_ul = profile.clone();
        let cipher_ul = cipher.clone();

        // Инициализируем потокобезопасную очередь реассемблирования входящих пакетов
        let rx_reassembler = Arc::new(Mutex::new(ReassemblyQueue::new()));
        // Семафор для ограничения числа одновременных запросов в CDN
        let concurrency_semaphore = Arc::new(tokio::sync::Semaphore::new(config_ahttp.concurrency));
        let tunnel_write_mutex = Arc::new(Mutex::new(tunnel_write));

        tokio::spawn(async move {
            info!("[AHTTP Client] Started Stateless Packet-Exchange Loop (Method: {})", uplink_method_str);
            let traffic_url = format!("{}{}?session_id={}", base_url, config_ahttp.traffic_path, session_id);
            // Коалесцируем до объёма, заданного в конфиге
            let mut batch_buf = BytesMut::with_capacity(config_ahttp.coalesce_budget_bytes);
            // Ждем максимум миллисекунд, заданных в конфиге
            let poll_timeout = Duration::from_millis(config_ahttp.poll_timeout_ms);

            loop {
                // Ждем пакет из TUN или срабатывает тайм-аут для отправки пустого полла
                let packet_opt = tokio::select! {
                    pkt = tunnel_packet_rx.recv() => pkt,
                    _ = tokio::time::sleep(poll_timeout) => None,
                };

                let mut tx_pkts_count = 0;

                if let Some(packet) = packet_opt {
                    let seq = sequence.fetch_add(1, Ordering::Relaxed);
                    if let Ok(encrypted) = wrap_packet_padded(&cipher_ul, &nonce_prefix, seq, packet, padding_step) {
                        frame_packet_into(&mut batch_buf, &encrypted);
                        tx_pkts_count += 1;
                    }

                    // Пакетная коалесценция на основе лимита из конфига
                    while batch_buf.len() < config_ahttp.coalesce_budget_bytes {
                        match tunnel_packet_rx.try_recv() {
                            Ok(p) => {
                                let seq = sequence.fetch_add(1, Ordering::Relaxed);
                                if let Ok(enc) = wrap_packet_padded(&cipher_ul, &nonce_prefix, seq, p, padding_step) {
                                    frame_packet_into(&mut batch_buf, &enc);
                                    tx_pkts_count += 1;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }

                let payload = batch_buf.split().freeze();

                // Ограничиваем уровень конкурентности перед запуском асинхронной задачи отправки
                let permit = match concurrency_semaphore.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };

                // Клонируем переменные для отправки в фоновом пуле задач
                let http_client_clone = http_client.clone();
                let uplink_method_clone = uplink_method.clone();
                let traffic_url_clone = traffic_url.clone();
                let profile_ul_clone = profile_ul.clone();
                let host_ul_clone = host_ul.clone();
                let cipher_ul_clone = cipher_ul.clone();
                let rx_reassembler_clone = rx_reassembler.clone();
                let tunnel_write_clone = tunnel_write_mutex.clone();

                tokio::spawn(async move {
                    let mut success = false;
                    let mut attempts = 0;

                    if !payload.is_empty() {
                        debug!("[AHTTP Client] >>> Sending {} bytes ({} packets)", payload.len(), tx_pkts_count);
                    }

                    while attempts < 3 {
                        // Генерируем полную HTTP-сигнатуру маскировки
                        let mut req = http_client_clone.request(uplink_method_clone.clone(), &traffic_url_clone);
                        req = apply_stealth_headers(req, &profile_ul_clone, &host_ul_clone);

                        let res = req.body(payload.to_vec()).send().await;

                        match res {
                            Ok(resp) if resp.status().is_success() => {
                                if let Ok(body) = resp.bytes().await {
                                    if !body.is_empty() {
                                        debug!("[AHTTP Client] <<< Received {} bytes", body.len());
                                        let mut cursor = std::io::Cursor::new(body);
                                        let mut rx_pkts_count = 0;

                                        // Блокируем дерево реассемблирования перед записью
                                        let mut reassembler = rx_reassembler_clone.lock().await;
                                        let mut tunnel_write_guard = tunnel_write_clone.lock().await;

                                        while let Ok(Some(encrypted_packet)) = read_next_packet(&mut cursor).await {
                                            if let Ok((seq, decrypted)) = unwrap_packet_with_seq(&cipher_ul_clone, encrypted_packet) {
                                                rx_pkts_count += 1;
                                                // Пропускаем пакет через скользящее окно упорядочивания
                                                let _ = reassembler.insert_and_drain(seq, decrypted, &mut *tunnel_write_guard).await;
                                            }
                                        }
                                        debug!("[AHTTP Client] <<< Unpacked {} valid packets", rx_pkts_count);
                                    }
                                    success = true;
                                    break;
                                }
                            }
                            Ok(resp) => { warn!("[AHTTP Client] CDN returned HTTP {}", resp.status()); }
                            Err(e) => { warn!("[AHTTP Client] Request failed: {}", e); }
                        }

                        attempts += 1;
                        tokio::time::sleep(Duration::from_millis(100 * attempts)).await;
                    }

                    if !success {
                        warn!("[AHTTP Client] Traffic exchange transaction failed.");
                    }

                    // Освобождаем слот семафора
                    drop(permit);
                });

                if tunnel_packet_rx.is_closed() { break; }
            }

            tunnel_reader_task.abort();
            let _ = tunnel_reader_task.await;
            info!("[AHTTP] Traffic loop exited cleanly.");
        });

        info!("[AHTTP] Transport session initialized.");

        // КРИТИЧНО: Возвращаем оригинальный AuthResponse, не ломая шлюз виртуального туннеля!
        Ok(ConnectionResult {
            auth_response, // Чистый и нетронутый
            vpn_stream: Box::new(client_stream),
            endpoint: None,
            connection: None,
            health_pause: Some(health_pause),
        })
    }
}
