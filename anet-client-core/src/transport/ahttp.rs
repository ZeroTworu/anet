use super::{ClientTransport, ConnectionResult};
use crate::auth::{AuthChannel, AuthHandler};
use crate::config::{CoreConfig, ServerConfig};
use anet_common::handshake_fragmentation::FragmentConfig;
use anet_common::http_help::BrowserProfile;
use anet_common::reassembly::ReassemblyQueue;
use anet_common::stream_framing::{frame_packet_into, read_next_packet};
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
use tokio::sync::Mutex;
use anet_common::transport::wrap_packet_padded;

fn unwrap_packet_with_seq(cipher: &anet_common::encryption::Cipher, raw_packet: Bytes) -> Result<(u64, Bytes)> {
    let mut buffer = raw_packet
        .try_into_mut()
        .map_err(|_| anyhow::anyhow!("Encrypted packet buffer is unexpectedly shared"))?;

    if buffer.len() < 12 + 16 {
        bail!("Packet too short");
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

struct AHttpAuthChannel {
    client: Client,
    base_url: String,
    origin: String,
    referer: String,
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

        let req = self.client.post(&req_path).header("Accept", "*/*");
        let req = self
            .profile
            .apply_to_reqwest(req, Some(&self.origin), Some(&self.referer));

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

        let dsn_url = Url::parse(&self.server.dsn)?;
        let scheme = dsn_url.scheme();
        let target_host = dsn_url.host_str().context("No host in DSN")?.to_string();
        let port = dsn_url.port_or_known_default().unwrap_or(if scheme == "https" { 443 } else { 80 });
        let mut base_url = format!("{}://{}{}", scheme, target_host, dsn_url.path());

        if base_url.ends_with('/') {
            base_url.pop();
        }

        let mut uplink_method_str = "POST".to_string();
        for (k, v) in dsn_url.query_pairs() {
            if k == "method" { uplink_method_str = v.into_owned(); }
        }
        let uplink_method = Method::from_bytes(uplink_method_str.as_bytes()).unwrap_or(Method::POST);

        let resolved_addr = self.resolve_host(&target_host, port).await?;
        info!("[AHTTP] Initializing XHTTP engine to {} (Pinned IP: {})", base_url, resolved_addr);

        let build_http_client = || -> Result<Client> {
            let mut builder = Client::builder()
                .resolve(&target_host, resolved_addr)
                .danger_accept_invalid_certs(true)
                .pool_max_idle_per_host(self.config.ahttp.pool_max_idle_per_host.max(2))
                .pool_idle_timeout(Some(Duration::from_secs(self.config.ahttp.pool_idle_timeout_secs)))
                .tcp_nodelay(self.config.ahttp.tcp_nodelay)
                .timeout(Duration::from_secs(self.config.ahttp.timeout_secs))
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

            builder.build().map_err(|e| anyhow::anyhow!("Cannot build a HTTP client: {}", e))
        };

        // Компактный Round-Robin пул из 1..4 HTTP/2 клиентов:
        // Все соединения равномерно прокачиваются фоновыми poll-запросами (не остывают и не теряют cwnd),
        // а внутри каждого соединения запросы мультиплексируются по HTTP/2 потокам.
        let pool_size = self.config.ahttp.concurrency.clamp(1, 4);
        let mut client_pool_vec = Vec::with_capacity(pool_size);
        for _ in 0..pool_size {
            client_pool_vec.push(build_http_client()?);
        }
        let primary_http_client = client_pool_vec[0].clone();
        let client_pool = Arc::new(client_pool_vec);

        let origin = format!("{}://{}", scheme, target_host);
        let referer = format!("{}/", base_url);

        let auth_channel = AHttpAuthChannel {
            client: primary_http_client.clone(),
            base_url: base_url.clone(),
            origin: origin.clone(),
            referer: referer.clone(),
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

        // Умеренный размер буферов (512 КБ duplex + 128 пакетов канал) предотвращает
        // 15-мегабайтный Bufferbloat и скачки пинга до 500+ мс при активной выгрузке (Upload).
        let (client_stream, internal_router) = tokio::io::duplex(512 * 1024);
        let (mut tunnel_read, tunnel_write) = tokio::io::split(internal_router);
        let (tunnel_packet_tx, mut tunnel_packet_rx) = tokio::sync::mpsc::channel::<Bytes>(128);

        let tunnel_reader_task = tokio::spawn(async move {
            while let Ok(Some(packet)) = read_next_packet(&mut tunnel_read).await {
                if tunnel_packet_tx.send(packet).await.is_err() { break; }
            }
        });

        let padding_step = self.config.stealth.padding_step;
        let config_ahttp = self.config.ahttp.clone();

        let origin_ul = origin;
        let referer_ul = referer;
        let profile_ul = profile.clone();
        let cipher_ul = cipher.clone();

        let rx_reassembler = Arc::new(Mutex::new(ReassemblyQueue::new(config_ahttp.reassembly_queue_max_size)));
        let concurrency_semaphore = Arc::new(tokio::sync::Semaphore::new(config_ahttp.concurrency));
        let tunnel_write_mutex = Arc::new(Mutex::new(tunnel_write));
        let downlink_notify = Arc::new(tokio::sync::Notify::new());
        let downlink_credits = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        tokio::spawn(async move {
            info!(
                "[AHTTP Client] Started Stateless Packet-Exchange Loop (Method: {}, TCP Pool: {}, Concurrency: {})",
                uplink_method_str, pool_size, config_ahttp.concurrency
            );
            let traffic_url = format!("{}{}?session_id={}", base_url, config_ahttp.traffic_path, session_id);
            // В HTTP/2 стартовое окно потока/соединения (RFC 7540 / Nginx) равно 65535 байт.
            // Ограничиваем один uplink-батч до 48 КБ (49152 байт), чтобы POST-запрос гарантированно
            // уходил за один RTT без паузы на ожидание WINDOW_UPDATE от Nginx.
            let uplink_budget_bytes = config_ahttp.coalesce_budget_bytes.min(49152);
            let mut batch_buf = BytesMut::with_capacity(uplink_budget_bytes + 2048);
            let poll_timeout = Duration::from_millis(config_ahttp.poll_timeout_ms);
            let micro_coalesce = Duration::from_micros(500);
            let mut rr_counter: usize = 0;

            loop {
                let has_poll_credit = downlink_credits.load(Ordering::Acquire) > 0
                    && concurrency_semaphore.available_permits() > 0;

                // 1. Ждем первый пакет, сигнал активного Downlink (self-clocking) ИЛИ таймаут пуллинга
                let (first_packet_opt, is_poll_wakeup) = if has_poll_credit {
                    let _ = downlink_credits.fetch_update(Ordering::AcqRel, Ordering::Acquire, |c| {
                        Some(c.saturating_sub(1))
                    });
                    (tunnel_packet_rx.try_recv().ok(), true)
                } else {
                    tokio::select! {
                        pkt = tunnel_packet_rx.recv() => {
                            match pkt {
                                Some(p) => (Some(p), false),
                                None => break, // Канал закрыт
                            }
                        }
                        _ = downlink_notify.notified() => {
                            let _ = downlink_credits.fetch_update(Ordering::AcqRel, Ordering::Acquire, |c| {
                                Some(c.saturating_sub(1))
                            });
                            (tunnel_packet_rx.try_recv().ok(), true)
                        }
                        _ = tokio::time::sleep(poll_timeout) => (None, true),
                    }
                };

                // 2. Если это холостой poll-таймаут, а свободных слотов concurrency нет —
                // не блокируемся в очереди за пермитом ради пустого запроса.
                let permit = if first_packet_opt.is_none() {
                    match concurrency_semaphore.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => continue,
                    }
                } else {
                    // Для реального трафика захватываем пермит ДО выгребания очереди!
                    match concurrency_semaphore.clone().acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => break,
                    }
                };

                let mut tx_pkts_count = 0;

                let first_pkt = match first_packet_opt {
                    Some(p) => Some(p),
                    None => tunnel_packet_rx.try_recv().ok(),
                };

                if let Some(packet) = first_pkt {
                    let seq = sequence.fetch_add(1, Ordering::Relaxed);
                    if let Ok(encrypted) = wrap_packet_padded(&cipher_ul, &nonce_prefix, seq, packet, padding_step) {
                        frame_packet_into(&mut batch_buf, &encrypted);
                        tx_pkts_count += 1;
                    }

                    // Выгребаем все уже накопившиеся в канале пакеты, не превышая 48 КБ
                    while batch_buf.len() + 1600 <= uplink_budget_bytes {
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

                    // Микро-коалесценция (до 0.5 мс) ТОЛЬКО для тяжелого Upload-трафика (>= 256 байт)
                    // и когда это НЕ форсированный Downlink-опрос. Одиночные TCP ACK (52 байта)
                    // и пинги уходят мгновенно (0 мкс), не задерживая раскрутку параллельных Download-слотов.
                    if !is_poll_wakeup && batch_buf.len() >= 256 && batch_buf.len() < uplink_budget_bytes / 2 {
                        let deadline = tokio::time::Instant::now() + micro_coalesce;
                        while batch_buf.len() + 1600 <= uplink_budget_bytes {
                            match tokio::time::timeout_at(deadline, tunnel_packet_rx.recv()).await {
                                Ok(Some(p)) => {
                                    let seq = sequence.fetch_add(1, Ordering::Relaxed);
                                    if let Ok(enc) = wrap_packet_padded(&cipher_ul, &nonce_prefix, seq, p, padding_step) {
                                        frame_packet_into(&mut batch_buf, &enc);
                                        tx_pkts_count += 1;
                                    }
                                    while batch_buf.len() + 1600 <= uplink_budget_bytes {
                                        match tunnel_packet_rx.try_recv() {
                                            Ok(next_p) => {
                                                let seq = sequence.fetch_add(1, Ordering::Relaxed);
                                                if let Ok(enc) = wrap_packet_padded(&cipher_ul, &nonce_prefix, seq, next_p, padding_step) {
                                                    frame_packet_into(&mut batch_buf, &enc);
                                                    tx_pkts_count += 1;
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

                let payload = batch_buf.split().freeze();
                batch_buf.reserve(uplink_budget_bytes + 2048);

                let worker_client = client_pool[rr_counter % pool_size].clone();
                rr_counter = rr_counter.wrapping_add(1);
                let uplink_method_clone = uplink_method.clone();
                let traffic_url_clone = traffic_url.clone();
                let profile_ul_clone = profile_ul.clone();
                let origin_ul_clone = origin_ul.clone();
                let referer_ul_clone = referer_ul.clone();
                let cipher_ul_clone = cipher_ul.clone();
                let rx_reassembler_clone = rx_reassembler.clone();
                let tunnel_write_clone = tunnel_write_mutex.clone();
                let downlink_notify_clone = downlink_notify.clone();
                let downlink_credits_clone = downlink_credits.clone();
                let max_concurrency = config_ahttp.concurrency;

                tokio::spawn(async move {
                    let mut success = false;
                    let mut attempts = 0;
                    let mut rx_bytes_total = 0usize;
                    let mut rx_pkts_total = 0usize;

                    if !payload.is_empty() {
                        debug!("[AHTTP Client] >>> Sending {} bytes ({} packets)", payload.len(), tx_pkts_count);
                    }

                    // Seamless Reconnect: Повторяем до 5 раз при обрывах со стороны CDN
                    while attempts < 5 {
                        let req = worker_client
                            .request(uplink_method_clone.clone(), &traffic_url_clone)
                            .header("Accept", "*/*");
                        let req = profile_ul_clone.apply_to_reqwest(
                            req,
                            Some(&origin_ul_clone),
                            Some(&referer_ul_clone),
                        );

                        // Передаем payload.clone() — zero-copy для Bytes
                        let res = req.body(reqwest::Body::from(payload.clone())).send().await;

                        match res {
                            Ok(resp) if resp.status().is_success() => {
                                if let Ok(body) = resp.bytes().await {
                                    if !body.is_empty() {
                                        rx_bytes_total = body.len();
                                        debug!("[AHTTP Client] <<< Received {} bytes", rx_bytes_total);
                                        let mut cursor = std::io::Cursor::new(body);
                                        let mut unpacked_batch = Vec::with_capacity(64);

                                        // 1. Дешифруем все пакеты ответа БЕЗ удержания мьютексов
                                        while let Ok(Some(encrypted_packet)) = read_next_packet(&mut cursor).await {
                                            if let Ok((seq, decrypted)) = unwrap_packet_with_seq(&cipher_ul_clone, encrypted_packet) {
                                                unpacked_batch.push((seq, decrypted));
                                            }
                                        }

                                        let rx_pkts_count = unpacked_batch.len();
                                        rx_pkts_total = rx_pkts_count;
                                        if rx_pkts_count > 0 {
                                            // 2. Один раз берем лок сборщика и вставляем весь батч
                                            let ready_packets = {
                                                let mut reassembler = rx_reassembler_clone.lock().await;
                                                reassembler.insert_batch(unpacked_batch)
                                            };

                                            // 3. Собираем готовые пакеты в единый буфер и пишем в туннель за ОДИН вызов write_all
                                            if !ready_packets.is_empty() {
                                                let mut out_buf = BytesMut::with_capacity(ready_packets.len() * 1500);
                                                for packet in ready_packets {
                                                    frame_packet_into(&mut out_buf, &packet);
                                                }
                                                let mut tunnel_write_guard = tunnel_write_clone.lock().await;
                                                if tunnel_write_guard.write_all(&out_buf).await.is_err() {
                                                    warn!("[AHTTP Client] Tunnel stream closed, discarding remaining packets.");
                                                }
                                            }
                                        }
                                        debug!("[AHTTP Client] <<< Unpacked {} valid packets", rx_pkts_count);
                                    }
                                }
                                success = true;
                                break;
                            }
                            Ok(resp) => {
                                warn!("[AHTTP Client] CDN returned HTTP {}", resp.status());
                                if resp.status() == reqwest::StatusCode::UNAUTHORIZED || resp.status() == reqwest::StatusCode::NOT_FOUND {
                                    break;
                                }
                            }
                            Err(e) => {
                                debug!("[AHTTP Client] Request failed: {}", e);
                            }
                        }

                        attempts += 1;
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }

                    if !success && !payload.is_empty() {
                        warn!("[AHTTP Client] Traffic exchange transaction failed after retries. Payload dropped.");
                    }

                    drop(permit);

                    // Downlink Self-Clocking: если сервер прислал данные, немедленно (без ожидания poll_timeout_ms)
                    // будим диспетчер для отправки следующего запроса; при получении полного пакета (>= 1300 байт)
                    // или 2+ пакетов — агрессивно наращиваем число параллельных poll-запросов до max_concurrency.
                    if rx_pkts_total > 0 {
                        if rx_bytes_total >= 1300 || rx_pkts_total >= 2 {
                            let _ = downlink_credits_clone.fetch_update(Ordering::AcqRel, Ordering::Acquire, |c| {
                                Some((c + 3).min(max_concurrency))
                            });
                        } else {
                            let _ = downlink_credits_clone.fetch_max(1, Ordering::AcqRel);
                        }
                        downlink_notify_clone.notify_one();
                    }
                });

                if tunnel_packet_rx.is_closed() { break; }
            }

            tunnel_reader_task.abort();
            let _ = tunnel_reader_task.await;
            info!("[AHTTP] Traffic loop exited cleanly.");
        });

        info!("[AHTTP] Transport session initialized.");

        Ok(ConnectionResult {
            auth_response,
            vpn_stream: Box::new(client_stream),
            endpoint: None,
            connection: None,
            health_pause: Some(health_pause),
            remote_ip: Some(resolved_addr.ip()),
            bypass_ips: Vec::new(),
            effective_mode: None,
            shutdown_hook: None,
        })
    }
}
