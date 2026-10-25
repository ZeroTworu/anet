use super::{ClientTransport, ConnectionResult};
use crate::auth::{AuthChannel, AuthHandler};
use crate::config::{CoreConfig, ServerConfig};
use anet_common::astp_lite::AstpLiteCipher;
use anet_common::base32;
use anet_common::consts::CHANNEL_BUFFER_SIZE;
use anet_common::dns_proto::{build_doh_query, parse_dns_txt_response};
use anet_common::doh_chunking::{calculate_max_chunk_payload, split_into_chunks};
use anet_common::handshake_fragmentation::FragmentConfig;
use anet_common::stream_framing::{frame_packet_into, read_next_packet};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use bytes::{Bytes, BytesMut};
use log::{debug, info, warn};
use reqwest::{Client, Url};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, Semaphore};

const RESOLVER_COOLDOWN_MS: u64 = 2_000;

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

struct ResolverPool {
    urls: Vec<String>,
    cooldown_until_ms: Vec<AtomicU64>,
    cursor: AtomicUsize,
}

impl ResolverPool {
    fn new(urls: Vec<String>) -> Self {
        let cooldown_until_ms = urls.iter().map(|_| AtomicU64::new(0)).collect();
        Self {
            urls,
            cooldown_until_ms,
            cursor: AtomicUsize::new(0),
        }
    }

    fn len(&self) -> usize {
        self.urls.len()
    }

    /// Selects the next healthy resolver (skipping resolvers currently in cooldown).
    fn next_healthy(&self) -> (usize, &str) {
        let n = self.urls.len();
        let now = now_epoch_ms();
        let start = self.cursor.fetch_add(1, Ordering::Relaxed);

        for offset in 0..n {
            let idx = (start + offset) % n;
            let until = self.cooldown_until_ms[idx].load(Ordering::Relaxed);
            if now >= until {
                return (idx, &self.urls[idx]);
            }
        }

        // All resolvers are in cooldown: pick the one whose cooldown expires soonest
        let mut best_idx = start % n;
        let mut best_until = u64::MAX;
        for idx in 0..n {
            let until = self.cooldown_until_ms[idx].load(Ordering::Relaxed);
            if until < best_until {
                best_until = until;
                best_idx = idx;
            }
        }
        (best_idx, &self.urls[best_idx])
    }

    fn mark_failed(&self, idx: usize) {
        let until = now_epoch_ms() + RESOLVER_COOLDOWN_MS;
        self.cooldown_until_ms[idx].store(until, Ordering::Relaxed);
    }

    fn mark_success(&self, idx: usize) {
        self.cooldown_until_ms[idx].store(0, Ordering::Relaxed);
    }

    /// Sends a DoH DNS wire query, checking DNS RCODE and automatically retrying on alternative healthy resolvers if one fails.
    async fn send_query_reliable(&self, client: &Client, query_bytes: &[u8]) -> Result<Bytes> {
        let max_attempts = self.urls.len().max(2);
        let mut last_err = None;

        for _ in 0..max_attempts {
            let (idx, resolver_url) = self.next_healthy();
            let req = client
                .post(resolver_url)
                .header("Content-Type", "application/dns-message")
                .header("Accept", "application/dns-message")
                .body(query_bytes.to_vec());

            match req.send().await {
                Ok(res) if res.status().is_success() => {
                    match res.bytes().await {
                        Ok(body) => {
                            if body.len() >= 12 {
                                let rcode = u16::from_be_bytes([body[2], body[3]]) & 0x000F;
                                if rcode == 0 {
                                    self.mark_success(idx);
                                    return Ok(body);
                                } else {
                                    self.mark_failed(idx);
                                    debug!(
                                        "[DoH] Resolver {} returned DNS RCODE {} (cooldown {}s)",
                                        resolver_url,
                                        rcode,
                                        RESOLVER_COOLDOWN_MS / 1000
                                    );
                                    last_err = Some(anyhow::anyhow!("Resolver {} DNS RCODE {}", resolver_url, rcode));
                                }
                            } else {
                                self.mark_failed(idx);
                                last_err = Some(anyhow::anyhow!("Resolver {} short DNS body", resolver_url));
                            }
                        }
                        Err(e) => {
                            self.mark_failed(idx);
                            debug!("[DoH] Resolver {} body read error (cooldown {}s): {}", resolver_url, RESOLVER_COOLDOWN_MS / 1000, e);
                            last_err = Some(anyhow::Error::from(e));
                        }
                    }
                }
                Ok(res) => {
                    self.mark_failed(idx);
                    debug!(
                        "[DoH] Resolver {} returned HTTP {} (cooldown {}s)",
                        resolver_url,
                        res.status(),
                        RESOLVER_COOLDOWN_MS / 1000
                    );
                    last_err = Some(anyhow::anyhow!("Resolver {} HTTP {}", resolver_url, res.status()));
                }
                Err(e) => {
                    self.mark_failed(idx);
                    debug!(
                        "[DoH] Resolver {} failed (cooldown {}s): {}",
                        resolver_url,
                        RESOLVER_COOLDOWN_MS / 1000,
                        e
                    );
                    last_err = Some(anyhow::Error::from(e));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("All DoH resolvers failed")))
    }
}

struct DohAuthChannel {
    client: Client,
    pool: Arc<ResolverPool>,
    domain_zone: String,
    temp_session_id: u32,
    hs_seq: AtomicU32,
    max_payload: usize,
    pending_response: Mutex<Option<Bytes>>,
    dup_hs: bool,
}

#[async_trait]
impl AuthChannel for DohAuthChannel {
    async fn send(&self, data: Bytes, _frag: &FragmentConfig) -> Result<()> {
        *self.pending_response.lock().await = None;
        let seq = self.hs_seq.fetch_add(1, Ordering::Relaxed);
        let chunks = split_into_chunks(self.temp_session_id, seq, &data, self.max_payload);
        if chunks.is_empty() {
            bail!("Empty handshake payload");
        }

        let total = chunks.len();
        for (idx, chunk) in chunks.into_iter().enumerate() {
            let b32_str = base32::encode(&chunk);
            let labels = base32::split_into_labels(&b32_str, 63);
            let qname = format!(
                "hs.{:08x}.{}.{}.{}.{}",
                self.temp_session_id, idx, total, labels, self.domain_zone
            );

            let query_bytes = build_doh_query(&qname, rand::random::<u16>());

            match self.pool.send_query_reliable(&self.client, &query_bytes).await {
                Ok(body) => {
                    if let Some(txt_data) = parse_dns_txt_response(&body) {
                        if txt_data != b"ACK" && txt_data != b"OK" {
                            if let Ok(decoded) = BASE64_STANDARD.decode(&txt_data) {
                                if !decoded.is_empty() {
                                    *self.pending_response.lock().await = Some(Bytes::from(decoded));
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("[DoH Auth] All resolvers failed for handshake chunk {}/{}: {}", idx + 1, total, e);
                }
            }

            // If duplicate handshake is enabled and there are multiple resolvers, send a backup copy via another healthy resolver
            if self.dup_hs && self.pool.len() > 1 && self.pending_response.lock().await.is_none() {
                let (_, alt_resolver_str) = self.pool.next_healthy();
                let alt_resolver = alt_resolver_str.to_string();
                let alt_client = self.client.clone();
                let alt_query = query_bytes.clone();
                tokio::spawn(async move {
                    let _ = alt_client
                        .post(&alt_resolver)
                        .header("Content-Type", "application/dns-message")
                        .header("Accept", "application/dns-message")
                        .body(alt_query)
                        .send()
                        .await;
                });
            }
        }

        Ok(())
    }

    async fn recv(&self, timeout: Duration) -> Result<Bytes> {
        let deadline = tokio::time::Instant::now() + timeout;

        // Check if response was already piggybacked in the last TXT answer
        if let Some(resp) = self.pending_response.lock().await.take() {
            return Ok(resp);
        }

        // Otherwise poll for handshake completion
        while tokio::time::Instant::now() < deadline {
            let nonce = rand::random::<u32>();
            let qname = format!("poll.{:08x}.{:08x}.{}", self.temp_session_id, nonce, self.domain_zone);
            let query_bytes = build_doh_query(&qname, rand::random::<u16>());

            if let Ok(body) = self.pool.send_query_reliable(&self.client, &query_bytes).await {
                if let Some(txt_data) = parse_dns_txt_response(&body) {
                    if txt_data != b"ACK" && txt_data != b"OK" {
                        if let Ok(decoded) = BASE64_STANDARD.decode(&txt_data) {
                            if !decoded.is_empty() {
                                return Ok(Bytes::from(decoded));
                            }
                        }
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        bail!("Handshake receive timed out over DoH")
    }
}

pub struct DohTransport {
    config: CoreConfig,
    server: ServerConfig,
}

impl DohTransport {
    pub fn new(config: CoreConfig, server: ServerConfig) -> Self {
        Self { config, server }
    }
}

#[async_trait]
impl ClientTransport for DohTransport {
    async fn connect(&self) -> Result<ConnectionResult> {
        let dsn_url = Url::parse(&self.server.dsn).context("Failed to parse DoH DSN")?;
        let domain_zone = dsn_url.host_str().context("No domain zone in DoH DSN")?.to_string();

        let mut resolvers = Vec::new();
        let mut arq_enabled = true;
        let mut dup_hs = true;
        let mut hold_ms = 1200u64;

        for (k, v) in dsn_url.query_pairs() {
            match k.as_ref() {
                "resolver" => resolvers.push(v.into_owned()),
                "arq" => arq_enabled = v.parse().unwrap_or(true),
                "dup_hs" => dup_hs = v.parse().unwrap_or(true),
                "hold_ms" => hold_ms = v.parse().unwrap_or(1200),
                _ => {}
            }
        }

        // Default independent DoH resolvers (RU-friendly: Yandex and AdGuard)
        if resolvers.is_empty() {
            resolvers.push("https://77.88.8.7/dns-query".to_string());
            resolvers.push("https://dns.adguard-dns.com/dns-query".to_string());
        }

        info!(
            "[DoH] Initializing transport for domain '{}' via {} resolvers (ARQ: {}, Hold: {}ms)",
            domain_zone,
            resolvers.len(),
            arq_enabled,
            hold_ms
        );

        let tx_http_client = Client::builder()
            .pool_max_idle_per_host(32)
            .pool_idle_timeout(Some(Duration::from_secs(60)))
            .tcp_nodelay(true)
            .connect_timeout(Duration::from_millis(1200))
            .timeout(Duration::from_millis(2500))
            .http2_adaptive_window(true)
            .build()
            .context("Failed to build TX HTTP/2 client for DoH")?;

        let rx_http_client = Client::builder()
            .pool_max_idle_per_host(16)
            .pool_idle_timeout(Some(Duration::from_secs(60)))
            .tcp_nodelay(true)
            .connect_timeout(Duration::from_millis(1200))
            .timeout(Duration::from_millis(hold_ms.min(800) + 1200))
            .http2_adaptive_window(true)
            .build()
            .context("Failed to build RX HTTP/2 client for DoH")?;

        let max_payload = calculate_max_chunk_payload(&domain_zone);
        // Reserve space for "hs.<8_hex>.<idx>.<total>." (~18 chars => ~12 raw bytes) so FQDN stays <= 253 chars
        let hs_max_payload = max_payload.saturating_sub(24).max(32);
        let temp_session_id = rand::random::<u32>() | 0x80000000;

        let resolver_pool = Arc::new(ResolverPool::new(resolvers.clone()));

        let auth_channel = DohAuthChannel {
            client: tx_http_client.clone(),
            pool: resolver_pool.clone(),
            domain_zone: domain_zone.clone(),
            temp_session_id,
            hs_seq: AtomicU32::new(0),
            max_payload: hs_max_payload,
            pending_response: Mutex::new(None),
            dup_hs,
        };

        info!("[DoH] Starting Phase I-IV ASTP handshake over DoH...");
        let auth = AuthHandler::new(&self.config, self.server.server_pub_key.as_deref())?;
        let (auth_response, shared_key) = auth.authenticate_once(&auth_channel).await?;

        let nonce_prefix_bytes: [u8; 4] = auth_response
            .nonce_prefix
            .as_slice()
            .try_into()
            .context("Invalid nonce_prefix length in AuthResponse")?;
        let session_id = u32::from_be_bytes(nonce_prefix_bytes);

        info!("[DoH] Authenticated successfully. Assigned session ID: {:08x}", session_id);

        // Collect all DoH resolver IPs into bypass_ips so DoH HTTPS requests never loop back into the TUN interface
        let mut bypass_ips = Vec::new();
        for res_url in &resolvers {
            if let Ok(parsed) = Url::parse(res_url) {
                if let Some(host) = parsed.host_str() {
                    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                        if !bypass_ips.contains(&ip) {
                            bypass_ips.push(ip);
                        }
                    } else {
                        let port = parsed.port_or_known_default().unwrap_or(443);
                        if let Ok(addrs) = tokio::net::lookup_host((host, port)).await {
                            for addr in addrs {
                                let ip = addr.ip();
                                if !bypass_ips.contains(&ip) {
                                    bypass_ips.push(ip);
                                }
                            }
                        }
                    }
                }
            }
        }

        let cipher = Arc::new(AstpLiteCipher::new(&shared_key));
        let sequence = Arc::new(AtomicU32::new(1));
        let health_pause = Arc::new(AtomicBool::new(false));

        let (client_stream, internal_router) = tokio::io::duplex(4 * 1024 * 1024);
        let (mut tunnel_read, tunnel_write) = tokio::io::split(internal_router);
        let (tunnel_packet_tx, mut tunnel_packet_rx) =
            tokio::sync::mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);

        let tunnel_reader_task = tokio::spawn(async move {
            while let Ok(Some(packet)) = read_next_packet(&mut tunnel_read).await {
                if tunnel_packet_tx.send(packet).await.is_err() {
                    break;
                }
            }
        });

        let tunnel_write_mutex = Arc::new(Mutex::new(tunnel_write));

        // 1. Uplink Loop: Sends outgoing IP packets from TUN via chunked DoH queries with retry and bounded concurrency
        {
            let http_client = tx_http_client.clone();
            let cipher = cipher.clone();
            let sequence = sequence.clone();
            let domain_zone = domain_zone.clone();
            let pool = resolver_pool.clone();
            let tx_sem = Arc::new(Semaphore::new(24));

            tokio::spawn(async move {
                info!("[DoH TX] Uplink dispatcher loop active");
                while let Some(packet) = tunnel_packet_rx.recv().await {
                    let seq = sequence.fetch_add(1, Ordering::Relaxed);
                    // ASTP-L: 0-byte overhead ChaCha20 encryption
                    let mut packet_buf = packet.to_vec();
                    cipher.apply_keystream(seq, session_id, &mut packet_buf);

                    let chunks = split_into_chunks(session_id, seq, &packet_buf, max_payload);
                    for chunk in chunks {
                        let b32_str = base32::encode(&chunk);
                        let labels = base32::split_into_labels(&b32_str, 63);
                        let qname = format!("{}.{}", labels, domain_zone);
                        let query_bytes = build_doh_query(&qname, rand::random::<u16>());

                        let client = http_client.clone();
                        let pool_clone = pool.clone();
                        let permit = match tx_sem.clone().acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => break,
                        };

                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(e) = pool_clone.send_query_reliable(&client, &query_bytes).await {
                                debug!("[DoH TX] Uplink chunk failed across all resolvers: {}", e);
                            }
                        });
                    }
                }
                tunnel_reader_task.abort();
                info!("[DoH TX] Uplink loop exited");
            });
        }

        // 2. Downlink Poller: Keeps 4 concurrent long-poll queries active on dedicated HTTP client
        {
            let poll_concurrency = 4;
            for worker_id in 0..poll_concurrency {
                let http_client = rx_http_client.clone();
                let cipher = cipher.clone();
                let domain_zone = domain_zone.clone();
                let pool = resolver_pool.clone();
                let tunnel_write = tunnel_write_mutex.clone();

                tokio::spawn(async move {
                    debug!("[DoH RX-{}] Long-poll worker initialized", worker_id);
                    let mut backoff_ms = 10;

                    loop {
                        let nonce_hex = format!("{:08x}", rand::random::<u32>());
                        let qname = format!("poll.{:08x}.{}.{}", session_id, nonce_hex, domain_zone);
                        let query_bytes = build_doh_query(&qname, rand::random::<u16>());

                        match pool.send_query_reliable(&http_client, &query_bytes).await {
                            Ok(body) => {
                                backoff_ms = 10;
                                if let Some(txt_data) = parse_dns_txt_response(&body) {
                                    if let Ok(mut raw_payload) = BASE64_STANDARD.decode(&txt_data) {
                                        if raw_payload.len() >= 4 {
                                            let seq = u32::from_be_bytes(raw_payload[0..4].try_into().unwrap());
                                            let ciphertext = &mut raw_payload[4..];
                                            cipher.apply_keystream(seq, session_id, ciphertext);

                                            let mut out_buf = BytesMut::with_capacity(ciphertext.len() + 16);
                                            if ciphertext.first() == Some(&0x00) {
                                                // Unpack batched packets: [0x00, len_be16, pkt1, len_be16, pkt2, ...]
                                                let mut pos = 1;
                                                while pos + 2 <= ciphertext.len() {
                                                    let pkt_len = u16::from_be_bytes([
                                                        ciphertext[pos],
                                                        ciphertext[pos + 1],
                                                    ]) as usize;
                                                    pos += 2;
                                                    if pos + pkt_len <= ciphertext.len() {
                                                        frame_packet_into(
                                                            &mut out_buf,
                                                            &ciphertext[pos..pos + pkt_len],
                                                        );
                                                        pos += pkt_len;
                                                    } else {
                                                        break;
                                                    }
                                                }
                                            } else {
                                                frame_packet_into(&mut out_buf, ciphertext);
                                            }

                                            if !out_buf.is_empty() {
                                                let mut guard = tunnel_write.lock().await;
                                                if guard.write_all(&out_buf).await.is_err() {
                                                    warn!("[DoH RX] Tunnel stream closed; exiting poller.");
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                debug!("[DoH RX-{}] Poll request failed: {}", worker_id, e);
                                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                                backoff_ms = (backoff_ms * 2).min(400);
                            }
                        }
                    }
                });
            }
        }

        info!("[DoH] Transport session fully established.");

        Ok(ConnectionResult {
            auth_response,
            vpn_stream: Box::new(client_stream),
            endpoint: None,
            connection: None,
            health_pause: Some(health_pause),
            remote_ip: None,
            bypass_ips,
            effective_mode: None,
            shutdown_hook: None,
        })
    }
}
