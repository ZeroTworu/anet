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
use reqwest::Client;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use url::Url;

struct DohAuthChannel {
    client: Client,
    resolvers: Vec<String>,
    resolver_idx: AtomicUsize,
    domain_zone: String,
    temp_session_id: u32,
    max_payload: usize,
    pending_response: Mutex<Option<Bytes>>,
    dup_hs: bool,
}

#[async_trait]
impl AuthChannel for DohAuthChannel {
    async fn send(&self, data: Bytes, _frag: &FragmentConfig) -> Result<()> {
        let chunks = split_into_chunks(self.temp_session_id, 0, &data, self.max_payload);
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

            let resolver_url = {
                let current = self.resolver_idx.fetch_add(1, Ordering::Relaxed);
                self.resolvers[current % self.resolvers.len()].clone()
            };

            let req = self
                .client
                .post(&resolver_url)
                .header("Content-Type", "application/dns-message")
                .header("Accept", "application/dns-message")
                .body(query_bytes.clone());

            let resp = req.send().await;
            match resp {
                Ok(res) if res.status().is_success() => {
                    if let Ok(body) = res.bytes().await {
                        if let Some(txt_data) = parse_dns_txt_response(&body) {
                            if let Ok(decoded) = BASE64_STANDARD.decode(&txt_data) {
                                if !decoded.is_empty() {
                                    *self.pending_response.lock().await = Some(Bytes::from(decoded));
                                }
                            }
                        }
                    }
                }
                Ok(res) => {
                    warn!("[DoH Auth] Resolver {} returned status {}", resolver_url, res.status());
                }
                Err(e) => {
                    warn!("[DoH Auth] Failed sending handshake query to {}: {}", resolver_url, e);
                }
            }

            // If duplicate handshake is enabled and there are multiple resolvers, duplicate the query
            if self.dup_hs && self.resolvers.len() > 1 && self.pending_response.lock().await.is_none() {
                let alt_resolver = {
                    let current = self.resolver_idx.fetch_add(1, Ordering::Relaxed);
                    self.resolvers[current % self.resolvers.len()].clone()
                };
                if alt_resolver != resolver_url {
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

            let resolver_url = {
                let current = self.resolver_idx.fetch_add(1, Ordering::Relaxed);
                self.resolvers[current % self.resolvers.len()].clone()
            };

            let req = self
                .client
                .post(&resolver_url)
                .header("Content-Type", "application/dns-message")
                .header("Accept", "application/dns-message")
                .body(query_bytes);

            if let Ok(res) = req.send().await {
                if res.status().is_success() {
                    if let Ok(body) = res.bytes().await {
                        if let Some(txt_data) = parse_dns_txt_response(&body) {
                            if let Ok(decoded) = BASE64_STANDARD.decode(&txt_data) {
                                if !decoded.is_empty() {
                                    return Ok(Bytes::from(decoded));
                                }
                            }
                        }
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(60)).await;
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

        let http_client = Client::builder()
            .pool_max_idle_per_host(16)
            .pool_idle_timeout(Some(Duration::from_secs(60)))
            .tcp_nodelay(true)
            .timeout(Duration::from_millis(hold_ms + 1500))
            .http2_adaptive_window(true)
            .build()
            .context("Failed to build HTTP/2 client for DoH")?;

        let max_payload = calculate_max_chunk_payload(&domain_zone);
        let temp_session_id = rand::random::<u32>() | 0x80000000;

        let auth_channel = DohAuthChannel {
            client: http_client.clone(),
            resolvers: resolvers.clone(),
            resolver_idx: AtomicUsize::new(0),
            domain_zone: domain_zone.clone(),
            temp_session_id,
            max_payload,
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
        let resolvers_arc = Arc::new(resolvers);
        let resolver_idx_tx = Arc::new(AtomicUsize::new(0));
        let resolver_idx_rx = Arc::new(AtomicUsize::new(0));

        // 1. Uplink Loop: Sends outgoing IP packets from TUN via chunked DoH queries
        {
            let http_client = http_client.clone();
            let cipher = cipher.clone();
            let sequence = sequence.clone();
            let domain_zone = domain_zone.clone();
            let resolvers = resolvers_arc.clone();
            let resolver_idx = resolver_idx_tx.clone();

            tokio::spawn(async move {
                info!("[DoH TX] Uplink dispatcher loop active");
                while let Some(mut packet) = tunnel_packet_rx.recv().await {
                    let seq = sequence.fetch_add(1, Ordering::Relaxed);
                    // ASTP-L: 0-byte overhead ChaCha20 encryption
                    cipher.apply_keystream(seq, session_id, &mut packet);

                    let chunks = split_into_chunks(session_id, seq, &packet, max_payload);
                    for chunk in chunks {
                        let b32_str = base32::encode(&chunk);
                        let labels = base32::split_into_labels(&b32_str, 63);
                        let qname = format!("{}.{}", labels, domain_zone);
                        let query_bytes = build_doh_query(&qname, rand::random::<u16>());

                        let resolver_url = {
                            let idx = resolver_idx.fetch_add(1, Ordering::Relaxed);
                            resolvers[idx % resolvers.len()].clone()
                        };

                        let client = http_client.clone();
                        tokio::spawn(async move {
                            let req = client
                                .post(&resolver_url)
                                .header("Content-Type", "application/dns-message")
                                .header("Accept", "application/dns-message")
                                .body(query_bytes);

                            if let Err(e) = req.send().await {
                                debug!("[DoH TX] Uplink chunk POST error to {}: {}", resolver_url, e);
                            }
                        });
                    }
                }
                tunnel_reader_task.abort();
                info!("[DoH TX] Uplink loop exited");
            });
        }

        // 2. Downlink Poller: Keeps 2 concurrent long-poll queries active for low-latency inbound traffic
        {
            let poll_concurrency = 2;
            for worker_id in 0..poll_concurrency {
                let http_client = http_client.clone();
                let cipher = cipher.clone();
                let domain_zone = domain_zone.clone();
                let resolvers = resolvers_arc.clone();
                let resolver_idx = resolver_idx_rx.clone();
                let tunnel_write = tunnel_write_mutex.clone();

                tokio::spawn(async move {
                    debug!("[DoH RX-{}] Long-poll worker initialized", worker_id);
                    let mut backoff_ms = 10;

                    loop {
                        let nonce_hex = format!("{:08x}", rand::random::<u32>());
                        let qname = format!("poll.{:08x}.{}.{}", session_id, nonce_hex, domain_zone);
                        let query_bytes = build_doh_query(&qname, rand::random::<u16>());

                        let resolver_url = {
                            let idx = resolver_idx.fetch_add(1, Ordering::Relaxed);
                            resolvers[idx % resolvers.len()].clone()
                        };

                        let req = http_client
                            .post(&resolver_url)
                            .header("Content-Type", "application/dns-message")
                            .header("Accept", "application/dns-message")
                            .body(query_bytes);

                        match req.send().await {
                            Ok(res) if res.status().is_success() => {
                                backoff_ms = 10;
                                if let Ok(body) = res.bytes().await {
                                    if let Some(txt_data) = parse_dns_txt_response(&body) {
                                        if let Ok(mut raw_payload) = BASE64_STANDARD.decode(&txt_data) {
                                            if raw_payload.len() >= 4 {
                                                let seq = u32::from_be_bytes(raw_payload[0..4].try_into().unwrap());
                                                let ciphertext = &mut raw_payload[4..];
                                                cipher.apply_keystream(seq, session_id, ciphertext);

                                                let mut out_buf = BytesMut::with_capacity(ciphertext.len() + 8);
                                                frame_packet_into(&mut out_buf, ciphertext);

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
                            Ok(res) => {
                                debug!("[DoH RX-{}] Resolver HTTP {}", worker_id, res.status());
                                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                                backoff_ms = (backoff_ms * 2).min(500);
                            }
                            Err(e) => {
                                debug!("[DoH RX-{}] Poll request failed: {}", worker_id, e);
                                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                                backoff_ms = (backoff_ms * 2).min(500);
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
            bypass_ips: Vec::new(),
            effective_mode: None,
            shutdown_hook: None,
        })
    }
}
