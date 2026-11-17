use super::{ClientTransport, ConnectionResult};
use crate::auth::{AuthChannel, AuthDenyError, AuthHandler};
use crate::config::{AhttpConfig, CoreConfig, ServerConfig};
use anet_common::consts::{CLIENT_SEQUENCE_START, SERVER_SEQUENCE_START};
use anet_common::encryption::Cipher;
use anet_common::handshake_fragmentation::FragmentConfig;
use anet_common::http_help::BrowserProfile;
use anet_common::reassembly::ReassemblyQueue;
use anet_common::stream_framing::{frame_packet_into, read_next_packet, FrameReader};
use anet_common::transport::{unwrap_packet_with_seq, wrap_packet_padded};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use log::{debug, info, warn};
use rand::Rng;
use reqwest::{Client, Method, StatusCode, Url};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, watch, Mutex, Notify, Semaphore};

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
        drop(is_auth);

        let req = self.client.post(&req_path).header("Accept", "*/*");
        let req = self
            .profile
            .apply_to_reqwest(req, Some(&self.origin), Some(&self.referer));

        let resp = req.body(reqwest::Body::from(data)).send().await?;

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

        let addrs = tokio::net::lookup_host(format!("{}:{}", host, port))
            .await
            .context(format!("Failed to resolve DNS for {}:{}", host, port))?;

        let addr = addrs.into_iter().next().context("No IP addresses found")?;
        Ok(addr)
    }
}

struct AhttpSessionState {
    gen_id: u64,
    session_id: String,
    cipher: Arc<Cipher>,
    nonce_prefix: [u8; 4],
    tx_sequence: Arc<AtomicU64>,
}

struct AhttpReauthContext {
    config: CoreConfig,
    server: ServerConfig,
    profile: BrowserProfile,
    client_pool: Arc<Vec<Client>>,
    base_url: String,
    origin: String,
    referer: String,
    expected_ip: String,
    expected_gateway: String,
}

struct IdlePollGuard {
    counter: Arc<AtomicUsize>,
    notify: Arc<Notify>,
    active: bool,
}

impl Drop for IdlePollGuard {
    fn drop(&mut self) {
        if self.active {
            self.counter.fetch_sub(1, Ordering::AcqRel);
            self.notify.notify_one();
        }
    }
}

fn atomic_try_take(counter: &AtomicUsize) -> bool {
    let mut cur = counter.load(Ordering::Acquire);
    while cur > 0 {
        match counter.compare_exchange_weak(cur, cur - 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(actual) => cur = actual,
        }
    }
    false
}

fn atomic_add_capped(counter: &AtomicUsize, delta: usize, max: usize) {
    let mut cur = counter.load(Ordering::Acquire);
    while cur < max {
        let next = cur.saturating_add(delta).min(max);
        match counter.compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break,
            Err(actual) => cur = actual,
        }
    }
}

fn try_claim_idle_poll(counter: &AtomicUsize, max_idle_polls: usize) -> bool {
    if max_idle_polls == 0 {
        return true;
    }
    let mut cur = counter.load(Ordering::Acquire);
    while cur < max_idle_polls {
        match counter.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(actual) => cur = actual,
        }
    }
    false
}

fn current_rel_ms(origin: Instant) -> u64 {
    origin.elapsed().as_millis().min(u64::MAX as u128) as u64
}

fn schedule_pool_backoff(origin: Instant, gate: &AtomicU64, delay: Duration) {
    let target = current_rel_ms(origin).saturating_add(delay.as_millis() as u64);
    gate.fetch_max(target, Ordering::AcqRel);
}

async fn wait_pool_backoff(
    origin: Instant,
    gate: &AtomicU64,
    stop_rx: &mut watch::Receiver<bool>,
) -> bool {
    loop {
        if *stop_rx.borrow() {
            return false;
        }
        let now = current_rel_ms(origin);
        let until = gate.load(Ordering::Acquire);
        if until <= now {
            return true;
        }
        let wait = Duration::from_millis(until - now);
        tokio::select! {
            biased;
            _ = stop_rx.changed() => return false,
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

fn parse_retry_after(headers: &reqwest::header::HeaderMap, max_ms: u64) -> Option<Duration> {
    let val = headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?.trim();
    if let Ok(secs) = val.parse::<u64>() {
        let ceiling = max_ms.max(100);
        let ms = secs.saturating_mul(1000).clamp(100, ceiling);
        return Some(Duration::from_millis(ms));
    }
    None
}

fn compute_retry_delay(attempt: u32, base_ms: u64, max_ms: u64) -> Duration {
    let shift = attempt.min(10);
    let exp = base_ms.saturating_mul(1u64 << shift).min(max_ms.max(base_ms));
    let min = (exp / 2).max(10);
    let jitter_ms = rand::rngs::OsRng.gen_range(min..=exp.max(min));
    Duration::from_millis(jitter_ms)
}

fn compute_idle_wait(empty_streak: usize, cfg: &AhttpConfig) -> Duration {
    if empty_streak == 0 {
        return Duration::from_millis(cfg.poll_timeout_ms);
    }
    let base = cfg.idle_poll_interval_ms;
    let max = cfg.idle_backoff_max_ms.max(base);
    if base == 0 {
        return Duration::ZERO;
    }
    let shift = (empty_streak - 1).min(6);
    let ms = base.saturating_mul(1u64 << shift).min(max);
    Duration::from_millis(ms)
}

async fn authenticate_http_session(
    client: &Client,
    base_url: &str,
    origin: &str,
    referer: &str,
    profile: &BrowserProfile,
    config: &CoreConfig,
    server: &ServerConfig,
    resume_session_id: Option<String>,
) -> Result<(anet_common::protocol::AuthResponse, [u8; 32])> {
    let auth_channel = AHttpAuthChannel {
        client: client.clone(),
        base_url: base_url.to_string(),
        origin: origin.to_string(),
        referer: referer.to_string(),
        profile: profile.clone(),
        is_auth_phase: Mutex::new(false),
        pending_response: Mutex::new(None),
        handshake_path: config.ahttp.handshake_path.clone(),
        auth_path: config.ahttp.auth_path.clone(),
    };
    let auth = AuthHandler::new_with_resume(
        config,
        server.server_pub_key.as_deref(),
        resume_session_id,
    )?;
    auth.authenticate_once(&auth_channel).await
}

#[allow(clippy::too_many_arguments)]
async fn try_reconnect_ahttp(
    expected_failed_gen: u64,
    state_tx: &watch::Sender<Arc<AhttpSessionState>>,
    reauth_lock: &Mutex<()>,
    reauth_ctx: &AhttpReauthContext,
    health_pause: &AtomicBool,
    global_stop_tx: &watch::Sender<bool>,
    global_stop_rx: &mut watch::Receiver<bool>,
    downlink_tx: &mpsc::Sender<(u64, Vec<(u64, Bytes)>)>,
    consecutive_failures: &AtomicU32,
) -> bool {
    let _guard = tokio::select! {
        biased;
        _ = global_stop_rx.changed() => return false,
        g = reauth_lock.lock() => g,
    };

    if *global_stop_rx.borrow() {
        return false;
    }

    let current = state_tx.borrow().clone();
    if current.gen_id != expected_failed_gen {
        // Другой воркер уже обновил сессию
        return true;
    }

    health_pause.store(true, Ordering::Release);
    let ahttp_cfg = &reauth_ctx.config.ahttp;
    let deadline = Instant::now() + ahttp_cfg.effective_reconnect_timeout(reauth_ctx.server.timeout_secs);
    let attempt_timeout = Duration::from_secs((ahttp_cfg.timeout_secs.max(5) * 2).min(30));
    let mut attempt: usize = 0;

    while Instant::now() < deadline {
        if *global_stop_rx.borrow() {
            health_pause.store(false, Ordering::Release);
            return false;
        }

        let client = &reauth_ctx.client_pool[attempt % reauth_ctx.client_pool.len()];
        attempt = attempt.wrapping_add(1);

        let res = tokio::select! {
            biased;
            _ = global_stop_rx.changed() => {
                health_pause.store(false, Ordering::Release);
                return false;
            }
            r = tokio::time::timeout(
                attempt_timeout,
                authenticate_http_session(
                    client,
                    &reauth_ctx.base_url,
                    &reauth_ctx.origin,
                    &reauth_ctx.referer,
                    &reauth_ctx.profile,
                    &reauth_ctx.config,
                    &reauth_ctx.server,
                    Some(current.session_id.clone()),
                ),
            ) => r,
        };

        match res {
            Ok(Ok((new_resp, new_key))) => {
                if ahttp_cfg.abort_on_ip_change
                    && (new_resp.ip != reauth_ctx.expected_ip
                        || new_resp.gateway != reauth_ctx.expected_gateway)
                {
                    warn!(
                        "[AHTTP] Reconnected session received new tunnel address ({} != {} / {} != {}); stopping transport so core reconfigures TUN",
                        new_resp.ip,
                        reauth_ctx.expected_ip,
                        new_resp.gateway,
                        reauth_ctx.expected_gateway
                    );
                    health_pause.store(false, Ordering::Release);
                    let _ = global_stop_tx.send(true);
                    return false;
                }

                let new_nonce: [u8; 4] = match new_resp.nonce_prefix.as_slice().try_into() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!("[AHTTP] Invalid nonce_prefix length during session reconnect");
                        health_pause.store(false, Ordering::Release);
                        let _ = global_stop_tx.send(true);
                        return false;
                    }
                };

                let next_gen = current.gen_id + 1;
                let next_state = Arc::new(AhttpSessionState {
                    gen_id: next_gen,
                    session_id: new_resp.session_id,
                    cipher: Arc::new(Cipher::new(&new_key)),
                    nonce_prefix: new_nonce,
                    tx_sequence: Arc::new(AtomicU64::new(CLIENT_SEQUENCE_START)),
                });
                info!(
                    "[AHTTP] Session resumed/reconnected cleanly (gen {} -> {}, session {})",
                    current.gen_id, next_gen, next_state.session_id
                );
                consecutive_failures.store(0, Ordering::Release);
                let _ = state_tx.send(next_state);
                let _ = downlink_tx.send((next_gen, Vec::new())).await;
                health_pause.store(false, Ordering::Release);
                return true;
            }
            Ok(Err(e)) => {
                if e.downcast_ref::<AuthDenyError>().is_some() {
                    warn!("[AHTTP] Server denied session reconnect: {}", e);
                    health_pause.store(false, Ordering::Release);
                    let _ = global_stop_tx.send(true);
                    return false;
                }
                warn!("[AHTTP] Session reconnect attempt failed: {}", e);
            }
            Err(_) => {
                warn!("[AHTTP] Session reconnect attempt timed out");
            }
        }

        let delay = ahttp_cfg.random_reconnect_retry_delay();
        tokio::select! {
            biased;
            _ = global_stop_rx.changed() => {
                health_pause.store(false, Ordering::Release);
                return false;
            }
            _ = tokio::time::sleep(delay) => {}
        }
    }

    warn!("[AHTTP] Session reconnect exhausted timeout; closing transport");
    health_pause.store(false, Ordering::Release);
    let _ = global_stop_tx.send(true);
    false
}

fn apply_downlink_batch(
    gid: u64,
    batch: Vec<(u64, Bytes)>,
    current_gen_id: &mut u64,
    reassembler: &mut ReassemblyQueue,
    downlink_buf: &mut BytesMut,
) {
    if gid < *current_gen_id {
        return;
    }
    if gid > *current_gen_id {
        reassembler.reset(SERVER_SEQUENCE_START);
        *current_gen_id = gid;
    }
    if batch.is_empty() {
        return;
    }
    for pkt in reassembler.insert_batch(batch) {
        frame_packet_into(downlink_buf, &pkt);
    }
}

async fn run_downlink_sink(
    mut tunnel_write: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    mut downlink_rx: mpsc::Receiver<(u64, Vec<(u64, Bytes)>)>,
    global_stop_tx: watch::Sender<bool>,
    mut global_stop_rx: watch::Receiver<bool>,
    ahttp_cfg: AhttpConfig,
) {
    let mut reassembler = ReassemblyQueue::with_config(
        ahttp_cfg.reassembly_queue_max_size.max(1),
        SERVER_SEQUENCE_START,
        ahttp_cfg.effective_reassembly_gap_timeout(),
    );
    let coalesce_budget = ahttp_cfg.coalesce_budget_bytes.max(4096);
    let mut current_gen_id: u64 = 1;
    let mut downlink_buf = BytesMut::with_capacity(coalesce_budget + 2048);

    loop {
        if *global_stop_rx.borrow() {
            break;
        }

        let gap_wait = reassembler.gap_remaining();
        let sleep_fut = async {
            match gap_wait {
                Some(dur) => tokio::time::sleep(dur).await,
                None => std::future::pending::<()>().await,
            }
        };

        tokio::select! {
            biased;
            _ = global_stop_rx.changed() => break,
            _ = sleep_fut, if gap_wait.is_some() => {
                for pkt in reassembler.flush_expired() {
                    frame_packet_into(&mut downlink_buf, &pkt);
                }
            }
            maybe_item = downlink_rx.recv() => {
                let Some((gid, batch)) = maybe_item else {
                    break;
                };
                apply_downlink_batch(
                    gid,
                    batch,
                    &mut current_gen_id,
                    &mut reassembler,
                    &mut downlink_buf,
                );
                while downlink_buf.len() < coalesce_budget {
                    match downlink_rx.try_recv() {
                        Ok((next_gid, next_batch)) => {
                            apply_downlink_batch(
                                next_gid,
                                next_batch,
                                &mut current_gen_id,
                                &mut reassembler,
                                &mut downlink_buf,
                            );
                        }
                        Err(_) => break,
                    }
                }
            }
        }

        if !downlink_buf.is_empty() {
            let to_write = downlink_buf.split().freeze();
            downlink_buf.reserve(coalesce_budget + 2048);
            if tunnel_write.write_all(&to_write).await.is_err() {
                warn!("[AHTTP Client] Tunnel stream closed, discarding remaining packets.");
                let _ = global_stop_tx.send(true);
                break;
            }
        }
    }

    let _ = tunnel_write.shutdown().await;
}

#[async_trait]
impl ClientTransport for AHttpTransport {
    async fn connect(&self) -> Result<ConnectionResult> {
        let tls_cfg = self.server.effective_tls_config(&self.config.stealth);
        let profile = BrowserProfile::with_tls_config(tls_cfg);

        let dsn_url = Url::parse(&self.server.dsn)?;
        let scheme = dsn_url.scheme();
        let target_host = dsn_url.host_str().context("No host in DSN")?.to_string();
        let port = dsn_url
            .port_or_known_default()
            .unwrap_or(if scheme == "https" { 443 } else { 80 });
        let mut base_url = format!("{}://{}{}", scheme, target_host, dsn_url.path());

        if base_url.ends_with('/') {
            base_url.pop();
        }

        let mut uplink_method_str = "POST".to_string();
        let mut dsn_cdn_mode = false;
        let mut dsn_budget_override: Option<usize> = None;
        let mut dsn_pool_override: Option<usize> = None;
        for (k, v) in dsn_url.query_pairs() {
            match k.as_ref() {
                "method" => uplink_method_str = v.into_owned(),
                "cdn" => dsn_cdn_mode = matches!(v.as_ref(), "1" | "true" | "yes"),
                "budget" => dsn_budget_override = v.parse::<usize>().ok(),
                "pool" => dsn_pool_override = v.parse::<usize>().ok(),
                _ => {}
            }
        }
        let uplink_method =
            Method::from_bytes(uplink_method_str.as_bytes()).unwrap_or(Method::POST);

        let resolved_addr = self.resolve_host(&target_host, port).await?;
        info!(
            "[AHTTP] Initializing XHTTP engine to {} (Pinned IP: {})",
            base_url, resolved_addr
        );

        let cookie_jar = Arc::new(reqwest::cookie::Jar::default());
        let build_http_client = || -> Result<Client> {
            let mut builder = profile.build_reqwest_builder(cookie_jar.clone())?;
            builder = builder
                .resolve(&target_host, resolved_addr)
                .pool_max_idle_per_host(self.config.ahttp.pool_max_idle_per_host.max(2))
                .pool_idle_timeout(Some(Duration::from_secs(
                    self.config.ahttp.pool_idle_timeout_secs,
                )))
                .tcp_nodelay(self.config.ahttp.tcp_nodelay)
                .timeout(Duration::from_secs(self.config.ahttp.timeout_secs.max(1)))
                .http2_adaptive_window(self.config.ahttp.http2_adaptive_window);

            if !self.config.ahttp.http2_adaptive_window {
                let stream_win = self
                    .config
                    .ahttp
                    .http2_initial_stream_window_size
                    .unwrap_or(if dsn_cdn_mode {
                        49152
                    } else {
                        profile.h2_initial_stream_window_size
                    });
                builder = builder.http2_initial_stream_window_size(stream_win);

                let conn_win = self
                    .config
                    .ahttp
                    .http2_initial_connection_window_size
                    .unwrap_or(if dsn_cdn_mode {
                        49152
                    } else {
                        profile.h2_initial_connection_window_size
                    });
                builder = builder.http2_initial_connection_window_size(conn_win);
            }

            if let Some(max_frame) = self.config.ahttp.http2_max_frame_size {
                builder = builder.http2_max_frame_size(max_frame);
            }

            let max_header = self
                .config
                .ahttp
                .http2_max_header_list_size
                .unwrap_or(profile.h2_max_header_list_size);
            builder = builder.http2_max_header_list_size(max_header);

            if let Some(ka_interval) = self.config.ahttp.http2_keep_alive_interval_secs {
                builder = builder.http2_keep_alive_interval(Some(Duration::from_secs(ka_interval)));

                if let Some(ka_timeout) = self.config.ahttp.http2_keep_alive_timeout_secs {
                    builder = builder.http2_keep_alive_timeout(Duration::from_secs(ka_timeout));
                }

                builder = builder
                    .http2_keep_alive_while_idle(self.config.ahttp.http2_keep_alive_while_idle);
            }

            builder
                .build()
                .map_err(|e| anyhow::anyhow!("Cannot build a HTTP client: {}", e))
        };

        let configured_pool = dsn_pool_override
            .or(self.config.ahttp.tcp_pool_size)
            .unwrap_or(4);
        let max_concurrency = self.config.ahttp.concurrency.max(1);
        let pool_size = if configured_pool == 0 {
            max_concurrency.clamp(1, 4)
        } else {
            configured_pool.clamp(1, max_concurrency)
        };
        let mut client_pool_vec = Vec::with_capacity(pool_size);
        for _ in 0..pool_size {
            client_pool_vec.push(build_http_client()?);
        }
        let primary_http_client = client_pool_vec[0].clone();
        let client_pool = Arc::new(client_pool_vec);

        let origin = format!("{}://{}", scheme, target_host);
        let referer = format!("{}/", base_url);

        let (auth_response, shared_key) = authenticate_http_session(
            &primary_http_client,
            &base_url,
            &origin,
            &referer,
            &profile,
            &self.config,
            &self.server,
            None,
        )
        .await?;

        let nonce_prefix: [u8; 4] = auth_response
            .nonce_prefix
            .as_slice()
            .try_into()
            .context("Invalid nonce_prefix length in AHTTP AuthResponse")?;
        let initial_state = Arc::new(AhttpSessionState {
            gen_id: 1,
            session_id: auth_response.session_id.clone(),
            cipher: Arc::new(Cipher::new(&shared_key)),
            nonce_prefix,
            tx_sequence: Arc::new(AtomicU64::new(CLIENT_SEQUENCE_START)),
        });

        let expected_ip = auth_response.ip.clone();
        let expected_gateway = auth_response.gateway.clone();
        let health_pause = Arc::new(AtomicBool::new(false));
        let (global_stop_tx, global_stop_rx) = watch::channel(false);
        let (state_tx_raw, mut state_rx) = watch::channel(initial_state);
        let state_tx = Arc::new(state_tx_raw);

        // Умеренный размер буферов (512 КБ duplex + конфигурируемый канал) защищает от Bufferbloat
        let (client_stream, internal_router) = tokio::io::duplex(512 * 1024);
        let (mut tunnel_read, tunnel_write) = tokio::io::split(internal_router);
        let (tunnel_packet_tx, mut tunnel_packet_rx) =
            mpsc::channel::<Bytes>(self.config.ahttp.effective_tx_queue_capacity());
        let (downlink_tx, downlink_rx) =
            mpsc::channel::<(u64, Vec<(u64, Bytes)>)>(self.config.ahttp.effective_downlink_queue_capacity());

        let reader_stop_tx = global_stop_tx.clone();
        let tunnel_reader_task = tokio::spawn(async move {
            let mut frame_reader = FrameReader::new();
            while let Ok(Some(packet)) = frame_reader.read_next_packet(&mut tunnel_read).await {
                if tunnel_packet_tx.send(packet).await.is_err() {
                    break;
                }
            }
            let _ = reader_stop_tx.send(true);
        });
        let tunnel_reader_abort = tunnel_reader_task.abort_handle();

        let downlink_sink_task = tokio::spawn(run_downlink_sink(
            tunnel_write,
            downlink_rx,
            global_stop_tx.clone(),
            global_stop_rx.clone(),
            self.config.ahttp.clone(),
        ));
        let downlink_sink_abort = downlink_sink_task.abort_handle();

        let padding_step = self.config.stealth.padding_step;
        let config_ahttp = self.config.ahttp.clone();

        let reauth_ctx = Arc::new(AhttpReauthContext {
            config: self.config.clone(),
            server: self.server.clone(),
            profile: profile.clone(),
            client_pool: client_pool.clone(),
            base_url: base_url.clone(),
            origin: origin.clone(),
            referer: referer.clone(),
            expected_ip,
            expected_gateway,
        });
        let reauth_lock = Arc::new(Mutex::new(()));

        let concurrency_semaphore = Arc::new(Semaphore::new(max_concurrency));
        let concurrency_sem_shutdown = concurrency_semaphore.clone();
        let downlink_notify = Arc::new(Notify::new());
        let downlink_credits = Arc::new(AtomicUsize::new(0));
        let inflight_idle_polls = Arc::new(AtomicUsize::new(0));
        let idle_notify = Arc::new(Notify::new());
        let consecutive_empty_polls = Arc::new(AtomicUsize::new(0));
        let consecutive_failures = Arc::new(AtomicU32::new(0));
        let pool_start = Instant::now();
        let pool_backoff_ms = Arc::new(AtomicU64::new(0));

        let inflight_aborts: Arc<std::sync::Mutex<Vec<tokio::task::AbortHandle>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let inflight_aborts_loop = inflight_aborts.clone();
        let loop_stop_tx = global_stop_tx.clone();
        let mut loop_stop_rx = global_stop_rx.clone();
        let loop_health_pause = health_pause.clone();

        let traffic_loop_task = tokio::spawn(async move {
            let uplink_budget_bytes = dsn_budget_override
                .or(if dsn_cdn_mode { Some(49152) } else { None })
                .or(config_ahttp.uplink_coalesce_budget_bytes)
                .unwrap_or(config_ahttp.coalesce_budget_bytes)
                .max(2048);
            info!(
                "[AHTTP Client] Started Stateless Packet-Exchange Loop (Method: {}, TCP Pool: {}, Concurrency: {}, Uplink Budget: {} B, Max Idle Polls: {})",
                uplink_method_str,
                pool_size,
                max_concurrency,
                uplink_budget_bytes,
                config_ahttp.max_idle_polls
            );
            let traffic_base_url = format!("{}{}", base_url, config_ahttp.traffic_path);
            let mut batch_buf = BytesMut::with_capacity(uplink_budget_bytes + 2048);
            let micro_coalesce = config_ahttp.effective_micro_coalesce();
            let micro_coalesce_min = config_ahttp.micro_coalesce_min_bytes;
            let body_read_timeout = Duration::from_secs(config_ahttp.timeout_secs.max(1));
            let mut rr_counter: usize = 0;

            loop {
                if *loop_stop_rx.borrow() {
                    break;
                }

                // Во время переподключения сессии ставим отправку новых транзакций на паузу
                if loop_health_pause.load(Ordering::Acquire) {
                    tokio::select! {
                        biased;
                        _ = loop_stop_rx.changed() => break,
                        res = state_rx.changed() => {
                            if res.is_err() {
                                break;
                            }
                        }
                        _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                    }
                    continue;
                }

                // Не штурмуем CDN во время глобального 429/503 backoff
                if !wait_pool_backoff(pool_start, &pool_backoff_ms, &mut loop_stop_rx).await {
                    break;
                }

                let has_poll_credit = downlink_credits.load(Ordering::Acquire) > 0
                    && concurrency_semaphore.available_permits() > 0;

                // 1. Ждем первый пакет, сигнал активного Downlink (self-clocking), либо окно одиночного idle long-poll
                let (first_packet_opt, is_poll_wakeup, used_credit) =
                    if has_poll_credit && atomic_try_take(&downlink_credits) {
                        (tunnel_packet_rx.try_recv().ok(), true, true)
                    } else {
                        let max_idle = config_ahttp.max_idle_polls;
                        let can_start_idle = max_idle == 0
                            || inflight_idle_polls.load(Ordering::Acquire) < max_idle;
                        let empty_streak = consecutive_empty_polls.load(Ordering::Acquire);
                        let idle_wait = compute_idle_wait(empty_streak, &config_ahttp);

                        tokio::select! {
                            biased;
                            _ = loop_stop_rx.changed() => break,
                            pkt = tunnel_packet_rx.recv() => {
                                match pkt {
                                    Some(p) => (Some(p), false, false),
                                    None => break,
                                }
                            }
                            _ = downlink_notify.notified() => {
                                if !atomic_try_take(&downlink_credits) {
                                    continue;
                                }
                                (tunnel_packet_rx.try_recv().ok(), true, true)
                            }
                            _ = idle_notify.notified(), if !can_start_idle => {
                                continue;
                            }
                            _ = tokio::time::sleep(idle_wait), if can_start_idle => (None, true, false),
                        }
                    };

                // 2. Раздельный захват слота concurrency для реального трафика и фонового опроса
                let permit = if first_packet_opt.is_none() {
                    match concurrency_semaphore.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            tokio::select! {
                                biased;
                                _ = loop_stop_rx.changed() => break,
                                _ = tokio::time::sleep(Duration::from_millis(2)) => continue,
                            }
                        }
                    }
                } else {
                    match concurrency_semaphore.clone().acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => break,
                    }
                };

                let cur_state = state_tx.borrow().clone();
                let mut tx_pkts_count = 0usize;

                let first_pkt = match first_packet_opt {
                    Some(p) => Some(p),
                    None => tunnel_packet_rx.try_recv().ok(),
                };

                if let Some(packet) = first_pkt {
                    consecutive_empty_polls.store(0, Ordering::Release);

                    let seq = cur_state.tx_sequence.fetch_add(1, Ordering::Relaxed);
                    if let Ok(encrypted) = wrap_packet_padded(
                        &cur_state.cipher,
                        &cur_state.nonce_prefix,
                        seq,
                        packet,
                        padding_step,
                    ) {
                        frame_packet_into(&mut batch_buf, &encrypted);
                        tx_pkts_count += 1;
                    }

                    while batch_buf.len() + 1600 <= uplink_budget_bytes {
                        match tunnel_packet_rx.try_recv() {
                            Ok(p) => {
                                let seq = cur_state.tx_sequence.fetch_add(1, Ordering::Relaxed);
                                if let Ok(enc) = wrap_packet_padded(
                                    &cur_state.cipher,
                                    &cur_state.nonce_prefix,
                                    seq,
                                    p,
                                    padding_step,
                                ) {
                                    frame_packet_into(&mut batch_buf, &enc);
                                    tx_pkts_count += 1;
                                }
                            }
                            Err(_) => break,
                        }
                    }

                    // Микро-коалесценция ТОЛЬКО для тяжелого Upload и не в режиме poll_wakeup
                    if !micro_coalesce.is_zero()
                        && !is_poll_wakeup
                        && batch_buf.len() >= micro_coalesce_min
                        && batch_buf.len() < uplink_budget_bytes / 2
                    {
                        let deadline = tokio::time::Instant::now() + micro_coalesce;
                        while batch_buf.len() + 1600 <= uplink_budget_bytes {
                            match tokio::time::timeout_at(deadline, tunnel_packet_rx.recv()).await
                            {
                                Ok(Some(p)) => {
                                    let seq = cur_state.tx_sequence.fetch_add(1, Ordering::Relaxed);
                                    if let Ok(enc) = wrap_packet_padded(
                                        &cur_state.cipher,
                                        &cur_state.nonce_prefix,
                                        seq,
                                        p,
                                        padding_step,
                                    ) {
                                        frame_packet_into(&mut batch_buf, &enc);
                                        tx_pkts_count += 1;
                                    }
                                    while batch_buf.len() + 1600 <= uplink_budget_bytes {
                                        match tunnel_packet_rx.try_recv() {
                                            Ok(next_p) => {
                                                let seq = cur_state
                                                    .tx_sequence
                                                    .fetch_add(1, Ordering::Relaxed);
                                                if let Ok(enc) = wrap_packet_padded(
                                                    &cur_state.cipher,
                                                    &cur_state.nonce_prefix,
                                                    seq,
                                                    next_p,
                                                    padding_step,
                                                ) {
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

                // Если это пустой фоновый опрос без активного download-кредита — резервируем idle-слот
                let is_pure_idle_poll = payload.is_empty() && !used_credit;
                let idle_guard = if is_pure_idle_poll && config_ahttp.max_idle_polls > 0 {
                    if !try_claim_idle_poll(&inflight_idle_polls, config_ahttp.max_idle_polls) {
                        drop(permit);
                        continue;
                    }
                    IdlePollGuard {
                        counter: inflight_idle_polls.clone(),
                        notify: idle_notify.clone(),
                        active: true,
                    }
                } else {
                    IdlePollGuard {
                        counter: inflight_idle_polls.clone(),
                        notify: idle_notify.clone(),
                        active: false,
                    }
                };

                let worker_client = client_pool[rr_counter % pool_size].clone();
                rr_counter = rr_counter.wrapping_add(1);
                let uplink_method_clone = uplink_method.clone();
                let traffic_base_url_clone = traffic_base_url.clone();
                let profile_ul_clone = profile.clone();
                let origin_ul_clone = origin.clone();
                let referer_ul_clone = referer.clone();
                let state_tx_clone = state_tx.clone();
                let reauth_lock_clone = reauth_lock.clone();
                let reauth_ctx_clone = reauth_ctx.clone();
                let health_pause_clone = loop_health_pause.clone();
                let global_stop_tx_clone = loop_stop_tx.clone();
                let mut worker_stop_rx = loop_stop_rx.clone();
                let downlink_tx_clone = downlink_tx.clone();
                let downlink_notify_clone = downlink_notify.clone();
                let downlink_credits_clone = downlink_credits.clone();
                let consecutive_empty_clone = consecutive_empty_polls.clone();
                let consecutive_failures_clone = consecutive_failures.clone();
                let pool_backoff_clone = pool_backoff_ms.clone();
                let cfg_clone = config_ahttp.clone();

                let req_task = tokio::spawn(async move {
                    let _idle_guard = idle_guard;
                    let mut rx_bytes_total = 0usize;
                    let mut rx_pkts_total = 0usize;
                    let mut got_http_ok = false;

                    let maybe_reconnect_gen = {
                        let _permit = permit;
                        let mut success = false;
                        let mut needs_reconnect = false;
                        let mut attempt: u32 = 0;
                        let max_attempts = cfg_clone.max_retries.saturating_add(1).max(1);
                        let retry_base_ms = cfg_clone.effective_retry_base_ms();
                        let retry_max_ms = cfg_clone.effective_retry_max_ms();

                        if !payload.is_empty() {
                            debug!(
                                "[AHTTP Client] >>> Sending {} bytes ({} packets)",
                                payload.len(),
                                tx_pkts_count
                            );
                        }

                        while attempt < max_attempts {
                            if *worker_stop_rx.borrow() {
                                break;
                            }
                            if state_tx_clone.borrow().gen_id != cur_state.gen_id {
                                // Сессия уже переподключена другим воркером
                                break;
                            }
                            if !wait_pool_backoff(
                                pool_start,
                                &pool_backoff_clone,
                                &mut worker_stop_rx,
                            )
                            .await
                            {
                                break;
                            }

                            let req_url = if cfg_clone.send_session_in_header
                                && !cfg_clone.session_id_header.trim().is_empty()
                            {
                                traffic_base_url_clone.clone()
                            } else {
                                format!(
                                    "{}?{}={}",
                                    traffic_base_url_clone,
                                    cfg_clone.effective_session_id_query_param(),
                                    cur_state.session_id
                                )
                            };

                            let mut req = worker_client
                                .request(uplink_method_clone.clone(), &req_url)
                                .header("Accept", "*/*");
                            if cfg_clone.send_session_in_header
                                && !cfg_clone.session_id_header.trim().is_empty()
                            {
                                req = req.header(
                                    cfg_clone.session_id_header.trim(),
                                    &cur_state.session_id,
                                );
                            }
                            let req = profile_ul_clone.apply_to_reqwest(
                                req,
                                Some(&origin_ul_clone),
                                Some(&referer_ul_clone),
                            );
                            let req = if payload.is_empty() {
                                req
                            } else {
                                req.body(reqwest::Body::from(payload.clone()))
                            };

                            let res = req.send().await;

                            match res {
                                Ok(resp) if resp.status().is_success() => {
                                    match tokio::time::timeout(body_read_timeout, resp.bytes()).await
                                    {
                                        Ok(Ok(body)) => {
                                            got_http_ok = true;
                                            success = true;
                                            if !body.is_empty() {
                                                rx_bytes_total = body.len();
                                                debug!(
                                                    "[AHTTP Client] <<< Received {} bytes",
                                                    rx_bytes_total
                                                );
                                                let mut cursor = std::io::Cursor::new(body);
                                                let mut unpacked_batch = Vec::with_capacity(64);

                                                while let Ok(Some(encrypted_packet)) =
                                                    read_next_packet(&mut cursor).await
                                                {
                                                    if let Ok((seq, decrypted)) =
                                                        unwrap_packet_with_seq(
                                                            &cur_state.cipher,
                                                            &encrypted_packet,
                                                        )
                                                    {
                                                        unpacked_batch.push((seq, decrypted));
                                                    }
                                                }

                                                let rx_pkts_count = unpacked_batch.len();
                                                rx_pkts_total = rx_pkts_count;
                                                if rx_pkts_count > 0 {
                                                    if downlink_tx_clone
                                                        .send((cur_state.gen_id, unpacked_batch))
                                                        .await
                                                        .is_err()
                                                    {
                                                        let _ = global_stop_tx_clone.send(true);
                                                    }
                                                }
                                                debug!(
                                                    "[AHTTP Client] <<< Unpacked {} valid packets",
                                                    rx_pkts_count
                                                );
                                            }
                                            break;
                                        }
                                        Ok(Err(e)) => {
                                            debug!(
                                                "[AHTTP Client] Response body read error (attempt {}/{}): {}",
                                                attempt + 1,
                                                max_attempts,
                                                e
                                            );
                                        }
                                        Err(_) => {
                                            debug!(
                                                "[AHTTP Client] Response body read timed out (attempt {}/{})",
                                                attempt + 1,
                                                max_attempts
                                            );
                                        }
                                    }
                                }
                                Ok(resp) => {
                                    let status = resp.status();
                                    let retry_after = parse_retry_after(
                                        resp.headers(),
                                        retry_max_ms.max(15_000),
                                    );
                                    warn!(
                                        "[AHTTP Client] CDN/Server returned HTTP {} (attempt {}/{})",
                                        status,
                                        attempt + 1,
                                        max_attempts
                                    );
                                    if status == StatusCode::UNAUTHORIZED
                                        || status == StatusCode::NOT_FOUND
                                    {
                                        needs_reconnect = true;
                                        break;
                                    }
                                    if status == StatusCode::TOO_MANY_REQUESTS
                                        || status == StatusCode::SERVICE_UNAVAILABLE
                                    {
                                        let delay = retry_after.unwrap_or_else(|| {
                                            compute_retry_delay(attempt, retry_base_ms, retry_max_ms)
                                        });
                                        schedule_pool_backoff(pool_start, &pool_backoff_clone, delay);
                                    }
                                }
                                Err(e) => {
                                    debug!(
                                        "[AHTTP Client] Request failed (attempt {}/{}): {}",
                                        attempt + 1,
                                        max_attempts,
                                        e
                                    );
                                }
                            }

                            attempt += 1;
                            if attempt < max_attempts {
                                let delay =
                                    compute_retry_delay(attempt - 1, retry_base_ms, retry_max_ms);
                                tokio::select! {
                                    biased;
                                    _ = worker_stop_rx.changed() => break,
                                    _ = tokio::time::sleep(delay) => {}
                                }
                            }
                        }

                        if success {
                            consecutive_failures_clone.store(0, Ordering::Release);
                            None
                        } else if state_tx_clone.borrow().gen_id == cur_state.gen_id {
                            if !payload.is_empty() {
                                warn!(
                                    "[AHTTP Client] Traffic exchange transaction failed after retries. Payload dropped."
                                );
                            }
                            let fails = consecutive_failures_clone.fetch_add(1, Ordering::AcqRel) + 1;
                            if needs_reconnect
                                || (cfg_clone.max_consecutive_failures > 0
                                    && fails >= cfg_clone.max_consecutive_failures)
                            {
                                Some(cur_state.gen_id)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    };

                    if let Some(failed_gen) = maybe_reconnect_gen {
                        let _ = try_reconnect_ahttp(
                            failed_gen,
                            &state_tx_clone,
                            &reauth_lock_clone,
                            &reauth_ctx_clone,
                            &health_pause_clone,
                            &global_stop_tx_clone,
                            &mut worker_stop_rx,
                            &downlink_tx_clone,
                            &consecutive_failures_clone,
                        )
                        .await;
                    }

                    if rx_pkts_total > 0 {
                        consecutive_empty_clone.store(0, Ordering::Release);
                        if rx_bytes_total >= 1300 || rx_pkts_total >= 2 {
                            atomic_add_capped(&downlink_credits_clone, 3, max_concurrency);
                        } else {
                            let _ = downlink_credits_clone.fetch_max(1, Ordering::AcqRel);
                        }
                        downlink_notify_clone.notify_one();
                    } else if got_http_ok && payload.is_empty() {
                        let prev = consecutive_empty_clone.load(Ordering::Acquire);
                        if prev < 32 {
                            let _ = consecutive_empty_clone.compare_exchange(
                                prev,
                                prev + 1,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            );
                        }
                    }
                });
                {
                    let mut guard = inflight_aborts_loop.lock().unwrap();
                    guard.retain(|h| !h.is_finished());
                    guard.push(req_task.abort_handle());
                }

                if tunnel_packet_rx.is_closed() {
                    break;
                }
            }

            let _ = loop_stop_tx.send(true);
            tunnel_reader_task.abort();
            let _ = tunnel_reader_task.await;
            downlink_sink_task.abort();
            let _ = downlink_sink_task.await;
            info!("[AHTTP] Traffic loop exited cleanly.");
        });
        let traffic_loop_abort = traffic_loop_task.abort_handle();

        info!("[AHTTP] Transport session initialized.");

        let shutdown_hook: super::ShutdownHook = Box::pin(async move {
            let _ = global_stop_tx.send(true);
            concurrency_sem_shutdown.close();
            traffic_loop_abort.abort();
            tunnel_reader_abort.abort();
            downlink_sink_abort.abort();
            let mut guard = inflight_aborts.lock().unwrap();
            for h in guard.drain(..) {
                h.abort();
            }
        });

        Ok(ConnectionResult {
            auth_response,
            vpn_stream: Box::new(client_stream),
            endpoint: None,
            connection: None,
            health_pause: Some(health_pause),
            remote_ip: Some(resolved_addr.ip()),
            bypass_ips: Vec::new(),
            effective_mode: None,
            shutdown_hook: Some(shutdown_hook),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue, RETRY_AFTER};

    #[test]
    fn retry_after_parser_handles_numeric_seconds_and_clamping() {
        let mut headers = HeaderMap::new();
        assert!(parse_retry_after(&headers, 15_000).is_none());

        headers.insert(RETRY_AFTER, HeaderValue::from_static("3"));
        assert_eq!(
            parse_retry_after(&headers, 15_000),
            Some(Duration::from_secs(3))
        );

        headers.insert(RETRY_AFTER, HeaderValue::from_static("120"));
        assert_eq!(
            parse_retry_after(&headers, 15_000),
            Some(Duration::from_millis(15_000))
        );

        headers.insert(RETRY_AFTER, HeaderValue::from_static("0"));
        assert_eq!(
            parse_retry_after(&headers, 15_000),
            Some(Duration::from_millis(100))
        );
    }

    #[test]
    fn idle_poll_slot_claim_and_drop_guard_work() {
        let counter = Arc::new(AtomicUsize::new(0));
        let notify = Arc::new(Notify::new());

        assert!(try_claim_idle_poll(&counter, 1));
        assert!(!try_claim_idle_poll(&counter, 1));
        assert_eq!(counter.load(Ordering::Acquire), 1);

        {
            let _guard = IdlePollGuard {
                counter: counter.clone(),
                notify,
                active: true,
            };
        }
        assert_eq!(counter.load(Ordering::Acquire), 0);
        assert!(try_claim_idle_poll(&counter, 1));
    }

    #[test]
    fn atomic_credit_helpers_respect_caps_and_zero_floor() {
        let credits = AtomicUsize::new(1);
        atomic_add_capped(&credits, 3, 3);
        assert_eq!(credits.load(Ordering::Acquire), 3);

        assert!(atomic_try_take(&credits));
        assert!(atomic_try_take(&credits));
        assert!(atomic_try_take(&credits));
        assert_eq!(credits.load(Ordering::Acquire), 0);
        assert!(!atomic_try_take(&credits));
    }
}
