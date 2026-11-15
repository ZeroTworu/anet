use super::{ClientTransport, ConnectionResult, ShutdownHook};
use crate::auth::{AuthChannel, AuthDenyError, AuthHandler};
use crate::config::{CoreConfig, ServerConfig};
use anet_common::config::StealthConfig;
use anet_common::consts::{
    COALESCE_BUDGET_BYTES, CRYPTO_COALESCE_BUDGET_BYTES, MAX_PENDING_JITTER_PACKETS, PADDING_MTU,
    RFB_HANDSHAKE_TIMEOUT, TRANSPORT_ENVELOPE_OVERHEAD, WRTC_MIN_IP_PACKET_LEN,
};
use anet_common::encryption::Cipher;
use anet_common::handshake_fragmentation::{write_fragmented, FragmentConfig};
use anet_common::padding_utils::calculate_padding_needed;
use anet_common::protocol::AuthResponse;
use anet_common::stream_framing::{frame_packet_into, FrameReader};
use anet_common::transport::{unwrap_packet_bytes_in_place, wrap_packet};
use anet_common::vnc::{
    encode_cut_text, read_cut_text, CLIENT_CUT_TEXT, RFB_VERSION, SECURITY_TYPE_NONE,
    SERVER_CUT_TEXT,
};
use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures::future::BoxFuture;
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use log::{info, warn};
use rand::{rngs::OsRng, rngs::StdRng, Rng, SeedableRng};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::io::{
    duplex, split, AsyncReadExt, AsyncWriteExt, BufReader, DuplexStream, ReadHalf, WriteHalf,
};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Mutex};
use tokio::task::AbortHandle;
use tokio::time::{sleep, timeout};

struct VncAuthChannel {
    stream: Mutex<TcpStream>,
}

#[async_trait]
impl AuthChannel for VncAuthChannel {
    async fn send(&self, data: Bytes, fragmentation: &FragmentConfig) -> Result<()> {
        let frame = encode_cut_text(CLIENT_CUT_TEXT, &data)?;
        let mut stream = self.stream.lock().await;
        write_fragmented(&mut *stream, &frame, fragmentation).await?;
        Ok(())
    }

    async fn recv(&self, recv_timeout: Duration) -> Result<Bytes> {
        let mut stream = self.stream.lock().await;
        timeout(recv_timeout, read_cut_text(&mut *stream, SERVER_CUT_TEXT))
            .await
            .context("timed out waiting for the VNC authentication response")??
            .context("VNC server closed during authentication")
    }
}

pub struct VncTransport {
    config: CoreConfig,
    server: ServerConfig,
}

impl VncTransport {
    pub fn new(config: CoreConfig, server: ServerConfig) -> Self {
        Self { config, server }
    }
}

struct AuthenticatedVncSession {
    addr: SocketAddr,
    stream: TcpStream,
    auth_response: AuthResponse,
    shared_key: [u8; 32],
}

async fn connect_authenticated(
    config: &CoreConfig,
    server: &ServerConfig,
    resume_session_id: Option<String>,
) -> Result<AuthenticatedVncSession> {
    let addr = resolve_address(&server.endpoint()?)?;
    info!("[VNC] Connecting to RFB endpoint {addr}");

    let mut stream = timeout(RFB_HANDSHAKE_TIMEOUT, TcpStream::connect(addr))
        .await
        .context("timed out connecting to the VNC endpoint")??;
    stream.set_nodelay(true)?;
    info!(
        "[VNC] TCP socket connected to {addr} (local: {:?}, nodelay: true)",
        stream.local_addr().ok()
    );
    timeout(
        RFB_HANDSHAKE_TIMEOUT,
        emulate_rfb_client_handshake(&mut stream),
    )
    .await
    .context("timed out during the VNC handshake")??;

    info!("[VNC] RFB handshake complete; starting ASTP authentication");
    let auth_channel = VncAuthChannel {
        stream: Mutex::new(stream),
    };
    let auth_handler =
        AuthHandler::new_with_resume(config, server.server_pub_key.as_deref(), resume_session_id)?;
    let (auth_response, shared_key) = auth_handler.authenticate_once(&auth_channel).await?;
    info!("[VNC] ASTP authenticated; assigned IP {}", auth_response.ip);

    let stream = auth_channel.stream.into_inner();
    Ok(AuthenticatedVncSession {
        addr,
        stream,
        auth_response,
        shared_key,
    })
}

fn session_lifetime(server: &ServerConfig) -> Option<Duration> {
    if server.vnc_min_session_secs == 0 || server.vnc_max_session_secs == 0 {
        return None;
    }
    let min = server.vnc_min_session_secs.max(30);
    let max = server.vnc_max_session_secs.max(min);
    Some(Duration::from_secs(OsRng.gen_range(min..=max)))
}

async fn wait_rotation(duration: Option<Duration>) {
    match duration {
        Some(d) => sleep(d).await,
        None => std::future::pending::<()>().await,
    }
}

#[async_trait]
impl ClientTransport for VncTransport {
    async fn connect(&self) -> Result<ConnectionResult> {
        let initial = connect_authenticated(&self.config, &self.server, None).await?;
        let auth_response = initial.auth_response.clone();
        let remote_ip = initial.addr.ip();
        let expected_ip = auth_response.ip.clone();
        let expected_gateway = auth_response.gateway.clone();
        let logical_session_id = auth_response.session_id.clone();

        let (client_stream, internal_stream) = duplex(512 * 1024);
        let (tunnel_reader, tunnel_writer) = split(internal_stream);

        let health_pause = Arc::new(AtomicBool::new(false));
        let supervisor_health_pause = health_pause.clone();
        let config = self.config.clone();
        let server = self.server.clone();
        let worker_aborts: Arc<StdMutex<Vec<AbortHandle>>> = Arc::new(StdMutex::new(Vec::new()));
        let worker_aborts_sup = worker_aborts.clone();

        let supervisor_task = tokio::spawn(async move {
            let mut active = initial;
            let mut tunnel_reader_opt = Some(tunnel_reader);
            let mut tunnel_writer_opt = Some(tunnel_writer);
            let mut frame_reader_opt = Some(FrameReader::new());

            'sessions: loop {
                let Some(t_reader) = tunnel_reader_opt.take() else { break 'sessions; };
                let Some(t_writer) = tunnel_writer_opt.take() else { break 'sessions; };
                let f_reader = frame_reader_opt.take().unwrap_or_else(FrameReader::new);

                let session_start = Instant::now();
                let cipher = Arc::new(Cipher::new(&active.shared_key));
                let nonce_prefix: [u8; 4] = match active.auth_response.nonce_prefix.as_slice().try_into() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!("[VNC] Server returned invalid nonce prefix");
                        break 'sessions;
                    }
                };
                let sequence = Arc::new(AtomicU64::new(0));
                let stealth = config.stealth.clone();
                let (reader, writer) = split(active.stream);

                let (stop_out_tx, stop_out_rx) = oneshot::channel::<()>();
                let (stop_in_tx, stop_in_rx) = oneshot::channel::<()>();

                let mut inbound = tokio::spawn(receive_from_server(
                    reader,
                    t_writer,
                    cipher.clone(),
                    stop_in_rx,
                ));
                let mut outbound = tokio::spawn(send_to_server(
                    t_reader,
                    f_reader,
                    writer,
                    cipher,
                    sequence,
                    nonce_prefix,
                    stealth,
                    stop_out_rx,
                ));
                {
                    let mut aborts = worker_aborts_sup.lock().unwrap();
                    aborts.clear();
                    aborts.push(inbound.abort_handle());
                    aborts.push(outbound.abort_handle());
                }

                let rotation_dur = session_lifetime(&server);
                let mut need_rotate = false;
                let mut stop_out_tx = Some(stop_out_tx);
                let mut stop_in_tx = Some(stop_in_tx);

                tokio::select! {
                    res_out = &mut outbound => {
                        if let Some(tx) = stop_in_tx.take() {
                            let _ = tx.send(());
                        }
                        match res_out {
                            Ok(Ok(Some((r, fr)))) => {
                                tunnel_reader_opt = Some(r);
                                frame_reader_opt = Some(fr);
                            }
                            Ok(Ok(None)) => {
                                info!("[VNC] Tunnel closed: client TUN stream closed. Duration: {:.1}s", session_start.elapsed().as_secs_f64());
                                inbound.abort();
                                break 'sessions;
                            }
                            Ok(Err(e)) => {
                                warn!("[VNC] Tunnel outbound stopped: {e:#}. Duration: {:.1}s", session_start.elapsed().as_secs_f64());
                                inbound.abort();
                                break 'sessions;
                            }
                            Err(_) => {
                                inbound.abort();
                                break 'sessions;
                            }
                        }
                        match inbound.await {
                            Ok(Ok(Some(w))) => tunnel_writer_opt = Some(w),
                            _ => break 'sessions,
                        }
                    }
                    res_in = &mut inbound => {
                        if let Some(tx) = stop_out_tx.take() {
                            let _ = tx.send(());
                        }
                        match res_in {
                            Ok(Ok(Some(w))) => tunnel_writer_opt = Some(w),
                            Ok(Ok(None)) => {
                                info!(
                                    "[VNC] Tunnel closed: remote VNC server closed TCP connection (EOF). Duration: {:.1}s ({:.2} min)",
                                    session_start.elapsed().as_secs_f64(),
                                    session_start.elapsed().as_secs_f64() / 60.0
                                );
                                outbound.abort();
                                break 'sessions;
                            }
                            Ok(Err(e)) => {
                                warn!("[VNC] Tunnel inbound stopped: {e:#}. Duration: {:.1}s", session_start.elapsed().as_secs_f64());
                                outbound.abort();
                                break 'sessions;
                            }
                            Err(_) => {
                                outbound.abort();
                                break 'sessions;
                            }
                        }
                        match outbound.await {
                            Ok(Ok(Some((r, fr)))) => {
                                tunnel_reader_opt = Some(r);
                                frame_reader_opt = Some(fr);
                            }
                            _ => break 'sessions,
                        }
                    }
                    _ = wait_rotation(rotation_dur) => {
                        need_rotate = true;
                        supervisor_health_pause.store(true, Ordering::Release);
                        if let Some(tx) = stop_out_tx.take() {
                            let _ = tx.send(());
                        }
                        if let Some(tx) = stop_in_tx.take() {
                            let _ = tx.send(());
                        }
                        match outbound.await {
                            Ok(Ok(Some((r, fr)))) => {
                                tunnel_reader_opt = Some(r);
                                frame_reader_opt = Some(fr);
                            }
                            _ => {
                                inbound.abort();
                                break 'sessions;
                            }
                        }
                        match inbound.await {
                            Ok(Ok(Some(w))) => tunnel_writer_opt = Some(w),
                            _ => break 'sessions,
                        }
                    }
                }

                if !need_rotate {
                    break 'sessions;
                }

                info!("[VNC] Periodic session rotation; reconnecting the same endpoint");
                let gap_ms = OsRng.gen_range(350..=1200);
                sleep(Duration::from_millis(gap_ms)).await;

                let deadline = Instant::now() + Duration::from_secs(server.timeout_secs.max(10) * 3);
                let mut reconnected = None;
                while Instant::now() < deadline {
                    match timeout(
                        Duration::from_secs(server.timeout_secs.max(10)),
                        connect_authenticated(&config, &server, Some(logical_session_id.clone())),
                    )
                    .await
                    {
                        Ok(Ok(candidate)) => {
                            if candidate.auth_response.ip == expected_ip
                                && candidate.auth_response.gateway == expected_gateway
                            {
                                reconnected = Some(candidate);
                                break;
                            }
                            warn!("[VNC] Rotated session received a different tunnel address");
                        }
                        Ok(Err(error)) => {
                            if error.downcast_ref::<AuthDenyError>().is_some() {
                                warn!("[VNC] Planned reconnect rejected by server: {error}");
                                break;
                            }
                            warn!("[VNC] Planned reconnect attempt failed: {error:#}");
                        }
                        Err(_) => warn!("[VNC] Planned reconnect attempt timed out"),
                    }
                    let delay_ms = OsRng.gen_range(350..=1400);
                    sleep(Duration::from_millis(delay_ms)).await;
                }

                match reconnected {
                    Some(new_sess) => {
                        active = new_sess;
                        supervisor_health_pause.store(false, Ordering::Release);
                    }
                    None => break 'sessions,
                }
            }
            supervisor_health_pause.store(false, Ordering::Release);
            info!("[VNC] Transport supervisor stopped");
        });

        let supervisor_abort = supervisor_task.abort_handle();
        let shutdown_hook: ShutdownHook = Box::pin(async move {
            supervisor_abort.abort();
            if let Ok(mut aborts) = worker_aborts.lock() {
                for h in aborts.drain(..) {
                    h.abort();
                }
            }
        });

        Ok(ConnectionResult {
            auth_response,
            vpn_stream: Box::new(client_stream),
            endpoint: None,
            connection: None,
            health_pause: Some(health_pause),
            remote_ip: Some(remote_ip), // Передаем IP в bypass
            bypass_ips: Vec::new(),
            effective_mode: None,
            shutdown_hook: Some(shutdown_hook),
        })
    }
}

fn resolve_address(address: &str) -> Result<SocketAddr> {
    address
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve VNC endpoint {address}"))?
        .next()
        .with_context(|| format!("VNC endpoint {address} resolved to no addresses"))
}

async fn emulate_rfb_client_handshake(stream: &mut TcpStream) -> Result<()> {
    let mut version = [0; 12];
    stream.read_exact(&mut version).await?;
    ensure!(&version == RFB_VERSION, "server does not speak RFB 3.8");
    stream.write_all(RFB_VERSION).await?;

    let security_count = stream.read_u8().await?;
    ensure!(security_count > 0, "VNC server offered no security types");
    let mut security_types = vec![0; usize::from(security_count)];
    stream.read_exact(&mut security_types).await?;
    ensure!(
        security_types.contains(&SECURITY_TYPE_NONE),
        "VNC server did not offer the negotiated security type"
    );
    stream.write_u8(SECURITY_TYPE_NONE).await?;

    let security_result = stream.read_u32().await?;
    ensure!(
        security_result == 0,
        "VNC server rejected security negotiation"
    );
    stream.write_u8(1).await?;

    read_server_init(stream).await
}

async fn read_server_init(stream: &mut TcpStream) -> Result<()> {
    let mut fixed = [0; 24];
    stream.read_exact(&mut fixed).await?;
    let width = u16::from_be_bytes(fixed[0..2].try_into().expect("fixed-size field"));
    let height = u16::from_be_bytes(fixed[2..4].try_into().expect("fixed-size field"));
    ensure!(
        width > 0 && height > 0,
        "VNC server returned an invalid desktop size"
    );

    let name_len = u32::from_be_bytes(fixed[20..24].try_into().expect("fixed-size field")) as usize;
    ensure!(name_len <= 1024, "VNC desktop name is too large");
    let mut name = vec![0; name_len];
    stream.read_exact(&mut name).await?;
    Ok(())
}

async fn send_to_server(
    mut tunnel_reader: ReadHalf<DuplexStream>,
    mut frame_reader: FrameReader,
    mut writer: WriteHalf<TcpStream>,
    cipher: Arc<Cipher>,
    sequence: Arc<AtomicU64>,
    nonce_prefix: [u8; 4],
    stealth: StealthConfig,
    mut stop_rx: oneshot::Receiver<()>,
) -> Result<Option<(ReadHalf<DuplexStream>, FrameReader)>> {
    let mut rng = StdRng::from_entropy();
    let jitter_enabled = stealth.max_jitter_ns > stealth.min_jitter_ns;
    let mut pending = FuturesUnordered::<BoxFuture<'static, Bytes>>::new();
    let mut input_open = true;

    let mut batch_buf = BytesMut::with_capacity(CRYPTO_COALESCE_BUDGET_BYTES);
    let mut pkt_count = 0u64;
    let mut byte_count = 0u64;
    let start = Instant::now();

    while input_open || !pending.is_empty() {
        let mut packet = if !jitter_enabled {
            tokio::select! {
                biased;
                _ = &mut stop_rx => {
                    let _ = writer.shutdown().await;
                    return Ok(Some((tunnel_reader, frame_reader)));
                }
                pkt_res = frame_reader.read_next_packet(&mut tunnel_reader) => {
                    match pkt_res? {
                        Some(packet) => packet,
                        None => return Ok(None),
                    }
                }
            }
        } else if pending.is_empty() {
            tokio::select! {
                biased;
                _ = &mut stop_rx => {
                    let _ = writer.shutdown().await;
                    return Ok(Some((tunnel_reader, frame_reader)));
                }
                pkt_res = frame_reader.read_next_packet(&mut tunnel_reader) => {
                    match pkt_res? {
                        Some(packet) => {
                            schedule_with_jitter(&mut pending, packet, &stealth, &mut rng);
                            while let Some(next_pkt) = frame_reader.try_next_packet()? {
                                schedule_with_jitter(&mut pending, next_pkt, &stealth, &mut rng);
                            }
                            continue;
                        }
                        None => {
                            input_open = false;
                            continue;
                        }
                    }
                }
            }
        } else if !input_open || pending.len() >= MAX_PENDING_JITTER_PACKETS {
            tokio::select! {
                biased;
                _ = &mut stop_rx => {
                    let _ = writer.shutdown().await;
                    return Ok(Some((tunnel_reader, frame_reader)));
                }
                packet = pending.next() => packet.expect("pending jitter queue is not empty"),
            }
        } else {
            tokio::select! {
                biased;
                _ = &mut stop_rx => {
                    let _ = writer.shutdown().await;
                    return Ok(Some((tunnel_reader, frame_reader)));
                }
                res = frame_reader.read_next_packet(&mut tunnel_reader) => {
                    match res? {
                        Some(packet) => {
                            schedule_with_jitter(&mut pending, packet, &stealth, &mut rng);
                            while let Some(next_pkt) = frame_reader.try_next_packet()? {
                                schedule_with_jitter(&mut pending, next_pkt, &stealth, &mut rng);
                            }
                            continue;
                        }
                        None => {
                            input_open = false;
                            continue;
                        }
                    }
                }
                packet = pending.next() => packet.expect("pending jitter queue is not empty"),
            }
        };

        batch_buf.clear();

        loop {
            if packet.len() >= WRTC_MIN_IP_PACKET_LEN {
                pkt_count += 1;
                let seq = sequence.fetch_add(1, Ordering::Relaxed);
                let total_len = packet.len() + TRANSPORT_ENVELOPE_OVERHEAD;
                let padding = calculate_padding_needed(total_len, stealth.padding_step);
                let safe_padding = if total_len + usize::from(padding) > PADDING_MTU {
                    0
                } else {
                    padding
                };

                let encrypted = wrap_packet(&cipher, &nonce_prefix, seq, packet, safe_padding)?;

                if let Ok(frame) = encode_cut_text(CLIENT_CUT_TEXT, &encrypted) {
                    batch_buf.extend_from_slice(&frame);
                }
            }

            if batch_buf.len() >= CRYPTO_COALESCE_BUDGET_BYTES {
                break;
            }

            if !jitter_enabled {
                match frame_reader.try_next_packet()? {
                    Some(p) => packet = p,
                    None => break,
                }
            } else {
                match pending.next().now_or_never().flatten() {
                    Some(p) => packet = p,
                    None => break,
                }
            }
        }

        if !batch_buf.is_empty() {
            byte_count += batch_buf.len() as u64;
            if let Err(e) = writer.write_all(&batch_buf).await {
                warn!(
                    "[VNC/Tx] TCP write failed on batch ({} bytes): {e:#}. Sent so far: {} packets, {} bytes in {:.1}s",
                    batch_buf.len(),
                    pkt_count,
                    byte_count,
                    start.elapsed().as_secs_f64()
                );
                return Err(e.into());
            }
        }
    }
    info!(
        "[VNC/Tx] Finished outbound stream. Total sent: {} packets, {} bytes in {:.1}s",
        pkt_count,
        byte_count,
        start.elapsed().as_secs_f64()
    );
    writer.shutdown().await?;
    Ok(None)
}

fn schedule_with_jitter(
    pending: &mut FuturesUnordered<BoxFuture<'static, Bytes>>,
    packet: Bytes,
    stealth: &StealthConfig,
    rng: &mut StdRng,
) {
    let delay = rng.gen_range(stealth.min_jitter_ns..=stealth.max_jitter_ns);
    pending.push(
        async move {
            if delay > 0 {
                sleep(Duration::from_nanos(delay)).await;
            }
            packet
        }
        .boxed(),
    );
}

async fn receive_from_server(
    reader: ReadHalf<TcpStream>,
    mut tunnel_writer: WriteHalf<DuplexStream>,
    cipher: Arc<Cipher>,
    mut stop_rx: oneshot::Receiver<()>,
) -> Result<Option<WriteHalf<DuplexStream>>> {
    let mut reader = BufReader::with_capacity(64 * 1024, reader);
    let mut write_buf = BytesMut::with_capacity(COALESCE_BUDGET_BYTES);
    let mut pkt_count = 0u64;
    let mut byte_count = 0u64;
    let start = Instant::now();
    let mut last_rx = start;

    loop {
        let encrypted = tokio::select! {
            biased;
            _ = &mut stop_rx => {
                return Ok(Some(tunnel_writer));
            }
            pkt_res = read_cut_text(&mut reader, SERVER_CUT_TEXT) => {
                match pkt_res? {
                    Some(p) => p,
                    None => break,
                }
            }
        };

        write_buf.clear();
        pkt_count += 1;
        byte_count += encrypted.len() as u64;
        last_rx = Instant::now();

        let packet = match unwrap_packet_bytes_in_place(&cipher, encrypted) {
            Ok(p) => p,
            Err(e) => {
                warn!("[VNC/Rx] Failed to unwrap/decrypt frame #{pkt_count}: {e:#}");
                return Err(e.into());
            }
        };
        frame_packet_into(&mut write_buf, &packet);

        while !reader.buffer().is_empty() && write_buf.len() < COALESCE_BUDGET_BYTES {
            match read_cut_text(&mut reader, SERVER_CUT_TEXT).await? {
                Some(next_enc) => {
                    pkt_count += 1;
                    byte_count += next_enc.len() as u64;
                    last_rx = Instant::now();
                    let next_pkt = match unwrap_packet_bytes_in_place(&cipher, next_enc) {
                        Ok(p) => p,
                        Err(e) => {
                            warn!("[VNC/Rx] Failed to unwrap/decrypt frame #{pkt_count}: {e:#}");
                            return Err(e.into());
                        }
                    };
                    frame_packet_into(&mut write_buf, &next_pkt);
                }
                None => break,
            }
        }

        tunnel_writer.write_all(&write_buf).await?;
    }

    info!(
        "[VNC/Rx] Server closed RFB connection (clean TCP EOF / FIN). Total received: {} frames, {} bytes in {:.1}s (last frame was {:.3}s ago)",
        pkt_count,
        byte_count,
        start.elapsed().as_secs_f64(),
        last_rx.elapsed().as_secs_f64()
    );
    tunnel_writer.shutdown().await?;
    Ok(None)
}
