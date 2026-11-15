use super::{ClientTransport, ConnectionResult, ShutdownHook};
use crate::auth::{AuthDenyError, AuthHandler, StreamAuthChannel};
use crate::config::{CoreConfig, ServerConfig};
use anet_common::config::StealthConfig;
use anet_common::consts::{
    normalize_ssh_banner, CHANNEL_BUFFER_SIZE, COALESCE_BUDGET_BYTES, CRYPTO_COALESCE_BUDGET_BYTES,
    MAX_PENDING_JITTER_PACKETS, PADDING_MTU, SSH_CHANNEL_WINDOW_SIZE, SSH_CONNECT_TIMEOUT,
    SSH_MAX_PACKET_SIZE, TRANSPORT_ENVELOPE_OVERHEAD, WRTC_MIN_IP_PACKET_LEN,
};
use anet_common::encryption::Cipher;
use anet_common::padding_utils::calculate_padding_needed;
use anet_common::protocol::AuthResponse;
use anet_common::stream_framing::{frame_packet_into, FrameReader};
use anet_common::transport::{unwrap_packet_bytes_in_place, wrap_packet};
use anyhow::{anyhow, ensure, Context, Result};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures::future::BoxFuture;
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use log::{info, warn};
use rand::{rngs::OsRng, rngs::StdRng, Rng, SeedableRng};
use russh::client::{connect_stream, Config as RusshClientConfig, Handle as RusshHandle, Handler};
use russh::keys::PublicKeyOrCertificate;
use russh::{Error as RusshError, SshId};
use std::future::Future;
use std::future::ready;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::io::{
    duplex, split, AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf,
};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Mutex};
use tokio::task::AbortHandle;
use tokio::time::{sleep, timeout};

struct ClientHandler;

impl Handler for ClientHandler {
    type Error = RusshError;

    fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        // Подлинность конечного узла дополнительно проверяется подписанным ASTP DH-обменом.
        ready(Ok(true))
    }
}

pub struct SshTransport {
    config: CoreConfig,
    server: ServerConfig,
}

impl SshTransport {
    pub fn new(config: CoreConfig, server: ServerConfig) -> Self {
        Self { config, server }
    }
}

struct AuthenticatedSshSession {
    address: SocketAddr,
    session: RusshHandle<ClientHandler>,
    reader: Box<dyn AsyncRead + Unpin + Send>,
    writer: Box<dyn AsyncWrite + Unpin + Send>,
    auth_response: AuthResponse,
    shared_key: [u8; 32],
}

async fn connect_authenticated(
    config: &CoreConfig,
    server: &ServerConfig,
    resume_session_id: Option<String>,
) -> Result<AuthenticatedSshSession> {
    let address = resolve_address(&server.endpoint()?)?;
    let user = server
        .ssh_user
        .as_deref()
        .or(config.transport.ssh_user.as_deref())
        .unwrap_or("root");

    let banner = normalize_ssh_banner(
        server
            .ssh_banner
            .as_deref()
            .or(config.transport.ssh_banner.as_deref()),
    );

    let ssh_config = Arc::new(RusshClientConfig {
        client_id: SshId::Standard(banner.into()),
        window_size: SSH_CHANNEL_WINDOW_SIZE,
        maximum_packet_size: SSH_MAX_PACKET_SIZE,
        channel_buffer_size: CHANNEL_BUFFER_SIZE,
        nodelay: true,
        ..Default::default()
    });

    let stream = timeout(SSH_CONNECT_TIMEOUT, TcpStream::connect(address))
        .await
        .context("timed out connecting to the SSH endpoint")??;
    stream.set_nodelay(true)?;
    info!(
        "[SSH] TCP socket connected to {address} (local: {:?}, nodelay: true)",
        stream.local_addr().ok()
    );
    info!("[SSH] Initiating SSH handshake with user '{user}'");
    let mut session = connect_stream(ssh_config, stream, ClientHandler).await?;

    ensure!(
        session.authenticate_none(user).await?.success(),
        "SSH none authentication was rejected"
    );
    info!("[SSH] Authenticated; opening the VPN channel with exec 'anet-vpn'");

    let channel = session.channel_open_session().await?;
    channel.exec(true, "anet-vpn").await?;
    info!("[SSH] Exec 'anet-vpn' accepted by server; channel stream opened");
    let channel_stream = channel.into_stream();
    let stream = Arc::new(Mutex::new(channel_stream));

    let (auth_response, shared_key) = {
        let auth_channel = StreamAuthChannel::new(stream.clone());
        let auth_handler =
            AuthHandler::new_with_resume(config, server.server_pub_key.as_deref(), resume_session_id)?;
        auth_handler.authenticate_once(&auth_channel).await?
    };
    info!("[SSH] ASTP authenticated; assigned IP {}", auth_response.ip);

    let stream = Arc::try_unwrap(stream)
        .map_err(|_| anyhow!("SSH authentication stream is still shared"))?
        .into_inner();
    let (reader, writer) = split(stream);

    Ok(AuthenticatedSshSession {
        address,
        session,
        reader: Box::new(reader),
        writer: Box::new(writer),
        auth_response,
        shared_key,
    })
}

fn session_lifetime(server: &ServerConfig) -> Option<Duration> {
    if server.ssh_min_session_secs == 0 || server.ssh_max_session_secs == 0 {
        return None;
    }
    let min = server.ssh_min_session_secs.max(30);
    let max = server.ssh_max_session_secs.max(min);
    Some(Duration::from_secs(OsRng.gen_range(min..=max)))
}

async fn wait_rotation(duration: Option<Duration>) {
    match duration {
        Some(d) => sleep(d).await,
        None => std::future::pending::<()>().await,
    }
}

#[async_trait]
impl ClientTransport for SshTransport {
    async fn connect(&self) -> Result<ConnectionResult> {
        let initial = connect_authenticated(&self.config, &self.server, None).await?;
        let auth_response = initial.auth_response.clone();
        let remote_ip = initial.address.ip();
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
                        warn!("[SSH] Server returned invalid nonce prefix");
                        break 'sessions;
                    }
                };
                let sequence = Arc::new(AtomicU64::new(0));
                let stealth = config.stealth.clone();

                let (stop_out_tx, stop_out_rx) = oneshot::channel::<()>();
                let (stop_in_tx, stop_in_rx) = oneshot::channel::<()>();

                let mut outbound = tokio::spawn(send_to_server(
                    t_reader,
                    f_reader,
                    active.writer,
                    stealth,
                    cipher.clone(),
                    sequence,
                    nonce_prefix,
                    stop_out_rx,
                ));
                let mut inbound = tokio::spawn(receive_from_server(
                    active.reader,
                    t_writer,
                    cipher,
                    stop_in_rx,
                ));
                {
                    let mut aborts = worker_aborts_sup.lock().unwrap();
                    aborts.clear();
                    aborts.push(outbound.abort_handle());
                    aborts.push(inbound.abort_handle());
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
                                info!("[SSH] Tunnel closed: client TUN stream closed. Duration: {:.1}s", session_start.elapsed().as_secs_f64());
                                inbound.abort();
                                break 'sessions;
                            }
                            Ok(Err(e)) => {
                                warn!("[SSH] Tunnel outbound stopped: {e:#}. Duration: {:.1}s", session_start.elapsed().as_secs_f64());
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
                                    "[SSH] Tunnel closed: remote SSH server closed channel/connection (EOF). Duration: {:.1}s ({:.2} min)",
                                    session_start.elapsed().as_secs_f64(),
                                    session_start.elapsed().as_secs_f64() / 60.0
                                );
                                outbound.abort();
                                break 'sessions;
                            }
                            Ok(Err(e)) => {
                                warn!("[SSH] Tunnel inbound stopped: {e:#}. Duration: {:.1}s", session_start.elapsed().as_secs_f64());
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

                drop(active.session);
                if !need_rotate {
                    break 'sessions;
                }

                info!("[SSH] Periodic session rotation; reconnecting the same endpoint");
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
                            warn!("[SSH] Rotated session received a different tunnel address");
                        }
                        Ok(Err(error)) => {
                            if error.downcast_ref::<AuthDenyError>().is_some() {
                                warn!("[SSH] Planned reconnect rejected by server: {error}");
                                break;
                            }
                            warn!("[SSH] Planned reconnect attempt failed: {error:#}");
                        }
                        Err(_) => warn!("[SSH] Planned reconnect attempt timed out"),
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
            info!("[SSH] Transport supervisor stopped");
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
            remote_ip: Some(remote_ip),
            bypass_ips: Vec::new(),
            effective_mode: None,
            shutdown_hook: Some(shutdown_hook),
        })
    }
}

fn resolve_address(address: &str) -> Result<SocketAddr> {
    address
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve SSH endpoint {address}"))?
        .next()
        .with_context(|| format!("SSH endpoint {address} resolved to no addresses"))
}

async fn send_to_server(
    mut tunnel_reader: ReadHalf<DuplexStream>,
    mut frame_reader: FrameReader,
    mut writer: Box<dyn AsyncWrite + Unpin + Send>,
    stealth: StealthConfig,
    cipher: Arc<Cipher>,
    sequence: Arc<AtomicU64>,
    nonce_prefix: [u8; 4],
    mut stop_rx: oneshot::Receiver<()>,
) -> Result<Option<(ReadHalf<DuplexStream>, FrameReader)>> {
    let padding_step = stealth.padding_step;
    let jitter_enabled = stealth.max_jitter_ns > stealth.min_jitter_ns;
    let mut rng = StdRng::from_entropy();
    let mut pending = FuturesUnordered::<BoxFuture<'static, Bytes>>::new();
    let mut input_open = true;
    let mut buf = BytesMut::with_capacity(CRYPTO_COALESCE_BUDGET_BYTES);

    let encrypt_into = |packet: Bytes, buf: &mut BytesMut| -> Result<()> {
        let seq = sequence.fetch_add(1, Ordering::Relaxed);
        let total_len = packet.len() + TRANSPORT_ENVELOPE_OVERHEAD;
        let pad = calculate_padding_needed(total_len, padding_step);
        let safe_pad = if total_len + usize::from(pad) > PADDING_MTU {
            0
        } else {
            pad
        };
        let encrypted = wrap_packet(&cipher, &nonce_prefix, seq, packet, safe_pad)?;
        frame_packet_into(buf, &encrypted);
        Ok(())
    };

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

        buf.clear();

        loop {
            if packet.len() >= WRTC_MIN_IP_PACKET_LEN {
                encrypt_into(packet, &mut buf)?;
            }

            if buf.len() >= CRYPTO_COALESCE_BUDGET_BYTES {
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

        if !buf.is_empty() {
            writer.write_all(&buf).await?;
        }
    }

    writer.shutdown().await?;
    Ok(None)
}

async fn receive_from_server(
    mut reader: Box<dyn AsyncRead + Unpin + Send>,
    mut tunnel_writer: WriteHalf<DuplexStream>,
    cipher: Arc<Cipher>,
    mut stop_rx: oneshot::Receiver<()>,
) -> Result<Option<WriteHalf<DuplexStream>>> {
    let mut frame_reader = FrameReader::new();
    let mut write_buf = BytesMut::with_capacity(COALESCE_BUDGET_BYTES);

    loop {
        let encrypted = tokio::select! {
            biased;
            _ = &mut stop_rx => {
                return Ok(Some(tunnel_writer));
            }
            pkt_res = frame_reader.read_next_packet(&mut reader) => {
                match pkt_res? {
                    Some(p) => p,
                    None => break,
                }
            }
        };

        write_buf.clear();
        let packet = unwrap_packet_bytes_in_place(&cipher, encrypted)?;
        frame_packet_into(&mut write_buf, &packet);

        while write_buf.len() < COALESCE_BUDGET_BYTES {
            match frame_reader.try_next_packet()? {
                Some(next_enc) => {
                    let next_pkt = unwrap_packet_bytes_in_place(&cipher, next_enc)?;
                    frame_packet_into(&mut write_buf, &next_pkt);
                }
                None => break,
            }
        }

        tunnel_writer.write_all(&write_buf).await?;
    }

    tunnel_writer.shutdown().await?;
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

#[cfg(test)]
mod tests {
    use anet_common::consts::{DEFAULT_SSH_BANNER, normalize_ssh_banner};

    #[test]
    fn ssh_banner_masks_russh_signature() {
        let default_banner = normalize_ssh_banner(None);
        assert_eq!(default_banner, DEFAULT_SSH_BANNER);
        assert!(default_banner.starts_with("SSH-2.0-OpenSSH_"));
        assert!(!default_banner.contains("russh"));

        let custom_without_prefix = normalize_ssh_banner(Some("OpenSSH_9.2p1 Debian-2+deb12u3\r\n"));
        assert_eq!(custom_without_prefix, "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3");
    }
}
