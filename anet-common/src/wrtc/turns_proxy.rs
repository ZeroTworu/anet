use bytes::BytesMut;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::task::AbortHandle;
use tokio::time::{sleep_until, Instant as TokioInstant};

const TURNS_MAX_CONCURRENT_SESSIONS: usize = 64;
const TURNS_SESSION_QUEUE_CAPACITY: usize = 512;
const TURNS_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(180);

/// Удерживает фоновую задачу локального UDP <-> TURNS (TLS 1.3 TCP:443) моста.
/// При дропе `TurnsProxyHandle` останавливаются и главный цикл, и все дочерние клиентские сессии.
pub struct TurnsProxyHandle {
    pub local_turn_url: String,
    pub remote_url: String,
    pub local_addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
    session_tasks: Arc<StdMutex<Vec<AbortHandle>>>,
}

impl std::fmt::Debug for TurnsProxyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnsProxyHandle")
            .field("local_turn_url", &self.local_turn_url)
            .field("remote_url", &self.remote_url)
            .field("local_addr", &self.local_addr)
            .finish()
    }
}

impl Drop for TurnsProxyHandle {
    fn drop(&mut self) {
        self.task.abort();
        if let Ok(mut guard) = self.session_tasks.lock() {
            for handle in guard.drain(..) {
                handle.abort();
            }
        }
    }
}

/// Поднимает локальный прозрачный мост `UDP (127.0.0.1:0) <-> TURNS (TLS 1.3 TCP:443)` или `TURN-TCP`.
///
/// На всех платформах (Android, iOS, Linux, Windows, macOS) `webrtc-rs` общается с этим
/// мостом по `127.0.0.1` через loopback-сокет в `HybridAsyncUdpSocket` (мимо `tun0`),
/// а сам мост устанавливает настоящее TLS 1.3 TCP:443 соединение через BoringSSL (Chrome Mimicry) с SNI `host`
/// (например, `bst-talk-stun7.ktalk.host:443` или `dtl-talk-stun5.ktalk.host:443`)
/// и инкапсулирует STUN и TURN `ChannelData` по RFC 5766 §11.4 / §11.5.
/// Каждый локальный UDP-порт `src: SocketAddr` получает изолированную TLS/TCP-сессию к TURN-серверу,
/// что исключает ошибку `437 Allocation Mismatch` при мультисокетном ICE (`udp_ice_socket_count > 1`).
pub fn spawn_turns_udp_proxy(
    host: String,
    resolved_ips: Vec<IpAddr>,
    port: u16,
    use_tls: bool,
    remote_url: String,
    connect_timeout: Duration,
    udp_buf_size: usize,
) -> anyhow::Result<TurnsProxyHandle> {
    let std_sock = std::net::UdpSocket::bind("127.0.0.1:0")?;
    std_sock.set_nonblocking(true)?;
    let sock_ref = socket2::SockRef::from(&std_sock);
    let buf_sz = udp_buf_size.max(2 * 1024 * 1024);
    let _ = sock_ref.set_recv_buffer_size(buf_sz);
    let _ = sock_ref.set_send_buffer_size(buf_sz);

    let local_addr = std_sock.local_addr()?;
    let udp_sock = Arc::new(UdpSocket::from_std(std_sock)?);
    let local_turn_url = format!("turn:{local_addr}");

    log::info!(
        "[WRTC TURNS Proxy] Bound local UDP bridge {} -> {} (TLS={}, SNI={}:{}, pre_resolved_ips={:?})",
        local_turn_url,
        remote_url,
        use_tls,
        host,
        port,
        resolved_ips
    );

    let remote_url_log = remote_url.clone();
    let session_tasks: Arc<StdMutex<Vec<AbortHandle>>> = Arc::new(StdMutex::new(Vec::new()));
    let session_tasks_bg = Arc::clone(&session_tasks);

    let task = tokio::spawn(async move {
        run_turns_proxy_loop(
            udp_sock,
            host,
            resolved_ips,
            port,
            use_tls,
            remote_url_log,
            connect_timeout,
            session_tasks_bg,
        )
        .await;
    });

    Ok(TurnsProxyHandle {
        local_turn_url,
        remote_url,
        local_addr,
        task,
        session_tasks,
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_turns_proxy_loop(
    udp_sock: Arc<UdpSocket>,
    host: String,
    resolved_ips: Vec<IpAddr>,
    port: u16,
    use_tls: bool,
    remote_url: String,
    connect_timeout: Duration,
    session_tasks: Arc<StdMutex<Vec<AbortHandle>>>,
) {
    let mut sessions: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut buf = vec![0u8; 65536];

    while let Ok((n, src)) = udp_sock.recv_from(&mut buf).await {
        if n < 4 {
            continue;
        }
        let pkt = buf[..n].to_vec();

        if let Some(tx) = sessions.get(&src) {
            match tx.try_send(pkt) {
                Ok(()) => continue,
                Err(TrySendError::Full(_)) => continue,
                Err(TrySendError::Closed(returned_pkt)) => {
                    sessions.remove(&src);
                    spawn_client_turn_session(
                        src,
                        returned_pkt,
                        &mut sessions,
                        &udp_sock,
                        &host,
                        &resolved_ips,
                        port,
                        use_tls,
                        &remote_url,
                        connect_timeout,
                        &session_tasks,
                    );
                    continue;
                }
            }
        }

        // Периодически очищаем завершённые каналы перед добавлением нового клиента
        sessions.retain(|_, tx| !tx.is_closed());
        if sessions.len() >= TURNS_MAX_CONCURRENT_SESSIONS {
            log::warn!(
                "[WRTC TURNS Proxy] Concurrent session cap ({TURNS_MAX_CONCURRENT_SESSIONS}) reached for {remote_url}; dropping new client {src}"
            );
            continue;
        }

        spawn_client_turn_session(
            src,
            pkt,
            &mut sessions,
            &udp_sock,
            &host,
            &resolved_ips,
            port,
            use_tls,
            &remote_url,
            connect_timeout,
            &session_tasks,
        );
    }

    if let Ok(mut guard) = session_tasks.lock() {
        for handle in guard.drain(..) {
            handle.abort();
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_client_turn_session(
    src: SocketAddr,
    first_pkt: Vec<u8>,
    sessions: &mut HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>,
    udp_sock: &Arc<UdpSocket>,
    host: &str,
    resolved_ips: &[IpAddr],
    port: u16,
    use_tls: bool,
    remote_url: &str,
    connect_timeout: Duration,
    session_tasks: &Arc<StdMutex<Vec<AbortHandle>>>,
) {
    let (pkt_tx, mut pkt_rx) = mpsc::channel::<Vec<u8>>(TURNS_SESSION_QUEUE_CAPACITY);
    sessions.insert(src, pkt_tx);

    let udp_sock_c = Arc::clone(udp_sock);
    let host_c = host.to_string();
    let mut ips_c = resolved_ips.to_vec();
    // Приоритизируем IPv4 перед IPv6, чтобы исключить неработающий IPv6 при перехвате маршрутов
    ips_c.sort_by_key(|ip| if ip.is_ipv4() { 0u8 } else { 1u8 });
    let remote_url_c = remote_url.to_string();

    let handle = tokio::spawn(async move {
        let target_addr_str = format!("{host_c}:{port}");
        let mut tcp_opt: Option<TcpStream> = None;
        let mut last_err_str: Option<String> = None;

        for ip in &ips_c {
            let sock_addr = SocketAddr::new(*ip, port);
            let per_ip_timeout = connect_timeout.min(Duration::from_secs(3));
            match tokio::time::timeout(per_ip_timeout, TcpStream::connect(sock_addr)).await {
                Ok(Ok(tcp)) => {
                    let _ = tcp.set_nodelay(true);
                    let sock_ref = socket2::SockRef::from(&tcp);
                    let _ = sock_ref.set_recv_buffer_size(4 * 1024 * 1024);
                    let _ = sock_ref.set_send_buffer_size(4 * 1024 * 1024);
                    tcp_opt = Some(tcp);
                    break;
                }
                Ok(Err(e)) => {
                    last_err_str = Some(format!("{sock_addr}: {e}"));
                }
                Err(_) => {
                    last_err_str = Some(format!("{sock_addr}: timed out after {per_ip_timeout:?}"));
                }
            }
        }

        if tcp_opt.is_none() {
            let connect_res = tokio::time::timeout(connect_timeout, async {
                let tcp = TcpStream::connect(&target_addr_str).await?;
                let _ = tcp.set_nodelay(true);
                let sock_ref = socket2::SockRef::from(&tcp);
                let _ = sock_ref.set_recv_buffer_size(4 * 1024 * 1024);
                let _ = sock_ref.set_send_buffer_size(4 * 1024 * 1024);
                Ok::<TcpStream, std::io::Error>(tcp)
            })
            .await;

            match connect_res {
                Ok(Ok(s)) => tcp_opt = Some(s),
                Ok(Err(e)) => {
                    last_err_str = Some(format!("{target_addr_str}: {e}"));
                }
                Err(_) => {
                    last_err_str = Some(format!("{target_addr_str}: timed out after {connect_timeout:?}"));
                }
            }
        }

        let Some(tcp_stream) = tcp_opt else {
            log::warn!(
                "[WRTC TURNS Proxy] TCP connect to {remote_url_c} ({target_addr_str}) for {src} failed: {}",
                last_err_str.unwrap_or_else(|| "unknown error".to_string())
            );
            return;
        };

        let remote_peer_ip = tcp_stream.peer_addr().ok();

        if use_tls {
            let tls_res = tokio::time::timeout(
                connect_timeout,
                crate::boring_tls::connect_raw_tls(&host_c, tcp_stream),
            )
            .await;

            match tls_res {
                Ok(Ok(tls_stream)) => {
                    log::info!(
                        "[WRTC TURNS Proxy] Connected TLS 1.3 session to {} (remote_addr={:?}, client={}) via BoringSSL",
                        remote_url_c,
                        remote_peer_ip,
                        src
                    );
                    let (reader, writer) = tokio::io::split(tls_stream);
                    bridge_turn_stream(
                        reader,
                        writer,
                        &udp_sock_c,
                        src,
                        &mut pkt_rx,
                        first_pkt,
                        &remote_url_c,
                    )
                    .await;
                }
                Ok(Err(e)) => {
                    log::warn!(
                        "[WRTC TURNS Proxy] TLS handshake with {remote_url_c} for {src} failed: {e}"
                    );
                }
                Err(_) => {
                    log::warn!(
                        "[WRTC TURNS Proxy] TLS handshake with {remote_url_c} for {src} timed out after {:?}",
                        connect_timeout
                    );
                }
            }
        } else {
            log::info!(
                "[WRTC TURNS Proxy] Connected TCP TURN session to {} (remote_addr={:?}, client={})",
                remote_url_c,
                remote_peer_ip,
                src
            );
            let (reader, writer) = tokio::io::split(tcp_stream);
            bridge_turn_stream(
                reader,
                writer,
                &udp_sock_c,
                src,
                &mut pkt_rx,
                first_pkt,
                &remote_url_c,
            )
            .await;
        }
    })
    .abort_handle();

    if let Ok(mut guard) = session_tasks.lock() {
        guard.retain(|h| !h.is_finished());
        guard.push(handle);
    }
}

/// Выполняет полнодуплексный бриджинг STUN / TURN `ChannelData` между потоком TCP/TLS (RFC 5766 §11.4/§11.5)
/// и выделенным локальным UDP-адресом `dst: SocketAddr` движка `webrtc-rs`.
async fn bridge_turn_stream<R, W>(
    mut reader: R,
    mut writer: W,
    udp_sock: &Arc<UdpSocket>,
    dst: SocketAddr,
    pkt_rx: &mut mpsc::Receiver<Vec<u8>>,
    first_pkt: Vec<u8>,
    remote_url: &str,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if let Err(e) = write_turn_tcp_frame(&mut writer, &first_pkt).await {
        log::warn!("[WRTC TURNS Proxy] Initial frame write to {remote_url} ({dst}) failed: {e}");
        return;
    }

    let mut read_buf = BytesMut::with_capacity(65536);
    let mut scratch = [0u8; 16384];
    let mut idle_deadline = TokioInstant::now() + TURNS_SESSION_IDLE_TIMEOUT;

    loop {
        tokio::select! {
            biased;
            read_res = reader.read(&mut scratch) => {
                match read_res {
                    Ok(0) => {
                        log::info!("[WRTC TURNS Proxy] Remote stream {remote_url} ({dst}) closed (EOF)");
                        break;
                    }
                    Ok(n) => {
                        idle_deadline = TokioInstant::now() + TURNS_SESSION_IDLE_TIMEOUT;
                        read_buf.extend_from_slice(&scratch[..n]);
                        loop {
                            if read_buf.len() < 4 {
                                break;
                            }
                            let b0 = read_buf[0];
                            let len_field = u16::from_be_bytes([read_buf[2], read_buf[3]]) as usize;
                            let (wire_frame_len, udp_frame_len) = if (b0 & 0xC0) == 0x00 {
                                // STUN Control Message (20-byte header + len_field body)
                                let total = 20 + len_field;
                                (total, total)
                            } else if (b0 & 0xC0) == 0x40 {
                                // TURN ChannelData Message (4-byte header + 4-byte padded payload on TCP/TLS)
                                let padded_len = (len_field + 3) & !3;
                                (4 + padded_len, 4 + len_field)
                            } else {
                                log::warn!(
                                    "[WRTC TURNS Proxy] Desynchronized frame header 0x{:02x} from {remote_url} ({dst}); resetting stream",
                                    b0
                                );
                                return;
                            };

                            if read_buf.len() < wire_frame_len {
                                break;
                            }

                            let frame = read_buf.split_to(wire_frame_len);
                            let _ = udp_sock.send_to(&frame[..udp_frame_len], dst).await;
                        }
                    }
                    Err(e) => {
                        log::warn!("[WRTC TURNS Proxy] Stream read error from {remote_url} ({dst}): {e}");
                        break;
                    }
                }
            }
            pkt_opt = pkt_rx.recv() => {
                let Some(pkt) = pkt_opt else {
                    break;
                };
                idle_deadline = TokioInstant::now() + TURNS_SESSION_IDLE_TIMEOUT;
                if let Err(e) = write_turn_tcp_frame(&mut writer, &pkt).await {
                    log::warn!("[WRTC TURNS Proxy] Stream write error to {remote_url} ({dst}): {e}");
                    break;
                }
                // Дренируем пачку готовых пакетов за один системный цикл
                for _ in 0..32 {
                    match pkt_rx.try_recv() {
                        Ok(more_pkt) => {
                            if let Err(e) = write_turn_tcp_frame(&mut writer, &more_pkt).await {
                                log::warn!("[WRTC TURNS Proxy] Batch write error to {remote_url} ({dst}): {e}");
                                return;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
            _ = sleep_until(idle_deadline) => {
                log::debug!("[WRTC TURNS Proxy] Idle timeout reached for {remote_url} ({dst}); closing session");
                break;
            }
        }
    }
}

async fn write_turn_tcp_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    pkt: &[u8],
) -> std::io::Result<()> {
    if pkt.len() < 4 {
        return Ok(());
    }
    let b0 = pkt[0];
    if (b0 & 0xC0) == 0x40 {
        // ChannelData: по RFC 5766 §11.4 длина в TCP/TLS обязана быть кратна 4 байтам
        let data_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        let unpadded_total = 4 + data_len;
        if pkt.len() < unpadded_total {
            return Ok(());
        }
        let padded_total = 4 + ((data_len + 3) & !3);
        if pkt.len() >= padded_total {
            writer.write_all(&pkt[..padded_total]).await?;
        } else {
            writer.write_all(&pkt[..unpadded_total]).await?;
            let pad = padded_total - unpadded_total;
            const ZEROS: [u8; 4] = [0u8; 4];
            writer.write_all(&ZEROS[..pad]).await?;
        }
    } else {
        writer.write_all(pkt).await?;
    }
    Ok(())
}
