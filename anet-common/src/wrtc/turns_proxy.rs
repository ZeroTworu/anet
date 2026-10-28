use bytes::BytesMut;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

/// Удерживает фоновую задачу локального UDP <-> TURNS (TLS 1.3 TCP:443) моста.
/// При дропе `TurnsProxyHandle` прокси-задача автоматически останавливается.
pub struct TurnsProxyHandle {
    pub local_turn_url: String,
    pub remote_url: String,
    pub local_addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
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
    }
}

/// Поднимает локальный прозрачный мост `UDP (127.0.0.1:0) <-> TURNS (TLS 1.3 TCP:443)` или `TURN-TCP`.
///
/// На всех платформах (Android, iOS, Linux, Windows, macOS) `webrtc-rs` общается с этим
/// мостом по `127.0.0.1` через loopback-сокет в `HybridAsyncUdpSocket` (мимо `tun0`),
/// а сам мост устанавливает настоящее TLS 1.3 TCP:443 соединение через BoringSSL (Chrome Mimicry) с SNI `host`
/// (например, `bst-talk-stun7.ktalk.host:443` или `dtl-talk-stun5.ktalk.host:443`)
/// и инкапсулирует STUN и TURN `ChannelData` по RFC 5766 §11.4 / §11.5.
pub fn spawn_turns_udp_proxy(
    host: String,
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
        "[WRTC TURNS Proxy] Bound local UDP bridge {} -> {} (TLS={}, SNI={}:{})",
        local_turn_url,
        remote_url,
        use_tls,
        host,
        port
    );

    let remote_url_log = remote_url.clone();
    let task = tokio::spawn(async move {
        run_turns_proxy_loop(
            udp_sock,
            host,
            port,
            use_tls,
            remote_url_log,
            connect_timeout,
        )
        .await;
    });

    Ok(TurnsProxyHandle {
        local_turn_url,
        remote_url,
        local_addr,
        task,
    })
}

async fn run_turns_proxy_loop(
    udp_sock: Arc<UdpSocket>,
    host: String,
    port: u16,
    use_tls: bool,
    remote_url: String,
    connect_timeout: Duration,
) {
    let (pkt_tx, mut pkt_rx) = mpsc::channel::<Vec<u8>>(1024);
    let client_peer: Arc<std::sync::Mutex<Option<SocketAddr>>> =
        Arc::new(std::sync::Mutex::new(None));

    // Фоновый приёмник UDP-дейтаграмм от локального WebRTC сокета (127.0.0.1)
    let udp_in = Arc::clone(&udp_sock);
    let client_peer_in = Arc::clone(&client_peer);
    let udp_reader_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, src)) = udp_in.recv_from(&mut buf).await {
            if n < 4 {
                continue;
            }
            if let Ok(mut g) = client_peer_in.lock() {
                *g = Some(src);
            }
            if pkt_tx.send(buf[..n].to_vec()).await.is_err() {
                break;
            }
        }
    });

    while let Some(first_pkt) = pkt_rx.recv().await {
        let target_addr_str = format!("{host}:{port}");
        let connect_res = tokio::time::timeout(connect_timeout, async {
            let tcp = TcpStream::connect(&target_addr_str).await?;
            let _ = tcp.set_nodelay(true);
            let sock_ref = socket2::SockRef::from(&tcp);
            let _ = sock_ref.set_recv_buffer_size(4 * 1024 * 1024);
            let _ = sock_ref.set_send_buffer_size(4 * 1024 * 1024);
            Ok::<TcpStream, std::io::Error>(tcp)
        })
        .await;

        let tcp_stream = match connect_res {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                log::warn!(
                    "[WRTC TURNS Proxy] TCP connect to {remote_url} ({target_addr_str}) failed: {e}"
                );
                tokio::time::sleep(Duration::from_millis(300)).await;
                continue;
            }
            Err(_) => {
                log::warn!(
                    "[WRTC TURNS Proxy] TCP connect to {remote_url} ({target_addr_str}) timed out after {:?}",
                    connect_timeout
                );
                continue;
            }
        };

        let remote_peer_ip = tcp_stream.peer_addr().ok();

        if use_tls {
            let tls_res = tokio::time::timeout(
                connect_timeout,
                crate::http_help::BrowserProfile::random().connect_ws_tls(&host, tcp_stream),
            )
            .await;

            match tls_res {
                Ok(Ok(tls_stream)) => {
                    log::info!(
                        "[WRTC TURNS Proxy] Connected TLS 1.3 session to {} (remote_addr={:?}) via BoringSSL",
                        remote_url,
                        remote_peer_ip
                    );
                    let (reader, writer) = tokio::io::split(tls_stream);
                    bridge_turn_stream(
                        reader,
                        writer,
                        &udp_sock,
                        &client_peer,
                        &mut pkt_rx,
                        first_pkt,
                        &remote_url,
                    )
                    .await;
                }
                Ok(Err(e)) => {
                    log::warn!("[WRTC TURNS Proxy] TLS handshake with {remote_url} failed: {e}");
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
                Err(_) => {
                    log::warn!(
                        "[WRTC TURNS Proxy] TLS handshake with {remote_url} timed out after {:?}",
                        connect_timeout
                    );
                }
            }
        } else {
            log::info!(
                "[WRTC TURNS Proxy] Connected TCP TURN session to {} (remote_addr={:?})",
                remote_url,
                remote_peer_ip
            );
            let (reader, writer) = tokio::io::split(tcp_stream);
            bridge_turn_stream(
                reader,
                writer,
                &udp_sock,
                &client_peer,
                &mut pkt_rx,
                first_pkt,
                &remote_url,
            )
            .await;
        }
    }

    udp_reader_task.abort();
}

/// Выполняет полнодуплексный бриджинг STUN / TURN `ChannelData` между потоком TCP/TLS (RFC 5766 §11.4/§11.5)
/// и локальным UDP-сокетом `webrtc-rs`.
async fn bridge_turn_stream<R, W>(
    mut reader: R,
    mut writer: W,
    udp_sock: &Arc<UdpSocket>,
    client_peer: &Arc<std::sync::Mutex<Option<SocketAddr>>>,
    pkt_rx: &mut mpsc::Receiver<Vec<u8>>,
    first_pkt: Vec<u8>,
    remote_url: &str,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if let Err(e) = write_turn_tcp_frame(&mut writer, &first_pkt).await {
        log::warn!("[WRTC TURNS Proxy] Initial frame write to {remote_url} failed: {e}");
        return;
    }

    let mut read_buf = BytesMut::with_capacity(65536);
    let mut scratch = [0u8; 16384];

    loop {
        tokio::select! {
            biased;
            read_res = reader.read(&mut scratch) => {
                match read_res {
                    Ok(0) => {
                        log::info!("[WRTC TURNS Proxy] Remote stream {remote_url} closed (EOF)");
                        break;
                    }
                    Ok(n) => {
                        read_buf.extend_from_slice(&scratch[..n]);
                        let dst_opt = client_peer.lock().ok().and_then(|g| *g);
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
                                    "[WRTC TURNS Proxy] Desynchronized frame header 0x{:02x} from {remote_url}; resetting stream",
                                    b0
                                );
                                return;
                            };

                            if read_buf.len() < wire_frame_len {
                                break;
                            }

                            let frame = read_buf.split_to(wire_frame_len);
                            if let Some(dst) = dst_opt {
                                let _ = udp_sock.send_to(&frame[..udp_frame_len], dst).await;
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("[WRTC TURNS Proxy] Stream read error from {remote_url}: {e}");
                        break;
                    }
                }
            }
            pkt_opt = pkt_rx.recv() => {
                let Some(pkt) = pkt_opt else {
                    break;
                };
                if let Err(e) = write_turn_tcp_frame(&mut writer, &pkt).await {
                    log::warn!("[WRTC TURNS Proxy] Stream write error to {remote_url}: {e}");
                    break;
                }
                // Дренируем пачку готовых пакетов за один системный цикл
                for _ in 0..32 {
                    match pkt_rx.try_recv() {
                        Ok(more_pkt) => {
                            if let Err(e) = write_turn_tcp_frame(&mut writer, &more_pkt).await {
                                log::warn!("[WRTC TURNS Proxy] Batch write error to {remote_url}: {e}");
                                return;
                            }
                        }
                        Err(_) => break,
                    }
                }
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
