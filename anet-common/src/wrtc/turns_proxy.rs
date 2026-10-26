use bytes::BytesMut;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_boring::SslConnectorExt;
use crate::boring_tls::build_chrome_ws_ssl_connector;

/// Запускает локальный UDP-проксирующий мост к удалённому серверу TURNS (TLS-over-TCP TURN)
/// или TCP-over-TURN, позволяющий `webrtc-rs` использовать протокол `turn:127.0.0.1:<port>`
/// со 100% браузерным TLS-отпечатком (BoringSSL Chrome Mimicry) и устойчивостью к блокировкам.
pub async fn start_turns_udp_bridge(
    local_bind_addr: SocketAddr,
    target_addr_str: String,
    host: String,
    use_tls: bool,
    remote_url: String,
) -> Result<(), anyhow::Error> {
    let udp_sock = Arc::new(UdpSocket::bind(local_bind_addr).await?);
    let client_peer = Arc::new(std::sync::Mutex::new(None::<SocketAddr>));
    let (pkt_tx, mut pkt_rx) = mpsc::channel::<Vec<u8>>(1024);

    // Фоновая задача чтения локального UDP от webrtc-rs и пересылки в TCP/TLS
    let udp_reader_sock = udp_sock.clone();
    let udp_client_peer = client_peer.clone();
    let udp_reader_task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match udp_reader_sock.recv_from(&mut buf).await {
                Ok((n, src)) => {
                    *udp_client_peer.lock().unwrap() = Some(src);
                    if pkt_tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    log::warn!("[WRTC TURNS Proxy] UDP recv error: {e}");
                    break;
                }
            }
        }
    });

    let connect_timeout = Duration::from_secs(5);

    // Ждём первого исходящего пакета от webrtc-rs (Allocation Request)
    let first_pkt = match pkt_rx.recv().await {
        Some(p) => p,
        None => {
            udp_reader_task.abort();
            return Ok(());
        }
    };

    loop {
        // Подключаем TCP сокет к TURNS-серверу
        let target_clone = target_addr_str.clone();
        let connect_res = tokio::time::timeout(connect_timeout, async move {
            let tcp = TcpStream::connect(&target_clone).await?;
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
                log::warn!("[WRTC TURNS Proxy] TCP connect to {remote_url} ({target_addr_str}) failed: {e}");
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
            let ssl_connector = match build_chrome_ws_ssl_connector() {
                Ok(b) => b.build(),
                Err(e) => {
                    log::warn!("[WRTC TURNS Proxy] Failed to build BoringSSL connector: {e}");
                    break;
                }
            };

            let tls_res = tokio::time::timeout(
                connect_timeout,
                ssl_connector.connect_async(&host, tcp_stream),
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
    Ok(())
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
