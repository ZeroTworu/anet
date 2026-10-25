use crate::auth_handler::ServerAuthHandler;
use crate::client_registry::ClientRegistry;
use crate::config::Config;
use anet_common::astp_lite::AstpLiteCipher;
use anet_common::base32;
use anet_common::consts::CHANNEL_BUFFER_SIZE;
use anet_common::dns_proto::{build_dns_txt_response, parse_dns_query};
use anet_common::doh_chunking::DohReassemblyQueue;
use anyhow::Result;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use bytes::Bytes;
use dashmap::DashMap;
use log::{debug, info, warn};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

struct DohClientSession {
    rx_router: Arc<Mutex<mpsc::Receiver<Bytes>>>,
    cipher: Arc<AstpLiteCipher>,
}

/// Определяет основной внешний IPv4-адрес сервера через таблицу маршрутизации ядра (без отправки пакетов).
fn detect_primary_ipv4() -> Option<std::net::IpAddr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("1.1.1.1:53").ok()?;
    let ip = sock.local_addr().ok()?.ip();
    if ip.is_unspecified() || ip.is_loopback() {
        None
    } else {
        Some(ip)
    }
}

pub async fn run_doh_dns_server(
    config: Arc<Config>,
    registry: Arc<ClientRegistry>,
    tun_tx: mpsc::Sender<Bytes>,
    auth_handler: ServerAuthHandler,
) -> Result<()> {
    let raw_bind = config.server.doh_bind_to.trim();
    let bind_to = if !raw_bind.contains(':') {
        format!("0.0.0.0:{}", raw_bind)
    } else {
        raw_bind.to_string()
    };
    let domain_zone = config
        .doh_transport
        .domain
        .trim_matches('.')
        .to_ascii_lowercase();
    let poll_hold_timeout_ms = config.doh_transport.poll_hold_timeout_ms;

    info!(
        "[DoH-DNS] Initializing authoritative UDP DNS server on {} for zone '*.{}' (Hold: {}ms)",
        bind_to, domain_zone, poll_hold_timeout_ms
    );

    let socket = match UdpSocket::bind(&bind_to).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            // На Linux (Ubuntu/Debian) systemd-resolved слушает 127.0.0.53:53, из-за чего
            // бинд на wildcard 0.0.0.0:53 падает с EADDRINUSE (os error 98), хотя внешний
            // интерфейс свободен. Попробуем автоматически забиндиться на основной внешний IPv4.
            let mut fallback_socket = None;
            if e.kind() == std::io::ErrorKind::AddrInUse && bind_to.starts_with("0.0.0.0:") {
                if let Some(port_str) = bind_to.strip_prefix("0.0.0.0:") {
                    if let Ok(port) = port_str.parse::<u16>() {
                        if let Some(primary_ip) = detect_primary_ipv4() {
                            let fallback_addr = SocketAddr::new(primary_ip, port);
                            match UdpSocket::bind(fallback_addr).await {
                                Ok(s) => {
                                    warn!(
                                        "[DoH-DNS] Could not bind wildcard {} ({}) — likely systemd-resolved occupying 127.0.0.53:{}. Automatically bound to primary interface {} instead.",
                                        bind_to, e, port, fallback_addr
                                    );
                                    fallback_socket = Some(Arc::new(s));
                                }
                                Err(fallback_err) => {
                                    warn!(
                                        "[DoH-DNS] Fallback bind to primary interface {} also failed: {}",
                                        fallback_addr, fallback_err
                                    );
                                }
                            }
                        }
                    }
                }
            }

            match fallback_socket {
                Some(s) => s,
                None => {
                    return Err(anyhow::Error::new(e).context(format!(
                        "Failed to bind UDP {} for DoH DNS (hint: check if systemd-resolved/dnsmasq occupies port 53 via `ss -ulpn | grep :53`, or set `doh_bind_to = \"<SERVER_PUBLIC_IP>:53\"`)",
                        bind_to
                    )));
                }
            }
        }
    };

    let active_sessions: Arc<DashMap<u32, Arc<DohClientSession>>> = Arc::new(DashMap::new());
    let reassembler: Arc<Mutex<DohReassemblyQueue>> =
        Arc::new(Mutex::new(DohReassemblyQueue::new(Duration::from_secs(10))));
    let handshake_reassembler: Arc<Mutex<DohReassemblyQueue>> =
        Arc::new(Mutex::new(DohReassemblyQueue::new(Duration::from_secs(15))));
    let temp_handshake_responses: Arc<DashMap<u32, (String, Instant)>> = Arc::new(DashMap::new());
    let phase_handshake_responses: Arc<DashMap<(u32, u32), (String, Instant)>> = Arc::new(DashMap::new());

    // Background garbage collector for incomplete packets and handshake state
    {
        let reassembler = reassembler.clone();
        let handshake_reassembler = handshake_reassembler.clone();
        let temp_responses = temp_handshake_responses.clone();
        let phase_responses = phase_handshake_responses.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                reassembler.lock().await.cleanup();
                handshake_reassembler.lock().await.cleanup();
                temp_responses.retain(|_, (_, created)| created.elapsed() < Duration::from_secs(30));
                phase_responses.retain(|_, (_, created)| created.elapsed() < Duration::from_secs(30));
            }
        });
    }

    let mut buf = [0u8; 4096];

    loop {
        let (len, remote_addr) = match socket.recv_from(&mut buf).await {
            Ok(res) => res,
            Err(e) => {
                warn!("[DoH-DNS] recv_from error: {}", e);
                continue;
            }
        };

        let raw_query = buf[..len].to_vec();
        let socket = socket.clone();
        let config = config.clone();
        let registry = registry.clone();
        let tun_tx = tun_tx.clone();
        let auth_handler = auth_handler.clone();
        let domain_zone = domain_zone.clone();
        let active_sessions = active_sessions.clone();
        let reassembler = reassembler.clone();
        let handshake_reassembler = handshake_reassembler.clone();
        let temp_handshake_responses = temp_handshake_responses.clone();
        let phase_handshake_responses = phase_handshake_responses.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_dns_datagram(
                raw_query,
                remote_addr,
                socket,
                domain_zone,
                poll_hold_timeout_ms,
                config,
                registry,
                tun_tx,
                auth_handler,
                active_sessions,
                reassembler,
                handshake_reassembler,
                temp_handshake_responses,
                phase_handshake_responses,
            )
            .await
            {
                debug!("[DoH-DNS] Error handling DNS query from {}: {}", remote_addr, e);
            }
        });
    }
}

async fn handle_dns_datagram(
    raw_query: Vec<u8>,
    remote_addr: SocketAddr,
    socket: Arc<UdpSocket>,
    domain_zone: String,
    poll_hold_timeout_ms: u64,
    _config: Arc<Config>,
    registry: Arc<ClientRegistry>,
    tun_tx: mpsc::Sender<Bytes>,
    auth_handler: ServerAuthHandler,
    active_sessions: Arc<DashMap<u32, Arc<DohClientSession>>>,
    reassembler: Arc<Mutex<DohReassemblyQueue>>,
    handshake_reassembler: Arc<Mutex<DohReassemblyQueue>>,
    temp_handshake_responses: Arc<DashMap<u32, (String, Instant)>>,
    phase_handshake_responses: Arc<DashMap<(u32, u32), (String, Instant)>>,
) -> Result<()> {
    let parsed_q = match parse_dns_query(&raw_query) {
        Some(q) => q,
        None => return Ok(()),
    };

    // Validate domain zone suffix
    if !parsed_q.qname.ends_with(&domain_zone) {
        // Query not for our domain: return empty response
        let resp = build_dns_txt_response(&raw_query, &parsed_q, None, 0);
        let _ = socket.send_to(&resp, remote_addr).await;
        return Ok(());
    }

    let prefix = parsed_q
        .qname
        .trim_end_matches(&domain_zone)
        .trim_end_matches('.');

    // Filter out QNAME-minimization probes: non-TXT queries (A, NS, SOA) or empty zone apex
    if parsed_q.qtype != anet_common::dns_proto::DNS_QTYPE_TXT || prefix.is_empty() {
        let resp = build_dns_txt_response(&raw_query, &parsed_q, None, 0);
        let _ = socket.send_to(&resp, remote_addr).await;
        return Ok(());
    }

    // Case 1: Downlink Long-Poll query ("poll.<session_id_hex>.<nonce_hex>")
    if prefix.starts_with("poll.") {
        let parts: Vec<&str> = prefix.split('.').collect();
        if parts.len() >= 2 {
            let session_id = match u32::from_str_radix(parts[1], 16) {
                Ok(sid) => sid,
                Err(_) => {
                    let resp = build_dns_txt_response(&raw_query, &parsed_q, None, 0);
                    let _ = socket.send_to(&resp, remote_addr).await;
                    return Ok(());
                }
            };

            let prefix_bytes = session_id.to_be_bytes();
            if let Some(client_info) = registry.get_by_prefix(&prefix_bytes) {
                client_info.last_activity.store(
                    std::time::SystemTime::now()
                        .duration_since(std::time::SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    Ordering::Relaxed,
                );

                let session = active_sessions
                    .entry(session_id)
                    .or_insert_with(|| {
                        let (tx_router, rx_router) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
                        registry.finalize_client(&client_info.assigned_ip, tx_router);
                        let cipher = Arc::new(AstpLiteCipher::new(client_info.cipher.raw_key()));
                        Arc::new(DohClientSession {
                            rx_router: Arc::new(Mutex::new(rx_router)),
                            cipher,
                        })
                    })
                    .value()
                    .clone();

                let effective_hold_ms = poll_hold_timeout_ms.min(350);
                let deadline = tokio::time::Instant::now() + Duration::from_millis(effective_hold_ms);
                let lock_deadline = tokio::time::Instant::now() + Duration::from_millis(80);
                let mut packets: Vec<Bytes> = Vec::new();
                let mut total_raw_bytes: usize = 0;
                const MAX_BATCH_RAW_BYTES: usize = 650;

                if let Ok(mut rx_router) = tokio::time::timeout_at(lock_deadline, session.rx_router.lock()).await {
                    let first_pkt = match rx_router.try_recv() {
                        Ok(p) => Some(p),
                        Err(_) => {
                            match tokio::time::timeout_at(deadline, rx_router.recv()).await {
                                Ok(Some(p)) => Some(p),
                                _ => None,
                            }
                        }
                    };

                    if let Some(first) = first_pkt {
                        total_raw_bytes += first.len();
                        packets.push(first);

                        while packets.len() < 16 {
                            match rx_router.try_recv() {
                                Ok(next_pkt) => {
                                    if total_raw_bytes + 2 + next_pkt.len() <= MAX_BATCH_RAW_BYTES {
                                        total_raw_bytes += 2 + next_pkt.len();
                                        packets.push(next_pkt);
                                    } else {
                                        // Put back is not supported on mpsc::Receiver; encrypt and send next_pkt on next poll?
                                        // Wait: mpsc::Receiver::try_recv consumes next_pkt! So we must include next_pkt if popped,
                                        // or stop before popping if total_raw_bytes is already near MAX_BATCH_RAW_BYTES.
                                        packets.push(next_pkt);
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                            if total_raw_bytes >= 500 {
                                break;
                            }
                        }
                    }
                }

                if !packets.is_empty() {
                    let seq = client_info.sequence.fetch_add(1, Ordering::Relaxed) as u32;
                    let mut packet_buf = if packets.len() == 1 {
                        packets[0].to_vec()
                    } else {
                        let mut buf = Vec::with_capacity(1 + total_raw_bytes + packets.len() * 2);
                        buf.push(0x00); // Batch marker (valid IPv4/IPv6 packets start with 0x4x or 0x6x)
                        for pkt in &packets {
                            let len_u16 = (pkt.len() as u16).to_be_bytes();
                            buf.extend_from_slice(&len_u16);
                            buf.extend_from_slice(pkt);
                        }
                        buf
                    };
                    session.cipher.apply_keystream(seq, session_id, &mut packet_buf);

                    let mut downlink_bytes = Vec::with_capacity(4 + packet_buf.len());
                    downlink_bytes.extend_from_slice(&seq.to_be_bytes());
                    downlink_bytes.extend_from_slice(&packet_buf);

                    let b64 = BASE64_STANDARD.encode(&downlink_bytes);
                    let resp = build_dns_txt_response(&raw_query, &parsed_q, Some(b64.as_bytes()), 0);
                    let _ = socket.send_to(&resp, remote_addr).await;
                    return Ok(());
                } else {
                    // Empty poll answer
                    let resp = build_dns_txt_response(&raw_query, &parsed_q, None, 0);
                    let _ = socket.send_to(&resp, remote_addr).await;
                    return Ok(());
                }
            } else if let Some(saved) = temp_handshake_responses.get(&session_id) {
                // Handshake poll
                let resp = build_dns_txt_response(&raw_query, &parsed_q, Some(saved.0.as_bytes()), 0);
                let _ = socket.send_to(&resp, remote_addr).await;
                return Ok(());
            } else {
                let resp = build_dns_txt_response(&raw_query, &parsed_q, None, 0);
                let _ = socket.send_to(&resp, remote_addr).await;
                return Ok(());
            }
        }
    }

    // Case 2: Handshake query ("hs.<session_id_hex>.<chunk_idx>.<total_chunks>.<base32_chunk>")
    if prefix.starts_with("hs.") {
        let parts: Vec<&str> = prefix.splitn(5, '.').collect();
        if parts.len() == 5 {
            let temp_session_id = u32::from_str_radix(parts[1], 16).unwrap_or(0);
            let b32_str = base32::join_labels(parts[4]);

            if let Ok(chunk_raw) = base32::decode(&b32_str) {
                if let Ok(hdr) = anet_common::doh_chunking::DohChunkHeader::decode(&chunk_raw) {
                    // If this handshake phase was already processed (e.g. duplicate query via dup_hs),
                    // return the cached response immediately without regenerating DH keys.
                    if let Some(cached) = phase_handshake_responses.get(&(temp_session_id, hdr.sequence)) {
                        let dns_resp = build_dns_txt_response(&raw_query, &parsed_q, Some(cached.0.as_bytes()), 0);
                        let _ = socket.send_to(&dns_resp, remote_addr).await;
                        return Ok(());
                    }
                    // Clear previous phase response from poll slot when a new phase starts
                    if hdr.sequence > 0 && hdr.chunk_index == 0 {
                        temp_handshake_responses.remove(&temp_session_id);
                    }
                }

                let assembled_opt = {
                    let mut reasm = handshake_reassembler.lock().await;
                    reasm.feed(&chunk_raw)?
                };

                if let Some((_sid, seq, full_handshake)) = assembled_opt {
                    if let Some(cached) = phase_handshake_responses.get(&(temp_session_id, seq)) {
                        let dns_resp = build_dns_txt_response(&raw_query, &parsed_q, Some(cached.0.as_bytes()), 0);
                        let _ = socket.send_to(&dns_resp, remote_addr).await;
                        return Ok(());
                    }

                    info!(
                        "[DoH-DNS] Handshake phase {} packet reassembled (sid={:08x}, len={} bytes, resolver={})",
                        seq,
                        temp_session_id,
                        full_handshake.len(),
                        remote_addr
                    );

                    let hs_addr = SocketAddr::from((
                        [
                            127,
                            254,
                            ((temp_session_id >> 16) & 0xFF) as u8,
                            ((temp_session_id >> 8) & 0xFF) as u8,
                        ],
                        (temp_session_id & 0xFFFF) as u16,
                    ));
                    let (response_opt, authenticated) = auth_handler
                        .process_handshake_packet(full_handshake, hs_addr, "doh")
                        .await?;

                    if let Some((client_info, _)) = authenticated {
                        let session_id = u32::from_be_bytes(client_info.nonce_prefix);
                        active_sessions.entry(session_id).or_insert_with(|| {
                            let (tx_router, rx_router) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
                            registry.finalize_client(&client_info.assigned_ip, tx_router);
                            let cipher = Arc::new(AstpLiteCipher::new(client_info.cipher.raw_key()));
                            Arc::new(DohClientSession {
                                rx_router: Arc::new(Mutex::new(rx_router)),
                                cipher,
                            })
                        });
                    }

                    if let Some(resp) = response_opt {
                        let b64 = BASE64_STANDARD.encode(&resp);
                        let now = Instant::now();
                        phase_handshake_responses.insert((temp_session_id, seq), (b64.clone(), now));
                        temp_handshake_responses.insert(temp_session_id, (b64.clone(), now));

                        let dns_resp = build_dns_txt_response(&raw_query, &parsed_q, Some(b64.as_bytes()), 0);
                        let _ = socket.send_to(&dns_resp, remote_addr).await;
                        return Ok(());
                    }
                }

                // Chunk acknowledged
                let dns_resp = build_dns_txt_response(&raw_query, &parsed_q, Some(b"ACK"), 0);
                let _ = socket.send_to(&dns_resp, remote_addr).await;
                return Ok(());
            }
        }
    }

    // Case 3: Data Uplink chunk ("<base32_chunk_labels>")
    let b32_str = base32::join_labels(prefix);
    if let Ok(chunk_raw) = base32::decode(&b32_str) {
        // Filter out intermediate QNAME-minimization suffixes whose session_id does not belong to an active client
        let hdr = match anet_common::doh_chunking::DohChunkHeader::decode(&chunk_raw) {
            Ok(h) => h,
            Err(_) => {
                let resp = build_dns_txt_response(&raw_query, &parsed_q, None, 0);
                let _ = socket.send_to(&resp, remote_addr).await;
                return Ok(());
            }
        };
        if registry.get_by_prefix(&hdr.session_id.to_be_bytes()).is_none() {
            let resp = build_dns_txt_response(&raw_query, &parsed_q, None, 0);
            let _ = socket.send_to(&resp, remote_addr).await;
            return Ok(());
        }

        let assembled_opt = {
            let mut reasm = reassembler.lock().await;
            reasm.feed(&chunk_raw)?
        };

        if let Some((session_id, seq, full_payload)) = assembled_opt {
            let prefix_bytes = session_id.to_be_bytes();
            if let Some(client_info) = registry.get_by_prefix(&prefix_bytes) {
                client_info.last_activity.store(
                    std::time::SystemTime::now()
                        .duration_since(std::time::SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    Ordering::Relaxed,
                );

                let cipher = AstpLiteCipher::new(client_info.cipher.raw_key());
                let mut decrypted = full_payload.to_vec();
                cipher.apply_keystream(seq, session_id, &mut decrypted);

                let packet_len = decrypted.len();
                if tun_tx.try_send(Bytes::from(decrypted)).is_ok() {
                    registry.record_rx(&client_info, packet_len, "doh");
                }
            }
        }

        let resp = build_dns_txt_response(&raw_query, &parsed_q, Some(b"OK"), 0);
        let _ = socket.send_to(&resp, remote_addr).await;
        return Ok(());
    }

    let resp = build_dns_txt_response(&raw_query, &parsed_q, None, 0);
    let _ = socket.send_to(&resp, remote_addr).await;
    Ok(())
}
