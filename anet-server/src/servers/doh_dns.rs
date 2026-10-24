use crate::auth_handler::ServerAuthHandler;
use crate::client_registry::ClientRegistry;
use crate::config::Config;
use anet_common::astp_lite::AstpLiteCipher;
use anet_common::base32;
use anet_common::consts::CHANNEL_BUFFER_SIZE;
use anet_common::dns_proto::{build_dns_txt_response, parse_dns_query};
use anet_common::doh_chunking::DohReassemblyQueue;
use anyhow::{Context, Result};
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

pub async fn run_doh_dns_server(
    config: Arc<Config>,
    registry: Arc<ClientRegistry>,
    tun_tx: mpsc::Sender<Bytes>,
    auth_handler: ServerAuthHandler,
) -> Result<()> {
    let bind_to = &config.server.doh_bind_to;
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

    let socket = Arc::new(UdpSocket::bind(bind_to).await.context("Failed to bind UDP 53 for DoH DNS")?);

    let active_sessions: Arc<DashMap<u32, Arc<DohClientSession>>> = Arc::new(DashMap::new());
    let reassembler: Arc<Mutex<DohReassemblyQueue>> =
        Arc::new(Mutex::new(DohReassemblyQueue::new(Duration::from_secs(10))));
    let handshake_reassembler: Arc<Mutex<DohReassemblyQueue>> =
        Arc::new(Mutex::new(DohReassemblyQueue::new(Duration::from_secs(15))));
    let temp_handshake_responses: Arc<DashMap<u32, (String, Instant)>> = Arc::new(DashMap::new());

    // Background garbage collector for incomplete packets and handshake state
    {
        let reassembler = reassembler.clone();
        let handshake_reassembler = handshake_reassembler.clone();
        let temp_responses = temp_handshake_responses.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                reassembler.lock().await.cleanup();
                handshake_reassembler.lock().await.cleanup();
                temp_responses.retain(|_, (_, created)| created.elapsed() < Duration::from_secs(30));
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

                let deadline = tokio::time::Instant::now() + Duration::from_millis(poll_hold_timeout_ms);
                let mut packet_opt = None;

                if let Ok(mut rx_router) = tokio::time::timeout_at(deadline, session.rx_router.lock()).await {
                    match rx_router.try_recv() {
                        Ok(p) => packet_opt = Some(p),
                        Err(_) => {
                            if let Ok(Some(p)) = tokio::time::timeout_at(deadline, rx_router.recv()).await {
                                packet_opt = Some(p);
                            }
                        }
                    }
                }

                if let Some(packet) = packet_opt {
                    let seq = client_info.sequence.fetch_add(1, Ordering::Relaxed) as u32;
                    let mut packet_buf = packet.to_vec();
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
                let assembled_opt = {
                    let mut reasm = handshake_reassembler.lock().await;
                    reasm.feed(&chunk_raw)?
                };

                if let Some((_sid, _seq, full_handshake)) = assembled_opt {
                    let hs_addr = SocketAddr::from((
                        [
                            127,
                            254,
                            ((temp_session_id >> 16) & 0xFF) as u8,
                            ((temp_session_id >> 8) & 0xFF) as u8,
                        ],
                        (temp_session_id & 0xFFFF) as u16,
                    ));
                    let (response_opt, _authenticated) = auth_handler
                        .process_handshake_packet(full_handshake, hs_addr, "doh")
                        .await?;

                    if let Some(resp) = response_opt {
                        let b64 = BASE64_STANDARD.encode(&resp);
                        temp_handshake_responses.insert(temp_session_id, (b64.clone(), Instant::now()));

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
