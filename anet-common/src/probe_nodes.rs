use crate::config::WrtcConfig;
use crate::consts::NONCE_LEN;
use crate::crypto_utils::{create_handshake_cipher, sign_data};
use crate::handshake_fragmentation::{FragmentConfig, send_fragmented_datagrams};
use crate::http_help::BrowserProfile;
use crate::protocol::{
    DhClientExchange, Message, TransportProbeRequest, TransportProbeResponse, message::Content,
};
use crate::stream_framing::{frame_packet, read_next_packet};
use crate::vnc::{
    CLIENT_CUT_TEXT, RFB_VERSION, SECURITY_TYPE_NONE, SERVER_CUT_TEXT, read_cut_text,
    write_cut_text,
};
use crate::wrtc::ktalk::KtalkClient;
use anyhow::{Context, Result, anyhow};
use base64::prelude::*;
use bytes::{BufMut, Bytes, BytesMut};
use ed25519_dalek::SigningKey;
use futures::stream::FuturesUnordered;
use futures::{SinkExt, StreamExt};
use prost::Message as ProstMessage;
use rand::RngCore;
use rand::rngs::OsRng;
use russh::client::Handler;
use std::collections::HashMap;
use std::future::ready;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_tungstenite::{
    client_async_with_config, tungstenite::protocol::Message as WsMessage,
};
use x25519_dalek::{PublicKey, StaticSecret};

pub const DEFAULT_PROBE_TIMEOUT_MS: u64 = 2800;
pub const MAX_CONCURRENT_NODE_PROBES: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProbeProtocol {
    Quic,
    Ssh,
    Vnc,
    Ws,
    Ahttp,
    Wrtc,
}

impl ProbeProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProbeProtocol::Quic => "QUIC",
            ProbeProtocol::Ssh => "SSH",
            ProbeProtocol::Vnc => "VNC",
            ProbeProtocol::Ws => "WS",
            ProbeProtocol::Ahttp => "AHTTP",
            ProbeProtocol::Wrtc => "WRTC",
        }
    }

    pub fn from_proto_str(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "ssh" => ProbeProtocol::Ssh,
            "vnc" => ProbeProtocol::Vnc,
            "ws" | "wss" | "websocket" => ProbeProtocol::Ws,
            "ahttp" | "http" | "https" => ProbeProtocol::Ahttp,
            "wrtc" => ProbeProtocol::Wrtc,
            _ => ProbeProtocol::Quic,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NodeProbeStatus {
    Checking = 0,
    Available = 1,
    Degraded = 2,
    Unavailable = 3,
}

impl NodeProbeStatus {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone)]
pub struct ProbeTarget {
    pub endpoint_index: usize,
    pub group_id: String,
    pub group_name: String,
    pub server_name: String,
    pub protocol: ProbeProtocol,
    pub dsn: String,
    pub host_port: String,
    pub websocket_url: Option<String>,
    pub ahttp_handshake_path: String,
    pub ssh_user: String,
    pub server_pub_key: String,
}

#[derive(Debug, Clone)]
pub struct EndpointProbeResult {
    pub endpoint_index: usize,
    pub group_id: String,
    pub group_name: String,
    pub server_name: String,
    pub protocol: ProbeProtocol,
    pub status: NodeProbeStatus,
    /// Чистый сетевой 1-RTT пинг без учёта времени установки TCP/TLS/SSH/RFB-сессии
    pub rtt_ms: Option<u32>,
    /// Полный пинг вместе с рукопожатием транспорта (DNS + TCP/TLS/SSH/RFB/Ktalk + пакет проверки)
    pub full_rtt_ms: Option<u32>,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct ProtocolBadgeStatus {
    pub name: String,
    pub protocol: ProbeProtocol,
    pub status: NodeProbeStatus,
    pub rtt_ms: Option<u32>,
    pub full_rtt_ms: Option<u32>,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct NodeGroupProbeSummary {
    pub group_id: String,
    pub group_name: String,
    pub status: NodeProbeStatus,
    /// Лучший чистый 1-RTT пинг среди доступных транспортов группы
    pub best_rtt_ms: Option<u32>,
    /// Полный пинг (с учётом рукопожатия) среди доступных транспортов группы
    pub best_full_rtt_ms: Option<u32>,
    pub reachable_endpoints: usize,
    pub total_endpoints: usize,
    pub protocols: Vec<ProtocolBadgeStatus>,
}

impl NodeGroupProbeSummary {
    pub fn format_dual_rtt(full_opt: Option<u32>, pure_opt: Option<u32>, unit: &str) -> Option<String> {
        match (full_opt, pure_opt) {
            (Some(full), Some(pure)) => Some(format!("{} / {} {}", full.max(pure), pure, unit)),
            (None, Some(pure)) => Some(format!("{} / {} {}", pure, pure, unit)),
            (Some(full), None) => Some(format!("{} {}", full, unit)),
            (None, None) => None,
        }
    }

    pub fn short_badge_text(&self) -> String {
        match self.status {
            NodeProbeStatus::Checking => "...".to_string(),
            NodeProbeStatus::Available => {
                if let Some(dual) =
                    Self::format_dual_rtt(self.best_full_rtt_ms, self.best_rtt_ms, "мс")
                {
                    if self.total_endpoints > 1 {
                        format!(
                            "{} · {}/{}",
                            dual, self.reachable_endpoints, self.total_endpoints
                        )
                    } else {
                        dual
                    }
                } else {
                    format!("{}/{}", self.reachable_endpoints, self.total_endpoints)
                }
            }
            NodeProbeStatus::Degraded => {
                if let Some(dual) =
                    Self::format_dual_rtt(self.best_full_rtt_ms, self.best_rtt_ms, "мс")
                {
                    format!(
                        "{} · {}/{}",
                        dual, self.reachable_endpoints, self.total_endpoints
                    )
                } else {
                    format!("{}/{}", self.reachable_endpoints, self.total_endpoints)
                }
            }
            NodeProbeStatus::Unavailable => {
                if self.total_endpoints > 1 {
                    format!("0/{}", self.total_endpoints)
                } else {
                    "недоступен".to_string()
                }
            }
        }
    }

    pub fn compact_protocols_text(&self) -> String {
        if self.protocols.is_empty() {
            return String::new();
        }
        if self.total_endpoints <= 1 && self.protocols.len() == 1 {
            let p = &self.protocols[0];
            let label = if !p.name.trim().is_empty()
                && !p.name.trim().eq_ignore_ascii_case(self.group_name.trim())
            {
                p.name.trim()
            } else {
                p.protocol.as_str()
            };
            return match p.status {
                NodeProbeStatus::Available | NodeProbeStatus::Degraded => {
                    if let (Some(full), Some(pure)) = (p.full_rtt_ms, p.rtt_ms) {
                        format!(
                            "{} • полный {} мс / чистый {} мс",
                            label,
                            full.max(pure),
                            pure
                        )
                    } else if let Some(pure) = p.rtt_ms {
                        format!("{} • {} мс", label, pure)
                    } else {
                        format!("{} • доступен", label)
                    }
                }
                NodeProbeStatus::Unavailable => {
                    format!("{} • транспорт недоступен", label)
                }
                NodeProbeStatus::Checking => {
                    format!("{} • проверка узла...", label)
                }
            };
        }

        let mut parts = Vec::with_capacity(self.protocols.len());
        for p in &self.protocols {
            let label = if !p.name.trim().is_empty() {
                p.name.trim()
            } else {
                p.protocol.as_str()
            };
            match p.status {
                NodeProbeStatus::Available | NodeProbeStatus::Degraded => {
                    if let (Some(full), Some(pure)) = (p.full_rtt_ms, p.rtt_ms) {
                        parts.push(format!("{}: {}/{} мс", label, full.max(pure), pure));
                    } else if let Some(pure) = p.rtt_ms {
                        parts.push(format!("{}: {} мс", label, pure));
                    } else {
                        parts.push(format!("{}: OK", label));
                    }
                }
                NodeProbeStatus::Unavailable => {
                    parts.push(format!("{}: недоступен", label));
                }
                NodeProbeStatus::Checking => {
                    parts.push(format!("{}: ...", label));
                }
            }
        }
        format!("В группе {}: {}", self.group_name, parts.join(" · "))
    }
}

#[derive(Debug, Clone, Default)]
pub struct NodeProbeSnapshot {
    pub checked_at_unix_ms: u64,
    pub is_checking: bool,
    pub completed_endpoints: usize,
    pub total_endpoints: usize,
    pub endpoints: Vec<EndpointProbeResult>,
    pub groups: Vec<NodeGroupProbeSummary>,
}

impl NodeProbeSnapshot {
    pub fn group_for_key(&self, id_or_name: &str) -> Option<&NodeGroupProbeSummary> {
        let raw_trimmed = id_or_name.trim();
        if raw_trimmed.is_empty() {
            return None;
        }
        // 1. Точное совпадение по group_id или group_name (без учёта регистра)
        if let Some(found) = self.groups.iter().find(|g| {
            g.group_id.trim().eq_ignore_ascii_case(raw_trimmed)
                || g.group_name.trim().eq_ignore_ascii_case(raw_trimmed)
        }) {
            return Some(found);
        }

        // 2. Нормализованное совпадение (без суффикса " (...)")
        let key = normalize_group_key(raw_trimmed);
        if key.is_empty() {
            return None;
        }
        self.groups
            .iter()
            .find(|g| {
                normalize_group_key(&g.group_id) == key
                    || normalize_group_key(&g.group_name) == key
            })
            .or_else(|| {
                self.groups.iter().find(|g| {
                    let gn = normalize_group_key(&g.group_name);
                    !gn.is_empty() && (key.contains(&gn) || gn.contains(&key))
                })
            })
    }
}

fn normalize_group_key(raw: &str) -> String {
    let trimmed = raw.trim();
    let without_suffix = match trimmed.find(" (") {
        Some(idx) => &trimmed[..idx],
        None => trimmed,
    };
    without_suffix.trim().to_lowercase()
}

fn decode_pub_key_bytes(server_pub_key_b64: &str) -> Result<Vec<u8>> {
    let bytes = BASE64_STANDARD
        .decode(server_pub_key_b64.trim())
        .context("Failed to decode server_pub_key base64")?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "Invalid server_pub_key length: {} bytes (expected 32)",
            bytes.len()
        ));
    }
    Ok(bytes)
}

pub fn build_transport_probe_packet(server_pub_key_b64: &str) -> Result<(Bytes, Vec<u8>)> {
    let pub_key_bytes = decode_pub_key_bytes(server_pub_key_b64)?;
    let cipher = create_handshake_cipher(&pub_key_bytes);

    let mut echo_nonce = vec![0u8; 12];
    rand::thread_rng().fill_bytes(&mut echo_nonce);

    // Добиваем пакет паддингом (64 байта), чтобы зашифрованный датаграмм (116 байт)
    // гарантированно превышал MIN_HANDSHAKE_LEN (78 байт) в MultiKeyAnetUdpSocket на сервере.
    let mut padding = vec![0u8; 64];
    rand::thread_rng().fill_bytes(&mut padding);

    let now_micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64;

    let msg = Message {
        padding,
        content: Some(Content::TransportProbeRequest(TransportProbeRequest {
            timestamp_micros: now_micros,
            nonce: echo_nonce.clone(),
        })),
    };

    let mut plain = Vec::with_capacity(112);
    msg.encode(&mut plain)?;

    let mut wire_nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut wire_nonce);

    let ciphertext = cipher
        .encrypt(&wire_nonce, Bytes::from(plain))
        .map_err(|e| anyhow!("Probe encryption failed: {}", e))?;

    let mut packet = BytesMut::with_capacity(NONCE_LEN + ciphertext.len());
    packet.put_slice(&wire_nonce);
    packet.put(ciphertext);

    Ok((packet.freeze(), echo_nonce))
}

/// Строит криптографически валидный пакет Фазы 1 (DhClientExchange) с одноразовым эфемерным ключом.
/// Позволяет проверять доступность QUIC/UDP и AHTTP узлов даже на серверах ветки `master`,
/// где ещё нет поддержки `TransportProbeRequest` (сервер расшифрует пакет и вернёт ASTP-ответ без создания сессии).
pub fn build_dh_probe_packet(server_pub_key_b64: &str) -> Result<Bytes> {
    let pub_key_bytes = decode_pub_key_bytes(server_pub_key_b64)?;
    let cipher = create_handshake_cipher(&pub_key_bytes);

    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let client_dh_pub = PublicKey::from(&ephemeral_secret);

    let mut signing_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut signing_bytes);
    let signing_key = SigningKey::from_bytes(&signing_bytes);
    let client_verifying_key = signing_key.verifying_key();
    let client_signed_dh_key = sign_data(&signing_key, client_dh_pub.as_bytes());

    let mut padding = vec![0u8; 32];
    OsRng.fill_bytes(&mut padding);

    let msg = Message {
        padding,
        content: Some(Content::DhClientExchange(DhClientExchange {
            public_key: client_dh_pub.as_bytes().to_vec(),
            client_signed_dh_key,
            client_public_key: client_verifying_key.to_bytes().to_vec(),
            resume_session_id: String::new(),
        })),
    };

    let mut plain = Vec::with_capacity(192);
    msg.encode(&mut plain)?;

    let mut wire_nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut wire_nonce);

    let ciphertext = cipher
        .encrypt(&wire_nonce, Bytes::from(plain))
        .map_err(|e| anyhow!("DH probe encryption failed: {}", e))?;

    let mut packet = BytesMut::with_capacity(NONCE_LEN + ciphertext.len());
    packet.put_slice(&wire_nonce);
    packet.put(ciphertext);

    Ok(packet.freeze())
}

pub fn parse_transport_probe_response(
    server_pub_key_b64: &str,
    encrypted_packet: &[u8],
    expected_nonce: &[u8],
) -> Result<TransportProbeResponse> {
    if encrypted_packet.len() < NONCE_LEN + 16 {
        return Err(anyhow!("Probe response packet too short"));
    }
    let pub_key_bytes = decode_pub_key_bytes(server_pub_key_b64)?;
    let cipher = create_handshake_cipher(&pub_key_bytes);

    let (nonce, ciphertext) = encrypted_packet.split_at(NONCE_LEN);
    let decrypted = cipher
        .decrypt(nonce, Bytes::copy_from_slice(ciphertext))
        .map_err(|e| anyhow!("Failed to decrypt probe response: {}", e))?;

    let msg = Message::decode(decrypted).context("Failed to decode probe response protobuf")?;
    match msg.content {
        Some(Content::TransportProbeResponse(resp)) => {
            if resp.echo_nonce != expected_nonce {
                return Err(anyhow!("Probe echo_nonce mismatch"));
            }
            Ok(resp)
        }
        _ => Err(anyhow!("Unexpected protobuf content in probe response")),
    }
}

/// Расшифровывает любой валидный ASTP-ответ сервера (`TransportProbeResponse`, `DhServerExchange` или `AuthError`).
/// Возвращает `Ok(true)`, если узел жив и принимает подключения, либо `Ok(false)`, если узел в режиме draining.
pub fn parse_any_astp_probe_response(
    server_pub_key_b64: &str,
    encrypted_packet: &[u8],
    expected_nonce: Option<&[u8]>,
) -> Result<bool> {
    if encrypted_packet.len() < NONCE_LEN + 16 {
        return Err(anyhow!("ASTP response packet too short"));
    }
    let pub_key_bytes = decode_pub_key_bytes(server_pub_key_b64)?;
    let cipher = create_handshake_cipher(&pub_key_bytes);

    let (nonce, ciphertext) = encrypted_packet.split_at(NONCE_LEN);
    let decrypted = cipher
        .decrypt(nonce, Bytes::copy_from_slice(ciphertext))
        .map_err(|e| anyhow!("Failed to decrypt ASTP response: {}", e))?;

    let msg = Message::decode(decrypted).context("Failed to decode ASTP response protobuf")?;
    match msg.content {
        Some(Content::TransportProbeResponse(resp)) => {
            if let Some(exp) = expected_nonce {
                if resp.echo_nonce != exp {
                    return Err(anyhow!("Probe echo_nonce mismatch"));
                }
            }
            Ok(resp.accepting_connections)
        }
        Some(Content::DhServerExchange(_)) => Ok(true),
        Some(Content::AuthError(err)) => {
            if err.message.contains("Node is not accepting new connections") {
                Ok(false)
            } else {
                Ok(true)
            }
        }
        _ => Err(anyhow!("Unexpected protobuf content in ASTP response")),
    }
}

async fn resolve_socket_addr(host_port: &str) -> Result<SocketAddr> {
    let normalized = host_port.trim();
    if let Ok(addr) = normalized.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let mut addrs = lookup_host(normalized)
        .await
        .with_context(|| format!("DNS lookup failed for {}", normalized))?;
    addrs
        .next()
        .ok_or_else(|| anyhow!("No addresses resolved for {}", normalized))
}

async fn measure_tcp_connect_rtt(host_port: &str, max_wait: Duration) -> Option<u32> {
    let addr = timeout(max_wait, resolve_socket_addr(host_port)).await.ok()?.ok()?;
    let started = Instant::now();
    let rtt = {
        let _stream = timeout(max_wait, TcpStream::connect(addr)).await.ok()?.ok()?;
        started.elapsed().as_millis().max(1) as u32
    };
    Some(rtt)
}

async fn measure_host_pure_rtt(addr: SocketAddr, max_wait: Duration) -> Option<u32> {
    let mut ports = vec![addr.port(), 443, 22, 80];
    ports.dedup();
    let mut futs = FuturesUnordered::new();
    for port in ports {
        let candidate = SocketAddr::new(addr.ip(), port);
        futs.push(async move {
            let started = Instant::now();
            match timeout(max_wait, TcpStream::connect(candidate)).await {
                Ok(Ok(_stream)) => {
                    let rtt = started.elapsed().as_millis().max(1) as u32;
                    Some(rtt)
                }
                _ => None,
            }
        });
    }
    while let Some(res) = futs.next().await {
        if let Some(rtt) = res {
            return Some(rtt);
        }
    }
    None
}

async fn probe_quic(target: &ProbeTarget, timeout_dur: Duration) -> Result<(u32, u32, String)> {
    let addr = resolve_socket_addr(&target.host_port).await?;
    let bind_addr = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(addr).await?;

    let (probe_pkt, expected_nonce) = build_transport_probe_packet(&target.server_pub_key)?;
    let frag_cfg = FragmentConfig::default();
    let mut recv_buf = [0u8; 2048];

    // 1. Быстрая попытка через легковесный TransportProbeRequest (с 2-байтным заголовком [0, 1] для DatagramReassembler)
    let full_started = Instant::now();
    let pure_started = Instant::now();
    send_fragmented_datagrams(&probe_pkt, &frag_cfg, |frag| {
        let s = &socket;
        async move { s.send(&frag).await.map(|_| ()) }
    })
    .await?;

    let fast_wait = Duration::from_millis(340).min(timeout_dur / 3);
    if let Ok(Ok(len)) = timeout(fast_wait, socket.recv(&mut recv_buf)).await {
        let first_rtt = pure_started.elapsed().as_millis().max(1) as u32;
        if let Ok(resp) = parse_transport_probe_response(
            &target.server_pub_key,
            &recv_buf[..len],
            &expected_nonce,
        ) {
            if !resp.accepting_connections {
                return Err(anyhow!("QUIC node not accepting connections"));
            }
            let mut best_pure_rtt = first_rtt;
            if let Ok((pkt2, nonce2)) = build_transport_probe_packet(&target.server_pub_key) {
                let warm_started = Instant::now();
                if send_fragmented_datagrams(&pkt2, &frag_cfg, |frag| {
                    let s = &socket;
                    async move { s.send(&frag).await.map(|_| ()) }
                })
                .await
                .is_ok()
                {
                    if let Ok(Ok(len2)) =
                        timeout(Duration::from_millis(400), socket.recv(&mut recv_buf)).await
                    {
                        if parse_transport_probe_response(
                            &target.server_pub_key,
                            &recv_buf[..len2],
                            &nonce2,
                        )
                        .is_ok()
                        {
                            let warm_rtt = warm_started.elapsed().as_millis().max(1) as u32;
                            best_pure_rtt = best_pure_rtt.min(warm_rtt);
                        }
                    }
                }
            }
            let full_rtt = full_started
                .elapsed()
                .as_millis()
                .max(best_pure_rtt as u128) as u32;
            return Ok((
                best_pure_rtt,
                full_rtt,
                format!("QUIC ASTP OK ({} / {} ms)", full_rtt, best_pure_rtt),
            ));
        }
    }

    // 2. Fallback для серверов на базе `master` (где поддерживается только DhClientExchange):
    // параллельно замеряем чистый 1-RTT до хоста и отправляем эфемерный DhClientExchange через send_fragmented_datagrams.
    let dh_pkt = build_dh_probe_packet(&target.server_pub_key)?;
    let rem_timeout = timeout_dur
        .checked_sub(full_started.elapsed())
        .unwrap_or(Duration::from_millis(1200))
        .max(Duration::from_millis(900));
    let per_dh_attempt = (rem_timeout / 2).max(Duration::from_millis(550));

    let tcp_pure_fut = measure_host_pure_rtt(addr, Duration::from_millis(650));
    let dh_fut = async {
        for attempt in 0..2 {
            let dh_started = Instant::now();
            send_fragmented_datagrams(&dh_pkt, &frag_cfg, |frag| {
                let s = &socket;
                async move { s.send(&frag).await.map(|_| ()) }
            })
            .await?;
            match timeout(per_dh_attempt, socket.recv(&mut recv_buf)).await {
                Ok(Ok(len)) => {
                    let dh_rtt = dh_started.elapsed().as_millis().max(1) as u32;
                    let accepting = parse_any_astp_probe_response(
                        &target.server_pub_key,
                        &recv_buf[..len],
                        None,
                    )?;
                    if !accepting {
                        return Err(anyhow!("QUIC node not accepting connections"));
                    }
                    return Ok(dh_rtt);
                }
                Ok(Err(e)) => {
                    if attempt == 1 {
                        return Err(anyhow!("UDP recv error: {}", e));
                    }
                }
                Err(_) => {
                    if attempt == 1 {
                        return Err(anyhow!("QUIC ASTP timeout"));
                    }
                }
            }
        }
        Err(anyhow!("QUIC probe failed"))
    };

    let (tcp_pure_opt, dh_res) = tokio::join!(tcp_pure_fut, dh_fut);
    let full_rtt = dh_res?;
    let pure_rtt = tcp_pure_opt
        .map(|p| p.min(full_rtt))
        .unwrap_or_else(|| (full_rtt / 3).max(1));

    Ok((
        pure_rtt,
        full_rtt.max(pure_rtt),
        format!("QUIC ASTP OK ({} / {} ms)", full_rtt.max(pure_rtt), pure_rtt),
    ))
}

struct SshProbeClientHandler;

impl Handler for SshProbeClientHandler {
    type Error = russh::Error;

    fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        ready(Ok(true))
    }
}

async fn probe_ssh(target: &ProbeTarget, timeout_dur: Duration) -> Result<(u32, u32, String)> {
    let full_started = Instant::now();
    let addr = resolve_socket_addr(&target.host_port).await?;
    let (probe_pkt, expected_nonce) = build_transport_probe_packet(&target.server_pub_key)?;

    let fut = async {
        let ssh_config = Arc::new(russh::client::Config {
            client_id: russh::SshId::Standard(crate::consts::DEFAULT_SSH_BANNER.into()),
            nodelay: true,
            ..Default::default()
        });
        let tcp_started = Instant::now();
        let tcp = TcpStream::connect(addr).await?;
        let tcp_rtt = tcp_started.elapsed().as_millis().max(1) as u32;
        let _ = tcp.set_nodelay(true);

        let mut session =
            russh::client::connect_stream(ssh_config, tcp, SshProbeClientHandler).await?;

        let user = if target.ssh_user.is_empty() {
            "hanyuu"
        } else {
            target.ssh_user.as_str()
        };
        let auth_res = session.authenticate_none(user).await?;
        if !auth_res.success() {
            let _ = session
                .disconnect(russh::Disconnect::ByApplication, "probe", "en")
                .await;
            return Err(anyhow!("SSH auth_none rejected"));
        }

        let channel = session.channel_open_session().await?;
        channel.exec(true, "anet-vpn").await?;
        let handshake_rtt = full_started.elapsed().as_millis().max(1) as u32;

        let mut stream = channel.into_stream();
        let framed = frame_packet(probe_pkt);
        let pure_started = Instant::now();
        stream.write_all(&framed).await?;
        stream.flush().await?;

        match read_next_packet(&mut stream).await {
            Ok(Some(reply)) => {
                let astp_rtt = pure_started.elapsed().as_millis().max(1) as u32;
                let full_rtt = full_started.elapsed().as_millis().max(1) as u32;
                let pure_rtt = astp_rtt.min(tcp_rtt);
                let _ = stream.shutdown().await;
                let _ = session
                    .disconnect(russh::Disconnect::ByApplication, "probe", "en")
                    .await;
                let accepting = parse_any_astp_probe_response(
                    &target.server_pub_key,
                    &reply,
                    Some(&expected_nonce),
                )?;
                if !accepting {
                    return Err(anyhow!("SSH node not accepting connections"));
                }
                Ok((
                    pure_rtt,
                    full_rtt.max(pure_rtt),
                    format!("SSH ASTP OK ({} / {} ms)", full_rtt.max(pure_rtt), pure_rtt),
                ))
            }
            Ok(None) | Err(_) => {
                let _ = stream.shutdown().await;
                let _ = session
                    .disconnect(russh::Disconnect::ByApplication, "probe", "en")
                    .await;
                Ok((
                    tcp_rtt,
                    handshake_rtt.max(tcp_rtt),
                    format!("SSH exec OK ({} / {} ms)", handshake_rtt.max(tcp_rtt), tcp_rtt),
                ))
            }
        }
    };

    timeout(timeout_dur, fut)
        .await
        .context("SSH probe timeout")?
}

async fn probe_vnc(target: &ProbeTarget, timeout_dur: Duration) -> Result<(u32, u32, String)> {
    let full_started = Instant::now();
    let addr = resolve_socket_addr(&target.host_port).await?;
    let (probe_pkt, expected_nonce) = build_transport_probe_packet(&target.server_pub_key)?;

    let fut = async {
        let tcp_started = Instant::now();
        let mut stream = TcpStream::connect(addr).await?;
        let tcp_rtt = tcp_started.elapsed().as_millis().max(1) as u32;
        let _ = stream.set_nodelay(true);

        let mut ver = [0u8; 12];
        stream.read_exact(&mut ver).await?;
        if &ver != RFB_VERSION {
            return Err(anyhow!("Invalid RFB banner"));
        }
        stream.write_all(RFB_VERSION).await?;

        let mut sec_types = [0u8; 2];
        stream.read_exact(&mut sec_types).await?;
        if sec_types[0] == 0 {
            return Err(anyhow!("VNC server offered 0 security types"));
        }
        stream.write_all(&[SECURITY_TYPE_NONE]).await?;

        let mut auth_res = [0u8; 4];
        stream.read_exact(&mut auth_res).await?;
        if auth_res != [0, 0, 0, 0] {
            return Err(anyhow!("VNC security result failed"));
        }

        // ClientInit (shared = 1)
        stream.write_all(&[1u8]).await?;

        // ServerInit (24 bytes header + name_len)
        let mut srv_init = [0u8; 24];
        stream.read_exact(&mut srv_init).await?;
        let name_len =
            u32::from_be_bytes([srv_init[20], srv_init[21], srv_init[22], srv_init[23]]) as usize;
        if name_len > 256 {
            return Err(anyhow!("Invalid VNC desktop name length"));
        }
        let mut name_buf = vec![0u8; name_len];
        stream.read_exact(&mut name_buf).await?;

        let rfb_rtt = full_started.elapsed().as_millis().max(1) as u32;

        let pure_started = Instant::now();
        write_cut_text(&mut stream, CLIENT_CUT_TEXT, &probe_pkt).await?;
        stream.flush().await?;

        match read_cut_text(&mut stream, SERVER_CUT_TEXT).await {
            Ok(Some(payload)) => {
                let astp_rtt = pure_started.elapsed().as_millis().max(1) as u32;
                let full_rtt = full_started.elapsed().as_millis().max(1) as u32;
                let pure_rtt = astp_rtt.min(tcp_rtt);
                let _ = stream.shutdown().await;
                let accepting = parse_any_astp_probe_response(
                    &target.server_pub_key,
                    &payload,
                    Some(&expected_nonce),
                )?;
                if !accepting {
                    return Err(anyhow!("VNC node not accepting connections"));
                }
                Ok((
                    pure_rtt,
                    full_rtt.max(pure_rtt),
                    format!("VNC ASTP OK ({} / {} ms)", full_rtt.max(pure_rtt), pure_rtt),
                ))
            }
            Ok(None) | Err(_) => {
                let _ = stream.shutdown().await;
                Ok((
                    tcp_rtt,
                    rfb_rtt.max(tcp_rtt),
                    format!("VNC RFB OK ({} / {} ms)", rfb_rtt.max(tcp_rtt), tcp_rtt),
                ))
            }
        }
    };

    timeout(timeout_dur, fut)
        .await
        .context("VNC probe timeout")?
}

async fn probe_ws(target: &ProbeTarget, timeout_dur: Duration) -> Result<(u32, u32, String)> {
    let ws_url = target
        .websocket_url
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(&target.dsn);

    // Зададим профиль с отключенной проверкой сертификатов для зондирования
    let mut tls_cfg = crate::boring_tls::get_default_tls_config();
    tls_cfg.verify_peer = false;
    let profile = BrowserProfile::with_tls_config(tls_cfg);

    let request = profile.build_ws_request(ws_url, None)?;
    let addr = resolve_socket_addr(&target.host_port).await?;

    let is_wss = ws_url
        .parse::<http::Uri>()
        .ok()
        .and_then(|u| u.scheme_str().map(|s| s.eq_ignore_ascii_case("wss") || s.eq_ignore_ascii_case("https")))
        .unwrap_or_else(|| ws_url.trim().starts_with("wss://"));

    let full_started = Instant::now();
    let (probe_pkt, expected_nonce) = build_transport_probe_packet(&target.server_pub_key)?;

    let fut = async {
        let tcp_started = Instant::now();
        let tcp_stream = TcpStream::connect(addr)
            .await
            .with_context(|| format!("WS TCP connect failed to {}", addr))?;
        let tcp_rtt = tcp_started.elapsed().as_millis().max(1) as u32;
        let _ = tcp_stream.set_nodelay(true);

        // Используем наш стрим (boring TLS или чистый TCP)
        let stream: Box<dyn crate::transport_trait::VpnStream> = if is_wss {
            let target_host = request.uri().host().unwrap_or("").to_string();
            let tls_stream = profile.connect_ws_tls(&target_host, tcp_stream).await?;
            Box::new(tls_stream)
        } else {
            Box::new(tcp_stream)
        };

        let (mut ws_stream, _) =
            client_async_with_config(request, stream, None).await?;
        let upgrade_rtt = full_started.elapsed().as_millis().max(1) as u32;

        let pure_started = Instant::now();
        if ws_stream.send(WsMessage::Binary(probe_pkt)).await.is_err() {
            return Ok((
                tcp_rtt,
                upgrade_rtt.max(tcp_rtt),
                format!("WS Upgrade OK ({} / {} ms)", upgrade_rtt.max(tcp_rtt), tcp_rtt),
            ));
        }

        match ws_stream.next().await {
            Some(Ok(WsMessage::Binary(data))) => {
                let astp_rtt = pure_started.elapsed().as_millis().max(1) as u32;
                let full_rtt = full_started.elapsed().as_millis().max(1) as u32;
                let pure_rtt = astp_rtt.min(tcp_rtt);
                let _ = ws_stream.close(None).await;
                let accepting = parse_any_astp_probe_response(
                    &target.server_pub_key,
                    &data,
                    Some(&expected_nonce),
                )?;
                if !accepting {
                    return Err(anyhow!("WS node not accepting connections"));
                }
                Ok((
                    pure_rtt,
                    full_rtt.max(pure_rtt),
                    format!("WS ASTP OK ({} / {} ms)", full_rtt.max(pure_rtt), pure_rtt),
                ))
            }
            Some(Ok(WsMessage::Close(_))) | None | Some(Err(_)) | _ => {
                let _ = ws_stream.close(None).await;
                Ok((
                    tcp_rtt,
                    upgrade_rtt.max(tcp_rtt),
                    format!("WS Upgrade OK ({} / {} ms)", upgrade_rtt.max(tcp_rtt), tcp_rtt),
                ))
            }
        }
    };

    timeout(timeout_dur, fut)
        .await
        .context("WS probe timeout")?
}

async fn probe_ahttp(target: &ProbeTarget, timeout_dur: Duration) -> Result<(u32, u32, String)> {
    let base_url = if target.dsn.starts_with("http://") || target.dsn.starts_with("https://") {
        target.dsn.trim_end_matches('/').to_string()
    } else if target.host_port.ends_with(":80") {
        format!("http://{}", target.host_port.trim_end_matches('/'))
    } else {
        format!("https://{}", target.host_port.trim_end_matches('/'))
    };

    let path = if target.ahttp_handshake_path.starts_with('/') {
        target.ahttp_handshake_path.as_str()
    } else {
        "/handshake"
    };
    let url = format!("{}{}", base_url, path);

    let dh_pkt = build_dh_probe_packet(&target.server_pub_key)?;

    let mut tls_cfg = crate::boring_tls::get_default_tls_config();
    tls_cfg.verify_peer = false;
    let profile = BrowserProfile::with_tls_config(tls_cfg);

    let client = profile
        .build_reqwest_builder(std::sync::Arc::new(reqwest::cookie::Jar::default()))?
        .timeout(timeout_dur)
        .pool_max_idle_per_host(2)
        .no_proxy()
        .build()?;

    let tcp_pure_fut = measure_tcp_connect_rtt(&target.host_port, Duration::from_millis(800));
    let http_fut = async {
        let full_started = Instant::now();
        let req = client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .body(dh_pkt.to_vec());
        let req = profile.apply_to_reqwest(req, Some(&base_url), Some(&base_url));

        let response = req.send().await.context("AHTTP request failed")?;
        let status = response.status();
        let body = response.bytes().await?;
        let full_rtt = full_started.elapsed().as_millis().max(1) as u32;
        Ok::<(reqwest::StatusCode, Bytes, u32), anyhow::Error>((status, body, full_rtt))
    };

    let (tcp_pure_opt, http_res) = tokio::join!(tcp_pure_fut, http_fut);
    let (status, body, full_rtt) = http_res?;

    if status.is_success() && !body.is_empty() {
        let accepting = parse_any_astp_probe_response(&target.server_pub_key, &body, None)?;
        if !accepting {
            return Err(anyhow!("AHTTP node refused connections"));
        }
        let pure_rtt = tcp_pure_opt
            .unwrap_or_else(|| (full_rtt / 3).max(1))
            .min(full_rtt);
        return Ok((
            pure_rtt,
            full_rtt.max(pure_rtt),
            format!("AHTTP ASTP OK ({} / {} ms)", full_rtt.max(pure_rtt), pure_rtt),
        ));
    }

    Err(anyhow!("AHTTP HTTP status {}", status))
}

async fn probe_wrtc(target: &ProbeTarget, timeout_dur: Duration) -> Result<(u32, u32, String)> {
    let uri: http::Uri = target.dsn.parse().context("Invalid WRTC DSN URI")?;
    let domain = uri
        .host()
        .ok_or_else(|| anyhow!("WRTC DSN missing domain"))?
        .to_string();
    let room_short_name = uri.path().trim_matches('/').to_string();
    if room_short_name.is_empty() {
        return Err(anyhow!("WRTC DSN missing room name"));
    }

    let mut tls_cfg = crate::boring_tls::get_default_tls_config();
    tls_cfg.verify_peer = false;
    let profile = BrowserProfile::with_tls_config(tls_cfg);

    let mut wrtc_cfg = WrtcConfig::default();
    let secs = (timeout_dur.as_secs()).max(2);
    wrtc_cfg.http_connect_timeout_secs = secs;
    wrtc_cfg.http_request_timeout_secs = secs;

    let ktalk = KtalkClient::new(profile, &wrtc_cfg)?;
    let secret = KtalkClient::generate_anonymous_secret();
    let host_port = format!("{}:443", domain);

    let fut = async {
        // Сначала измеряем чистый 1-RTT TCP SYN->SYN-ACK до шлюза сигналинга без конкуренции с TLS
        let tcp_rtt_opt = measure_tcp_connect_rtt(&host_port, Duration::from_millis(900)).await;

        let full_started = Instant::now();
        let session = ktalk
            .authorize_session(&domain, &room_short_name, None, &secret)
            .await?;

        // Соединение в пуле ktalk.http уже установлено (TCP + TLS прогреты) — замеряем одиночный запрос
        let warm_started = Instant::now();
        let room = ktalk
            .resolve_room(&domain, &room_short_name, &session.token)
            .await?;
        let warm_rtt = warm_started.elapsed().as_millis().max(1) as u32;
        let full_rtt = full_started.elapsed().as_millis().max(1) as u32;

        if room.conference_id.is_empty() {
            return Err(anyhow!("Empty Ktalk conferenceId"));
        }

        let pure_rtt = match tcp_rtt_opt {
            Some(tcp_ms) => warm_rtt.min(tcp_ms),
            None => warm_rtt,
        };

        Ok((
            pure_rtt,
            full_rtt.max(pure_rtt),
            format!(
                "WRTC Signaling OK ({} / {} ms)",
                full_rtt.max(pure_rtt),
                pure_rtt
            ),
        ))
    };

    timeout(timeout_dur, fut)
        .await
        .context("WRTC signaling timeout")?
}

pub async fn probe_single_target(
    target: &ProbeTarget,
    timeout_dur: Duration,
) -> EndpointProbeResult {
    let hard_limit = timeout_dur + Duration::from_millis(500);
    let inner_fut = async {
        match target.protocol {
            ProbeProtocol::Quic => probe_quic(target, timeout_dur).await,
            ProbeProtocol::Ssh => probe_ssh(target, timeout_dur).await,
            ProbeProtocol::Vnc => probe_vnc(target, timeout_dur).await,
            ProbeProtocol::Ws => probe_ws(target, timeout_dur).await,
            ProbeProtocol::Ahttp => probe_ahttp(target, timeout_dur).await,
            ProbeProtocol::Wrtc => probe_wrtc(target, timeout_dur).await,
        }
    };
    let res = match timeout(hard_limit, inner_fut).await {
        Ok(r) => r,
        Err(_) => Err(anyhow!("Probe timed out")),
    };

    match res {
        Ok((pure_rtt_ms, full_rtt_ms, detail)) => EndpointProbeResult {
            endpoint_index: target.endpoint_index,
            group_id: target.group_id.clone(),
            group_name: target.group_name.clone(),
            server_name: target.server_name.clone(),
            protocol: target.protocol,
            status: NodeProbeStatus::Available,
            rtt_ms: Some(pure_rtt_ms),
            full_rtt_ms: Some(full_rtt_ms.max(pure_rtt_ms)),
            detail,
        },
        Err(err) => EndpointProbeResult {
            endpoint_index: target.endpoint_index,
            group_id: target.group_id.clone(),
            group_name: target.group_name.clone(),
            server_name: target.server_name.clone(),
            protocol: target.protocol,
            status: NodeProbeStatus::Unavailable,
            rtt_ms: None,
            full_rtt_ms: None,
            detail: err.to_string(),
        },
    }
}

pub fn build_initial_snapshot(targets: &[ProbeTarget]) -> NodeProbeSnapshot {
    let endpoints: Vec<EndpointProbeResult> = targets
        .iter()
        .map(|t| EndpointProbeResult {
            endpoint_index: t.endpoint_index,
            group_id: t.group_id.clone(),
            group_name: t.group_name.clone(),
            server_name: t.server_name.clone(),
            protocol: t.protocol,
            status: NodeProbeStatus::Checking,
            rtt_ms: None,
            full_rtt_ms: None,
            detail: "Проверка...".to_string(),
        })
        .collect();

    let groups = aggregate_groups(targets, &endpoints, true);
    NodeProbeSnapshot {
        checked_at_unix_ms: 0,
        is_checking: !targets.is_empty(),
        completed_endpoints: 0,
        total_endpoints: targets.len(),
        endpoints,
        groups,
    }
}

pub async fn probe_targets(targets: &[ProbeTarget], timeout_dur: Duration) -> NodeProbeSnapshot {
    probe_targets_with_progress(targets, timeout_dur, |_| {}).await
}

pub async fn probe_targets_with_progress<F>(
    targets: &[ProbeTarget],
    timeout_dur: Duration,
    mut on_progress: F,
) -> NodeProbeSnapshot
where
    F: FnMut(NodeProbeSnapshot),
{
    let total_endpoints = targets.len();
    if total_endpoints == 0 {
        return NodeProbeSnapshot::default();
    }

    let mut current_endpoints: Vec<EndpointProbeResult> = targets
        .iter()
        .map(|t| EndpointProbeResult {
            endpoint_index: t.endpoint_index,
            group_id: t.group_id.clone(),
            group_name: t.group_name.clone(),
            server_name: t.server_name.clone(),
            protocol: t.protocol,
            status: NodeProbeStatus::Checking,
            rtt_ms: None,
            full_rtt_ms: None,
            detail: "Проверка...".to_string(),
        })
        .collect();

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_NODE_PROBES));
    let mut futures = FuturesUnordered::new();

    for (pos, target) in targets.iter().cloned().enumerate() {
        let sem = semaphore.clone();
        futures.push(async move {
            let mut res = {
                let _permit = sem.clone().acquire_owned().await.ok();
                probe_single_target(&target, timeout_dur).await
            };
            if res.status == NodeProbeStatus::Unavailable {
                tokio::time::sleep(Duration::from_millis(120)).await;
                let _permit = sem.acquire_owned().await.ok();
                let retry_res = probe_single_target(&target, timeout_dur).await;
                if retry_res.status != NodeProbeStatus::Unavailable {
                    res = retry_res;
                }
            }
            (pos, res)
        });
    }

    let mut completed_endpoints = 0usize;
    while let Some((pos, res)) = futures.next().await {
        {
            if pos < current_endpoints.len() {
                current_endpoints[pos] = res;
            }
            completed_endpoints += 1;
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let groups = aggregate_groups(targets, &current_endpoints, true);
            let partial = NodeProbeSnapshot {
                checked_at_unix_ms: now_ms,
                is_checking: true,
                completed_endpoints,
                total_endpoints,
                endpoints: current_endpoints.clone(),
                groups,
            };
            on_progress(partial);
        }
    }

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let groups = aggregate_groups(targets, &current_endpoints, false);
    NodeProbeSnapshot {
        checked_at_unix_ms: now_ms,
        is_checking: false,
        completed_endpoints: total_endpoints,
        total_endpoints,
        endpoints: current_endpoints,
        groups,
    }
}

fn aggregate_groups(
    targets: &[ProbeTarget],
    endpoints: &[EndpointProbeResult],
    global_is_checking: bool,
) -> Vec<NodeGroupProbeSummary> {
    let mut group_order: Vec<(String, String)> = Vec::new();
    for t in targets {
        if !group_order.iter().any(|(gid, _)| gid == &t.group_id) {
            group_order.push((t.group_id.clone(), t.group_name.clone()));
        }
    }

    let mut summaries = Vec::with_capacity(group_order.len());
    for (group_id, group_name) in group_order {
        let group_eps: Vec<&EndpointProbeResult> = endpoints
            .iter()
            .filter(|e| e.group_id == group_id)
            .collect();
        let total = group_eps.len();
        let any_ep_checking = group_eps
            .iter()
            .any(|e| e.status == NodeProbeStatus::Checking);
        let group_checking = (global_is_checking && any_ep_checking) || total == 0;

        let reachable = group_eps
            .iter()
            .filter(|e| e.status == NodeProbeStatus::Available)
            .count();

        let best_ep = group_eps
            .iter()
            .filter(|e| e.status == NodeProbeStatus::Available && e.rtt_ms.is_some())
            .min_by_key(|e| e.rtt_ms.unwrap_or(u32::MAX));

        let best_rtt_ms = best_ep.and_then(|e| e.rtt_ms);
        let best_full_rtt_ms = best_ep
            .and_then(|e| e.full_rtt_ms)
            .or_else(|| group_eps.iter().filter_map(|e| e.full_rtt_ms).min());

        let status = if group_checking {
            NodeProbeStatus::Checking
        } else if reachable == total {
            NodeProbeStatus::Available
        } else if reachable > 0 {
            NodeProbeStatus::Degraded
        } else {
            NodeProbeStatus::Unavailable
        };

        let mut protocols = Vec::with_capacity(group_eps.len());
        for ep in &group_eps {
            let p_status = if global_is_checking && ep.status == NodeProbeStatus::Checking {
                NodeProbeStatus::Checking
            } else {
                ep.status
            };
            let ep_name = if !ep.server_name.trim().is_empty() {
                ep.server_name.trim().to_string()
            } else {
                ep.protocol.as_str().to_string()
            };
            protocols.push(ProtocolBadgeStatus {
                name: ep_name,
                protocol: ep.protocol,
                status: p_status,
                rtt_ms: ep.rtt_ms,
                full_rtt_ms: ep.full_rtt_ms,
                detail: ep.detail.clone(),
            });
        }

        summaries.push(NodeGroupProbeSummary {
            group_id,
            group_name,
            status,
            best_rtt_ms,
            best_full_rtt_ms,
            reachable_endpoints: reachable,
            total_endpoints: total,
            protocols,
        });
    }

    summaries
}

pub fn extract_probe_targets_from_toml(raw_toml: &str) -> Vec<ProbeTarget> {
    let Ok(root) = toml::from_str::<toml::Value>(raw_toml) else {
        return Vec::new();
    };
    let Some(root_map) = root.as_table() else {
        return Vec::new();
    };

    let global_pub_key = root_map
        .get("keys")
        .and_then(|k| k.as_table())
        .and_then(|k| k.get("server_pub_key"))
        .and_then(|v| v.as_str())
        .or_else(|| {
            root_map
                .get("crypto")
                .and_then(|c| c.as_table())
                .and_then(|c| c.get("server_pub_key"))
                .and_then(|v| v.as_str())
        })
        .or_else(|| root_map.get("server_pub_key").and_then(|v| v.as_str()))
        .unwrap_or("")
        .trim()
        .to_string();

    let default_ssh_user = root_map
        .get("transport")
        .and_then(|t| t.as_table())
        .and_then(|t| t.get("ssh_user"))
        .and_then(|v| v.as_str())
        .unwrap_or("hanyuu")
        .trim()
        .to_string();

    let ahttp_handshake_path = root_map
        .get("ahttp")
        .and_then(|a| a.as_table())
        .and_then(|a| a.get("handshake_path"))
        .and_then(|v| v.as_str())
        .unwrap_or("/handshake")
        .trim()
        .to_string();

    let Some(servers_arr) = root_map.get("servers").and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    let has_groups = servers_arr.iter().any(|item| {
        item.as_table()
            .and_then(|t| t.get("group_name"))
            .and_then(|v| v.as_str())
            .map_or(false, |g| !g.trim().is_empty())
    });

    // Подсчитываем частоту DSN для конфигов без групп, чтобы точки с одинаковым DSN
    // (например, FN WRTC VIDEO / WS / DC / P2P с общим dsn = "wrtc://kontur") получали уникальные group_id
    let mut dsn_counts: HashMap<String, usize> = HashMap::new();
    for item in servers_arr {
        if let Some(tbl) = item.as_table() {
            if let Some(dsn_str) = tbl.get("dsn").and_then(|v| v.as_str()) {
                let trimmed = dsn_str.trim();
                if !trimmed.is_empty() {
                    *dsn_counts.entry(trimmed.to_string()).or_insert(0) += 1;
                }
            }
        }
    }

    let mut targets = Vec::with_capacity(servers_arr.len());
    for (idx, item) in servers_arr.iter().enumerate() {
        let Some(tbl) = item.as_table() else {
            continue;
        };

        let server_pub_key = tbl
            .get("server_pub_key")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| global_pub_key.clone());

        let ssh_user = tbl
            .get("ssh_user")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| default_ssh_user.clone());

        let dsn_opt = tbl
            .get("dsn")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let (dsn, protocol, host_port, websocket_url) = if let Some(dsn_str) = dsn_opt {
            let Ok(uri) = dsn_str.parse::<http::Uri>() else {
                continue;
            };
            let scheme = uri.scheme_str().unwrap_or("quic").to_lowercase();
            let proto = ProbeProtocol::from_proto_str(&scheme);
            let Some(host) = uri.host() else {
                continue;
            };
            let port = uri.port_u16().unwrap_or(match scheme.as_str() {
                "https" | "wss" | "wrtc" | "quic" => 443,
                "http" | "ws" => 80,
                "ssh" => 22,
                "vnc" => 5900,
                _ => 443,
            });
            let hp = format!("{}:{}", host, port);
            let ws_url = if proto == ProbeProtocol::Ws {
                Some(dsn_str.clone())
            } else {
                None
            };
            (dsn_str, proto, hp, ws_url)
        } else {
            let host = tbl
                .get("host")
                .or_else(|| tbl.get("address"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if host.is_empty() {
                continue;
            }
            let proto_str = tbl
                .get("proto")
                .or_else(|| tbl.get("mode"))
                .and_then(|v| v.as_str())
                .unwrap_or("quic")
                .trim()
                .to_lowercase();
            let proto = ProbeProtocol::from_proto_str(&proto_str);
            let ws_url = tbl
                .get("websocket_url")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let dsn_synthesized = ws_url
                .clone()
                .unwrap_or_else(|| format!("{}://{}", proto_str, host));
            (dsn_synthesized, proto, host, ws_url)
        };

        let name = tbl
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let item_group_name = tbl
            .get("group_name")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let (group_id, group_name) = if has_groups && item_group_name.is_some() {
            let g_name = item_group_name.unwrap();
            let g_id = tbl
                .get("group_id")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| g_name.clone());
            (g_id, g_name)
        } else {
            let fallback_name = name.clone().unwrap_or_else(|| {
                let host_only = host_port
                    .split(':')
                    .next()
                    .unwrap_or(host_port.as_str());
                format!("{}:{}", host_only, protocol.as_str())
            });
            let is_duplicate_dsn = dsn_counts.get(dsn.as_str()).copied().unwrap_or(0) > 1
                || targets.iter().any(|t: &ProbeTarget| t.group_id == dsn);
            let unique_id = if is_duplicate_dsn && name.is_some() {
                fallback_name.clone()
            } else {
                dsn.clone()
            };
            (unique_id, fallback_name)
        };

        let server_name = name
            .clone()
            .unwrap_or_else(|| protocol.as_str().to_string());

        targets.push(ProbeTarget {
            endpoint_index: idx,
            group_id,
            group_name,
            server_name,
            protocol,
            dsn,
            host_port,
            websocket_url,
            ahttp_handshake_path: ahttp_handshake_path.clone(),
            ssh_user,
            server_pub_key,
        });
    }

    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_probe_packet_roundtrip() {
        let raw_key = [42u8; 32];
        let pub_key_b64 = BASE64_STANDARD.encode(raw_key);

        let (pkt, expected_nonce) =
            build_transport_probe_packet(&pub_key_b64).expect("build probe");

        let server_cipher = create_handshake_cipher(&raw_key);
        let (wire_nonce, ciphertext) = pkt.split_at(NONCE_LEN);
        let decrypted = server_cipher
            .decrypt(wire_nonce, Bytes::copy_from_slice(ciphertext))
            .expect("decrypt req");
        let msg = Message::decode(decrypted).expect("decode req");
        match msg.content {
            Some(Content::TransportProbeRequest(req)) => {
                assert_eq!(req.nonce, expected_nonce);
            }
            _ => panic!("Expected TransportProbeRequest"),
        }

        let resp_msg = Message {
            padding: vec![],
            content: Some(Content::TransportProbeResponse(TransportProbeResponse {
                timestamp_micros: 123456,
                echo_nonce: expected_nonce.clone(),
                accepting_connections: true,
            })),
        };
        let mut plain_resp = Vec::new();
        resp_msg.encode(&mut plain_resp).unwrap();
        let resp_nonce = [9u8; NONCE_LEN];
        let resp_ct = server_cipher
            .encrypt(&resp_nonce, Bytes::from(plain_resp))
            .expect("encrypt resp");
        let mut encrypted_resp = BytesMut::with_capacity(NONCE_LEN + resp_ct.len());
        encrypted_resp.put_slice(&resp_nonce);
        encrypted_resp.put(resp_ct);

        let parsed =
            parse_transport_probe_response(&pub_key_b64, &encrypted_resp, &expected_nonce)
                .expect("parse");
        assert_eq!(parsed.echo_nonce, expected_nonce);
        assert!(parsed.accepting_connections);
    }

    #[test]
    fn test_extract_probe_targets_from_dsn_toml() {
        let toml_str = r#"
[keys]
server_pub_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

[[servers]]
name = "Frankfurt QUIC"
dsn = "quic://1.2.3.4:443"
group_name = "Frankfurt #1"
group_id = "grp-fra-1"

[[servers]]
name = "Frankfurt SSH"
dsn = "ssh://1.2.3.4:2222"
group_name = "Frankfurt #1"
group_id = "grp-fra-1"

[[servers]]
name = "Helsinki VNC"
dsn = "vnc://5.6.7.8:5900"
group_name = "Helsinki #1"
group_id = "grp-hel-1"
"#;
        let targets = extract_probe_targets_from_toml(toml_str);
        assert_eq!(targets.len(), 3);
        assert_eq!(targets[0].group_id, "grp-fra-1");
        assert_eq!(targets[0].group_name, "Frankfurt #1");
        assert_eq!(targets[0].protocol, ProbeProtocol::Quic);
        assert_eq!(targets[1].protocol, ProbeProtocol::Ssh);
        assert_eq!(targets[2].group_id, "grp-hel-1");
        assert_eq!(targets[2].protocol, ProbeProtocol::Vnc);

        let snap = build_initial_snapshot(&targets);
        assert_eq!(snap.groups.len(), 2);
        assert_eq!(snap.total_endpoints, 3);
        assert_eq!(snap.completed_endpoints, 0);
        assert_eq!(snap.groups[0].total_endpoints, 2);
        assert_eq!(snap.groups[1].total_endpoints, 1);
        assert!(snap.group_for_key("grp-fra-1").is_some());
        assert!(snap.group_for_key("Frankfurt #1").is_some());
    }
}
