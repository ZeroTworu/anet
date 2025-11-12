use anet_common::consts::{AUTH_PREFIX_LEN, MAX_PACKET_SIZE, NONCE_LEN};
use anet_common::crypto_utils::check_auth_prefix;
use anet_common::encryption::Cipher;
use anet_common::transport;
use anet_common::udp_poller::TokioUdpPoller;
use arc_swap::ArcSwap;
use bytes::Bytes;
use dashmap::DashMap;
use log::{debug, error, info, warn};
use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use std::fmt::{Debug, Formatter};
use std::io;
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context as StdContext, Poll};
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub type StreamSender = mpsc::Sender<Bytes>;

// --- НОВАЯ СТРУКТУРА: Временное DH Состояние ---
#[derive(Clone)]
pub struct TempDHInfo {
    pub shared_key: [u8; 32],
    pub created_at: Instant,
    pub client_fingerprint: String,
}

pub struct ClientTransportInfo {
    pub cipher: Arc<Cipher>,
    pub sequence: Arc<AtomicU64>,
    pub assigned_ip: String,
    pub session_id: String,
    pub nonce_prefix: [u8; 4],
    pub remote_addr: ArcSwap<SocketAddr>,
}

pub type HandshakeData = (Bytes, SocketAddr);

pub struct MultiKeyAnetUdpSocket {
    io: Arc<UdpSocket>,
    // Используются в handle_connection/cleanup
    // O(1) для приема QUIC
    clients_by_prefix: Arc<DashMap<[u8; 4], Arc<ClientTransportInfo>>>,
    // O(1) для отправки QUIC
    clients_by_addr: Arc<DashMap<SocketAddr, Arc<ClientTransportInfo>>>,
    auth_tx: mpsc::Sender<HandshakeData>,
}

impl MultiKeyAnetUdpSocket {
    pub fn new(
        io: Arc<UdpSocket>,
        clients_by_prefix: Arc<DashMap<[u8; 4], Arc<ClientTransportInfo>>>,
        clients_by_addr: Arc<DashMap<SocketAddr, Arc<ClientTransportInfo>>>,
        auth_tx: mpsc::Sender<HandshakeData>,
    ) -> Self {
        Self {
            io,
            clients_by_prefix,
            clients_by_addr,
            auth_tx,
        }
    }
}

impl Debug for MultiKeyAnetUdpSocket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiKeyAnetUdpSocket")
            .field("local_addr", &self.io.local_addr())
            .finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for MultiKeyAnetUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(TokioUdpPoller {
            io: self.io.clone(),
        })
    }

    #[inline]
    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let destination_addr = transmit.destination;

        // O(1) LOOKUP для отправки QUIC
        if let Some(entry) = self.clients_by_addr.get(&destination_addr) {
            let info = entry.value();
            let seq = info.sequence.fetch_add(1, Ordering::Relaxed);

            // Все, что нашлось по адресу, считается частью ANet QUIC туннеля,
            // и должно быть обернуто. (Иначе это логическая ошибка)
            match transport::wrap_packet(
                &info.cipher,
                &info.nonce_prefix,
                seq,
                Bytes::copy_from_slice(transmit.contents),
            ) {
                Ok(wrapped_packet) => {
                    match self.io.try_send_to(&wrapped_packet, destination_addr) {
                        Ok(_) => Ok(()),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
                        Err(e) => {
                            warn!(
                                "[ANet] UDP send failed for {}: {}. QUIC will retransmit.",
                                destination_addr, e
                            );
                            Ok(())
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "[ANet] Failed to wrap outgoing packet for {}: {}",
                        destination_addr, e
                    );
                    Ok(())
                }
            }
        } else {
            // No client info found (not authenticated yet or connection closed).
            Ok(())
        }
    }

    fn poll_recv(
        &self,
        cx: &mut StdContext<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut recv_buf = vec![0u8; MAX_PACKET_SIZE];
        let mut read_buf = tokio::io::ReadBuf::new(&mut recv_buf);

        match self.io.poll_recv_from(cx, &mut read_buf) {
            Poll::Ready(Ok(remote_addr)) => {
                let filled_len = read_buf.filled().len();
                if filled_len == 0 {
                    return Poll::Pending;
                }
                let raw_packet = &recv_buf[..filled_len];

                // 1. ПРОВЕРКА AUTH HANDSHAKE (8 байт RND XOR MAGIC)
                if filled_len >= AUTH_PREFIX_LEN
                    && check_auth_prefix(&raw_packet[..AUTH_PREFIX_LEN])
                {
                    // Это Auth пакет. Отправляем в Auth Handler
                    let full_packet = Bytes::copy_from_slice(raw_packet);

                    if self.auth_tx.try_send((full_packet, remote_addr)).is_err() {
                        warn!(
                            "[ANet] Auth channel buffer full, dropping handshake packet from {}.",
                            remote_addr
                        );
                    }

                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }

                // 2. ПРОВЕРКА ANET-QUIC (если не Auth, это должно быть зашифровано ANet)
                if filled_len < NONCE_LEN + 1 {
                    // Короткий пакет (Non-Auth). Отбрасываем, так как нет информации для QUIC
                    debug!(
                        "[ANet] Dropping short/non-ANET QUIC packet (len: {}) from {}",
                        filled_len, remote_addr
                    );
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }

                let nonce_prefix: [u8; 4] = raw_packet[..4].try_into().unwrap();

                // O(1) LOOKUP по nonce_prefix
                if let Some(entry) = self.clients_by_prefix.get(&nonce_prefix) {
                    let client_info = entry.value();

                    // --- ЛОГИКА РОУМИНГА/ОБНОВЛЕНИЯ АДРЕСА ---
                    let current_known_addr_guard = client_info.remote_addr.load();
                    let current_known_addr = (*current_known_addr_guard).deref();

                    if current_known_addr != &remote_addr {
                        // Удаление старой записи из clients_by_addr, добавление новой
                        if self.clients_by_addr.remove(current_known_addr).is_some() {
                            // Обновляем ArcSwap<SocketAddr>
                            client_info.remote_addr.store(Arc::new(remote_addr));
                            // Добавляем новый ключ (remote_addr) в DashMap Tx
                            self.clients_by_addr
                                .insert(remote_addr, client_info.clone());

                            info!(
                                "[ANet Roaming] Address updated: {} -> {}. VPN IP: {}",
                                current_known_addr, remote_addr, client_info.assigned_ip
                            );
                        } else {
                            // Это сложная ситуация, когда ArcSwap обновился, но Map уже удалил старый ключ.
                            // Обновляем ArcSwap, чтобы Quinn получил актуальный адрес.
                            client_info.remote_addr.store(Arc::new(remote_addr));
                        }
                    }

                    // --- Дешифровка ANET и передача QUIC ---
                    match transport::unwrap_packet(&client_info.cipher, raw_packet) {
                        Ok(quic_payload) => {
                            if bufs.is_empty() {
                                return Poll::Ready(Ok(0));
                            }

                            let copy_len = std::cmp::min(quic_payload.len(), bufs[0].len());
                            bufs[0][..copy_len].copy_from_slice(&quic_payload[..copy_len]);

                            meta[0] = RecvMeta {
                                addr: remote_addr,
                                len: copy_len,
                                stride: copy_len,
                                dst_ip: None,
                                ecn: None,
                            };

                            Poll::Ready(Ok(1))
                        }
                        Err(e) => {
                            warn!(
                                "[ANet] Decryption failed for known prefix {:?} from {}: {}. Dropping.",
                                nonce_prefix, remote_addr, e
                            );
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    }
                } else {
                    debug!(
                        "[ANet] Received packet with unknown ANET nonce prefix {:?} from {}. Dropping.",
                        nonce_prefix, remote_addr
                    );
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
}
