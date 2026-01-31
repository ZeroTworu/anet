use crate::client_registry::ClientRegistry;
use anet_common::config::StealthConfig;
use anet_common::consts::{MAX_PACKET_SIZE, MIN_HANDSHAKE_LEN, NONCE_LEN, PADDING_MTU};
use anet_common::padding_utils::calculate_padding_needed;
use anet_common::transport;
use anet_common::udp_poller::TokioUdpPoller;
use bytes::Bytes;
use log::{debug, error, warn};
use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use std::fmt::{Debug, Formatter};
use std::io;
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context as StdContext, Poll};
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub type StreamSender = mpsc::Sender<Bytes>;

#[derive(Clone)]
pub struct TempDHInfo {
    pub shared_key: [u8; 32],
    pub created_at: Instant,
    pub client_fingerprint: String,
}

pub type HandshakeData = (Bytes, SocketAddr);

pub struct MultiKeyAnetUdpSocket {
    io: Arc<UdpSocket>,
    registry: Arc<ClientRegistry>,
    auth_tx: mpsc::Sender<HandshakeData>,
    stealth_config: StealthConfig,
}

impl MultiKeyAnetUdpSocket {
    pub fn new(
        io: Arc<UdpSocket>,
        registry: Arc<ClientRegistry>,
        auth_tx: mpsc::Sender<HandshakeData>,
        stealth_config: StealthConfig,
    ) -> Self {
        Self {
            io,
            registry,
            auth_tx,
            stealth_config,
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
        if let Some(info) = self.registry.get_by_addr(&transmit.destination) {
            let seq = info.sequence.fetch_add(1, Ordering::Relaxed);

            let total_len = transmit.contents.len() + 38;
            let padding = calculate_padding_needed(total_len, self.stealth_config.padding_step);
            let safe_padding = if total_len + (padding as usize) > PADDING_MTU {
                0
            } else {
                padding
            };

            match transport::wrap_packet(
                &info.cipher,
                &info.nonce_prefix,
                seq,
                Bytes::copy_from_slice(transmit.contents),
                safe_padding,
            ) {
                Ok(wrapped) => match self.io.try_send_to(&wrapped, transmit.destination) {
                    Ok(_) => Ok(()),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
                    Err(e) => {
                        warn!(
                            "[Socket] UDP send failed for {}: {}. QUIC will retransmit.",
                            transmit.destination, e
                        );
                        Ok(())
                    }
                },
                Err(e) => {
                    error!(
                        "[Socket] Failed to wrap outgoing packet for {}: {}",
                        transmit.destination, e
                    );
                    Ok(())
                }
            }
        } else {
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

                // 1. Проверяем, похоже ли это на пакет сессии (мин длина)
                if filled_len >= NONCE_LEN + 1 {
                    let nonce_prefix: [u8; 4] = raw_packet[..4].try_into().unwrap();

                    // Если есть в реестре - это сессия
                    if let Some(client_info) = self.registry.get_by_prefix(&nonce_prefix) {
                        self.registry.update_client_addr(&client_info, remote_addr);

                        match transport::unwrap_packet(&client_info.cipher, raw_packet) {
                            Ok(quic_payload) => {
                                if bufs.is_empty() {
                                    return Poll::Ready(Ok(0));
                                }
                                let copy_len = quic_payload.len().min(bufs[0].len());
                                bufs[0][..copy_len].copy_from_slice(&quic_payload[..copy_len]);
                                meta[0] = RecvMeta {
                                    addr: remote_addr,
                                    len: copy_len,
                                    stride: copy_len,
                                    dst_ip: None,
                                    ecn: None,
                                };
                                return Poll::Ready(Ok(1));
                            }
                            Err(e) => {
                                // Ошибка дешифровки сессии. Возможно коллизия префикса или атака.
                                // Но раз префикс совпал, мы не передаем это в AuthHandler,
                                // так как AuthHandler ожидает случайный Nonce, а не наш Sequence.
                                warn!("Session decryption failed for {}: {}", remote_addr, e);
                                cx.waker().wake_by_ref();
                                return Poll::Pending;
                            }
                        }
                    }
                }

                // 2. Если не сессия - возможно это Handshake.
                // Отправляем в AuthHandler, если длина проходит минимальный порог
                if filled_len >= MIN_HANDSHAKE_LEN {
                    // Try_send, чтобы не блокировать IO поток
                    if self
                        .auth_tx
                        .try_send((Bytes::copy_from_slice(raw_packet), remote_addr))
                        .is_err()
                    {
                        warn!(
                            "[Socket] Auth channel full, dropping handshake from {}.",
                            remote_addr
                        );
                    }
                } else {
                    debug!(
                        "[Socket] Dropping short unknown packet from {}",
                        remote_addr
                    );
                }

                // В любом случае (Handshake или мусор) для QUIC сокета это "ничего"
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
}
