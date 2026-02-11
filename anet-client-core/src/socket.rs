use anet_common::config::StealthConfig;
use anet_common::consts::{MAX_PACKET_SIZE, NONCE_PREFIX_LEN, PADDING_MTU};
use anet_common::encryption::Cipher;
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
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use tokio::net::UdpSocket;

/// Улучшенная реализация AsyncUdpSocket с полным сокрытием QUIC
pub struct AnetUdpSocket {
    io: Arc<UdpSocket>,
    cipher: Arc<Cipher>,
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    sequence: Arc<AtomicU64>,
    stealth_config: StealthConfig,
}

impl AnetUdpSocket {
    pub fn new(
        io: Arc<UdpSocket>,
        cipher: Arc<Cipher>,
        nonce_prefix: [u8; NONCE_PREFIX_LEN],
        stealth_config: StealthConfig,
    ) -> Self {
        Self {
            io,
            cipher,
            nonce_prefix,
            sequence: Arc::new(AtomicU64::new(0)),
            stealth_config,
        }
    }
}

impl Debug for AnetUdpSocket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnetUdpSocket")
            .field("local_addr", &self.io.local_addr())
            .finish()
    }
}

impl AsyncUdpSocket for AnetUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(TokioUdpPoller {
            io: self.io.clone(),
        })
    }

    #[inline]
    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        // 1. Считаем полный размер пакета на проводе
        // Overhead = 38 байт (12 Nonce + 16 Tag + 8 Seq + 2 Len)
        let total_len = transmit.contents.len() + 38;

        // 2. Считаем сколько нулей добавить
        let padding = calculate_padding_needed(total_len, self.stealth_config.padding_step);

        // *Safety check: не превышаем MTU ~1450*
        let safe_padding = if total_len + (padding as usize) > PADDING_MTU {
            0
        } else {
            padding
        };

        match transport::wrap_packet(
            &self.cipher,
            &self.nonce_prefix,
            seq,
            Bytes::copy_from_slice(transmit.contents),
            safe_padding,
        ) {
            Ok(wrapped_packet) => {
                match self.io.try_send_to(&wrapped_packet, transmit.destination) {
                    Ok(_) => Ok(()),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
                    Err(e) => {
                        // Логируем, но не паникуем. QUIC обработает потерю.
                        warn!("[ANet] Socket send failed: {}. QUIC will retransmit.", e);
                        Ok(())
                    }
                }
            }
            Err(e) => {
                // Это серьезная ошибка в логике, логируем как error.
                error!("[ANet] Failed to wrap QUIC packet for seq {}: {}", seq, e);
                // Все равно возвращаем Ok, чтобы не обрушить Quinn
                Ok(())
            }
        }
    }

    #[inline]
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
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

                let raw_packet_mut = &mut recv_buf[..filled_len];

                // Пытаемся расшифровать
                match transport::unwrap_packet_in_place(&self.cipher, raw_packet_mut) {
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
                        Poll::Ready(Ok(1)) // Успешно обработали 1 пакет
                    }
                    Err(e) => {
                        // Это может быть просто "левый" пакет в сети. Логируем на уровне debug.
                        debug!(
                            "[ANet] Failed to unwrap packet from {}: {}. Dropping.",
                            remote_addr, e
                        );
                        cx.waker().wake_by_ref();
                        Poll::Pending // Сообщаем Tokio, что нужно попробовать снова
                    }
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
