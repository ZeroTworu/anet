use crate::encryption::Cipher;
use crate::transport;
use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use tokio::net::UdpSocket;

/// Наша реализация AsyncUdpSocket, которая оборачивает стандартный Tokio UdpSocket
/// и добавляет слой шифрования (обфускации).
pub struct AnetUdpSocket {
    io: Arc<UdpSocket>,       // Реальный сокет
    cipher: Arc<Cipher>,      // Шифр для "обертки"
    sequence: Arc<AtomicU64>, // Счетчик последовательности для nonce
}

impl AnetUdpSocket {
    pub fn new(io: Arc<UdpSocket>, cipher: Arc<Cipher>) -> Self {
        Self {
            io,
            cipher,
            sequence: Arc::new(AtomicU64::new(0)),
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

// Реализуем трейт, который нужен `quinn::Endpoint`
impl AsyncUdpSocket for AnetUdpSocket {
    // В v0.11 create_io_poller принимает Arc<Self>
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(TokioUdpPoller {
            io: self.io.clone(),
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);

        // Оборачиваем пакет QUIC в наш транспортный протокол
        match transport::wrap_packet(
            &self.cipher,
            seq,
            bytes::Bytes::copy_from_slice(transmit.contents),
        ) {
            Ok(wrapped_packet) => {
                // Пытаемся отправить синхронно, как того требует API
                match self.io.try_send_to(&wrapped_packet, transmit.destination) {
                    Ok(_) => Ok(()),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        // Важно правильно обрабатывать WouldBlock
                        Err(e)
                    }
                    Err(e) => {
                        log::error!("AnetUdpSocket failed to send: {}", e);
                        // QUIC умеет обрабатывать потери, поэтому мы можем "проглотить" ошибку,
                        // возвращая Ok, чтобы не паниковать.
                        Ok(())
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to wrap QUIC packet: {}", e);
                // Если не смогли зашифровать, просто пропускаем отправку.
                Ok(())
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut recv_buf = vec![0u8; 65535]; // Буфер для чтения "обернутого" пакета

        let mut read_buf = tokio::io::ReadBuf::new(&mut recv_buf);

        match self.io.poll_recv_from(cx, &mut read_buf) {
            Poll::Ready(Ok(remote_addr)) => {
                let filled_len = read_buf.filled().len();
                if filled_len == 0 {
                    return Poll::Pending;
                }

                // "Разворачиваем" пакет
                match transport::unwrap_packet(&self.cipher, &recv_buf[..filled_len]) {
                    Ok(unwrapped_packet) => {
                        if bufs.is_empty() {
                            return Poll::Ready(Ok(0));
                        }
                        let copy_len = std::cmp::min(unwrapped_packet.len(), bufs[0].len());
                        bufs[0][..copy_len].copy_from_slice(&unwrapped_packet[..copy_len]);

                        meta[0] = RecvMeta {
                            addr: remote_addr,
                            len: copy_len,
                            stride: copy_len,
                            dst_ip: None,
                            ecn: None,
                        };
                        Poll::Ready(Ok(1))
                    }
                    Err(_) => {
                        // Не смогли расшифровать. Игнорируем пакет.
                        cx.waker().wake_by_ref();
                        Poll::Pending
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

#[derive(Debug)]
pub struct TokioUdpPoller {
    pub io: Arc<UdpSocket>,
}

impl Future for TokioUdpPoller {
    type Output = io::Result<()>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.io.poll_send_ready(cx).map(|res| res.map(|_| ()))
    }
}

impl UdpPoller for TokioUdpPoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self).poll(cx)
    }
}
