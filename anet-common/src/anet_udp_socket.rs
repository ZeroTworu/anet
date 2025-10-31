use crate::encryption::Cipher;
use crate::transport;
use log::{error, info};
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
use bytes::Bytes;
use tokio::net::UdpSocket;
use rand::RngCore;

/// Улучшенная реализация AsyncUdpSocket с полным сокрытием QUIC
pub struct AnetUdpSocket {
    io: Arc<UdpSocket>,
    cipher: Arc<Cipher>,
    session_id: [u8; 16],
    sequence: Arc<AtomicU64>,
    handshake_sent: Arc<std::sync::atomic::AtomicBool>,
}

impl AnetUdpSocket {
    pub fn new(io: Arc<UdpSocket>, cipher: Arc<Cipher>, session_id: [u8; 16]) -> Self {
        Self {
            io,
            cipher,
            session_id,
            sequence: Arc::new(AtomicU64::new(0)),
            handshake_sent: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Отправляет initial handshake для установки соединения
    pub async fn send_initial_handshake(&self, remote_addr: SocketAddr) -> io::Result<()> {
        if self.handshake_sent.load(Ordering::Acquire) {
            return Ok(());
        }

        let mut rng = rand::rng();
        let mut client_id = [0u8; 16];
        rng.fill_bytes(&mut client_id);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        info!("Sending initial handshake to {} with session_id: {:?}", remote_addr, self.session_id);
        match transport::wrap_handshake(&self.cipher, self.session_id, client_id, timestamp) {
            Ok(handshake_packet) => {
                // Отправляем с случайной задержкой для обфускации
                // let delay_ms = rng.next_u32() % 100;
                // tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms as u64)).await;

                match self.io.try_send_to(&handshake_packet, remote_addr) {
                    Ok(_) => {
                        info!("Initial handshake sent to {}", remote_addr);
                        self.handshake_sent.store(true, Ordering::Release);
                        Ok(())
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        error!("Would block when sending handshake");
                        Err(e)
                    }
                    Err(e) => {
                        error!("Failed to send handshake: {}", e);
                        Err(e)
                    }
                }
            }
            Err(e) => {
                error!("Failed to wrap handshake: {}", e);
                Err(io::Error::new(io::ErrorKind::Other, e.to_string()))
            }
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

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);

        match transport::wrap_packet(
            &self.cipher,
            self.session_id,
            seq,
            Bytes::copy_from_slice(transmit.contents),
        ) {
            Ok(wrapped_packet) => {
                // Добавляем случайную задержку для обфускации timing analysis
                // let mut rng = rand::rng();
                // let should_delay = rng.random_bool(0.3); // 30% пакетов с задержкой
                //
                // if should_delay {
                //     // Неблокирующая задержка - в реальности нужно было бы использовать асинхронность,
                //     // но так как try_send синхронный, мы просто пропускаем задержку
                //     // Допилить!
                //     trace!("Simulating transmission delay for packet {}", seq);
                // }

                match self.io.try_send_to(&wrapped_packet, transmit.destination) {
                    Ok(_) => Ok(()),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
                    Err(e) => {
                        error!("AnetUdpSocket failed to send: {}", e);
                        Ok(()) // QUIC обработает потерю
                    }
                }
            }
            Err(e) => {
                error!("Failed to wrap QUIC packet: {}", e);
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
        let mut recv_buf = vec![0u8; 65535];
        let mut read_buf = tokio::io::ReadBuf::new(&mut recv_buf);

        match self.io.poll_recv_from(cx, &mut read_buf) {
            Poll::Ready(Ok(remote_addr)) => {
                let filled_len = read_buf.filled().len();
                if filled_len == 0 {
                    return Poll::Pending;
                }

                // Пытаемся расшифровать как data packet
                match transport::unwrap_packet(&self.cipher, self.session_id, &recv_buf[..filled_len]) {
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
                        Poll::Ready(Ok(copy_len))
                    }
                    Err(_) => {
                        // Не смогли расшифровать - возможно это handshake response, игнорируем
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
