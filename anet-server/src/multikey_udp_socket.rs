use anet_common::udp_poller::TokioUdpPoller;
use anet_common::consts::MAX_PACKET_SIZE;
use anet_common::encryption::Cipher;
use anet_common::transport;
use bytes::Bytes;
use dashmap::DashMap;
use log::{error, info, warn};
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context as StdContext, Poll};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub type StreamSender = mpsc::Sender<Bytes>;

#[derive(Clone)]
pub struct ClientTransportInfo {
    pub cipher: Arc<Cipher>,
    pub addr: Option<SocketAddr>,
    pub sequence: Arc<AtomicU64>,
    pub assigned_ip: String,
    pub session_id: String,
    pub session_id_bytes: [u8; 16],
}

// Упрощенный MultiKeyAnetUdpSocket - используем ту же структуру клиентов что и ANetServer
pub struct MultiKeyAnetUdpSocket {
    io: Arc<UdpSocket>,
    clients: Arc<DashMap<String, ClientTransportInfo>>, // ИЗМЕНЕНО: Mutex -> DashMap
    pending_handshakes: Arc<DashMap<SocketAddr, String>>, // ИЗМЕНЕНО: Mutex -> DashMap
}

impl MultiKeyAnetUdpSocket {
    pub fn new(io: Arc<UdpSocket>, clients: Arc<DashMap<String, ClientTransportInfo>>) -> Self {
        Self {
            io,
            clients,
            pending_handshakes: Arc::new(DashMap::new()),
        }
    }

    /// Обрабатывает входящий handshake
    pub fn handle_handshake(&self, remote_addr: SocketAddr, packet_data: &[u8]) -> Option<String> {
        info!(
            "Processing handshake from {}, available clients: {}",
            remote_addr,
            self.clients.len()
        );

        // Пробуем все известные клиенты для расшифровки handshake
        for entry in self.clients.iter() {
            let session_id_str = entry.key();
            let client_info = entry.value();

            info!("Trying client with session_id: {}", session_id_str);

            if let Ok((_client_id, timestamp)) = transport::unwrap_handshake(
                &client_info.cipher,
                client_info.session_id_bytes,
                packet_data,
            ) {
                // Проверяем timestamp для защиты от replay атак
                let current_time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                if current_time.abs_diff(timestamp) > 30 {
                    warn!(
                        "Handshake timestamp too old from {}: {} vs {}",
                        remote_addr, timestamp, current_time
                    );
                    continue;
                }

                info!(
                    "Handshake received from {} for session {}",
                    remote_addr, session_id_str
                );

                // Сохраняем сопоставление адреса и session_id
                self.pending_handshakes
                    .insert(remote_addr, session_id_str.clone());

                return Some(session_id_str.clone());
            } else {
                info!("Failed to decrypt with session_id: {}", session_id_str);
            }
        }

        warn!(
            "No matching session found for handshake from {}",
            remote_addr
        );
        None
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

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let destination_addr = transmit.destination;
        let seq;
        let cipher;
        let session_id_bytes;

        // Сначала ищем по pending handshakes
        if let Some(entry) = self.pending_handshakes.get(&destination_addr) {
            let session_id_str = entry.value();
            if let Some(client_info) = self.clients.get(session_id_str) {
                seq = client_info.sequence.fetch_add(1, Ordering::Relaxed);
                cipher = client_info.cipher.clone();
                session_id_bytes = client_info.session_id_bytes;
            } else {
                info!("1 No client found for destination: {}", destination_addr);
                return Ok(());
            }
        } else {
            // Ищем клиента по адресу
            let client_info = self
                .clients
                .iter()
                .find(|entry| entry.addr == Some(destination_addr));

            if let Some(entry) = client_info {
                seq = entry.sequence.fetch_add(1, Ordering::Relaxed);
                cipher = entry.cipher.clone();
                session_id_bytes = entry.session_id_bytes;
            } else {
                info!("2 No client found for destination: {}", destination_addr);
                return Ok(());
            }
        }

        let packet = transport::wrap_packet(
            &cipher,
            session_id_bytes,
            seq,
            Bytes::copy_from_slice(transmit.contents),
        );

        match packet {
            Ok(wrapped_packet) => match self.io.try_send_to(&wrapped_packet, destination_addr) {
                Ok(_) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
                Err(e) => {
                    error!("MultiKeyAnetUdpSocket failed to send: {}", e);
                    Ok(())
                }
            },
            Err(e) => {
                error!("Failed to wrap outgoing packet: {}", e);
                Ok(())
            }
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
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }

                let packet_slice = &recv_buf[..filled_len];

                // Сначала проверяем, знаем ли мы уже этот адрес
                let session_id_opt = self
                    .pending_handshakes
                    .get(&remote_addr)
                    .map(|entry| entry.value().clone());

                let mut unwrapped_data: Option<Bytes> = None;
                let mut found_session_id = None;

                if let Some(session_id_str) = session_id_opt {
                    // Уже есть сопоставление - пробуем расшифровать как data packet
                    if let Some(client_info) = self.clients.get(&session_id_str) {
                        if let Ok(data_packet) = transport::unwrap_packet(
                            &client_info.cipher,
                            client_info.session_id_bytes,
                            packet_slice,
                        ) {
                            unwrapped_data = Some(data_packet);
                            found_session_id = Some(session_id_str);
                        }
                    }
                } else {
                    // Нет сопоставления - пробуем обработать как handshake
                    if let Some(session_id_str) = self.handle_handshake(remote_addr, packet_slice) {
                        info!(
                            "Handshake processed for: {}, SEID: {}",
                            remote_addr, session_id_str
                        );
                        cx.waker().wake_by_ref();
                        return Poll::Pending; // Handshake пакет не содержит QUIC данных
                    }

                    // Если не handshake, пробуем все известные клиенты для data packets
                    for entry in self.clients.iter() {
                        let session_id_str = entry.key();
                        let client_info = entry.value();

                        if let Ok(data_packet) = transport::unwrap_packet(
                            &client_info.cipher,
                            client_info.session_id_bytes,
                            packet_slice,
                        ) {
                            unwrapped_data = Some(data_packet);
                            found_session_id = Some(session_id_str.clone());

                            // Обновляем адрес клиента
                            self.pending_handshakes
                                .insert(remote_addr, session_id_str.clone());
                            break;
                        }
                    }
                }

                if let (Some(data), Some(session_id_str)) = (unwrapped_data, found_session_id) {
                    if bufs.is_empty() {
                        return Poll::Ready(Ok(0));
                    }

                    let copy_len = std::cmp::min(data.len(), bufs[0].len());
                    bufs[0][..copy_len].copy_from_slice(&data[..copy_len]);

                    meta[0] = RecvMeta {
                        addr: remote_addr,
                        len: copy_len,
                        stride: copy_len,
                        dst_ip: None,
                        ecn: None,
                    };

                    // Обновляем адрес в основной структуре клиентов
                    if let Some(mut client_info) = self.clients.get_mut(&session_id_str) {
                        client_info.addr = Some(remote_addr);
                    }

                    Poll::Ready(Ok(1))
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Poll::Ready(Err(e)) => {
                error!("Error receiving from socket: {}", e);
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
}
