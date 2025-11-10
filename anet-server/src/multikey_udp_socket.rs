// anet-server/src/multikey_udp_socket.rs

use anet_common::consts::MAX_PACKET_SIZE;
use anet_common::encryption::Cipher;
use anet_common::transport;
use anet_common::udp_poller::TokioUdpPoller;
use bytes::Bytes;
use dashmap::DashMap;
use log::{debug, error, info, warn};
use quinn::{AsyncUdpSocket, UdpPoller, udp::{RecvMeta, Transmit}};
use std::fmt::{Debug, Formatter};
use std::io;
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context as StdContext, Poll};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use std::sync::Mutex;
use parking_lot::RwLock;

pub type StreamSender = mpsc::Sender<Bytes>;


pub struct ClientTransportInfo {
    pub cipher: Arc<Cipher>,
    pub addr: Arc<RwLock<Option<SocketAddr>>>,
    pub sequence: Arc<AtomicU64>,
    pub assigned_ip: String,
    pub session_id: String,
    pub nonce_prefix: [u8; 4],
}

pub struct MultiKeyAnetUdpSocket {
    io: Arc<UdpSocket>,
    // Карта для отправки (медленный поиск по IP)
    clients_by_seid: Arc<DashMap<String, Arc<ClientTransportInfo>>>,
    // Карта для приема (быстрый поиск по Nonce)
    clients_by_prefix: Arc<DashMap<[u8; 4], Arc<ClientTransportInfo>>>,
}

impl MultiKeyAnetUdpSocket {
    pub fn new(
        io: Arc<UdpSocket>,
        clients_by_seid: Arc<DashMap<String, Arc<ClientTransportInfo>>>,
        clients_by_prefix: Arc<DashMap<[u8; 4], Arc<ClientTransportInfo>>>,
    ) -> Self {
        Self {
            io,
            clients_by_seid,
            clients_by_prefix,
        }
    }
    // --- Удаляем handle_handshake, он больше не нужен ---
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

        // --- ИЩЕМ КЛИЕНТА ПО АДРЕСУ ДЛЯ ОТПРАВКИ (O(N), но это менее критично) ---
        // Это по-прежнему слабое место, но оно не вызывает RcvbufErrors.
        let client_info = self
            .clients_by_seid
            .iter()
            .find(|entry| {
                let addr_lock = entry.addr.read();
                *addr_lock == Some(destination_addr)
            });

        if let Some(entry) = client_info {
            let info = entry.value();
            let seq = info.sequence.fetch_add(1, Ordering::Relaxed);

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
                            warn!("[ANet] UDP send failed for {}: {}. QUIC will retransmit.", destination_addr, e);
                            Ok(())
                        }
                    }
                }
                Err(e) => {
                    error!("[ANet] Failed to wrap outgoing packet for {}: {}", destination_addr, e);
                    Ok(())
                }
            }
        } else {
            // Это нормально во время хендшейка QUIC, когда IP еще не ассоциирован.
            debug!("[ANet] No client found for destination {} during send.", destination_addr);
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
                if filled_len < 12 { // Минимальный размер пакета - Nonce
                    return Poll::Pending;
                }
                let raw_packet = &recv_buf[..filled_len];

                // --- НОВАЯ ЛОГИКА O(1) ПОИСКА ---
                let nonce_prefix: [u8; 4] = raw_packet[..4].try_into().unwrap();

                if let Some(client_info) = self.clients_by_prefix.get(&nonce_prefix) {
                    // Ключ найден! Пробуем расшифровать.
                    match transport::unwrap_packet(&client_info.cipher, raw_packet) {
                        Ok(quic_payload) => {
                            if bufs.is_empty() { return Poll::Ready(Ok(0)); }

                            let copy_len = std::cmp::min(quic_payload.len(), bufs[0].len());
                            bufs[0][..copy_len].copy_from_slice(&quic_payload[..copy_len]);

                            meta[0] = RecvMeta {
                                addr: remote_addr,
                                len: copy_len,
                                stride: copy_len, dst_ip: None, ecn: None,
                            };

                            // --- КРИТИЧЕСКИ ВАЖНО: Обновляем IP-адрес клиента ---
                            // Это позволит `handle_connection` и `try_send` найти его.
                            // Мы не можем просто изменить значение в DashMap, нужно сделать `entry.addr = ...`
                            // Но DashMap возвращает `Ref`, а не `RefMut` на `.get()`. 
                            // Проще всего обновить его так:
                            // client_info.value().addr = Some(remote_addr);
                            if *client_info.addr.read() != Some(remote_addr) {
                                let mut addr_lock = client_info.addr.write();
                                *addr_lock = Some(remote_addr);
                            }


                            return Poll::Ready(Ok(1));
                        }
                        Err(e) => {
                            warn!("[ANet] Decryption failed for known prefix {:?} from {}: {}. Dropping.", nonce_prefix, remote_addr, e);
                        }
                    }
                } else {
                    debug!("[ANet] Received packet with unknown nonce prefix {:?} from {}. Dropping.", nonce_prefix, remote_addr);
                }

                // Если мы дошли сюда, пакет был плохой, но мы не хотим блокировать цикл
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