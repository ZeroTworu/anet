use crate::client_registry::ClientRegistry;
use anet_common::config::StealthConfig;
use anet_common::consts::{
    MAX_PACKET_SIZE, MIN_HANDSHAKE_LEN, NONCE_LEN, PADDING_MTU, TRANSPORT_ENVELOPE_OVERHEAD,
};
use anet_common::handshake_fragmentation::DatagramReassembler;
use anet_common::padding_utils::calculate_padding_needed;
use anet_common::transport;
use anet_common::udp_poller::TokioUdpPoller;
use bytes::Bytes;
use dashmap::DashMap;
use log::{debug, warn};
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
    pub static_ip: Option<String>,
    pub user_id: Option<String>,
    pub resume_session_id: String,
    /// Ограничение скорости в kbps из `AccessGrant`, `None` = без
    /// ограничения. Переносится в `ClientTransportInfo` при завершении
    /// хендшейка (см. `auth_handler::handle_encrypted_auth`).
    pub speed_limit_kbps: Option<u32>,
}

pub type HandshakeData = (Bytes, SocketAddr);

pub struct MultiKeyAnetUdpSocket {
    io: Arc<UdpSocket>,
    registry: Arc<ClientRegistry>,
    auth_tx: mpsc::Sender<HandshakeData>,
    stealth_config: StealthConfig,
    // Реассемблер фрагментированных UDP-хендшейков, по адресу источника.
    // Храним вместе с меткой времени первого фрагмента — если сборка не
    // завершилась в разумное время (клиент оборвался/потерял датаграмму),
    // запись самоочищается при следующем обращении с того же адреса, без
    // отдельной фоновой GC-задачи.
    reassemblers: Arc<DashMap<SocketAddr, (Instant, DatagramReassembler)>>,
}

const REASSEMBLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

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
            reassemblers: Arc::new(DashMap::new()),
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

            let total_len = transmit.contents.len() + TRANSPORT_ENVELOPE_OVERHEAD;
            let padding = calculate_padding_needed(total_len, self.stealth_config.padding_step);
            let safe_padding = if total_len + (padding as usize) > PADDING_MTU {
                0
            } else {
                padding
            };

            let wrapped = transport::wrap_packet_slice(
                &info.cipher,
                &info.nonce_prefix,
                seq,
                transmit.contents,
                safe_padding,
            )
            .map_err(io::Error::other)?;
            self.io
                .try_send_to(&wrapped, transmit.destination)
                .map(|_| ())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("no session for {}", transmit.destination),
            ))
        }
    }

    fn poll_recv(
        &self,
        cx: &mut StdContext<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut count = 0;
        // Индекс текущего буфера Quinn, который мы хотим заполнить
        let mut i = 0;

        let mut recv_buf = [0u8; MAX_PACKET_SIZE];

        // Читаем, пока есть свободные буферы у Quinn
        while i < bufs.len() {
            let mut read_buf = tokio::io::ReadBuf::new(&mut recv_buf);

            match self.io.poll_recv_from(cx, &mut read_buf) {
                Poll::Ready(Ok(remote_addr)) => {
                    let filled_len = read_buf.filled().len();
                    if filled_len == 0 {
                        break;
                    }

                    let raw_packet_mut = &mut recv_buf[..filled_len];
                    let mut packet_for_quinn = false;

                    // 1. Попытка распознать сессию (Session Data)
                    if filled_len >= NONCE_LEN + 1 {
                        // Пробуем взять префикс
                        if let Ok(nonce_prefix) = raw_packet_mut[..4].try_into() {
                            if let Some(client_info) = self.registry.get_by_prefix(&nonce_prefix) {
                                self.registry.update_client_addr(&client_info, remote_addr);

                                match transport::unwrap_packet_in_place(
                                    &client_info.cipher,
                                    raw_packet_mut,
                                ) {
                                    Ok(quic_payload) => {
                                        // УРА! Это пакет для Quinn (данные туннеля)
                                        let buf = &mut bufs[i];
                                        let copy_len = quic_payload.len().min(buf.len());
                                        buf[..copy_len].copy_from_slice(&quic_payload[..copy_len]);

                                        meta[i] = RecvMeta {
                                            addr: remote_addr,
                                            len: copy_len,
                                            stride: copy_len,
                                            dst_ip: None,
                                            ecn: None,
                                        };

                                        count += 1;
                                        i += 1; // Переходим к следующему слоту Quinn
                                        packet_for_quinn = true;
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Session decryption failed for {}: {}",
                                            remote_addr, e
                                        );
                                        // Пакет битый, Quinn его не получит.
                                        // Но цикл не прерываем, читаем дальше.
                                    }
                                }
                            }
                        }
                    }

                    // 2. Если это не пакет сессии - проверяем Хендшейк
                    if !packet_for_quinn {
                        // Собираем через реассемблер ДО проверки MIN_HANDSHAKE_LEN:
                        // отдельные фрагменты хендшейка (при включённой
                        // фрагментации на клиенте)
                        let complete: Option<Vec<u8>> = {
                            let mut entry = self
                                .reassemblers
                                .entry(remote_addr)
                                .and_modify(|(ts, reassembler)| {
                                    if ts.elapsed() > REASSEMBLY_TIMEOUT {
                                        *reassembler = DatagramReassembler::new();
                                    }
                                    *ts = Instant::now();
                                })
                                .or_insert_with(|| (Instant::now(), DatagramReassembler::new()));

                            entry.1.feed(raw_packet_mut)
                        };

                        debug!(
                            "[Socket] Start reassembling handshake from {}:",
                            remote_addr
                        );
                        if let Some(complete) = complete {
                            self.reassemblers.remove(&remote_addr);

                            if complete.len() >= MIN_HANDSHAKE_LEN {
                                let packet_copy = Bytes::from(complete);
                                if self.auth_tx.try_send((packet_copy, remote_addr)).is_err() {
                                    warn!("[Socket] Auth channel full, dropping packet");
                                }
                            } else {
                                warn!(
                                    "[Socket] Reassembled handshake too short from {} ({} bytes), dropping",
                                    remote_addr,
                                    complete.len()
                                );
                            }
                        }
                    }
                }
                Poll::Ready(Err(error)) => {
                    if count > 0 {
                        return Poll::Ready(Ok(count));
                    }
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => {
                    // Сокет пуст. Больше читать нечего.
                    break;
                }
            }
        }

        if count > 0 {
            Poll::Ready(Ok(count))
        } else {
            // Если count == 0, но мы вернули Pending - это корректно.
            // Waker был зарегистрирован последним вызовом poll_recv_from.
            Poll::Pending
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        true
    }
}
