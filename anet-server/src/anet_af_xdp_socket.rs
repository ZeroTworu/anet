use crate::client_registry::ClientRegistry;
use anet_common::config::StealthConfig;
use anet_common::consts::{MIN_HANDSHAKE_LEN, NONCE_LEN, PADDING_MTU};
use anet_common::padding_utils::calculate_padding_needed;
use anet_common::transport;
use bytes::Bytes;
use log::{error, warn, info, debug};
use quinn::{AsyncUdpSocket, UdpPoller, udp::{RecvMeta, Transmit}};
use std::{io, net::{SocketAddr, Ipv4Addr}, sync::Arc, task::{Context, Poll}, pin::Pin, fmt::Debug};
use std::fmt::Formatter;
use std::num::NonZeroU32;
use std::ffi::CString;
use std::os::unix::io::AsRawFd;
use tokio::io::unix::AsyncFd;
use xsk_rs::{
    RxQueue, FillQueue, CompQueue, TxQueue, Umem, FrameDesc, Socket,
    config::{SocketConfig, UmemConfig, Interface, QueueSize, FrameSize, BindFlags, LibxdpFlags, XdpFlags}
};
use pnet_packet::{Packet, MutablePacket};
use pnet_packet::ethernet::{EthernetPacket, EtherTypes, MutableEthernetPacket};
use pnet_packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::udp::{UdpPacket, MutableUdpPacket};
use std::sync::atomic::Ordering;
use tokio::sync::mpsc;
use parking_lot::Mutex;

pub type HandshakeData = (Bytes, SocketAddr);

pub struct AnetAfXdpSocket {
    rx_q: Mutex<RxQueue>,
    tx_q: Mutex<TxQueue>,
    fq: Mutex<FillQueue>,
    cq: Mutex<CompQueue>,
    umem: Umem,
    async_fd: AsyncFd<i32>,

    registry: Arc<ClientRegistry>,
    auth_tx: mpsc::Sender<HandshakeData>,
    stealth_config: StealthConfig,

    local_mac: Mutex<[u8; 6]>,
    gateway_mac: Mutex<[u8; 6]>,
    local_ip: Mutex<Ipv4Addr>,
    bind_port: u16,
    tx_free_frames: Mutex<Vec<FrameDesc>>,
}

impl AnetAfXdpSocket {
    pub fn new(
        iface_name: &str,
        bind_port: u16,
        registry: Arc<ClientRegistry>,
        auth_tx: mpsc::Sender<HandshakeData>,
        stealth_config: StealthConfig,
    ) -> anyhow::Result<Self> {
        let interfaces = netdev::get_interfaces();
        let iface = interfaces.iter()
            .find(|i| i.name == iface_name)
            .ok_or_else(|| anyhow::anyhow!("Interface {} not found", iface_name))?;

        // Инициализируем из системы, но будем переучиваться по ходу дела
        let local_mac = iface.mac_addr.map(|m| m.octets()).unwrap_or([0; 6]);
        let local_ip = iface.ipv4.first().map(|ip| ip.addr).unwrap_or(Ipv4Addr::UNSPECIFIED);
        let gateway_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

        let f_size = FrameSize::new(2048).unwrap();
        let q_size = QueueSize::new(4096).unwrap();

        let (umem, descs) = Umem::new(
            UmemConfig::builder().frame_size(f_size).fill_queue_size(q_size).comp_queue_size(q_size).build()?,
            NonZeroU32::new(4096).unwrap(),
            false
        )?;
        let (rx_descs, tx_descs) = descs.split_at(2048);

        // Вызываем Socket::new только ОДИН раз
        let c_iface_name = CString::new(iface_name)?;
        let (tx_q, rx_q, fq_cq_opt) = unsafe {
            Socket::new(
                SocketConfig::builder()
                    .rx_queue_size(q_size)
                    .tx_queue_size(q_size)
                    .bind_flags( BindFlags::XDP_COPY)
                    .xdp_flags(XdpFlags::XDP_FLAGS_HW_MODE)
                    .libxdp_flags(LibxdpFlags::XSK_LIBXDP_FLAGS_INHIBIT_PROG_LOAD)
                    .build(),
                &umem,
                &Interface::new(c_iface_name),
                0
            )?
        };

        let (mut fq, cq) = fq_cq_opt.ok_or_else(|| anyhow::anyhow!("Failed to create FQ/CQ"))?;

        // Берем FD от очереди, а не создаем новый сокет!
        let raw_fd = rx_q.fd().as_raw_fd();

        // Устанавливаем O_NONBLOCK для надёжности
        unsafe {
            let flags = libc::fcntl(raw_fd, libc::F_GETFL, 0);
            if flags != -1 {
                libc::fcntl(raw_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }

        // КЛЮЧЕВОЕ: добавляем интерес к записи
        let async_fd = AsyncFd::with_interest(
            raw_fd,
            tokio::io::Interest::READABLE | tokio::io::Interest::WRITABLE,
        )?;

        unsafe { fq.produce(rx_descs); }

        Ok(Self {
            async_fd,
            rx_q: Mutex::new(rx_q),
            tx_q: Mutex::new(tx_q),
            fq: Mutex::new(fq),
            cq: Mutex::new(cq),
            tx_free_frames: Mutex::new(tx_descs.to_vec()),
            umem, registry, auth_tx, stealth_config,
            local_mac: Mutex::new(local_mac),
            gateway_mac: Mutex::new(gateway_mac),
            local_ip: Mutex::new(local_ip),
            bind_port,
        })
    }

    unsafe fn set_desc_len(desc: &mut FrameDesc, len: u32) {
        let ptr = desc as *mut _ as *mut u8;
        *(ptr.add(8) as *mut u32) = len;
    }

    fn get_tx_frame(&self) -> Option<FrameDesc> {
        let mut free_frames = self.tx_free_frames.lock();
        let mut completed = [FrameDesc::default(); 64];
        let n = unsafe { self.cq.lock().consume(&mut completed) };
        if n > 0 {
            free_frames.extend_from_slice(&completed[..n]);
            //info!("[AF_XDP] Freed {} TX frames, now {} free", n, free_frames.len());
        }
        free_frames.pop().map(|mut d| {
            unsafe { Self::set_desc_len(&mut d, 1792); }
            d
        })
    }
    pub fn fd(&self) -> i32 { *self.async_fd.get_ref() }
}

impl Debug for AnetAfXdpSocket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl AsyncUdpSocket for AnetAfXdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AfXdpPoller { socket: self.clone() })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
    //     info!(
    //     "[AF_XDP] try_send, SRC: {:?}, DST: {}, PAYLOAD: {} bytes",
    //     transmit.src_ip, transmit.destination, transmit.contents.len()
    // );
        let Some(info) = self.registry.get_by_addr(&transmit.destination) else {
            warn!("[AF_XDP] try_send: no client found for {}", transmit.destination);
            return Ok(());
        };
        let SocketAddr::V4(dest_v4) = transmit.destination else { return Ok(()); };

        let mut desc = self.get_tx_frame().ok_or_else(|| io::Error::new(io::ErrorKind::WouldBlock, "UMEM TX Full"))?;
        let seq = info.sequence.fetch_add(1, Ordering::Relaxed);
        let wrapped = transport::wrap_packet(
            &info.cipher,
            &info.nonce_prefix,
            seq,
            Bytes::copy_from_slice(transmit.contents),
            0,
        ).unwrap();

        let total_eth_len = 14 + 20 + 8 + wrapped.len();

        unsafe {
            let data = self.umem.data_mut(&mut desc);
            let m_data = std::slice::from_raw_parts_mut(data.as_ptr() as *mut u8, total_eth_len);

            let mut eth_pkt = MutableEthernetPacket::new(m_data).unwrap();
            eth_pkt.set_source((*self.local_mac.lock()).into());
            // Если вы ещё не переключились на широковещательный MAC – сделайте это
            eth_pkt.set_destination((*self.gateway_mac.lock()).into());
            eth_pkt.set_ethertype(EtherTypes::Ipv4);

            let mut ip_pkt = MutableIpv4Packet::new(eth_pkt.payload_mut()).unwrap();
            ip_pkt.set_version(4);
            ip_pkt.set_header_length(5);
            ip_pkt.set_total_length((20 + 8 + wrapped.len()) as u16);
            ip_pkt.set_identification(0x1337);
            ip_pkt.set_flags(pnet_packet::ipv4::Ipv4Flags::DontFragment);
            ip_pkt.set_ttl(64);
            ip_pkt.set_next_level_protocol(IpNextHeaderProtocols::Udp);

            let src_ip = *self.local_ip.lock();
            ip_pkt.set_source(src_ip);
            ip_pkt.set_destination(*dest_v4.ip());

            ip_pkt.set_checksum(0);
            let ip_cksum = pnet_packet::ipv4::checksum(&ip_pkt.to_immutable());
            ip_pkt.set_checksum(ip_cksum);

            //info!("[try_send] SRC IP: {}, DST IP: {}", src_ip, dest_v4.ip());

            let mut udp_pkt = MutableUdpPacket::new(ip_pkt.payload_mut()).unwrap();
            udp_pkt.set_source(self.bind_port);
            udp_pkt.set_destination(dest_v4.port());
            udp_pkt.set_length((8 + wrapped.len()) as u16);
            udp_pkt.set_payload(&wrapped);

            udp_pkt.set_checksum(0);
            let udp_cksum = pnet_packet::udp::ipv4_checksum(&udp_pkt.to_immutable(), &src_ip, dest_v4.ip());
            udp_pkt.set_checksum(udp_cksum);

            Self::set_desc_len(&mut desc, total_eth_len as u32);
        }

        let mut tx_lock = self.tx_q.lock();
        if unsafe { tx_lock.produce(&[desc]) } == 1 {
            match tx_lock.wakeup() {
                Ok(_) => {  },
                Err(e) => warn!("[try_send] TX wakeup failed: {:?}", e),
            }
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // Всегда пробуем прочитать из кольца
        let mut descs = [FrameDesc::default(); 16];
        let rcvd = unsafe { self.rx_q.lock().consume(&mut descs) };
        //info!("[AF_XDP] poll_recv: consumed {} frames", rcvd);

        if rcvd == 0 {
            // Нет данных — перепланируем задачу и сообщим Quinn, что пока ничего нет
            return self.async_fd.poll_read_ready(cx)?.map(|_| Ok(0));
        }

        let mut count = 0;
        // Буферы Quinn могут быть заполнены не полностью, но мы обработаем столько, сколько влезет
        for i in 0..rcvd {
            if count >= bufs.len() {
                warn!("[AF_XDP] Quinn buffers full ({}). Returning early with {} packets.", bufs.len(), count);
                unsafe { self.fq.lock().produce(&descs[i..rcvd]); }
                break;
            }

            let frame = unsafe { self.umem.data(&descs[i]) };
            let raw_bytes = frame.contents();

            // --- Ethernet + IPv4 + UDP разбор (без изменений) ---
            let Some(eth) = EthernetPacket::new(raw_bytes) else { continue; };
            if eth.get_ethertype() != EtherTypes::Ipv4 { continue; }
            let Some(ip_pkt) = Ipv4Packet::new(eth.payload()) else { continue; };
            if ip_pkt.get_next_level_protocol() != IpNextHeaderProtocols::Udp { continue; }
            let Some(udp) = UdpPacket::new(ip_pkt.payload()) else { continue; };
            if udp.get_destination() != self.bind_port { continue; }

            // Обучение MAC / IP (как в оригинале)
            let src_mac = eth.get_source().octets();
            let dst_mac = eth.get_destination().octets();
            let learned_ip = ip_pkt.get_destination();
            {
                let mut g_mac = self.gateway_mac.lock();
                let mut l_mac = self.local_mac.lock();
                let mut l_ip = self.local_ip.lock();
                if *g_mac != src_mac {
                    *g_mac = src_mac;
                    info!("[AF_XDP] Learned Gateway MAC: {:02x?}", src_mac);
                }
                if *l_mac != dst_mac { *l_mac = dst_mac; }
                if *l_ip != learned_ip {
                    *l_ip = learned_ip;
                    info!("[AF_XDP] Local IP Synced: {}", learned_ip);
                }
            }

            let remote_addr = SocketAddr::new(ip_pkt.get_source().into(), udp.get_source());
            let payload = udp.payload();
            //info!("[AF_XDP] INCOMING: {} -> {} | Payload: {} bytes", remote_addr, self.bind_port, payload.len());

            let mut packet_for_quinn = false;

            // Попытка дешифровать как сессионный пакет (QUIC)
            if payload.len() >= NONCE_LEN + 1 {
                if let Ok(nonce_prefix) = payload[..4].try_into() {
                    if let Some(client_info) = self.registry.get_by_prefix(&nonce_prefix) {
                        self.registry.update_client_addr(&client_info, remote_addr);
                        let mut payload_mut = payload.to_vec();
                        match transport::unwrap_packet_in_place(&client_info.cipher, &mut payload_mut) {
                            Ok(quic_payload) => {
                                let buf = &mut bufs[count];
                                let copy_len = quic_payload.len().min(buf.len());
                                buf[..copy_len].copy_from_slice(&quic_payload[..copy_len]);
                                meta[count] = RecvMeta {
                                    addr: remote_addr,
                                    len: copy_len,
                                    stride: copy_len,
                                    dst_ip: None,
                                    ecn: None,
                                };
                                count += 1;
                                packet_for_quinn = true;
                                //info!("[AF_XDP] -> Packet routed to QUINN");
                            }
                            Err(e) => {
                                info!("[AF_XDP] -> Decryption failed for registered client: {}", e);
                            }
                        }
                    } else {
                        debug!("[AF_XDP] No session for prefix");
                    }
                }
            }

            if !packet_for_quinn && payload.len() >= MIN_HANDSHAKE_LEN {
                info!("[AF_XDP] -> Packet routed to AUTH WORKER");
                let _ = self.auth_tx.try_send((Bytes::copy_from_slice(payload), remote_addr));
            } else if !packet_for_quinn {
                info!("[AF_XDP] -> Packet DROPPED (too short or unknown)");
            }
        }

        // Возвращаем все фреймы обратно в кольцо заполнения
        unsafe { self.fq.lock().produce(&descs[..rcvd]); }

        if count > 0 {
            // info!("[AF_XDP] poll_recv: returning {} packets to Quinn", count);
            Poll::Ready(Ok(count))
        } else {
            // Если нет пакетов для Quinn, всё равно перепланируем
            self.async_fd.poll_read_ready(cx)?.map(|_| Ok(0))
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::new((*self.local_ip.lock()).into(), self.bind_port))
    }
}

impl AnetAfXdpSocket {
    pub fn send_raw_to(&self, payload: &[u8], destination: SocketAddr) -> io::Result<()> {
        info!("send_raw_to called");
        let SocketAddr::V4(dest_v4) = destination else { return Ok(()); };
        let mut desc = self.get_tx_frame().ok_or_else(|| io::Error::new(io::ErrorKind::WouldBlock, "UMEM TX Full"))?;
        let total_eth_len = 14 + 20 + 8 + payload.len();

        unsafe {
            let data = self.umem.data_mut(&mut desc);
            let m_data = std::slice::from_raw_parts_mut(data.as_ptr() as *mut u8, total_eth_len);

            let mut eth_pkt = MutableEthernetPacket::new(m_data).unwrap();
            eth_pkt.set_source((*self.local_mac.lock()).into());
            eth_pkt.set_destination((*self.gateway_mac.lock()).into());
            eth_pkt.set_ethertype(EtherTypes::Ipv4);

            let mut ip_pkt = MutableIpv4Packet::new(eth_pkt.payload_mut()).unwrap();
            ip_pkt.set_version(4);
            ip_pkt.set_header_length(5);
            ip_pkt.set_total_length((20 + 8 + payload.len()) as u16);
            ip_pkt.set_identification(0x1338);
            ip_pkt.set_ttl(64);
            ip_pkt.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ip_pkt.set_source(*self.local_ip.lock());
            ip_pkt.set_destination(*dest_v4.ip());

            ip_pkt.set_checksum(0);
            let ip_cksum = pnet_packet::ipv4::checksum(&ip_pkt.to_immutable());
            ip_pkt.set_checksum(ip_cksum);

            // === ЛОГИРУЕМ ЗДЕСЬ, до создания udp_pkt ===
            let src_ip = ip_pkt.get_source();
            let dst_ip = ip_pkt.get_destination();
            info!("[send_raw_to] SRC IP: {}, DST IP: {}", src_ip, dst_ip);

            let mut udp_pkt = MutableUdpPacket::new(ip_pkt.payload_mut()).unwrap();
            udp_pkt.set_source(self.bind_port);
            udp_pkt.set_destination(dest_v4.port());
            udp_pkt.set_length((8 + payload.len()) as u16);
            udp_pkt.set_payload(payload);

            udp_pkt.set_checksum(0);
            let udp_cksum = pnet_packet::udp::ipv4_checksum(&udp_pkt.to_immutable(), &src_ip, &dst_ip);
            udp_pkt.set_checksum(udp_cksum);

            // === ЛОГИРУЕМ ПОРТЫ И ПАЙЛОАД ===
            let src_port = udp_pkt.get_source();
            let dst_port = udp_pkt.get_destination();
            info!("[send_raw_to] SRC PORT: {}, DST PORT: {}", src_port, dst_port);
            info!("[send_raw_to] PAYLOAD LEN: {}", payload.len());

            // === ЛОГИРУЕМ ПОЛНЫЙ ФРЕЙМ (после всех mutable операций) ===
            info!("[send_raw_to] FULL FRAME ({} bytes): {:?}", total_eth_len, &m_data[..total_eth_len]);

            Self::set_desc_len(&mut desc, total_eth_len as u32);
        }
        let mut tx_lock = self.tx_q.lock();
        let transmitted = unsafe { tx_lock.produce(&[desc]) };
        info!("[send_raw_to] TRANSMITTED: {}", transmitted);
        if transmitted == 1 {
            match tx_lock.wakeup() {
                Ok(_) => {},
                Err(e) => warn!("[send_raw_to] TX wakeup failed: {:?}", e),
            }
        }
        Ok(())
    }
}

struct AfXdpPoller { socket: Arc<AnetAfXdpSocket> }
impl Debug for AfXdpPoller { fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result { f.debug_struct("AfXdpPoller").finish() } }
impl UdpPoller for AfXdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Проверяем, есть ли свободные TX-дескрипторы
        let free_count = {
            let free_frames = self.socket.tx_free_frames.lock();
            free_frames.len()
        };
        if free_count > 0 {
            //info!("[AF_XDP] poll_writable: free frames available ({}), returning Ready", free_count);
            return Poll::Ready(Ok(()));
        }

        // Если нет свободных, ждём событие от ядра
        match self.socket.async_fd.poll_write_ready(cx) {
            Poll::Ready(Ok(_)) => {
                // info!("[AF_XDP] poll_writable -> Ready (epoll)");
                Poll::Ready(Ok(()))
            }
            Poll::Pending => {
                // info!("[AF_XDP] poll_writable -> Pending");
                Poll::Pending
            }
            Poll::Ready(Err(e)) => {
                // error!("[AF_XDP] poll_writable error: {}", e);
                Poll::Ready(Err(e))
            }
        }
    }
}