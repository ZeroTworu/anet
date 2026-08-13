
#![cfg(windows)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use log::{error, info, warn};
use tokio::sync::mpsc;
use windivert::layer::{NetworkLayer, SocketLayer};
use windivert::prelude::*;
use windivert_sys::ChecksumFlags;
use dashmap::DashMap;

use crate::flow_map::{BypassSet, FlowKey, FlowMap, FlowOwner};
use crate::policy::AppPolicy;
use crate::proc_name::image_name_for_pid;

const RECV_BUF: usize = 0xFFFF;

// Тип для хранения NAT-таблицы
pub type NatMap = Arc<DashMap<FlowKey, (IpAddr, windivert::address::WinDivertAddress<NetworkLayer>)>>;

// Тип для "липкого" решения tunnel/direct на весь поток (ключ = (proto, local_port)).
// Без этого решение пересчитывается на каждый пакет и может измениться в середине
// уже установленного TCP-соединения, что рвёт его (см. PR_CONNECT_RESET_ERROR).
pub type DecisionSet = Arc<DashMap<FlowKey, bool>>;

// ============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// ============================================================================

/// Очистка контрольных сумм перед перерасчетом драйвером.
fn clear_checksums(data: &mut [u8]) {
    if data.is_empty() { return; }
    let version = data[0] >> 4;
    if version == 4 {
        if data.len() < 20 { return; }
        let ihl = ((data[0] & 0x0F) * 4) as usize;
        if data.len() < ihl { return; }

        data[10] = 0;
        data[11] = 0;

        let protocol = data[9];
        if protocol == 6 {
            if data.len() >= ihl + 18 { data[ihl + 16] = 0; data[ihl + 17] = 0; }
        } else if protocol == 17 {
            if data.len() >= ihl + 8 { data[ihl + 6] = 0; data[ihl + 7] = 0; }
        }
    }
}

/// Зажим размера TCP пакетов (MSS Clamping).
fn clamp_tcp_mss(data: &mut [u8], max_mss: u16) -> bool {
    let version = data[0] >> 4;
    let (ihl, protocol) = if version == 4 {
        if data.len() < 20 { return false; }
        let ihl = ((data[0] & 0x0F) * 4) as usize;
        if data.len() < ihl + 20 { return false; }
        (ihl, data[9])
    } else { return false; };

    if protocol != 6 { return false; }

    let tcp_offset = ihl;
    if data.len() < tcp_offset + 20 { return false; }

    let tcp_flags = data[tcp_offset + 13];
    if (tcp_flags & 0x02) == 0 { return false; }

    let tcp_hdr_len = ((data[tcp_offset + 12] >> 4) * 4) as usize;
    if data.len() < tcp_offset + tcp_hdr_len { return false; }

    let mut opt_offset = tcp_offset + 20;
    let opt_end = tcp_offset + tcp_hdr_len;
    let mut modified = false;

    while opt_offset < opt_end {
        let kind = data[opt_offset];
        if kind == 0 { break; }
        if kind == 1 { opt_offset += 1; continue; }

        if opt_offset + 1 >= opt_end { break; }
        let len = data[opt_offset + 1] as usize;
        if len < 2 || opt_offset + len > opt_end { break; }

        if kind == 2 && len == 4 {
            let current_mss = u16::from_be_bytes([data[opt_offset + 2], data[opt_offset + 3]]);
            if current_mss > max_mss {
                let new_mss = max_mss.to_be_bytes();
                data[opt_offset + 2] = new_mss[0];
                data[opt_offset + 3] = new_mss[1];
                modified = true;
            }
        }
        opt_offset += len;
    }
    modified
}

// ============================================================================
// ПОТОК 1: ОТСЛЕЖИВАНИЕ СОКЕТОВ (SOCKET TRACKER)
// ============================================================================
pub fn run_socket_tracker(
    handle: Arc<WinDivert<SocketLayer>>,
    map: FlowMap,
    nat_map: NatMap,
    decisions: DecisionSet,
) -> Result<()> {
    let mut buf = [0u8; RECV_BUF];
    info!("appfilter: Socket tracker thread initialized and running.");

    loop {
        let packet = match handle.recv(Some(&mut buf)) {
            Ok(p) => p,
            Err(e) => {
                info!("appfilter: Socket tracker stopped (handle closed or error: {})", e);
                break;
            }
        };

        let pid = packet.address.process_id();

        let local_port = packet.address.local_port();
        let protocol = packet.address.protocol();
        let event = packet.address.event();

        let key = FlowKey::new(protocol, local_port);

        match event {
            WinDivertEvent::SocketConnect | WinDivertEvent::SocketAccept | WinDivertEvent::SocketBind => {
                // Игнорируем системные PID 0 и 4 (Kernel)
                if pid != 0 && pid != 4 {
                    let new_image_name = image_name_for_pid(pid);

                    if let Some(ref img) = new_image_name {
                        info!(
                            "appfilter: Socket track | Event: {:?} | App: {} (PID: {}) | Port: {} | Proto: {}",
                            event, img, pid, local_port, protocol
                        );
                        map.insert(key, FlowOwner {
                            process_id: pid,
                            image_name: new_image_name,
                        });
                    } else {
                        // Не перезаписываем, если в карте уже есть известное имя
                        let existing_has_name = map.lookup(&key)
                            .and_then(|owner| owner.image_name)
                            .is_some();

                        if !existing_has_name {
                            map.insert(key, FlowOwner {
                                process_id: pid,
                                image_name: None,
                            });
                        }
                    }
                }
            }
            WinDivertEvent::SocketClose => {
                map.remove(&key);
                nat_map.remove(&key);
                decisions.remove(&key);
            }
            _ => {}
        }
    }
    Ok(())
}

// ============================================================================
// ПОТОК 2: МАРШРУТИЗАТОР И NAT ПАКЕТОВ (PACKET ROUTER)
// ============================================================================
pub fn run_packet_router(
    handle: Arc<WinDivert<NetworkLayer>>,
    map: FlowMap,
    bypass: BypassSet,
    policy: AppPolicy,
    to_tunnel: mpsc::Sender<Bytes>,
    mut from_tunnel: mpsc::Receiver<Bytes>,
    vpn_ip: IpAddr,
    nat_map: NatMap,
    decisions: DecisionSet,
) -> Result<()> {

    // --- ВХОДЯЩИЙ ТРАФИК (Из туннеля в Windows) ---
    {
        let handle = handle.clone();
        let nat_map = nat_map.clone();
        std::thread::spawn(move || {
            info!("appfilter: Inbound packet reinjector thread running.");
            while let Some(pkt) = from_tunnel.blocking_recv() {
                let mut wd = unsafe { WinDivertPacket::<NetworkLayer>::new(pkt.to_vec()) };
                wd.address.set_outbound(false);

                if let Some(key) = classify(&wd.data) {
                    let lookup_key = FlowKey::new(key.protocol, key.dport);

                    if let Some(orig) = nat_map.get(&lookup_key) {
                        let (orig_ip, orig_addr) = orig.value();

                        wd.address = orig_addr.clone();
                        wd.address.set_outbound(false);
                        wd.address.set_impostor(true);

                        // DNAT: Восстанавливаем оригинальный физический IP-адрес
                        if let IpAddr::V4(v4) = orig_ip {
                            if key.dst_addr.is_ipv4() {
                                wd.data.to_mut()[16..20].copy_from_slice(&v4.octets());
                            }
                        }

                        clear_checksums(wd.data.to_mut());
                        clamp_tcp_mss(wd.data.to_mut(), 1360);

                        let _ = wd.recalculate_checksums(ChecksumFlags::new());
                        if let Err(e) = handle.send(&wd) {
                            error!("appfilter: Reinject (from tunnel) failed: {e}");
                            break;
                        }
                    } else {
                        info!("appfilter: [INBOUND] Dropped | No NAT entry found for Port: {}", key.dport);
                    }
                }
            }
            info!("appfilter: Reinjector stopped.");
        });
    }

    info!("appfilter: Packet router started (policy={policy:?})");
    let mut buf = [0u8; RECV_BUF];

    // --- ИСХОДЯЩИЙ ТРАФИК (Из Windows в Туннель или напрямую) ---
    loop {
        let packet = match handle.recv(Some(&mut buf)) {
            Ok(p) => p,
            Err(e) => {
                info!("appfilter: Packet router stopped (handle closed or error: {})", e);
                break;
            }
        };

        if !packet.address.outbound() {
            let mut p = packet;
            p.address.set_impostor(true);
            if let Err(e) = handle.send(&p) {
                error!("appfilter: Failed to re-inject inbound packet: {e}");
            }
            continue;
        }

        match classify(&packet.data) {
            Some(key) => {
                if bypass.contains_blocking(&key.src_addr) || bypass.contains_blocking(&key.dst_addr) {
                    if let Err(e) = handle.send(&packet) {
                        error!("appfilter: Failed to re-inject bypass list packet: {e}");
                    }
                    continue;
                }

                let lookup_key = FlowKey::new(key.protocol, key.sport);

                // "Липкое" решение: раз зафиксированный tunnel=true для потока (proto, local_port)
                // не пересматривается до SocketClose — это защищает уже принятые в туннель
                // потоки от разрыва при флуктуациях FlowMap.
                let tunnel = if let Some(true) = decisions.get(&lookup_key).map(|d| *d) {
                    true
                } else {
                    // Гонка при первом пакете абсолютно нового потока: Socket-tracker
                    // (отдельный поток/хендл) мог ещё не успеть записать владельца, хотя
                    // сам SYN/ClientHello уже долетел до Network-слоя. Если решить "direct"
                    // прямо сейчас, а через пакет-другой владелец найдётся и мы переключимся
                    // на "tunnel" — TCP-соединение обломается на стороне сервера (несовпадение
                    // src IP у уже установленного потока = PR_CONNECT_RESET_ERROR). Поэтому для
                    // ПЕРВОГО пакета нового потока даём Socket-tracker'у короткое окно догнать,
                    // прежде чем фиксировать решение.
                    let mut owner_opt = map.lookup(&lookup_key);
                    if owner_opt.is_none() {
                        for _ in 0..5 {
                            std::thread::sleep(std::time::Duration::from_millis(1));
                            owner_opt = map.lookup(&lookup_key);
                            if owner_opt.is_some() {
                                break;
                            }
                        }
                    }

                    let result = owner_opt
                        .as_ref()
                        .map(|owner| policy.should_tunnel(owner))
                        .unwrap_or(false);
                    if result {
                        decisions.insert(lookup_key, true);
                    }
                    result
                };
                let owner_opt = map.lookup(&lookup_key);

                if tunnel {
                    // Блокируем IPv6 для быстрой сработки IPv4 Fallback
                    if key.src_addr.is_ipv6() {
                        info!("appfilter: IPv6 packet dropped to trigger IPv4 fallback for port: {}", key.sport);
                        continue;
                    }

                    let is_new_flow = !nat_map.contains_key(&lookup_key);
                    if is_new_flow {
                        let app_name = owner_opt.as_ref().and_then(|o| o.image_name.clone()).unwrap_or_else(|| Arc::from("unknown"));
                        info!("appfilter: [TUNNEL OUT] >>> Intercepted new flow | App: {} | Proto: {} | Port: {} -> Dest: {}",
                            app_name, key.protocol, key.sport, key.dst_addr);
                    }

                    nat_map.insert(lookup_key, (key.src_addr, packet.address.clone()));

                    let mut wd = unsafe { WinDivertPacket::<NetworkLayer>::new(packet.data.to_vec()) };
                    wd.address = packet.address.clone();
                    wd.address.set_outbound(true);

                    // SNAT: Подменяем Source IP на выданный сервером VPN IP
                    if let IpAddr::V4(v4) = vpn_ip {
                        wd.data.to_mut()[12..16].copy_from_slice(&v4.octets());
                    }

                    clear_checksums(wd.data.to_mut());
                    clamp_tcp_mss(wd.data.to_mut(), 1360);

                    let _ = wd.recalculate_checksums(ChecksumFlags::new());

                    if let Err(e) = to_tunnel.try_send(Bytes::copy_from_slice(&wd.data)) {
                        match e {
                            tokio::sync::mpsc::error::TrySendError::Full(_) => {
                                warn!("appfilter: Tunnel uplink buffer full! Dropping packet.");
                            }
                            tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                                info!("appfilter: Tunnel channel closed, stopping router.");
                                break;
                            }
                        }
                    }
                } else {
                    let is_new_flow = !nat_map.contains_key(&lookup_key);
                    if is_new_flow {
                        let app_name = owner_opt.as_ref().and_then(|o| o.image_name.clone()).unwrap_or_else(|| Arc::from("untracked"));
                        info!("appfilter: [CLEAR OUT] >>> Direct internet route | App: {} | Proto: {} | Port: {} -> Dest: {}",
                            app_name, key.protocol, key.sport, key.dst_addr);
                    }

                    if let Err(e) = handle.send(&packet) {
                        error!("appfilter: Failed to re-inject bypassed packet: {e}");
                    }
                }
            }
            None => {
                if let Err(e) = handle.send(&packet) {
                    error!("appfilter: Failed to re-inject untyped packet: {e}");
                }
            }
        }
    }

    Ok(())
}

// ============================================================================
// ПАРСЕР ПАКЕТОВ
// ============================================================================

struct NetworkPacketKey {
    protocol: u8,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    sport: u16,
    dport: u16,
}

fn classify(data: &[u8]) -> Option<NetworkPacketKey> {
    let version = data.first()? >> 4;
    match version {
        4 => classify_v4(data),
        6 => classify_v6(data),
        _ => None,
    }
}

fn classify_v4(data: &[u8]) -> Option<NetworkPacketKey> {
    if data.len() < 20 { return None; }
    let ihl = (data[0] & 0x0F) as usize * 4;
    if data.len() < ihl + 4 { return None; }

    let protocol = data[9];
    if protocol != 6 && protocol != 17 { return None; }

    let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    let sport = u16::from_be_bytes([data[ihl], data[ihl + 1]]);
    let dport = u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]);

    Some(NetworkPacketKey { protocol, src_addr: IpAddr::V4(src), dst_addr: IpAddr::V4(dst), sport, dport })
}

fn classify_v6(data: &[u8]) -> Option<NetworkPacketKey> {
    if data.len() < 40 { return None; }

    let next_header = data[6];
    if next_header != 6 && next_header != 17 { return None; }

    let mut src_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&data[8..24]);
    let src = Ipv6Addr::from(src_bytes);

    let mut dst_bytes = [0u8; 16];
    dst_bytes.copy_from_slice(&data[24..40]);
    let dst = Ipv6Addr::from(dst_bytes);

    let transport_offset = 40;
    if data.len() < transport_offset + 4 { return None; }

    let sport = u16::from_be_bytes([data[transport_offset], data[transport_offset + 1]]);
    let dport = u16::from_be_bytes([data[transport_offset + 2], data[transport_offset + 3]]);

    Some(NetworkPacketKey {
        protocol: next_header,
        src_addr: IpAddr::V6(src),
        dst_addr: IpAddr::V6(dst),
        sport,
        dport,
    })
}
