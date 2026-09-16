#![cfg(windows)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use dashmap::DashMap;
use log::{debug, error, info, warn};
use tokio::sync::mpsc;
use windivert::layer::{NetworkLayer, SocketLayer};
use windivert::prelude::*;
use windivert_sys::ChecksumFlags;

use crate::flow_map::{BypassSet, FlowKey, FlowMap, FlowOwner};
use crate::policy::AppPolicy;
use crate::proc_name::image_name_for_pid;

const RECV_BUF: usize = 0xFFFF;

/// Сколько держим запись в NAT-таблице после SocketClose, чтобы дать
/// долететь финальным FIN/RST/data от сервера.
const NAT_GRACE_PERIOD: Duration = Duration::from_secs(60);

/// Короткое окно ожидания записи в FlowMap для первого пакета нового flow
/// (гонка между socket-tracker'ом и packet-router'ом).
const FLOW_RACE_STEP: Duration = Duration::from_millis(1);
const FLOW_RACE_RETRIES: u32 = 5;

// ============================================================================
// ТИПЫ
// ============================================================================

/// Ключ NAT-таблицы. Специально НЕ содержит local_addr: входящий из туннеля
/// пакет имеет dst = vpn_ip, а не реальный локальный IP клиента, поэтому
/// local_addr на входящей стороне восстановить нельзя. Для уникальности
/// хватает (proto, local_port, remote_addr, remote_port).
pub type NatKey = (u8, u16, IpAddr, u16);

pub type NatMap =
    Arc<DashMap<NatKey, (IpAddr, windivert::address::WinDivertAddress<NetworkLayer>)>>;

/// «Липкое» решение tunnel/direct на весь TCP/UDP поток.
/// Ключ — полный 5-tuple, чтобы разные соединения с одинаковым local_port
/// (например, серверные accept'ы) не затирали друг друга.
pub type DecisionSet = Arc<DashMap<FlowKey, bool>>;

/// Множество flow, для которых мы уже напечатали `[BYPASS]` в лог.
/// Без него долгоживущие соединения (например, сам туннель к VPN-серверу)
/// генерируют по строке на каждый пакет и забивают лог.
pub type LoggedBypass = Arc<DashMap<FlowKey, ()>>;

#[inline]
fn nat_key_outbound(k: &NetworkPacketKey) -> NatKey {
    (k.protocol, k.sport, k.dst_addr, k.dport)
}

#[inline]
fn nat_key_inbound(k: &NetworkPacketKey) -> NatKey {
    (k.protocol, k.dport, k.src_addr, k.sport)
}

/// Пакеты, которые appfilter не должен трогать ни при каких условиях:
/// loopback, multicast, broadcast, link-local, unspecified (0.0.0.0 / ::).
#[inline]
fn is_ignored_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_link_local()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_multicast() || v6.is_unspecified()
        }
    }
}

// ============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// ============================================================================

fn clear_checksums(data: &mut [u8]) {
    if data.is_empty() {
        return;
    }
    let version = data[0] >> 4;
    if version == 4 {
        if data.len() < 20 {
            return;
        }
        let ihl = ((data[0] & 0x0F) * 4) as usize;
        if data.len() < ihl {
            return;
        }

        data[10] = 0;
        data[11] = 0;

        let protocol = data[9];
        if protocol == 6 {
            if data.len() >= ihl + 18 {
                data[ihl + 16] = 0;
                data[ihl + 17] = 0;
            }
        } else if protocol == 17 {
            if data.len() >= ihl + 8 {
                data[ihl + 6] = 0;
                data[ihl + 7] = 0;
            }
        }
    }
}

fn clamp_tcp_mss(data: &mut [u8], max_mss: u16) -> bool {
    let version = data[0] >> 4;
    let (ihl, protocol) = if version == 4 {
        if data.len() < 20 {
            return false;
        }
        let ihl = ((data[0] & 0x0F) * 4) as usize;
        if data.len() < ihl + 20 {
            return false;
        }
        (ihl, data[9])
    } else {
        return false;
    };

    if protocol != 6 {
        return false;
    }

    let tcp_offset = ihl;
    if data.len() < tcp_offset + 20 {
        return false;
    }

    let tcp_flags = data[tcp_offset + 13];
    if (tcp_flags & 0x02) == 0 {
        return false;
    }

    let tcp_hdr_len = ((data[tcp_offset + 12] >> 4) * 4) as usize;
    if data.len() < tcp_offset + tcp_hdr_len {
        return false;
    }

    let mut opt_offset = tcp_offset + 20;
    let opt_end = tcp_offset + tcp_hdr_len;
    let mut modified = false;

    while opt_offset < opt_end {
        let kind = data[opt_offset];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            opt_offset += 1;
            continue;
        }

        if opt_offset + 1 >= opt_end {
            break;
        }
        let len = data[opt_offset + 1] as usize;
        if len < 2 || opt_offset + len > opt_end {
            break;
        }

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
    logged_bypass: LoggedBypass,
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
        let local_addr = packet.address.local_address();
        let local_port = packet.address.local_port();
        let remote_addr = packet.address.remote_address();
        let remote_port = packet.address.remote_port();
        let protocol = packet.address.protocol();
        let event = packet.address.event();

        match event {
            // SocketConnect (клиент) и SocketAccept (сервер) — единственные
            // события, где известен полный 5-tuple. Именно их и пишем в FlowMap.
            WinDivertEvent::SocketConnect | WinDivertEvent::SocketAccept => {
                if pid == 0 || pid == 4 {
                    continue;
                }

                // Loopback / multicast / link-local — не наш трафик.
                // Отсекаем здесь, чтобы не забивать FlowMap записями,
                // которые роутер всё равно проигнорирует.
                if is_ignored_ip(&local_addr) || is_ignored_ip(&remote_addr) {
                    continue;
                }

                let key = FlowKey::new(protocol, local_addr, local_port, remote_addr, remote_port);

                let new_image_name = image_name_for_pid(pid);

                if let Some(ref img) = new_image_name {
                    // Перенесено в debug: при policy=Include это событие
                    // случается на каждый DNS-запрос svchost'а и на каждое
                    // loopback-соединение Battle.net — info-уровень слишком шумный.
                    debug!(
                        "appfilter: Socket track | Event: {:?} | App: {} (PID: {}) | {}:{} -> {}:{} | Proto: {}",
                        event, img, pid, local_addr, local_port, remote_addr, remote_port, protocol
                    );
                    map.insert(
                        key,
                        FlowOwner {
                            process_id: pid,
                            image_name: new_image_name,
                        },
                    );
                } else {
                    // Не перезаписываем, если в карте уже есть запись с именем.
                    let existing_has_name = map
                        .lookup(&key)
                        .and_then(|owner| owner.image_name)
                        .is_some();

                    if !existing_has_name {
                        map.insert(
                            key,
                            FlowOwner {
                                process_id: pid,
                                image_name: None,
                            },
                        );
                    }
                }
            }

            // SocketBind — удалённый адрес ещё не известен (0.0.0.0:0).
            // Запись создаст последующий Connect/Accept с полным ключом.
            WinDivertEvent::SocketBind => {}

            WinDivertEvent::SocketClose => {
                let flow_key =
                    FlowKey::new(protocol, local_addr, local_port, remote_addr, remote_port);
                let nat_key: NatKey = (protocol, local_port, remote_addr, remote_port);

                map.remove(&flow_key);
                decisions.remove(&flow_key);
                logged_bypass.remove(&flow_key);

                // nat_map чистим с задержкой: сервер может ещё досылать
                // FIN/RST/data по уже закрытому соединению.
                let nat_map = nat_map.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(NAT_GRACE_PERIOD);
                    nat_map.remove(&nat_key);
                });
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
    logged_bypass: LoggedBypass,
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
                    let lookup_key = nat_key_inbound(&key);

                    if let Some(orig) = nat_map.get(&lookup_key) {
                        let (orig_ip, orig_addr) = orig.value();

                        wd.address = orig_addr.clone();
                        wd.address.set_outbound(false);
                        wd.address.set_impostor(true);

                        // DNAT: восстанавливаем оригинальный физический IP-адрес
                        // в поле dst (байты 16..20 в IPv4-заголовке).
                        if let (IpAddr::V4(v4), IpAddr::V4(_)) = (orig_ip, key.dst_addr) {
                            wd.data.to_mut()[16..20].copy_from_slice(&v4.octets());
                        }

                        clear_checksums(wd.data.to_mut());
                        clamp_tcp_mss(wd.data.to_mut(), 1360);

                        let _ = wd.recalculate_checksums(ChecksumFlags::new());
                        if let Err(e) = handle.send(&wd) {
                            error!("appfilter: Reinject (from tunnel) failed: {e}");
                            break;
                        }
                    } else {
                        // Штатная ситуация: пакет от stale-flow или от сессии,
                        // установленной до старта appfilter. Дропаем тихо.
                        debug!(
                            "appfilter: [INBOUND] Dropped (no NAT entry) | {:?}:{} <- {:?}:{}",
                            key.dst_addr, key.dport, key.src_addr, key.sport
                        );
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

        // Пакет с impostor уже был нами отмечен ранее — не перехватываем.
        if !packet.address.outbound() {
            let mut p = packet;
            p.address.set_impostor(true);
            if let Err(e) = handle.send(&p) {
                error!("appfilter: Failed to re-inject inbound packet: {e}");
            }
            continue;
        }

        let key = match classify(&packet.data) {
            Some(k) => k,
            None => {
                if let Err(e) = handle.send(&packet) {
                    error!("appfilter: Failed to re-inject untyped packet: {e}");
                }
                continue;
            }
        };

        // Loopback / multicast / broadcast / link-local / unspecified —
        // не наш трафик вообще: ни туннель, ни policy к ним не относятся.
        if is_ignored_ip(&key.src_addr) || is_ignored_ip(&key.dst_addr) {
            if let Err(e) = handle.send(&packet) {
                error!("appfilter: Failed to re-inject ignored packet: {e}");
            }
            continue;
        }

        // Явный bypass-лист: пакет должен уйти напрямую, минуя туннель.
        // Логируем только первый пакет каждого flow, чтобы долгоживущие
        // соединения (например, сам туннель к VPN-серверу) не забивали лог.
        if bypass.contains_blocking(&key.src_addr) || bypass.contains_blocking(&key.dst_addr) {
            let flow_key = FlowKey::new(
                key.protocol,
                key.src_addr,
                key.sport,
                key.dst_addr,
                key.dport,
            );
            if logged_bypass.insert(flow_key, ()).is_none() {
                info!(
                    "appfilter: [BYPASS] explicit list | Proto: {} | {}:{} -> {}:{}",
                    key.protocol, key.src_addr, key.sport, key.dst_addr, key.dport
                );
            }
            if let Err(e) = handle.send(&packet) {
                error!("appfilter: Failed to re-inject bypass list packet: {e}");
            }
            continue;
        }

        let flow_key = FlowKey::new(
            key.protocol,
            key.src_addr,
            key.sport,
            key.dst_addr,
            key.dport,
        );

        // «Липкое» решение: tunnel=true ИЛИ false фиксируется один раз на весь flow.
        // freshly_decided == true только в том пакете, где решение принято впервые
        // (нужно, чтобы не логировать один и тот же flow на каждый пакет).
        let (tunnel, owner_opt, freshly_decided) =
            if let Some(v) = decisions.get(&flow_key).map(|d| *d) {
                (v, map.lookup(&flow_key), false)
            } else {
                let mut owner_opt = map.lookup(&flow_key);
                if owner_opt.is_none() {
                    // Гонка при первом пакете: socket-tracker мог ещё не успеть.
                    for _ in 0..FLOW_RACE_RETRIES {
                        std::thread::sleep(FLOW_RACE_STEP);
                        owner_opt = map.lookup(&flow_key);
                        if owner_opt.is_some() {
                            break;
                        }
                    }
                }

                let result = owner_opt
                    .as_ref()
                    .map(|o| policy.should_tunnel(o))
                    .unwrap_or(false);

                // Фиксируем решение ТОЛЬКО если владелец известен. Иначе ждём
                // следующего пакета — если залипнуть сейчас, соединение уйдёт
                // не туда из-за слишком раннего «untracked».
                let decided = owner_opt.is_some();
                if decided {
                    decisions.insert(flow_key, result);
                }
                (result, owner_opt, decided)
            };

        if freshly_decided {
            let app_name = owner_opt
                .as_ref()
                .and_then(|o| o.image_name.clone())
                .unwrap_or_else(|| Arc::from("unknown"));
            if tunnel {
                info!(
                    "appfilter: [TUNNEL OUT] >>> Intercepted new flow | App: {} | Proto: {} | {}:{} -> {}:{}",
                    app_name, key.protocol, key.src_addr, key.sport, key.dst_addr, key.dport
                );
            } else {
                info!(
                    "appfilter: [CLEAR OUT] >>> Direct internet route | App: {} | Proto: {} | {}:{} -> {}:{}",
                    app_name, key.protocol, key.src_addr, key.sport, key.dst_addr, key.dport
                );
            }
        }

        if tunnel {
            // Блокируем IPv6 для быстрой сработки IPv4 fallback.
            if key.src_addr.is_ipv6() {
                info!(
                    "appfilter: IPv6 packet dropped to trigger IPv4 fallback for port: {}",
                    key.sport
                );
                continue;
            }

            let nat_key = nat_key_outbound(&key);
            nat_map.insert(nat_key, (key.src_addr, packet.address.clone()));

            let mut wd = unsafe { WinDivertPacket::<NetworkLayer>::new(packet.data.to_vec()) };
            wd.address = packet.address.clone();
            wd.address.set_outbound(true);

            // SNAT: подменяем Source IP на выданный сервером VPN IP.
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
            if let Err(e) = handle.send(&packet) {
                error!("appfilter: Failed to re-inject bypassed packet: {e}");
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
    if data.len() < 20 {
        return None;
    }
    let ihl = (data[0] & 0x0F) as usize * 4;
    if data.len() < ihl + 4 {
        return None;
    }

    let protocol = data[9];
    if protocol != 6 && protocol != 17 {
        return None;
    }

    let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    let sport = u16::from_be_bytes([data[ihl], data[ihl + 1]]);
    let dport = u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]);

    Some(NetworkPacketKey {
        protocol,
        src_addr: IpAddr::V4(src),
        dst_addr: IpAddr::V4(dst),
        sport,
        dport,
    })
}

fn classify_v6(data: &[u8]) -> Option<NetworkPacketKey> {
    if data.len() < 40 {
        return None;
    }

    let next_header = data[6];
    if next_header != 6 && next_header != 17 {
        return None;
    }

    let mut src_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&data[8..24]);
    let src = Ipv6Addr::from(src_bytes);

    let mut dst_bytes = [0u8; 16];
    dst_bytes.copy_from_slice(&data[24..40]);
    let dst = Ipv6Addr::from(dst_bytes);

    let transport_offset = 40;
    if data.len() < transport_offset + 4 {
        return None;
    }

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