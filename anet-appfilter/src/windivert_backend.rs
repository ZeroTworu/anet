#![cfg(windows)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use dashmap::DashMap;
use log::{debug, error, info, warn};
use tokio::sync::mpsc;
use windivert::layer::{NetworkLayer, SocketLayer};
use windivert::prelude::*;
use windivert::sys::ChecksumFlags;

use crate::flow_map::{BypassSet, FlowKey, FlowMap, FlowOwner};
use crate::policy::AppPolicy;
use crate::proc_name::image_name_for_pid;

const RECV_BUF: usize = 0xFFFF;
const NAT_GRACE_PERIOD: Duration = Duration::from_secs(45);
const FLOW_CLOSE_GRACE_PERIOD: Duration = Duration::from_secs(15);
const SWEEPER_INTERVAL: Duration = Duration::from_secs(2);
const FLOW_RACE_STEP: Duration = Duration::from_millis(1);
const FLOW_RACE_RETRIES: u32 = 8;
const DEFAULT_TCP_MSS: u16 = 1360;

pub type NatKey = (u8, u16, IpAddr, u16);

#[derive(Clone)]
pub struct NatEntry {
    pub orig_ip: IpAddr,
    pub orig_addr: windivert::address::WinDivertAddress<NetworkLayer>,
    pub expires_at: Option<Instant>,
    pub confirmed: bool,
}

pub type NatMap = Arc<DashMap<NatKey, NatEntry>>;
pub type DecisionSet = Arc<DashMap<FlowKey, bool>>;
pub type LoggedBypass = Arc<DashMap<FlowKey, ()>>;

#[inline]
fn nat_key_outbound(k: &NetworkPacketKey) -> NatKey {
    (k.protocol, k.sport, k.dst_addr, k.dport)
}

#[inline]
fn nat_key_inbound(k: &NetworkPacketKey) -> NatKey {
    (k.protocol, k.dport, k.src_addr, k.sport)
}

#[inline]
fn is_ignored_ip(ip: &IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_link_local()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
                || v6.is_unspecified()
        }
    }
}

/// Проверка локального адреса в SocketLayer: в отличие от `is_ignored_ip`,
/// НЕ отбрасывает `0.0.0.0` / `::` (`is_unspecified()`), так как при `SocketConnect`
/// и `SocketBind` ядро Windows часто передаёт `INADDR_ANY` до выбора маршрута.
#[inline]
fn is_ignored_local_ip(ip: &IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_multicast() || v4.is_broadcast() || v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_multicast() || v6.is_unicast_link_local()
        }
    }
}

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
// ПОТОК 1: SOCKET TRACKER
// ============================================================================
pub fn run_socket_tracker(
    handle: Arc<WinDivert<SocketLayer>>,
    map: FlowMap,
    nat_map: NatMap,
    decisions: DecisionSet,
    logged_bypass: LoggedBypass,
) -> Result<()> {
    info!("appfilter: Socket tracker thread initialized and running.");

    let closing_flows: Arc<DashMap<FlowKey, Instant>> = Arc::new(DashMap::new());
    let closing_ports: Arc<DashMap<(u8, u16), Instant>> = Arc::new(DashMap::new());

    // Единый фоновый сборщик устаревших NAT-записей и закрытых сокетов (без порождения потоков на каждый SocketClose)
    {
        let nat_map_sweeper = nat_map.clone();
        let map_sweeper = map.clone();
        let decisions_sweeper = decisions.clone();
        let logged_bypass_sweeper = logged_bypass.clone();
        let closing_flows_sweeper = closing_flows.clone();
        let closing_ports_sweeper = closing_ports.clone();

        std::thread::Builder::new()
            .name("anet-nat-sweeper".to_string())
            .spawn(move || {
                loop {
                    std::thread::sleep(SWEEPER_INTERVAL);
                    let now = Instant::now();

                    nat_map_sweeper.retain(|_, entry| match entry.expires_at {
                        Some(exp) => exp > now,
                        None => true,
                    });

                    let mut expired_flows = Vec::new();
                    closing_flows_sweeper.retain(|flow_key, exp| {
                        if *exp <= now {
                            expired_flows.push(*flow_key);
                            false
                        } else {
                            true
                        }
                    });
                    for fk in expired_flows {
                        map_sweeper.remove(&fk);
                        decisions_sweeper.remove(&fk);
                        logged_bypass_sweeper.remove(&fk);
                    }

                    let mut expired_ports = Vec::new();
                    closing_ports_sweeper.retain(|port_key, exp| {
                        if *exp <= now {
                            expired_ports.push(*port_key);
                            false
                        } else {
                            true
                        }
                    });
                    for (proto, port) in expired_ports {
                        if proto == 17 {
                            map_sweeper.remove_udp_port(port);
                        } else if proto == 6 {
                            map_sweeper.remove_tcp_port(port);
                        }
                    }
                }
            })?;
    }

    loop {
        let packet = match handle.recv() {
            Ok(p) => p,
            Err(e) => {
                info!("appfilter: Socket tracker stopped ({})", e);
                break;
            }
        };

        let pid = packet.address.process_id();
        let local_addr = packet.address.local_address().to_canonical();
        let local_port = packet.address.local_port();
        let remote_addr = packet.address.remote_address().to_canonical();
        let remote_port = packet.address.remote_port();
        let protocol = packet.address.protocol();
        let event = packet.address.event();

        match event {
            WinDivertEvent::SocketConnect | WinDivertEvent::SocketAccept => {
                if pid == 0 || pid == 4 {
                    continue;
                }
                if is_ignored_local_ip(&local_addr) || is_ignored_ip(&remote_addr) {
                    continue;
                }

                let key = FlowKey::new(protocol, local_addr, local_port, remote_addr, remote_port);
                closing_flows.remove(&key);
                if local_port != 0 {
                    closing_ports.remove(&(protocol, local_port));
                }

                let new_image_name = image_name_for_pid(pid);
                let owner = FlowOwner {
                    process_id: pid,
                    image_name: new_image_name.clone(),
                };

                if let Some(ref img) = new_image_name {
                    debug!(
                        "appfilter: Socket track | App: {} (PID: {}) | {}:{} -> {}:{} | Proto: {}",
                        img, pid, local_addr, local_port, remote_addr, remote_port, protocol
                    );
                    map.insert(key, owner.clone());
                } else {
                    let existing_has_name = map
                        .lookup(&key)
                        .and_then(|existing| existing.image_name)
                        .is_some();

                    if !existing_has_name {
                        map.insert(key, owner.clone());
                    }
                }

                if local_port != 0 {
                    if protocol == 17 {
                        map.insert_udp_port(local_port, owner);
                    } else if protocol == 6 {
                        map.insert_tcp_port(local_port, owner);
                    }
                }
            }

            // Отслеживание TCP/UDP сокетов, вызывающих bind() / listen() (в т.ч. BitTorrent / игры / P2P)
            WinDivertEvent::SocketBind | WinDivertEvent::SocketListen => {
                if pid == 0 || pid == 4 || local_port == 0 {
                    continue;
                }
                if is_ignored_local_ip(&local_addr) {
                    continue;
                }
                closing_ports.remove(&(protocol, local_port));

                let img = image_name_for_pid(pid);
                let owner = FlowOwner {
                    process_id: pid,
                    image_name: img.clone(),
                };

                if protocol == 17 {
                    if let Some(ref name) = img {
                        debug!(
                            "appfilter: UDP Bind tracked: port {} -> {} (PID: {})",
                            local_port, name, pid
                        );
                    }
                    map.insert_udp_port(local_port, owner);
                } else if protocol == 6 {
                    if let Some(ref name) = img {
                        debug!(
                            "appfilter: TCP Bind/Listen tracked: port {} -> {} (PID: {})",
                            local_port, name, pid
                        );
                    }
                    map.insert_tcp_port(local_port, owner);
                }
            }

            WinDivertEvent::SocketClose => {
                let flow_key =
                    FlowKey::new(protocol, local_addr, local_port, remote_addr, remote_port);
                let nat_key: NatKey = (protocol, local_port, remote_addr, remote_port);
                let now = Instant::now();

                // Помечаем NAT-запись временем устаревания (для корректного завершения FIN/ACK)
                if let Some(mut entry) = nat_map.get_mut(&nat_key) {
                    entry.expires_at = Some(now + NAT_GRACE_PERIOD);
                }

                // Планируем отложенную очистку flow и порта через фоновый sweeper
                closing_flows.insert(flow_key, now + FLOW_CLOSE_GRACE_PERIOD);
                if local_port != 0 && remote_addr.is_unspecified() {
                    closing_ports.insert((protocol, local_port), now + FLOW_CLOSE_GRACE_PERIOD);
                }
            }

            _ => {}
        }
    }
    Ok(())
}

// ============================================================================
// ПОТОК 2: PACKET ROUTER (10 АРГУМЕНТОВ — ПОЛНАЯ СОВМЕСТИМОСТЬ)
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
    let target_tcp_mss = DEFAULT_TCP_MSS;
    let self_pid = std::process::id();

    // Входящий трафик (из туннеля в Windows)
    {
        let handle = handle.clone();
        let nat_map = nat_map.clone();
        std::thread::Builder::new()
            .name("anet-inbound-reinject".to_string())
            .spawn(move || {
                info!("appfilter: Inbound packet reinjector thread running.");
                while let Some(pkt) = from_tunnel.blocking_recv() {
                    let mut wd = unsafe { WinDivertPacket::<NetworkLayer>::new(pkt.to_vec()) };
                    wd.address.set_outbound(false);

                    if let Some(key) = classify(&wd.data) {
                        let lookup_key = nat_key_inbound(&key);

                        if let Some(orig) = nat_map.get(&lookup_key) {
                            let orig_ip = orig.orig_ip;
                            let orig_addr = orig.orig_addr.clone();

                            wd.address = orig_addr;
                            wd.address.set_outbound(false);
                            wd.address.set_impostor(true);

                            // DNAT: восстанавливаем физический IP
                            if let (IpAddr::V4(v4), IpAddr::V4(_)) = (orig_ip, key.dst_addr) {
                                wd.data.to_mut()[16..20].copy_from_slice(&v4.octets());
                            }

                            clear_checksums(wd.data.to_mut());
                            clamp_tcp_mss(wd.data.to_mut(), target_tcp_mss);

                            let _ = wd.recalculate_checksums(ChecksumFlags::new());
                            if let Err(e) = handle.send(&wd) {
                                error!("appfilter: Reinject (from tunnel) failed: {e}");
                                break;
                            }
                        } else {
                            debug!(
                                "appfilter: [INBOUND] Dropped (no NAT entry) | {:?}:{} <- {:?}:{}",
                                key.dst_addr, key.dport, key.src_addr, key.sport
                            );
                        }
                    }
                }
                info!("appfilter: Reinjector stopped.");
            })?;
    }

    info!("appfilter: Packet router started (policy={policy:?}, target_mss={target_tcp_mss})");
    let mut buf = [0u8; RECV_BUF];

    loop {
        let packet = match handle.recv(&mut buf) {
            Ok(p) => p,
            Err(e) => {
                info!("appfilter: Packet router stopped ({})", e);
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

        let key = match classify(&packet.data) {
            Some(k) => k,
            None => {
                if let Err(e) = handle.send(&packet) {
                    error!("appfilter: Failed to re-inject untyped packet: {e}");
                }
                continue;
            }
        };

        if is_ignored_ip(&key.src_addr) || is_ignored_ip(&key.dst_addr) {
            if let Err(e) = handle.send(&packet) {
                error!("appfilter: Failed to re-inject ignored packet: {e}");
            }
            continue;
        }

        // Проверка явного bypass списка (VPN сервер, TURN/Ktalk, прямые маршруты и CIDR)
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

        let nat_key = nat_key_outbound(&key);

        // Соединение считается подтверждённым туннельным потоком ТОЛЬКО если решение было принято
        // по реальному владельцу (confirmed == true). Это защищает финальные FIN/ACK пакеты от утечки
        // при закрытии сокета в Include-режиме и одновременно не застревает в туннеле при гонке в Exclude-режиме.
        let is_confirmed_tunnel_flow = nat_map
            .get(&nat_key)
            .is_some_and(|entry| entry.confirmed);

        let (tunnel, owner_opt, freshly_decided) = if is_confirmed_tunnel_flow {
            (true, map.lookup(&flow_key), false)
        } else if let Some(v) = decisions.get(&flow_key).map(|d| *d) {
            (v, map.lookup(&flow_key), false)
        } else {
            let mut owner_opt = map.lookup(&flow_key);
            if owner_opt.is_none() {
                for _ in 0..FLOW_RACE_RETRIES {
                    std::thread::sleep(FLOW_RACE_STEP);
                    owner_opt = map.lookup(&flow_key);
                    if owner_opt.is_some() {
                        break;
                    }
                }
            }

            // Никогда не заворачиваем в туннель собственные сокеты самого процесса VPN-клиента
            if owner_opt.as_ref().is_some_and(|o| o.process_id == self_pid) {
                decisions.insert(flow_key, false);
                nat_map.remove(&nat_key);
                (false, owner_opt, true)
            } else {
                let result = policy.should_tunnel(owner_opt.as_ref());
                let can_lock_decision = owner_opt.is_some()
                    || matches!(policy, AppPolicy::Include(_) | AppPolicy::All);
                if can_lock_decision {
                    decisions.insert(flow_key, result);
                    if !result {
                        nat_map.remove(&nat_key);
                    }
                }
                (result, owner_opt, can_lock_decision)
            }
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
            if key.src_addr.is_ipv6() {
                debug!(
                    "appfilter: IPv6 packet dropped for tunnel flow on port: {}",
                    key.sport
                );
                continue;
            }

            let is_confirmed = is_confirmed_tunnel_flow || freshly_decided;
            nat_map.insert(
                nat_key,
                NatEntry {
                    orig_ip: key.src_addr,
                    orig_addr: packet.address.clone(),
                    expires_at: None,
                    confirmed: is_confirmed,
                },
            );

            let mut wd = unsafe { WinDivertPacket::<NetworkLayer>::new(packet.data.to_vec()) };
            wd.address = packet.address.clone();
            wd.address.set_outbound(true);

            if let IpAddr::V4(v4) = vpn_ip {
                wd.data.to_mut()[12..16].copy_from_slice(&v4.octets());
            }

            clear_checksums(wd.data.to_mut());
            clamp_tcp_mss(wd.data.to_mut(), target_tcp_mss);

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
        } else if let Err(e) = handle.send(&packet) {
            error!("appfilter: Failed to re-inject bypassed packet: {e}");
        }
    }

    Ok(())
}

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
        src_addr: IpAddr::V6(src).to_canonical(),
        dst_addr: IpAddr::V6(dst).to_canonical(),
        sport,
        dport,
    })
}