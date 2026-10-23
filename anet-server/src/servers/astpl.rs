//! Серверный модуль транспорта ASTP-L (Anet Stealth Transport Protocol — Light).
//!
//! Объединяет:
//! - Userspace Control Plane (4-фазное рукопожатие ASTP поверх UDP с поддержкой
//!   `DatagramReassembler`, совместимое с общим UDP-портом `astpl_bind_to`).
//! - Загрузчик и менеджер eBPF Data Plane (`astpl_xdp_ingress` на внешнем сетевом
//!   интерфейсе `eth0` и `astpl_tc_egress` на `tun0`), синхронизирующий BPF-карты
//!   `ASTPL_CONFIG`, `ASTPL_INGRESS_MAP` и `ASTPL_EGRESS_MAP` с `ClientRegistry`.
//! - Прозрачный Userspace Fallback (и обработку внутритуннельных ICMP-зондов `0x414E`),
//!   если ядерный eBPF-слой недоступен или пакет намеренно пропущен через `XDP_PASS`.

use crate::auth_handler::ServerAuthHandler;
use crate::client_registry::{ClientRegistry, ClientTransportInfo};
use crate::config::Config;
use crate::shaper::{bump_memlock_rlimit, init_ebpf_logger};
use anet_common::astpl::{
    bind_astpl_udp_socket, unwrap_astpl_packet_in_place, wrap_astpl_packet_into, ASTPL_HEADER_LEN,
};
use anet_common::consts::{CHANNEL_BUFFER_SIZE, MAX_PACKET_SIZE, MIN_HANDSHAKE_LEN};
use anet_common::handshake_fragmentation::DatagramReassembler;
use anet_ebpf_common::{
    AstplConfig, EgressRoutingData, IngressSessionData, ASTPL_CONFIG_MAP, ASTPL_EGRESS_MAP,
    ASTPL_INGRESS_MAP,
};
use anyhow::{anyhow, Context, Result};
use aya::maps::HashMap as AyaHashMap;
use aya::programs::tc::{SchedClassifier, TcAttachType};
use aya::programs::{Xdp, XdpMode};
use aya::Ebpf;
use bytes::Bytes;
use dashmap::DashMap;
use log::{debug, error, info, warn};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::sync::{mpsc, Mutex};

const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(5);
const BPF_SYNC_INTERVAL: Duration = Duration::from_secs(2);

pub struct AstplEbpfManager {
    ebpf: Arc<Mutex<Ebpf>>,
    eth_iface: String,
    tun_iface: String,
}

impl AstplEbpfManager {
    /// Загружает (или переиспользует из `Shaper`) встроенный eBPF-объект,
    /// инициализирует `ASTPL_CONFIG`, прикрепляет `astpl_xdp_ingress` к внешнему
    /// интерфейсу и (если `Shaper` ещё не прикрепил `tc_egress`) прикрепляет
    /// `astpl_tc_egress` к TUN-интерфейсу.
    pub async fn attach(
        config: &Config,
        tun_iface: &str,
        bind_addr: SocketAddr,
        shared_ebpf: Option<Arc<Mutex<Ebpf>>>,
    ) -> Result<Self> {
        let eth_iface = Self::resolve_external_iface(config).await?;
        let eth_ifindex = Self::read_ifindex(&eth_iface).await?;
        let server_ip = Self::resolve_server_ipv4(config, &eth_iface, bind_addr).await?;
        let server_port = bind_addr.port();
        let tun_self_ip = config
            .network
            .self_ip
            .trim()
            .parse::<Ipv4Addr>()
            .unwrap_or(Ipv4Addr::UNSPECIFIED);
        let tun_gw_ip = config
            .network
            .gateway
            .trim()
            .parse::<Ipv4Addr>()
            .unwrap_or(Ipv4Addr::UNSPECIFIED);

        info!(
            "[ASTP-L eBPF] Initializing on external iface '{}' (ifindex={}, ip={}, port={}) <-> TUN '{}' (self_ip={}, gw={})",
            eth_iface, eth_ifindex, server_ip, server_port, tun_iface, tun_self_ip, tun_gw_ip
        );

        let shaper_attached = shared_ebpf.is_some();
        let ebpf_arc = match shared_ebpf {
            Some(existing) => existing,
            None => {
                bump_memlock_rlimit();
                let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/anet-ebpf"));
                let mut ebpf =
                    Ebpf::load(bytes).context("Failed to load embedded anet-ebpf object")?;
                init_ebpf_logger(&mut ebpf);
                Arc::new(Mutex::new(ebpf))
            }
        };

        Self::configure_kernel_routing(&eth_iface, tun_iface).await;
        Self::cleanup_stale_xdp(&eth_iface).await;

        {
            let mut ebpf = ebpf_arc.lock().await;

            // 1. Записываем глобальную конфигурацию ASTPL_CONFIG (ключ 0)
            {
                let mut cfg_map: AyaHashMap<_, u32, AstplConfig> = AyaHashMap::try_from(
                    ebpf.map_mut(ASTPL_CONFIG_MAP)
                        .context("ASTPL_CONFIG map missing from anet-ebpf")?,
                )?;
                let astpl_cfg = AstplConfig {
                    astpl_port_be: server_port.to_be(),
                    _pad: 0,
                    server_ip_be: u32::from_ne_bytes(server_ip.octets()),
                    eth_ifindex,
                    tun_ip_be: u32::from_ne_bytes(tun_self_ip.octets()),
                    tun_gw_be: u32::from_ne_bytes(tun_gw_ip.octets()),
                    _pad2: 0,
                };
                cfg_map.insert(0, astpl_cfg, 0)?;
            }

            // 2. Загружаем и прикрепляем astpl_xdp_ingress на внешний интерфейс (Driver -> Skb fallback)
            {
                let xdp: &mut Xdp = ebpf
                    .program_mut("astpl_xdp_ingress")
                    .context("astpl_xdp_ingress program missing from anet-ebpf object")?
                    .try_into()?;
                xdp.load()?;

                match xdp.attach(&eth_iface, XdpMode::Driver) {
                    Ok(_) => {
                        info!(
                            "[ASTP-L eBPF] Attached astpl_xdp_ingress to '{}' in XdpMode::Driver (Native)",
                            eth_iface
                        );
                    }
                    Err(driver_err) => {
                        warn!(
                            "[ASTP-L eBPF] Native XDP on '{}' unavailable ({}), falling back to XdpMode::Skb",
                            eth_iface, driver_err
                        );
                        xdp.attach(&eth_iface, XdpMode::Skb).with_context(|| {
                            format!("Failed to attach astpl_xdp_ingress to '{}'", eth_iface)
                        })?;
                        info!(
                            "[ASTP-L eBPF] Attached astpl_xdp_ingress to '{}' in XdpMode::Skb (Generic)",
                            eth_iface
                        );
                    }
                }
            }

            // 3. Если Shaper не активен, вешаем astpl_tc_egress на egress TUN-интерфейса.
            // (Если Shaper активен, его программа `tc_egress` уже вызывает `try_astpl_tc_egress`.)
            if !shaper_attached {
                Self::ensure_clsact(tun_iface).await;
                Self::cleanup_stale_tc_egress(tun_iface).await;

                let egress: &mut SchedClassifier = ebpf
                    .program_mut("astpl_tc_egress")
                    .context("astpl_tc_egress program missing from anet-ebpf object")?
                    .try_into()?;
                egress.load()?;
                egress
                    .attach(tun_iface, TcAttachType::Egress)
                    .with_context(|| {
                        format!("Failed to attach astpl_tc_egress to TUN '{}'", tun_iface)
                    })?;
                info!(
                    "[ASTP-L eBPF] Attached astpl_tc_egress to TUN '{}'",
                    tun_iface
                );
            } else {
                info!(
                    "[ASTP-L eBPF] Reusing Shaper tc_egress hook on TUN '{}' for ASTP-L encapsulation",
                    tun_iface
                );
            }
        }

        // Важно: в драйвере virtio_net вызов `virtnet_xdp_set` при `xdp.attach` пересчитывает
        // `netdev_features_t` интерфейса (`netdev_update_features`), поэтому отключаем
        // GRO/LRO повторно ПОСЛЕ прикрепления XDP-программы.
        Self::disable_rx_coalescing_offloads(&eth_iface).await;

        Ok(Self {
            ebpf: ebpf_arc,
            eth_iface,
            tun_iface: tun_iface.to_string(),
        })
    }

    /// Регистрирует сессию клиента в ядерных BPF-картах `ASTPL_INGRESS_MAP` и `ASTPL_EGRESS_MAP`.
    pub async fn register_session(&self, client_info: &ClientTransportInfo) -> Result<()> {
        let assigned_ipv4: Ipv4Addr = client_info
            .assigned_ip
            .parse()
            .with_context(|| format!("Invalid assigned IPv4 '{}'", client_info.assigned_ip))?;
        let remote_addr = **client_info.remote_addr.load();
        let client_ipv4 = match remote_addr.ip() {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .ok_or_else(|| anyhow!("ASTP-L eBPF supports only IPv4 endpoints, got {}", v6))?,
        };

        let prefix_key = u32::from_ne_bytes(client_info.nonce_prefix);
        let assigned_ip_be = u32::from_ne_bytes(assigned_ipv4.octets());
        let client_ip_be = u32::from_ne_bytes(client_ipv4.octets());
        let client_port_be = remote_addr.port().to_be();

        let ingress_val = IngressSessionData {
            crypto_seed: client_info.crypto_seed,
            rx_bytes: 0,
            last_seen_ns: 0,
            assigned_ip: assigned_ip_be,
            last_seq: 0,
            client_ip: client_ip_be,
            client_port: client_port_be,
            _pad: 0,
        };

        let egress_val = EgressRoutingData {
            crypto_seed: client_info.crypto_seed,
            tx_bytes: 0,
            last_seen_ns: 0,
            dst_ip: client_ip_be,
            nonce_prefix: prefix_key,
            tx_seq: 1,
            dst_port: client_port_be,
            _pad: 0,
        };

        let mut ebpf = self.ebpf.lock().await;
        {
            let mut ingress_map: AyaHashMap<_, u32, IngressSessionData> = AyaHashMap::try_from(
                ebpf.map_mut(ASTPL_INGRESS_MAP)
                    .context("ASTPL_INGRESS_MAP missing")?,
            )?;
            ingress_map.insert(prefix_key, ingress_val, 0)?;
        }
        {
            let mut egress_map: AyaHashMap<_, u32, EgressRoutingData> = AyaHashMap::try_from(
                ebpf.map_mut(ASTPL_EGRESS_MAP)
                    .context("ASTPL_EGRESS_MAP missing")?,
            )?;
            egress_map.insert(assigned_ip_be, egress_val, 0)?;
        }

        info!(
            "[ASTP-L eBPF] Session registered: prefix=0x{:08x}, tun_ip={}, endpoint={}:{}",
            u32::from_be_bytes(client_info.nonce_prefix),
            assigned_ipv4,
            client_ipv4,
            remote_addr.port()
        );
        Ok(())
    }

    /// Обновляет внешний адрес клиента в BPF-картах (например, при получении control-пакета с нового адреса).
    pub async fn update_session_endpoint(
        &self,
        client_info: &ClientTransportInfo,
        new_addr: SocketAddr,
    ) {
        let client_ipv4 = match new_addr.ip() {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => v4,
                None => return,
            },
        };
        let Ok(assigned_ipv4) = client_info.assigned_ip.parse::<Ipv4Addr>() else {
            return;
        };

        let prefix_key = u32::from_ne_bytes(client_info.nonce_prefix);
        let assigned_ip_be = u32::from_ne_bytes(assigned_ipv4.octets());
        let client_ip_be = u32::from_ne_bytes(client_ipv4.octets());
        let client_port_be = new_addr.port().to_be();

        let mut ebpf = self.ebpf.lock().await;
        if let Some(map) = ebpf.map_mut(ASTPL_INGRESS_MAP) {
            if let Ok(mut ingress_map) = AyaHashMap::<_, u32, IngressSessionData>::try_from(map) {
                if let Ok(mut data) = ingress_map.get(&prefix_key, 0) {
                    if data.client_ip != client_ip_be || data.client_port != client_port_be {
                        data.client_ip = client_ip_be;
                        data.client_port = client_port_be;
                        let _ = ingress_map.insert(prefix_key, data, 0);
                    }
                }
            }
        }
        if let Some(map) = ebpf.map_mut(ASTPL_EGRESS_MAP) {
            if let Ok(mut egress_map) = AyaHashMap::<_, u32, EgressRoutingData>::try_from(map) {
                if let Ok(mut data) = egress_map.get(&assigned_ip_be, 0) {
                    if data.dst_ip != client_ip_be || data.dst_port != client_port_be {
                        data.dst_ip = client_ip_be;
                        data.dst_port = client_port_be;
                        let _ = egress_map.insert(assigned_ip_be, data, 0);
                    }
                }
            }
        }
    }

    /// Удаляет сессию клиента из BPF-карт `ASTPL_INGRESS_MAP` и `ASTPL_EGRESS_MAP`.
    pub async fn remove_session(&self, nonce_prefix: [u8; 4], assigned_ip: Option<Ipv4Addr>) {
        let prefix_key = u32::from_ne_bytes(nonce_prefix);
        let mut ebpf = self.ebpf.lock().await;

        if let Some(map) = ebpf.map_mut(ASTPL_INGRESS_MAP) {
            if let Ok(mut ingress_map) = AyaHashMap::<_, u32, IngressSessionData>::try_from(map) {
                let _ = ingress_map.remove(&prefix_key);
            }
        }
        if let Some(ip) = assigned_ip {
            let ip_key = u32::from_ne_bytes(ip.octets());
            if let Some(map) = ebpf.map_mut(ASTPL_EGRESS_MAP) {
                if let Ok(mut egress_map) = AyaHashMap::<_, u32, EgressRoutingData>::try_from(map) {
                    let _ = egress_map.remove(&ip_key);
                }
            }
        }
    }

    /// Читает накопленные ядерные счётчики (`rx_bytes`, `tx_bytes`, `last_seen_ns`) и
    /// обновлённый `client_ip`/`client_port` (NAT Rebinding) из BPF-карт в `ClientRegistry`.
    pub async fn sync_with_registry(&self, registry: &ClientRegistry) {
        let sessions = registry.astpl_sessions();
        if sessions.is_empty() {
            return;
        }

        let mut ebpf = self.ebpf.lock().await;

        for client_info in sessions {
            let prefix_key = u32::from_ne_bytes(client_info.nonce_prefix);
            let ip_key = client_info
                .assigned_ip
                .parse::<Ipv4Addr>()
                .ok()
                .map(|ip| u32::from_ne_bytes(ip.octets()));

            let prev_rx = client_info.ebpf_synced_rx.load(Ordering::Relaxed);
            let prev_tx = client_info.ebpf_synced_tx.load(Ordering::Relaxed);
            let mut rx_bytes = prev_rx;
            let mut last_seen_ns = client_info.ebpf_last_seen_ns.load(Ordering::Relaxed);
            let mut last_rx_seq = 0u32;
            let mut kernel_addr = None;

            if let Some(map) = ebpf.map_mut(ASTPL_INGRESS_MAP) {
                if let Ok(ingress_map) = AyaHashMap::<_, u32, IngressSessionData>::try_from(map) {
                    if let Ok(ing) = ingress_map.get(&prefix_key, 0) {
                        rx_bytes = ing.rx_bytes;
                        last_seen_ns = ing.last_seen_ns;
                        last_rx_seq = ing.last_seq;
                        if ing.client_ip != 0 && ing.client_port != 0 {
                            kernel_addr = Some(SocketAddr::new(
                                IpAddr::V4(Ipv4Addr::from(ing.client_ip.to_ne_bytes())),
                                u16::from_be(ing.client_port),
                            ));
                        }
                    }
                }
            }

            let mut tx_bytes = prev_tx;
            let mut last_tx_seq = 0u32;
            if let Some(k) = ip_key {
                if let Some(map) = ebpf.map_mut(ASTPL_EGRESS_MAP) {
                    if let Ok(egress_map) = AyaHashMap::<_, u32, EgressRoutingData>::try_from(map) {
                        if let Ok(eg) = egress_map.get(&k, 0) {
                            tx_bytes = eg.tx_bytes;
                            last_tx_seq = eg.tx_seq;
                        }
                    }
                }
            }

            if rx_bytes != prev_rx || tx_bytes != prev_tx {
                info!(
                    "[ASTP-L eBPF Stats] tun_ip={} | XDP rx={} B (+{} B, last_seq={}) | TC tx={} B (+{} B, tx_seq={}) | endpoint={:?}",
                    client_info.assigned_ip,
                    rx_bytes,
                    rx_bytes.saturating_sub(prev_rx),
                    last_rx_seq,
                    tx_bytes,
                    tx_bytes.saturating_sub(prev_tx),
                    last_tx_seq,
                    kernel_addr
                );
            }

            registry.sync_astpl_session_stats(
                &client_info,
                rx_bytes,
                tx_bytes,
                last_seen_ns,
                kernel_addr,
            );
        }
    }

    pub fn eth_iface(&self) -> &str {
        &self.eth_iface
    }

    pub fn tun_iface(&self) -> &str {
        &self.tun_iface
    }

    async fn resolve_external_iface(config: &Config) -> Result<String> {
        if let Some(ref iface) = config.server.astpl_iface {
            let trimmed = iface.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_string());
            }
        }

        // Автоопределение интерфейса маршрута по умолчанию из /proc/net/route
        let route_table = tokio::fs::read_to_string("/proc/net/route")
            .await
            .context("Failed to read /proc/net/route to auto-detect external interface")?;

        for line in route_table.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 2 && cols[1] == "00000000" {
                return Ok(cols[0].to_string());
            }
        }

        Err(anyhow!(
            "Could not auto-detect default network interface from /proc/net/route; set server.astpl_iface in server.toml"
        ))
    }

    async fn read_ifindex(iface: &str) -> Result<u32> {
        let path = format!("/sys/class/net/{}/ifindex", iface);
        let content = tokio::fs::read_to_string(&path)
            .await
            .with_context(|| format!("Failed to read {}", path))?;
        content
            .trim()
            .parse::<u32>()
            .with_context(|| format!("Invalid ifindex in {}", path))
    }

    async fn resolve_server_ipv4(
        config: &Config,
        eth_iface: &str,
        bind_addr: SocketAddr,
    ) -> Result<Ipv4Addr> {
        if let Some(ref pub_ip) = config.server.astpl_public_ip {
            let trimmed = pub_ip.trim();
            if !trimmed.is_empty() {
                return trimmed
                    .parse::<Ipv4Addr>()
                    .with_context(|| format!("Invalid server.astpl_public_ip '{}'", trimmed));
            }
        }

        if let IpAddr::V4(v4) = bind_addr.ip() {
            if !v4.is_unspecified() && !v4.is_loopback() {
                return Ok(v4);
            }
        }

        // Пытаемся определить глобальный IPv4 на интерфейсе через `ip -4 -o addr show dev <eth_iface>`
        if let Ok(output) = Command::new("ip")
            .args(["-4", "-o", "addr", "show", "dev", eth_iface, "scope", "global"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .await
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for token in stdout.split_whitespace() {
                    if let Some((ip_str, _prefix)) = token.split_once('/') {
                        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                            return Ok(ip);
                        }
                    }
                }
            }
        }

        // Fallback: определяем исходящий локальный IPv4 через UDP route lookup
        if let Ok(probe_sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if probe_sock.connect("8.8.8.8:80").is_ok() {
                if let Ok(SocketAddr::V4(local)) = probe_sock.local_addr() {
                    if !local.ip().is_unspecified() {
                        return Ok(*local.ip());
                    }
                }
            }
        }

        Err(anyhow!(
            "Could not determine external IPv4 for interface '{}'; set server.astpl_public_ip in server.toml",
            eth_iface
        ))
    }

    async fn configure_kernel_routing(eth_iface: &str, tun_iface: &str) {
        // Для того чтобы декапсулированные в XDP на eth0 пакеты с src=10.0.0.x
        // не отбрасывались ядром как martian source (rp_filter), отключаем rp_filter на eth_iface и tun_iface.
        for key in [
            "net.ipv4.ip_forward=1".to_string(),
            "net.ipv4.conf.all.rp_filter=0".to_string(),
            "net.ipv4.conf.default.rp_filter=0".to_string(),
            format!("net.ipv4.conf.{}.rp_filter=0", eth_iface),
            format!("net.ipv4.conf.{}.rp_filter=0", tun_iface),
        ] {
            let _ = Command::new("sysctl")
                .args(["-w", &key])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .output()
                .await;
        }

        Self::disable_rx_coalescing_offloads(eth_iface).await;
    }

    /// Отключает GRO/LRO (`rx-gro`, `rx-gro-hw`, `rx-gro-list`, `rx-lro`) на внешнем интерфейсе:
    /// 1. Напрямую через ядерный `ioctl(SIOCETHTOOL, ETHTOOL_SFEATURES)` (не требует установленного пакета `ethtool`).
    /// 2. Дублирует вызовом `ethtool -K` (если утилита установлена в системе).
    /// Это гарантирует, что `napi_gro_receive` на `ens3` не склеивает входящие TCP-сегменты (Download)
    /// в GSO-суперпакеты (`skb->len > MTU`, `CHECKSUM_PARTIAL`), и все пакеты проходят через ядерный TC fast-path.
    async fn disable_rx_coalescing_offloads(eth_iface: &str) {
        match Self::disable_gro_lro_via_ioctl(eth_iface) {
            Ok(disabled) if !disabled.is_empty() => {
                info!(
                    "[ASTP-L eBPF] Disabled RX coalescing features on '{}' via SIOCETHTOOL: {}",
                    eth_iface,
                    disabled.join(", ")
                );
            }
            Ok(_) => {
                debug!(
                    "[ASTP-L eBPF] SIOCETHTOOL on '{}' completed (no matching GRO/LRO features needed changes)",
                    eth_iface
                );
            }
            Err(e) => {
                warn!(
                    "[ASTP-L eBPF] SIOCETHTOOL GRO/LRO disable on '{}' failed: {}",
                    eth_iface, e
                );
            }
        }

        for bin in ["ethtool", "/usr/sbin/ethtool", "/sbin/ethtool"] {
            if let Ok(out) = Command::new(bin)
                .args(["-K", eth_iface, "gro", "off", "lro", "off"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .output()
                .await
            {
                if out.status.success() {
                    break;
                }
            }
        }
    }

    fn disable_gro_lro_via_ioctl(iface: &str) -> Result<Vec<String>> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;

            const SIOCETHTOOL: usize = 0x8946;
            const ETHTOOL_GSSET_INFO: u32 = 0x0000_0037;
            const ETHTOOL_GSTRINGS: u32 = 0x0000_001b;
            const ETHTOOL_SFEATURES: u32 = 0x0000_003b;
            const ETH_SS_FEATURES: u32 = 4;
            const ETH_GSTRING_LEN: usize = 32;
            const MAX_FEATURES: usize = 256;
            const MAX_FEATURE_BLOCKS: usize = (MAX_FEATURES + 31) / 32;
            const IFNAMSIZ: usize = 16;

            unsafe extern "C" {
                fn ioctl(fd: i32, request: usize, arg: *mut core::ffi::c_void) -> i32;
            }

            #[repr(C)]
            struct EthtoolSsetInfo {
                cmd: u32,
                reserved: u32,
                sset_mask: u64,
                data: u32,
            }

            #[repr(C)]
            struct EthtoolGstrings {
                cmd: u32,
                string_set: u32,
                len: u32,
                data: [[u8; ETH_GSTRING_LEN]; MAX_FEATURES],
            }

            #[repr(C)]
            #[derive(Clone, Copy, Default)]
            struct EthtoolSetFeaturesBlock {
                valid: u32,
                requested: u32,
            }

            #[repr(C)]
            struct EthtoolSfeatures {
                cmd: u32,
                size: u32,
                features: [EthtoolSetFeaturesBlock; MAX_FEATURE_BLOCKS],
            }

            #[repr(C)]
            struct Ifreq {
                ifr_name: [u8; IFNAMSIZ],
                ifr_data: *mut core::ffi::c_void,
            }

            let name_bytes = iface.as_bytes();
            if name_bytes.is_empty() || name_bytes.len() >= IFNAMSIZ {
                return Err(anyhow!("Invalid interface name '{}'", iface));
            }

            let mut ifr_name = [0u8; IFNAMSIZ];
            ifr_name[..name_bytes.len()].copy_from_slice(name_bytes);

            let sock =
                std::net::UdpSocket::bind("0.0.0.0:0").context("UdpSocket::bind for SIOCETHTOOL")?;
            let fd = sock.as_raw_fd();

            // 1. Запрашиваем количество поддерживаемых фич (ETH_SS_FEATURES)
            let mut sset_info = EthtoolSsetInfo {
                cmd: ETHTOOL_GSSET_INFO,
                reserved: 0,
                sset_mask: 1u64 << ETH_SS_FEATURES,
                data: 0,
            };
            let mut ifr = Ifreq {
                ifr_name,
                ifr_data: (&mut sset_info as *mut EthtoolSsetInfo).cast(),
            };
            if unsafe { ioctl(fd, SIOCETHTOOL, (&mut ifr as *mut Ifreq).cast()) } < 0 {
                return Err(std::io::Error::last_os_error()).context("ioctl(ETHTOOL_GSSET_INFO)");
            }

            let n_features = (sset_info.data as usize).min(MAX_FEATURES);
            if n_features == 0 {
                return Ok(Vec::new());
            }

            // 2. Читаем строковые имена фич (ETHTOOL_GSTRINGS)
            let mut gstrings = EthtoolGstrings {
                cmd: ETHTOOL_GSTRINGS,
                string_set: ETH_SS_FEATURES,
                len: n_features as u32,
                data: [[0u8; ETH_GSTRING_LEN]; MAX_FEATURES],
            };
            ifr.ifr_data = (&mut gstrings as *mut EthtoolGstrings).cast();
            if unsafe { ioctl(fd, SIOCETHTOOL, (&mut ifr as *mut Ifreq).cast()) } < 0 {
                return Err(std::io::Error::last_os_error()).context("ioctl(ETHTOOL_GSTRINGS)");
            }

            // 3. Формируем битовую маску отключения для rx-gro / rx-gro-hw / rx-gro-list / rx-lro
            let n_blocks = (n_features + 31) / 32;
            let mut sfeatures = EthtoolSfeatures {
                cmd: ETHTOOL_SFEATURES,
                size: n_blocks as u32,
                features: [EthtoolSetFeaturesBlock::default(); MAX_FEATURE_BLOCKS],
            };

            let mut disabled_names = Vec::new();
            for idx in 0..n_features {
                let raw = &gstrings.data[idx];
                let end = raw.iter().position(|&c| c == 0).unwrap_or(ETH_GSTRING_LEN);
                let Ok(feat_name) = std::str::from_utf8(&raw[..end]) else {
                    continue;
                };
                if matches!(
                    feat_name,
                    "rx-gro" | "rx-gro-hw" | "rx-gro-list" | "rx-lro"
                ) {
                    let block = idx / 32;
                    let bit = 1u32 << (idx % 32);
                    sfeatures.features[block].valid |= bit;
                    sfeatures.features[block].requested &= !bit;
                    disabled_names.push(feat_name.to_string());
                }
            }

            if disabled_names.is_empty() {
                return Ok(disabled_names);
            }

            ifr.ifr_data = (&mut sfeatures as *mut EthtoolSfeatures).cast();
            if unsafe { ioctl(fd, SIOCETHTOOL, (&mut ifr as *mut Ifreq).cast()) } < 0 {
                return Err(std::io::Error::last_os_error()).context("ioctl(ETHTOOL_SFEATURES)");
            }

            Ok(disabled_names)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = iface;
            Ok(Vec::new())
        }
    }

    async fn cleanup_stale_xdp(iface: &str) {
        for mode in ["xdp", "xdpgeneric"] {
            let _ = Command::new("ip")
                .args(["link", "set", "dev", iface, mode, "off"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .output()
                .await;
        }
    }

    async fn ensure_clsact(iface: &str) {
        let _ = Command::new("tc")
            .args(["qdisc", "add", "dev", iface, "clsact"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .await;
    }

    async fn cleanup_stale_tc_egress(iface: &str) {
        let _ = Command::new("tc")
            .args(["filter", "del", "dev", iface, "egress"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .await;
    }
}

pub async fn run_astpl_server(
    config: Arc<Config>,
    registry: Arc<ClientRegistry>,
    tun_tx: mpsc::Sender<Bytes>,
    auth_handler: ServerAuthHandler,
    tun_iface: String,
) -> Result<()> {
    let bind_to = config.server.astpl_bind_to.trim();
    let socket = Arc::new(
        bind_astpl_udp_socket(bind_to)
            .with_context(|| format!("Failed to bind ASTP-L UDP socket on {}", bind_to))?,
    );
    let local_addr = socket.local_addr()?;
    info!("Starting ASTP-L [eBPF XDP/TC + UDP Auth] Server on {}", local_addr);

    let shared_ebpf = registry.get_shaper().map(|s| s.ebpf());
    match AstplEbpfManager::attach(&config, &tun_iface, local_addr, shared_ebpf).await {
        Ok(manager) => {
            let manager_arc = Arc::new(manager);
            registry.set_astpl_ebpf(manager_arc.clone());

            let sync_mgr = manager_arc;
            let sync_reg = registry.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(BPF_SYNC_INTERVAL).await;
                    sync_mgr.sync_with_registry(&sync_reg).await;
                }
            });
        }
        Err(e) => {
            warn!(
                "[ASTP-L] Failed to attach eBPF fast-path ({}). Operating in Userspace UDP fallback mode.",
                e
            );
        }
    }

    let reassemblers: Arc<DashMap<SocketAddr, (Instant, DatagramReassembler)>> =
        Arc::new(DashMap::new());
    let mut recv_buf = vec![0u8; MAX_PACKET_SIZE];

    loop {
        let (len, remote_addr) = match socket.recv_from(&mut recv_buf).await {
            Ok(res) => res,
            Err(e) => {
                warn!("[ASTP-L] UDP recv_from error: {}", e);
                continue;
            }
        };
        if len == 0 {
            continue;
        }

        // 1. Проверяем, принадлежит ли пакет уже авторизованной ASTP-L сессии
        //    (попадает сюда при `seq == 0` control-пакетах или в режиме Userspace fallback).
        if len >= ASTPL_HEADER_LEN {
            if let Ok(nonce_prefix) = recv_buf[..4].try_into() {
                if let Some(client_info) = registry.get_by_prefix(&nonce_prefix) {
                    if client_info.protocol == "astpl" {
                        let expected_ip = client_info.assigned_ip.parse::<Ipv4Addr>().ok();
                        match unwrap_astpl_packet_in_place(
                            client_info.crypto_seed,
                            &mut recv_buf[..len],
                            expected_ip,
                        ) {
                            Ok((_prefix, seq, inner_pkt)) => {
                                let prev_addr = **client_info.remote_addr.load();
                                registry.update_client_addr(&client_info, remote_addr);
                                if prev_addr != remote_addr {
                                    if let Some(ebpf_mgr) = registry.get_astpl_ebpf() {
                                        let ci = client_info.clone();
                                        tokio::spawn(async move {
                                            ebpf_mgr.update_session_endpoint(&ci, remote_addr).await;
                                        });
                                    }
                                }

                                if seq == 0 {
                                    registry.touch_client(&client_info);
                                    continue;
                                }

                                // Обработка внутритуннельного ICMP Echo Request зонда (0x414E)
                                if let Some(reply) =
                                    anet_common::icmp_probe::handle_in_tunnel_icmp_probe(inner_pkt)
                                {
                                    registry.touch_client(&client_info);
                                    registry
                                        .route_packet_to_client(&client_info.assigned_ip, reply)
                                        .await;
                                    continue;
                                }

                                let pkt_len = inner_pkt.len();
                                let pkt_bytes = Bytes::copy_from_slice(inner_pkt);
                                match tun_tx.try_send(pkt_bytes) {
                                    Ok(_) => {
                                        registry.record_rx(&client_info, pkt_len, "astpl");
                                    }
                                    Err(mpsc::error::TrySendError::Full(_)) => {
                                        warn!(
                                            "[ASTP-L] TUN channel full, dropping packet from {}",
                                            client_info.assigned_ip
                                        );
                                    }
                                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                                }
                                continue;
                            }
                            Err(e) => {
                                // Если пакет пришёл с известным nonce_prefix активной сессии,
                                // но внутренний пакет не прошёл проверку (например, IPv6 или старый src_ip
                                // от открытых до VPN сокетов клиента), не отправляем его в DatagramReassembler.
                                debug!(
                                    "[ASTP-L] Dropped non-IPv4/mismatched packet for session {} from {}: {}",
                                    client_info.assigned_ip, remote_addr, e
                                );
                                continue;
                            }
                        }
                    }
                }
            }
        }

        // 2. Пакет не принадлежит активной сессии — собираем фрагменты хендшейка через DatagramReassembler
        let complete: Option<Vec<u8>> = {
            let mut entry = reassemblers
                .entry(remote_addr)
                .and_modify(|(ts, reassembler)| {
                    if ts.elapsed() > REASSEMBLY_TIMEOUT {
                        *reassembler = DatagramReassembler::new();
                    }
                    *ts = Instant::now();
                })
                .or_insert_with(|| (Instant::now(), DatagramReassembler::new()));

            entry.1.feed(&recv_buf[..len])
        };

        debug!("[ASTP-L] Reassembling handshake fragment from {}", remote_addr);
        let Some(complete) = complete else {
            continue;
        };
        reassemblers.remove(&remote_addr);

        if complete.len() < MIN_HANDSHAKE_LEN {
            warn!(
                "[ASTP-L] Reassembled handshake too short from {} ({} bytes), dropping",
                remote_addr,
                complete.len()
            );
            continue;
        }

        let packet_copy = Bytes::from(complete);
        let handler = auth_handler.clone();
        let sock = socket.clone();
        let reg = registry.clone();

        tokio::spawn(async move {
            match handler
                .process_handshake_packet(packet_copy, remote_addr, "astpl")
                .await
            {
                Ok((Some(resp_bytes), auth_tuple)) => {
                    if let Some((client_info, _auth_resp)) = auth_tuple {
                        // Запускаем задачу отправки пакетов из userspace (для ICMP-ответов и Userspace fallback).
                        // Используем старший бит seq (0x8000_0000), чтобы последовательности не пересекались с ядерным tx_seq.
                        let (tx_router, mut rx_router) =
                            mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
                        reg.finalize_client(&client_info.assigned_ip, tx_router);

                        // Регистрируем сессию в ядерных BPF-картах ДО отправки AuthResponse клиенту,
                        // чтобы первый же пакет данных клиента гарантированно попал в XDP fast-path.
                        if let Some(ebpf_mgr) = reg.get_astpl_ebpf() {
                            if let Err(e) = ebpf_mgr.register_session(&client_info).await {
                                error!(
                                    "[ASTP-L eBPF] Failed to populate BPF maps for {}: {}",
                                    client_info.assigned_ip, e
                                );
                            }
                        }

                        let ci_writer = client_info.clone();
                        let sock_writer = sock.clone();
                        tokio::spawn(async move {
                            let mut wrap_buf = Vec::with_capacity(MAX_PACKET_SIZE);
                            while let Some(inner_ip_pkt) = rx_router.recv().await {
                                let raw_seq = ci_writer.sequence.fetch_add(1, Ordering::Relaxed) as u32;
                                let seq = (raw_seq | 0x8000_0000).max(1);
                                wrap_astpl_packet_into(
                                    &mut wrap_buf,
                                    &ci_writer.nonce_prefix,
                                    seq,
                                    ci_writer.crypto_seed,
                                    &inner_ip_pkt,
                                );
                                let dst = **ci_writer.remote_addr.load();
                                if let Err(e) = sock_writer.send_to(&wrap_buf, dst).await {
                                    warn!(
                                        "[ASTP-L] UDP send_to error for {} ({}): {}",
                                        ci_writer.assigned_ip, dst, e
                                    );
                                }
                            }
                        });
                    }

                    let _ = sock.send_to(&resp_bytes, remote_addr).await;
                }
                Ok((None, _)) => {}
                Err(e) => {
                    warn!("[ASTP-L Handshake fail] {}: {}", remote_addr, e);
                }
            }
        });
    }

    Ok(())
}
