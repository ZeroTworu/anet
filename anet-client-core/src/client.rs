use crate::statistic;
#[cfg(all(windows, feature = "per-app"))]
use anyhow::Context;
use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use ipnet::IpNet;
use log::{error, info, warn};
use quinn::Endpoint;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncWriteExt, split as io_split};
use tokio::net::lookup_host;
use tokio::select;
use tokio::spawn;
use tokio::sync::Notify;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinHandle;
use tokio::time::sleep;

#[cfg(all(windows, feature = "per-app"))]
use anet_appfilter::{AppFilter, AppPolicy};
use anet_common::consts::COALESCE_BUDGET_BYTES;
use anet_common::icmp_probe::{
    PROBE_IDENTIFIER, build_ipv4_icmp_echo_request, parse_ipv4_icmp_echo_reply,
};
use anet_common::protocol::{AuthResponse, BillingType as ProtoBillingType};
use anet_common::stream_framing::{frame_packet_into, read_next_packet};

#[cfg(all(windows, feature = "per-app"))]
use crate::config::PerAppMode;

use crate::auth::AuthDenyError;
use crate::config::{CoreConfig, ServerConfig};
use crate::dns::{DnsManager, get_dns_manager};
use crate::events::{AccountInfo, ClientState, account_info, client_state, err, status, warn};
use crate::traits::{RouteManager, TunFactory};
use crate::transport::factory::create_transport;

struct RunningSession {
    endpoint: Option<Endpoint>,
    shutdown_notify: Arc<Notify>,
    reconnect_signal: Arc<Notify>,
    disconnect_reason: Arc<Mutex<String>>,
    main_task: JoinHandle<()>,
    stats_task: Option<JoinHandle<()>>,
    iface_name: String,
    shutdown_hook: Option<crate::transport::ShutdownHook>,
}

pub struct AnetClient {
    config: CoreConfig,
    tun_factory: Box<dyn TunFactory>,
    route_manager: Arc<dyn RouteManager>,
    dns_manager: Box<dyn DnsManager>,
    rule_cache: crate::rule_updater::RuleCacheManager,
    session: Mutex<Option<RunningSession>>,
    stop_requested: AtomicBool,
    is_active: AtomicBool,
    cancel_signal: Arc<Notify>,
}

impl AnetClient {
    pub fn new(
        config: CoreConfig,
        tun_factory: Box<dyn TunFactory>,
        route_manager: Box<dyn RouteManager>,
    ) -> Self {
        let dns_manager = get_dns_manager();
        let rule_cache = crate::rule_updater::RuleCacheManager::new(
            crate::rule_updater::default_rules_cache_path(),
        );
        Self {
            config,
            tun_factory,
            route_manager: Arc::from(route_manager),
            dns_manager,
            rule_cache,
            session: Mutex::new(None),
            stop_requested: AtomicBool::new(false),
            is_active: AtomicBool::new(false),
            cancel_signal: Arc::new(Notify::new()),
        }
    }

    async fn sync_rules_cache(&self, config: &CoreConfig) {
        if let Some(rules_server_url) = config.get_rules_server_url() {
            match tokio::time::timeout(
                Duration::from_secs(5),
                self.rule_cache.update_from_server(&rules_server_url),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    let msg = format!(
                        "[RuleCache] Failed to download rules.abc from {rules_server_url}: {e}"
                    );
                    warn!("{msg}");
                    status(&msg);
                }
                Err(_) => {
                    let msg = format!(
                        "[RuleCache] Timeout downloading rules.abc from {rules_server_url} (using cached rules if available)"
                    );
                    warn!("{msg}");
                    status(&msg);
                }
            }
        } else {
            let msg = "[RuleCache] Server URL for rules.abc is not configured (set [routing] rules_url in client.toml)";
            warn!("{msg}");
            status(msg);
        }
    }

    pub fn get_config(&self) -> CoreConfig {
        self.config.clone()
    }

    async fn resolve_list(&self, list: &[String]) -> Vec<IpNet> {
        let mut result = Vec::new();
        if list.is_empty() {
            return result;
        }

        let dns_servers = &self.config.main.dns_server_list;
        let mut resolver_config = ResolverConfig::new();
        for dns in dns_servers {
            if let Ok(ip) = IpAddr::from_str(dns) {
                let socket = SocketAddr::new(ip, 53);
                resolver_config.add_name_server(NameServerConfig::new(socket, Protocol::Udp));
            }
        }
        if resolver_config.name_servers().is_empty() {
            resolver_config = ResolverConfig::google();
        }
        let resolver = TokioAsyncResolver::tokio(resolver_config, ResolverOpts::default());

        for target in list {
            let trimmed = target.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(net) = IpNet::from_str(trimmed) {
                result.push(net);
                continue;
            }
            if let Ok(ip) = IpAddr::from_str(trimmed) {
                result.push(IpNet::from(ip));
                continue;
            }
            let clean = trimmed.trim_start_matches('*').trim_start_matches('.');
            if clean.is_empty() {
                continue;
            }
            match resolver.lookup_ip(clean).await {
                Ok(lookup) => {
                    for ip in lookup.iter() {
                        if ip.is_ipv4() {
                            result.push(IpNet::from(ip));
                        }
                    }
                }
                Err(e) => warn!("[Core] Failed to resolve {}: {}", clean, e),
            }
        }

        let mut normalized_result: Vec<IpNet> = result
            .into_iter()
            .filter_map(|net| IpNet::new(net.network(), net.prefix_len()).ok())
            .collect();

        normalized_result.sort();
        normalized_result.dedup();

        normalized_result
    }

    pub fn is_running(&self) -> bool {
        self.is_active.load(Ordering::SeqCst) || self.session.lock().unwrap().is_some()
    }

    pub async fn start(&self) -> Result<()> {
        if self
            .is_active
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(anyhow!("VPN tunnel is already active"));
        }

        self.stop_requested.store(false, Ordering::SeqCst);

        let mut config_clone = self.config.clone();
        if let Err(e) = config_clone.sanitize() {
            self.is_active.store(false, Ordering::SeqCst);
            client_state(ClientState::Failed, format!("Config error: {}", e), None);
            return Err(e);
        }

        // Синхронизируем rules.abc сразу при старте клиента до поднятия туннеля (едино для CLI, GUI, Android, macOS, Windows, iOS)
        self.sync_rules_cache(&config_clone).await;

        info!("[Core] Starting failover connection loop...");
        warn("[Core] Starting connection loop...");
        client_state(ClientState::Connecting, "Starting connection loop", None);

        let mut current_server_index = 0;

        loop {
            if self.stop_requested.load(Ordering::SeqCst) {
                info!("[Core] Stop requested by user. Exiting connection loop.");
                break;
            }

            let reconnect_signal = Arc::new(Notify::new());

            let server = &config_clone.servers[current_server_index];

            let server_name = server.get_name();
            info!(
                "[Core] Connecting to server '{}' ({})",
                server_name, server.dsn
            );
            status(format!("Connecting to '{}'...", server_name));
            client_state(
                ClientState::Connecting,
                format!("Connecting to '{}'", server_name),
                Some(server_name.clone()),
            );

            match self.connect_and_run(server, reconnect_signal.clone()).await {
                Ok(()) => {
                    if self.stop_requested.load(Ordering::SeqCst) {
                        info!("[Core] Stop requested by user. Exiting connection loop.");
                        break;
                    }

                    warn!(
                        "[Core] Connection with server '{}' lost. Switching to the next node...",
                        server_name
                    );
                    warn("Connection lost. Reconnecting...");
                    client_state(
                        ClientState::Reconnecting,
                        "Connection lost; reconnecting",
                        Some(server_name.clone()),
                    );

                    current_server_index = (current_server_index + 1) % config_clone.servers.len();
                    select! {
                        _ = sleep(Duration::from_secs(2)) => {}
                        _ = self.cancel_signal.notified() => {
                            info!("[Core] Connection loop sleep cancelled by user.");
                            break;
                        }
                    }
                }
                Err(e) => {
                    if self.stop_requested.load(Ordering::SeqCst) {
                        info!("[Core] Stop requested by user. Exiting connection loop.");
                        break;
                    }

                    if let Some(auth_err) =
                        should_abort_on_auth_deny(&e, config_clone.servers.len())
                    {
                        error!(
                            "[Core] Authentication denied by server '{}': {}. Stopping connection loop.",
                            server_name, auth_err.message
                        );
                        err(auth_err.message.clone());
                        client_state(
                            ClientState::Failed,
                            format!("Auth error: {}", auth_err.message),
                            Some(server_name.clone()),
                        );
                        self.stop_requested.store(true, Ordering::SeqCst);
                        break;
                    }

                    error!(
                        "[Core] Connection failed or timed out for server '{}': {}",
                        server_name, e
                    );
                    err(format!("Node error: {}", e));
                    client_state(
                        ClientState::Reconnecting,
                        format!("Node error: {e}"),
                        Some(server_name.clone()),
                    );

                    current_server_index = (current_server_index + 1) % config_clone.servers.len();
                    select! {
                        _ = sleep(Duration::from_secs(2)) => {}
                        _ = self.cancel_signal.notified() => {
                            info!("[Core] Connection loop sleep cancelled by user.");
                            break;
                        }
                    }
                }
            }
        }

        self.is_active.store(false, Ordering::SeqCst);
        Ok(())
    }

    #[cfg(all(windows, feature = "per-app"))]
    async fn acquire_packet_source(
        &self,
        _server: &ServerConfig,
        auth: &anet_common::protocol::AuthResponse,
    ) -> anyhow::Result<(
        tokio::sync::mpsc::Sender<bytes::Bytes>,
        tokio::sync::mpsc::Receiver<bytes::Bytes>,
        String,
        Option<anet_appfilter::AppFilter>,
    )> {
        let (tun_tx, tun_rx, iface_name) = self.tun_factory.create_tun(auth).await?;
        let mode = self.config.main.per_app_mode;

        if mode == PerAppMode::All
            || (mode == PerAppMode::Include && self.config.main.per_app.is_empty())
        {
            info!("[Core] Per-app mode is disabled (All applications)");
            status("[Core] Per-app mode is disabled (All applications)");
            return Ok((tun_tx, tun_rx, iface_name, None));
        }

        let initial_bypass: Vec<IpAddr> = self
            .config
            .servers
            .iter()
            .filter_map(|s| s.host_port().ok())
            .filter_map(|(host, _)| IpAddr::from_str(&host).ok())
            .collect();

        let policy = match mode {
            crate::config::PerAppMode::Exclude => {
                anet_appfilter::AppPolicy::exclude(self.config.main.per_app.clone())
            }
            crate::config::PerAppMode::Include => {
                anet_appfilter::AppPolicy::include(self.config.main.per_app.clone())
            }
            crate::config::PerAppMode::All => {
                anet_appfilter::AppPolicy::exclude(Vec::<String>::new())
            }
        };

        let vpn_ip = IpAddr::from_str(&auth.ip).context("Failed to parse assigned VPN IP")?;

        let (filter, tx, rx) = anet_appfilter::AppFilter::start(policy, initial_bypass, vpn_ip)?;

        let (server_host, server_port) = _server.host_port()?;
        if let Ok(ip) = IpAddr::from_str(&server_host) {
            filter.add_bypass(ip).await;
        } else if let Ok(mut addrs) =
            tokio::net::lookup_host((server_host.as_str(), server_port)).await
        {
            if let Some(sa) = addrs.next() {
                filter.add_bypass(sa.ip()).await;
            }
        }

        let apps_names = self.config.main.per_app.join(", ");
        let mode_str = match mode {
            PerAppMode::All => "all",
            PerAppMode::Include => "include",
            PerAppMode::Exclude => "exclude",
        };

        info!(
            "[Core] Per-app mode active, apps: [{}], mode: [{}]",
            apps_names, mode_str,
        );
        status(format!(
            "[Core] Per-app mode active, apps: [{}], mode: [{}]",
            apps_names, mode_str,
        ));

        tokio::spawn(async move {
            let mut rx = tun_rx;
            while rx.recv().await.is_some() {}
        });

        Ok((tx, rx, iface_name, Some(filter)))
    }

    #[cfg(not(all(windows, feature = "per-app")))]
    async fn acquire_packet_source(
        &self,
        _server: &ServerConfig,
        auth: &AuthResponse,
    ) -> Result<(Sender<Bytes>, Receiver<Bytes>, String, Option<()>)> {
        let (tx, rx, iface) = self.tun_factory.create_tun(auth).await?;
        Ok((tx, rx, iface, None))
    }

    async fn connect_and_run(
        &self,
        server: &ServerConfig,
        reconnect_signal: Arc<Notify>,
    ) -> Result<()> {
        let mut config_clone = self.config.clone();
        config_clone.sanitize()?;

        let transport = create_transport(&config_clone, server)?;
        let conn_timeout = Duration::from_secs(server.timeout_secs.max(30));

        let connect_fut = transport.connect();
        let stop_flag = &self.stop_requested;

        let result = tokio::select! {
            res = tokio::time::timeout(conn_timeout, connect_fut) => {
                match res {
                    Ok(Ok(auth_res)) => auth_res,
                    Ok(Err(e)) => return Err(e),
                    Err(_) => return Err(anyhow::anyhow!("Connection handshake timed out")),
                }
            }
            _ = async {
                loop {
                    if stop_flag.load(Ordering::SeqCst) {
                        break;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
            } => {
                info!("[Core] Handshake cancelled by user.");
                return Ok(());
            }
        };

        if self.stop_requested.load(Ordering::SeqCst) {
            info!("[Core] Connection cancelled before configuring tunnel.");
            return Ok(());
        }

        info!("[Core] Authentication successful. Configuring tunnel interface...");
        status("[Core] Authentication successful. Configuring tunnel interface...");

        self.route_manager.backup_routes().await?;

        let (server_host, server_port) = server.host_port()?;
        let mut bypass_ips = Vec::new();
        if let Ok(server_ip) = IpAddr::from_str(&server_host) {
            bypass_ips.push(server_ip);
        } else if let Ok(resolved) = lookup_host((server_host.as_str(), server_port)).await {
            bypass_ips.extend(resolved.map(|addr| addr.ip()));
            bypass_ips.sort_unstable();
            bypass_ips.dedup();
        }
        for server_ip in bypass_ips {
            let prefix = if server_ip.is_ipv4() { 32 } else { 128 };
            self.route_manager
                .add_bypass_route(server_ip, prefix)
                .await?;
        }

        // ГАРАНТИЯ: если транспорт закрепил конкретный IP CDN (Round-Robin),
        // обязательно добавляем его в обход туннеля, чтобы избежать петли маршрутизации!
        if let Some(pinned_ip) = result.remote_ip {
            let prefix = if pinned_ip.is_ipv4() { 32 } else { 128 };
            self.route_manager
                .add_bypass_route(pinned_ip, prefix)
                .await?;
        }

        for bypass_ip in result.bypass_ips {
            let prefix = if bypass_ip.is_ipv4() { 32 } else { 128 };
            self.route_manager
                .add_bypass_route(bypass_ip, prefix)
                .await?;
        }

        // Гарантируем, что прямые DNS-резолверы для Direct-правил всегда идут в обход туннеля
        for direct_dns_ip in crate::dns_interceptor::DIRECT_UPSTREAM_DNS_IPS {
            let _ = self
                .route_manager
                .add_bypass_route(IpAddr::V4(direct_dns_ip), 32)
                .await;
        }

        // Инициализация и синхронизация движка Smart DNS, Geo-Routing и AdBlock (.abc + Local Overrides)
        // Выполняется ДО acquire_packet_source, чтобы все платформы (Linux, Windows, macOS, Android VpnService, iOS)
        // получили актуальные статические Direct-подсети в RouteManager до поднятия TUN-интерфейса.
        let local_overrides = Arc::new(anet_filter_core::LocalOverrides::from_config(
            &config_clone.routing.overrides,
        ));
        let rule_cache = self.rule_cache.clone();
        if let Some(rules_server_url) = config_clone.get_rules_server_url() {
            // Добавляем IP сервера правил в обход туннеля для фоновых ETag-обновлений
            if let Ok(uri) = rules_server_url.parse::<http::Uri>() {
                if let Some(host) = uri.host() {
                    let port = uri.port_u16().unwrap_or(if uri.scheme_str() == Some("https") {
                        443
                    } else {
                        80
                    });
                    if let Ok(ip) = IpAddr::from_str(host) {
                        let prefix = if ip.is_ipv4() { 32 } else { 128 };
                        let _ = self.route_manager.add_bypass_route(ip, prefix).await;
                    } else if let Ok(addrs) = lookup_host((host, port)).await {
                        for addr in addrs {
                            let ip = addr.ip();
                            let prefix = if ip.is_ipv4() { 32 } else { 128 };
                            let _ = self.route_manager.add_bypass_route(ip, prefix).await;
                        }
                    }
                }
            }

            if !rule_cache.is_loaded() {
                self.sync_rules_cache(&config_clone).await;
            }

            let rc_bg = rule_cache.clone();
            let url_bg = rules_server_url.clone();
            let shutdown_bg = self.cancel_signal.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = sleep(Duration::from_secs(600)) => {
                            if let Err(e) = rc_bg.update_from_server(&url_bg).await {
                                log::debug!("[RuleCache] Periodic rules.abc check failed: {e}");
                            }
                        }
                        _ = shutdown_bg.notified() => break,
                    }
                }
            });
        }

        let per_app_requested = cfg!(all(windows, feature = "per-app"))
            && config_clone.main.per_app_mode != crate::config::PerAppMode::All
            && !(config_clone.main.per_app_mode == crate::config::PerAppMode::Include
                && config_clone.main.per_app.is_empty());

        if !per_app_requested && config_clone.main.route_for.is_empty() {
            // Применяем локальные исключения [routing.overrides] direct из client.toml
            if !config_clone.routing.overrides.direct.is_empty() {
                let local_direct_routes = self
                    .resolve_list(&config_clone.routing.overrides.direct)
                    .await;
                for net in local_direct_routes.iter() {
                    let _ = self
                        .route_manager
                        .add_bypass_route(net.network(), net.prefix_len())
                        .await;
                }
            }

            // Применяем статические CIDR-маршруты Direct из скомпилированного rules.abc
            let abc_direct_routes = rule_cache.collect_direct_routes();
            if !abc_direct_routes.is_empty() {
                let mut applied = 0usize;
                for (ip, prefix) in abc_direct_routes {
                    if self.route_manager.add_bypass_route(ip, prefix).await.is_ok() {
                        applied += 1;
                    }
                }
                let msg = format!(
                    "[RuleCache] Applied {} static Direct CIDR bypass routes from rules.abc",
                    applied
                );
                info!("{msg}");
                status(&msg);
            }
        }

        let (tx_to_tun, mut rx_from_tun, iface_name, _app_filter) = self
            .acquire_packet_source(server, &result.auth_response)
            .await?;

        let direct_ip_cache = crate::direct_ip_cache::DirectIpCache::new();
        let dns_interceptor = crate::dns_interceptor::DnsInterceptor::new(
            local_overrides.clone(),
            direct_ip_cache.clone(),
        );

        let session_start = Instant::now();
        let disconnect_reason = Arc::new(Mutex::new("Normal session termination".to_string()));

        let last_rx_time = Arc::new(Mutex::new(Instant::now()));
        let last_tx_time = Arc::new(Mutex::new(Instant::now()));

        let total_rx_bytes = Arc::new(AtomicU64::new(0));
        let total_tx_bytes = Arc::new(AtomicU64::new(0));
        let total_rx_packets = Arc::new(AtomicU64::new(0));
        let total_tx_packets = Arc::new(AtomicU64::new(0));

        let shutdown_notify = Arc::new(Notify::new());
        let notify_tx = shutdown_notify.clone();
        let notify_rx = shutdown_notify.clone();

        let client_ip_opt: Option<std::net::Ipv4Addr> = result.auth_response.ip.parse().ok();
        let gateway_ip_opt: Option<std::net::Ipv4Addr> = result.auth_response.gateway.parse().ok();

        let last_rtt_us = Arc::new(AtomicU64::new(u64::MAX));
        let last_reply_us = Arc::new(AtomicU64::new(0));
        let (tx_probe, mut rx_probe) = tokio::sync::mpsc::channel::<Bytes>(64);

        // Внутритуннельный генератор ICMP Echo Request для универсального измерения честного RTT.
        // Работает для ВСЕХ видов транспорта (QUIC, SSH, VNC, AHTTP, WS, WRTC) прямо внутри шифрованного потока.
        // Не требует raw-сокетов и повышенных прав ОС (полная совместимость с Linux, Windows, macOS, Android, iOS).
        if let (Some(client_ip), Some(gateway_ip)) = (client_ip_opt, gateway_ip_opt) {
            let tx_probe_c = tx_probe.clone();
            let probe_shutdown = shutdown_notify.clone();
            let probe_start_time = session_start;

            tokio::spawn(async move {
                let mut seq: u16 = 0;
                // Небольшая задержка перед первым зондом для завершения инициализации туннеля
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(150)) => {}
                    _ = probe_shutdown.notified() => return,
                }

                loop {
                    seq = seq.wrapping_add(1);
                    let now_us = probe_start_time.elapsed().as_micros() as u64;
                    let probe_packet = build_ipv4_icmp_echo_request(
                        client_ip,
                        gateway_ip,
                        PROBE_IDENTIFIER,
                        seq,
                        now_us,
                    );

                    if tx_probe_c.send(probe_packet).await.is_err() {
                        break;
                    }

                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                        _ = probe_shutdown.notified() => break,
                    }
                }
            });
        }

        let (mut stream_reader, mut stream_writer) = io_split(result.vpn_stream);

        let tx_time = last_tx_time.clone();
        let tx_bytes = total_tx_bytes.clone();
        let tx_packets = total_tx_packets.clone();
        let sig_t1 = reconnect_signal.clone();
        let reason_t1 = disconnect_reason.clone();
        let tx_to_tun_dns = tx_to_tun.clone();
        let tx_probe_dns = tx_probe.clone();
        let route_manager_dns = self.route_manager.clone();
        let dns_servers_list = config_clone.main.dns_server_list.clone();
        let dns_interceptor_tx = dns_interceptor.clone();
        let rule_cache_tx = rule_cache.clone();
        let local_overrides_tx = local_overrides.clone();
        let direct_ip_cache_tx = direct_ip_cache.clone();

        let t1 = spawn(async move {
            let mut write_buf = BytesMut::with_capacity(COALESCE_BUDGET_BYTES);

            // Возвращает true, если пакет должен идти в VPN-туннель, или false, если он перехвачен/отброшен
            let should_forward_to_tunnel = |pkt: &Bytes| -> bool {
                // Блокируем оппортунистический DoH/DoT к публичным резолверам, чтобы браузеры использовали UDP:53
                if crate::dns_interceptor::is_encrypted_dns_packet(pkt) {
                    return false;
                }

                match dns_interceptor_tx.handle_packet(pkt, |domain| rule_cache_tx.lookup_domain(domain)) {
                    crate::dns_interceptor::InterceptResult::Handled(synth_reply) => {
                        let _ = tx_to_tun_dns.try_send(synth_reply);
                        return false;
                    }
                    crate::dns_interceptor::InterceptResult::Drop => {
                        return false;
                    }
                    crate::dns_interceptor::InterceptResult::DirectQuery => {
                        let interceptor_c = dns_interceptor_tx.clone();
                        let pkt_c = pkt.clone();
                        let dns_c = dns_servers_list.clone();
                        let tun_tx_c = tx_to_tun_dns.clone();
                        let probe_tx_c = tx_probe_dns.clone();
                        let rm_c = route_manager_dns.clone();
                        tokio::spawn(async move {
                            if let Some((reply_pkt, resolved_ips)) =
                                interceptor_c.resolve_direct_dns_packet(&pkt_c, &dns_c).await
                            {
                                if !resolved_ips.is_empty() {
                                    let routes: Vec<(IpAddr, u8)> = resolved_ips
                                        .iter()
                                        .map(|ip| (*ip, if ip.is_ipv4() { 32 } else { 128 }))
                                        .collect();
                                    let _ = rm_c.add_bypass_routes(&routes).await;
                                    log::info!(
                                        "[DNS/Direct] Added OS bypass routes for {:?}",
                                        resolved_ips
                                    );
                                }
                                let _ = tun_tx_c.send(reply_pkt).await;
                            } else {
                                // Fallback: если прямой UDP:53 заблокирован провайдером, отправляем запрос в туннель
                                // (ответ будет перехвачен в t2 и IP-адреса также получат bypass-маршруты до отдачи браузеру)
                                let _ = probe_tx_c.send(pkt_c).await;
                            }
                        });
                        return false;
                    }
                    crate::dns_interceptor::InterceptResult::PassThrough => {}
                }

                if let Some(dst_ip) = crate::dns_interceptor::extract_packet_dst_ip(pkt) {
                    let ip_action = local_overrides_tx
                        .lookup_ip(dst_ip)
                        .or_else(|| direct_ip_cache_tx.check(&dst_ip))
                        .or_else(|| rule_cache_tx.lookup_ip(dst_ip));

                    if matches!(
                        ip_action,
                        Some(
                            anet_filter_core::RuleAction::Block
                                | anet_filter_core::RuleAction::Direct
                        )
                    ) {
                        return false;
                    }
                }

                true
            };

            loop {
                let (packet, is_probe) = tokio::select! {
                    biased;
                    probe_pkt = rx_probe.recv() => {
                        match probe_pkt {
                            Some(p) => (p, true),
                            None => {
                                match rx_from_tun.recv().await {
                                    Some(p) => (p, false),
                                    None => break,
                                }
                            }
                        }
                    }
                    pkt = rx_from_tun.recv() => {
                        match pkt {
                            Some(p) => (p, false),
                            None => {
                                info!("[Tunnel/Tx] Local TUN packet channel closed (adapter or worker stopped).");
                                *reason_t1.lock().unwrap() = "Local TUN packet channel closed (adapter or worker stopped)".to_string();
                                sig_t1.notify_one();
                                break;
                            }
                        }
                    }
                    _ = notify_tx.notified() => {
                        info!("[Tunnel/Tx] Worker received shutdown notification.");
                        break;
                    }
                };

                write_buf.clear();
                if is_probe || should_forward_to_tunnel(&packet) {
                    *tx_time.lock().unwrap() = Instant::now();
                    let len = packet.len() as u64;
                    tx_bytes.fetch_add(len, Ordering::Relaxed);
                    tx_packets.fetch_add(1, Ordering::Relaxed);
                    frame_packet_into(&mut write_buf, &packet);
                }

                while write_buf.len() < COALESCE_BUDGET_BYTES {
                    match rx_from_tun.try_recv() {
                        Ok(p) => {
                            if should_forward_to_tunnel(&p) {
                                let len = p.len() as u64;
                                tx_bytes.fetch_add(len, Ordering::Relaxed);
                                tx_packets.fetch_add(1, Ordering::Relaxed);
                                frame_packet_into(&mut write_buf, &p);
                            }
                        }
                        Err(_) => {
                            if let Ok(p) = rx_probe.try_recv() {
                                let len = p.len() as u64;
                                tx_bytes.fetch_add(len, Ordering::Relaxed);
                                tx_packets.fetch_add(1, Ordering::Relaxed);
                                frame_packet_into(&mut write_buf, &p);
                            }
                            break;
                        }
                    }
                }

                if write_buf.is_empty() {
                    continue;
                }

                // ВНИМАНИЕ: ЗДЕСЬ УДАЛЁН flush().await, ИНАЧЕ QUIC И SSH РАБОТАЮТ КАК STOP-AND-WAIT
                if let Err(e) = stream_writer.write_all(&write_buf).await {
                    warn!("[Tunnel/Tx] Failed to write {} bytes to VPN stream: {e:#}", write_buf.len());
                    *reason_t1.lock().unwrap() = format!("Failed to write {} bytes to VPN stream: {e:#}", write_buf.len());
                    sig_t1.notify_one();
                    break;
                }
            }
        });

        let rx_time = last_rx_time.clone();
        let rx_bytes = total_rx_bytes.clone();
        let rx_packets = total_rx_packets.clone();
        let sig_t2 = reconnect_signal.clone();
        let reason_t2 = disconnect_reason.clone();
        let last_rtt_rx = last_rtt_us.clone();
        let last_reply_rx = last_reply_us.clone();
        let probe_start_rx = session_start;
        let dns_interceptor_rx = dns_interceptor.clone();
        let rule_cache_rx = rule_cache.clone();
        let route_manager_rx = self.route_manager.clone();
        let t2 = spawn(async move {
            loop {
                select! {
                    res = read_next_packet(&mut stream_reader) => {
                        match res {
                            Ok(Some(packet)) => {
                                *rx_time.lock().unwrap() = Instant::now();
                                let len = packet.len() as u64;
                                rx_bytes.fetch_add(len, Ordering::Relaxed);
                                rx_packets.fetch_add(1, Ordering::Relaxed);

                                // Перехватываем внутритуннельный ICMP Echo Reply (замер честного RTT)
                                if let Some(c_ip) = client_ip_opt {
                                    if let Some((_seq, sent_ts_us)) = parse_ipv4_icmp_echo_reply(
                                        &packet,
                                        c_ip,
                                        PROBE_IDENTIFIER,
                                    ) {
                                        let now_us = probe_start_rx.elapsed().as_micros() as u64;
                                        let sample_us = now_us.saturating_sub(sent_ts_us);

                                        // Экспоненциальное сглаживание EWMA (alpha = 0.25):
                                        // smoothed_rtt = 0.75 * smoothed_rtt + 0.25 * sample
                                        let prev_us = last_rtt_rx.load(Ordering::Relaxed);
                                        let smoothed_us = if prev_us == u64::MAX {
                                            sample_us
                                        } else {
                                            ((prev_us * 3) + sample_us) / 4
                                        };

                                        last_rtt_rx.store(smoothed_us.max(100), Ordering::Relaxed);
                                        last_reply_rx.store(now_us, Ordering::Relaxed);
                                        log::debug!(
                                            "[Probe/RTT] In-tunnel RTT: {:.2} ms (sample: {:.2} ms, seq: {})",
                                            smoothed_us as f64 / 1000.0,
                                            sample_us as f64 / 1000.0,
                                            _seq
                                        );
                                        continue; // Поглощаем ответ зонда, не отдаем в локальный TUN интерфейс ОС
                                    }
                                }

                                // Если из туннеля пришел DNS-ответ для Direct-домена, регистрируем bypass-маршруты ДО передачи пакета в ОС
                                if let Some((qname, resolved_ips)) = dns_interceptor_rx
                                    .inspect_dns_response(&packet, |domain| rule_cache_rx.lookup_domain(domain))
                                {
                                    if !resolved_ips.is_empty() {
                                        let routes: Vec<(IpAddr, u8)> = resolved_ips
                                            .iter()
                                            .map(|ip| (*ip, if ip.is_ipv4() { 32 } else { 128 }))
                                            .collect();
                                        let _ = route_manager_rx.add_bypass_routes(&routes).await;
                                        log::info!(
                                            "[DNS/Direct] Domain '{}' resolved via tunnel -> added OS bypass routes for {:?}",
                                            qname,
                                            resolved_ips
                                        );
                                    }
                                }

                                if tx_to_tun.send(packet).await.is_err() {
                                    warn!("[Tunnel/Rx] Failed to send packet to TUN channel (channel closed or dropped).");
                                    *reason_t2.lock().unwrap() = "Failed to send packet to TUN channel (channel closed or dropped)".to_string();
                                    sig_t2.notify_one();
                                    break;
                                }
                            }
                            Ok(None) => {
                                info!("[Tunnel/Rx] VPN stream reached EOF (server or remote transport closed stream).");
                                *reason_t2.lock().unwrap() = "VPN stream reached EOF (server or remote transport closed stream)".to_string();
                                sig_t2.notify_one();
                                break;
                            }
                            Err(e) => {
                                warn!("[Tunnel/Rx] Failed reading frame/packet from VPN stream: {e:#}");
                                *reason_t2.lock().unwrap() = format!("Failed reading frame/packet from VPN stream: {e:#}");
                                sig_t2.notify_one();
                                break;
                            }
                        }
                    }
                    _ = notify_rx.notified() => {
                        info!("[Tunnel/Rx] Worker received shutdown notification.");
                        break;
                    }
                }
            }
        });

        let per_app_active = _app_filter.is_some();

        if !per_app_active {
            if !config_clone.main.route_for.is_empty() {
                let include_routes = self.resolve_list(&config_clone.main.route_for).await;
                for net in include_routes.iter() {
                    self.route_manager
                        .add_specific_route(
                            net.network(),
                            net.prefix_len(),
                            &result.auth_response.gateway,
                            &iface_name,
                        )
                        .await?;
                }
            } else {
                if !config_clone.main.exclude_route_for.is_empty() {
                    let exclude_routes = self
                        .resolve_list(&config_clone.main.exclude_route_for)
                        .await;
                    for net in exclude_routes.iter() {
                        self.route_manager
                            .add_bypass_route(net.network(), net.prefix_len())
                            .await?;
                    }
                }

                self.route_manager
                    .set_default_route(&result.auth_response.gateway, &iface_name)
                    .await?;
            }

            if !config_clone.main.dns_server_list.is_empty() {
                let dns_ips: Vec<IpAddr> = config_clone
                    .main
                    .dns_server_list
                    .iter()
                    .filter_map(|s| IpAddr::from_str(s).ok())
                    .collect();
                let dns_ipv4: Vec<std::net::Ipv4Addr> = dns_ips
                    .iter()
                    .filter_map(|ip| match ip {
                        IpAddr::V4(addr) => Some(*addr),
                        _ => None,
                    })
                    .collect();

                if !dns_ipv4.is_empty() {
                    let _ = self.dns_manager.set_dns(&iface_name, &dns_ipv4);
                }
            }
        }

        let monitor_shutdown = shutdown_notify.clone();
        let monitor_reconnect = reconnect_signal.clone();
        let rx_check = last_rx_time.clone();
        let tx_check = last_tx_time.clone();
        let quic_conn = result.connection.clone();
        let reason_health = disconnect_reason.clone();

        let health_pause = result.health_pause.clone();
        let health_task = tokio::spawn(async move {
            let check_interval = Duration::from_secs(3);

            loop {
                tokio::select! {
                    _ = sleep(check_interval) => {}
                    _ = monitor_shutdown.notified() => {
                        break;
                    }
                }

                if health_pause.as_ref().is_some_and(|pause| pause.load(Ordering::Acquire)) {
                    *rx_check.lock().unwrap() = Instant::now();
                    *tx_check.lock().unwrap() = Instant::now();
                    continue;
                }

                if let Some(ref conn) = quic_conn {
                    if let Some(reason) = conn.close_reason() {
                        let stats = conn.stats();
                        warn!(
                            "[Health] Underlying QUIC connection closed: {:?}. Stats: RTT={:?}, Lost(Tx)={}, UDP Tx={}/Rx={} datagrams, Cwnd={} B. Triggering reconnect...",
                            reason, stats.path.rtt, stats.path.lost_packets, stats.udp_tx.datagrams, stats.udp_rx.datagrams, stats.path.cwnd
                        );
                        *reason_health.lock().unwrap() = format!("Underlying QUIC connection closed: {reason:?}");
                        client_state(ClientState::Reconnecting, format!("Connection closed: {reason:?}"), None);
                        monitor_reconnect.notify_one();
                        break;
                    }
                }
            }
        });

        let stats_shutdown = shutdown_notify.clone();
        let stats_task = {
            let provider: Arc<dyn statistic::StatsProvider> =
                if let Some(ref conn) = result.connection {
                    Arc::new(statistic::QuicStatsProvider::new(conn.clone()))
                } else {
                    Arc::new(statistic::StreamStatsProvider::new(
                        total_rx_bytes.clone(),
                        total_tx_bytes.clone(),
                        total_rx_packets.clone(),
                        total_tx_packets.clone(),
                    ))
                };

            // Оборачиваем provider в PingStatsProvider с общим атомиком задержки.
            // Для QUIC: если Quinn нативно возвращает RTT, он используется в первую очередь.
            // Для всех остальных транспортов (SSH/VNC/AHTTP/WS/WRTC): честный сквозной RTT
            // берется из внутритуннельного замера ICMP Echo Reply от ядра сервера.
            let full_provider: Arc<dyn statistic::StatsProvider> =
                statistic::PingStatsProvider::new_with_atomic(
                    provider.clone(),
                    last_rtt_us.clone(),
                    last_reply_us.clone(),
                    session_start,
                );

            let fast_handle =
                statistic::start_fast_stats_monitor(full_provider.clone(), stats_shutdown.clone());

            let slow_handle = if config_clone.stats.enabled {
                Some(statistic::start_stats_monitor(
                    full_provider,
                    config_clone.stats.interval_minutes,
                    stats_shutdown,
                ))
            } else {
                None
            };

            Some(spawn(async move {
                if let Some(slow) = slow_handle {
                    let _ = tokio::join!(fast_handle, slow);
                } else {
                    let _ = fast_handle.await;
                }
            }))
        };

        if self.stop_requested.load(Ordering::SeqCst) {
            info!("[Core] Connection cancelled before storing session.");
            status("[Core] Connection cancelled before storing session.");
            if let Some(hook) = result.shutdown_hook {
                let _ = tokio::time::timeout(Duration::from_millis(500), hook).await;
            }
            let _ = self.dns_manager.restore_dns(&iface_name);
            let _ = self.route_manager.restore_routes().await;
            return Ok(());
        }

        {
            let mut state = self.session.lock().unwrap();
            *state = Some(RunningSession {
                endpoint: result.endpoint,
                shutdown_notify: shutdown_notify.clone(),
                reconnect_signal: reconnect_signal.clone(),
                disconnect_reason: disconnect_reason.clone(),
                main_task: tokio::spawn(async move {
                    let _ = tokio::join!(t1, t2);
                }),
                stats_task,
                iface_name: iface_name.clone(),
                shutdown_hook: result.shutdown_hook,
            });
        }

        let billing_str =
            match ProtoBillingType::try_from(result.auth_response.billing_type).unwrap() {
                ProtoBillingType::NoTariffNoGroup => "Без тарифа и группы",
                ProtoBillingType::Group => "Группа",
                ProtoBillingType::Individual => "Индивидуальный тариф",
                ProtoBillingType::GroupAndIndividual => "Группа + индивидуальный тариф",
                _ => "Не указан",
            };

        let group_str = result.auth_response.group_name.as_deref().unwrap_or("—");

        let consumed_str = result
            .auth_response
            .traffic_consumed
            .map(|c| format_bytes(c.max(0) as u64))
            .unwrap_or_else(|| "0 B".to_string());

        let limit_str = result
            .auth_response
            .traffic_limit
            .map(|l| format_bytes(l.max(0) as u64))
            .unwrap_or_else(|| "Безлимит".to_string());

        let speed_str = match result.auth_response.speed_limit_kbps {
            Some(kbps) if kbps > 0 => {
                if kbps >= 1024 {
                    format!("{:.2} Мбит/с", kbps as f64 / 1024.0)
                } else {
                    format!("{} Кбит/с", kbps)
                }
            }
            _ => "Безлимит".to_string(),
        };

        let expires_str = result
            .auth_response
            .expires_at
            .as_deref()
            .unwrap_or("Бессрочно");

        let sessions_str = if result.auth_response.allowed_sessions > 0 {
            format!(
                "{} / {}",
                result.auth_response.active_sessions, result.auth_response.allowed_sessions
            )
        } else {
            format!("{} / Безлимит", result.auth_response.active_sessions)
        };

        let format_tariff_row = |label: &str, val: &str| -> String {
            let left_part = format!("  {:<18}", label);
            let prefix_len = left_part.chars().count();
            let total_content_width: usize = 71;
            let val_space = total_content_width.saturating_sub(prefix_len);
            let val_chars = val.chars().count();
            if val_chars > val_space {
                let truncated: String = val.chars().take(val_space.saturating_sub(3)).collect();
                format!("             ║{}{:<width$}║", left_part, format!("{}...", truncated), width = val_space)
            } else {
                let pad = val_space - val_chars;
                format!("             ║{}{}{}║", left_part, val, " ".repeat(pad))
            }
        };

        info!(
            "\n            ╔═══════════════════════════════════════════════════════════════════════╗\n             ║                         ACCOUNT & TARIFF INFO                         ║\n             ╠═══════════════════════════════════════════════════════════════════════╣\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n             ╚═══════════════════════════════════════════════════════════════════════╝",
            format_tariff_row("Тарификация:", billing_str),
            format_tariff_row("Группа:", group_str),
            format_tariff_row("Сессии:", &sessions_str),
            format_tariff_row("Скорость:", &speed_str),
            format_tariff_row("Трафик за период:", &consumed_str),
            format_tariff_row("Лимит трафика:", &limit_str),
            format_tariff_row("Действует до:", expires_str),
        );

        status(format!(
            "Тариф: {} | Группа: {} | Трафик: {} / {}",
            billing_str, group_str, consumed_str, limit_str
        ));

        account_info(AccountInfo {
            billing_str: billing_str.to_string(),
            group_str: group_str.to_string(),
            sessions_str: sessions_str.clone(),
            speed_str: speed_str.clone(),
            consumed_str: consumed_str.clone(),
            limit_str: limit_str.clone(),
            expires_str: expires_str.to_string(),
            active_sessions: result.auth_response.active_sessions,
            allowed_sessions: result.auth_response.allowed_sessions,
            speed_limit_kbps: result.auth_response.speed_limit_kbps.map(|k| k as u64),
            traffic_consumed_bytes: result.auth_response.traffic_consumed.map(|c| c.max(0) as u64),
            traffic_limit_bytes: result.auth_response.traffic_limit.map(|l| l.max(0) as u64),
            expires_at: result.auth_response.expires_at.clone(),
        });

        let active_node_name = match result.effective_mode.as_deref() {
            Some(mode) => format!("{} ({})", server.get_name(), mode),
            None => server.get_name(),
        };

        info!(
            "[Core] VPN interface configured. Tunnel UP. Active node: {}",
            active_node_name
        );
        status(format!(
            "[Core] VPN interface configured. Tunnel UP. Active node: {}",
            active_node_name
        ));
        status(format!("Connected. Local IP: {}", result.auth_response.ip));
        status("VPN Tunnel UP");
        client_state(
            ClientState::Connected,
            format!("Connected. Local IP: {}", result.auth_response.ip),
            Some(active_node_name.clone()),
        );

        reconnect_signal.notified().await;

        let duration = session_start.elapsed();
        let last_rx = last_rx_time.lock().unwrap().elapsed();
        let last_tx = last_tx_time.lock().unwrap().elapsed();
        let rx_b = total_rx_bytes.load(Ordering::Relaxed);
        let rx_p = total_rx_packets.load(Ordering::Relaxed);
        let tx_b = total_tx_bytes.load(Ordering::Relaxed);
        let tx_p = total_tx_packets.load(Ordering::Relaxed);
        let final_reason = disconnect_reason.lock().unwrap().clone();

        warn!(
            "[Core] ==================== SESSION DISCONNECT REPORT ====================\n\
             [Core] Active Server: '{}' ({})\n\
             [Core] Assigned IP: {}\n\
             [Core] Session Duration: {:.1}s ({:.2} min)\n\
             [Core] Disconnect Trigger: {}\n\
             [Core] Traffic Statistics:\n\
             [Core]   -> Tx (Uploaded):   {} in {} packets (last packet sent {:.3}s ago)\n\
             [Core]   <- Rx (Downloaded): {} in {} packets (last packet received {:.3}s ago)\n\
             [Core] ===================================================================",
            active_node_name,
            server.endpoint().unwrap_or_default(),
            result.auth_response.ip,
            duration.as_secs_f64(),
            duration.as_secs_f64() / 60.0,
            final_reason,
            format_bytes(tx_b),
            tx_p,
            last_tx.as_secs_f64(),
            format_bytes(rx_b),
            rx_p,
            last_rx.as_secs_f64(),
        );

        info!("[Core] Cleaning up dead session...");
        status("[Core] Cleaning up dead session...");
        shutdown_notify.notify_waiters();
        health_task.abort();

        let session_to_clean = {
            let mut state = self.session.lock().unwrap();
            state.take()
        };
        if let Some(sess) = session_to_clean {
            if let Some(hook) = sess.shutdown_hook {
                let _ = tokio::time::timeout(Duration::from_millis(500), hook).await;
            }
            if let Some(ref endpoint) = sess.endpoint {
                endpoint.close(0u32.into(), b"reconnecting");
            }
            if let Some(task) = sess.stats_task {
                task.abort();
            }
            sess.shutdown_notify.notify_waiters();
            if tokio::time::timeout(Duration::from_secs(2), sess.main_task).await.is_err() {
                warn!("[Core] Main task did not finish in 2s during cleanup, proceeding");
            }
        }

        let _ = self.dns_manager.restore_dns(&iface_name);
        let _ = self.route_manager.restore_routes().await;

        Ok(())
    }

    pub fn trigger_reconnect(&self) {
        if self.stop_requested.load(Ordering::SeqCst) {
            return;
        }
        let state = self.session.lock().unwrap();
        if let Some(ref running) = *state {
            info!("[Core] Reconnect requested externally (network switch or watchdog).");
            *running.disconnect_reason.lock().unwrap() = "External reconnect request (network switch or watchdog)".to_string();
            running.shutdown_notify.notify_waiters();
            running.reconnect_signal.notify_one();
        }
    }

    pub async fn stop(&self) -> anyhow::Result<()> {
        self.stop_requested.store(true, Ordering::SeqCst);
        self.cancel_signal.notify_waiters();

        let session = {
            let mut state = self.session.lock().unwrap();
            state.take()
        };

        if let Some(running) = session {
            info!("[Core] Stopping VPN...");
            status("[Core] Stopping VPN...");
            client_state(ClientState::Stopping, "Stopping VPN", None);
            *running.disconnect_reason.lock().unwrap() = "User requested stop".to_string();
            running.shutdown_notify.notify_waiters();
            running.reconnect_signal.notify_one();

            if let Some(hook) = running.shutdown_hook {
                let _ = tokio::time::timeout(Duration::from_millis(500), hook).await;
            }

            if let Some(task) = running.stats_task {
                task.abort();
            }

            if tokio::time::timeout(Duration::from_millis(500), running.main_task).await.is_err() {
                warn!("[Core] Main task did not exit in 500ms, proceeding with teardown");
            }

            if let Some(endpoint) = running.endpoint {
                endpoint.close(0u32.into(), b"Disconnected by user");
            }

            let _ = self.dns_manager.restore_dns(&running.iface_name);
            let _ = self.route_manager.restore_routes().await;
            info!("[Core] VPN Stopped.");
            status("[Core] VPN Stopped.");
            client_state(ClientState::Stopped, "VPN stopped", None);
        } else {
            info!("[Core] VPN Stopped (no active session).");
            status("[Core] VPN Stopped.");
            client_state(ClientState::Stopped, "VPN stopped", None);
        }
        Ok(())
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

    let b = bytes as f64;
    if b < KIB {
        format!("{} B", bytes)
    } else if b < MIB {
        format!("{:.2} KiB", b / KIB)
    } else if b < GIB {
        format!("{:.2} MiB", b / MIB)
    } else {
        format!("{:.2} GiB", b / GIB)
    }
}

fn should_abort_on_auth_deny(err: &anyhow::Error, server_count: usize) -> Option<&AuthDenyError> {
    let auth_err = err.downcast_ref::<AuthDenyError>()?;
    if !auth_err.is_node_transient() || server_count <= 1 {
        Some(auth_err)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anet_common::consts::NONCE_LEN;
    use anet_common::crypto_utils;
    use anet_common::protocol::{
        AuthDenyNotification, Message as AnetMessage, message::Content,
    };
    use async_trait::async_trait;
    use base64::prelude::*;
    use ed25519_dalek::SigningKey;
    use prost::Message;
    use std::sync::atomic::AtomicUsize;
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;

    struct DummyRouteManager;

    #[async_trait]
    impl RouteManager for DummyRouteManager {
        async fn backup_routes(&self) -> Result<()> {
            Ok(())
        }
        async fn add_bypass_route(&self, _target: IpAddr, _prefix: u8) -> Result<()> {
            Ok(())
        }
        async fn set_default_route(&self, _gateway: &str, _interface_name: &str) -> Result<()> {
            Ok(())
        }
        async fn add_specific_route(
            &self,
            _target: IpAddr,
            _prefix: u8,
            _gateway: &str,
            _interface_name: &str,
        ) -> Result<()> {
            Ok(())
        }
        async fn restore_routes(&self) -> Result<()> {
            Ok(())
        }
    }

    struct DummyTunFactory;

    #[async_trait]
    impl TunFactory for DummyTunFactory {
        async fn create_tun(
            &self,
            _auth: &AuthResponse,
        ) -> Result<(mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>, String)> {
            let (tx, rx) = mpsc::channel(8);
            Ok((tx, rx, "tun0".to_string()))
        }
    }

    #[test]
    fn test_should_abort_on_auth_deny_account_errors() {
        let limit_err: anyhow::Error =
            AuthDenyError::new("Достигнут лимит одновременных подключений").into();
        assert!(should_abort_on_auth_deny(&limit_err, 1).is_some());
        assert!(should_abort_on_auth_deny(&limit_err, 5).is_some());

        let banned_err: anyhow::Error =
            AuthDenyError::new("Учетная запись заблокирована").into();
        assert!(should_abort_on_auth_deny(&banned_err, 3).is_some());
    }

    #[test]
    fn test_should_abort_on_auth_deny_node_transient_errors() {
        let drain_err: anyhow::Error =
            AuthDenyError::new("Node is not accepting new connections").into();
        // Если нода всего одна — останавливаемся, чтобы не крутиться в бесконечном цикле
        assert!(should_abort_on_auth_deny(&drain_err, 1).is_some());
        // Если нод несколько — разрешаем failover на следующую ноду
        assert!(should_abort_on_auth_deny(&drain_err, 2).is_none());

        let auth_down_err: anyhow::Error =
            AuthDenyError::new("Все сервера авторизации недоступны").into();
        assert!(should_abort_on_auth_deny(&auth_down_err, 1).is_some());
        assert!(should_abort_on_auth_deny(&auth_down_err, 3).is_none());
    }

    #[test]
    fn test_should_abort_on_auth_deny_ignores_network_errors() {
        let net_err = anyhow::anyhow!("Connection handshake timed out");
        assert!(should_abort_on_auth_deny(&net_err, 1).is_none());
        assert!(should_abort_on_auth_deny(&net_err, 3).is_none());
    }

    #[tokio::test]
    async fn test_client_start_exits_loop_immediately_on_auth_error() {
        let client_signing = SigningKey::from_bytes(&[33u8; 32]);
        let server_signing = SigningKey::from_bytes(&[44u8; 32]);
        let server_pub_bytes = server_signing.verifying_key().to_bytes().to_vec();

        // Поднимаем локальный UDP-сокет, имитирующий QUIC-сервер, который отвечает AuthError
        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let packets_received = Arc::new(AtomicUsize::new(0));
        let packets_received_clone = packets_received.clone();
        let server_pub_clone = server_pub_bytes.clone();

        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            if let Ok((_len, peer_addr)) = server_sock.recv_from(&mut buf).await {
                packets_received_clone.fetch_add(1, Ordering::SeqCst);
                let deny_msg = AnetMessage {
                    content: Some(Content::AuthError(AuthDenyNotification {
                        message: "Достигнут лимит одновременных подключений".to_string(),
                    })),
                    padding: vec![],
                };
                let mut raw = Vec::new();
                deny_msg.encode(&mut raw).unwrap();
                let cipher = crypto_utils::create_handshake_cipher(&server_pub_clone);
                let nonce = [9u8; NONCE_LEN];
                let ct = cipher.encrypt(&nonce, Bytes::from(raw)).unwrap();
                let mut pkt = BytesMut::with_capacity(NONCE_LEN + ct.len());
                pkt.extend_from_slice(&nonce);
                pkt.extend_from_slice(&ct);
                let _ = server_sock.send_to(&pkt, peer_addr).await;
            }
        });

        let mut cfg = CoreConfig::default();
        cfg.keys.private_key = BASE64_STANDARD.encode(client_signing.to_bytes());
        cfg.keys.server_pub_key = BASE64_STANDARD.encode(&server_pub_bytes);
        cfg.servers = vec![
            ServerConfig {
                dsn: format!("quic://{}?name=Node1&timeout=5", server_addr),
                ..Default::default()
            },
            ServerConfig {
                dsn: format!("quic://{}?name=Node2&timeout=5", server_addr),
                ..Default::default()
            },
        ];

        let client = AnetClient::new(
            cfg,
            Box::new(DummyTunFactory),
            Box::new(DummyRouteManager),
        );

        // Запускаем start() с жестким таймаутом 1.5с (если бы сработал sleep(2s) реконнекта или ретраи — тест бы упал по таймауту)
        let res = tokio::time::timeout(Duration::from_millis(1500), client.start())
            .await
            .expect("client.start() must not enter reconnect sleep on fatal AuthError");
        assert!(res.is_ok());
        assert!(!client.is_running());
        assert_eq!(packets_received.load(Ordering::SeqCst), 1);

        let _ = server_task.await;
    }
}

