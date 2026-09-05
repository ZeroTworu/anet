use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
#[cfg(all(windows, feature = "per-app"))]
use anyhow::Context;
use bytes::{Bytes, BytesMut};
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use ipnet::IpNet;
use log::{error, info, warn};
use quinn::Endpoint;
use tokio::io::{split as io_split, AsyncWriteExt};
use tokio::net::lookup_host;
use tokio::select;
use tokio::spawn;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::sleep;

#[cfg(all(windows, feature = "per-app"))]
use anet_appfilter::{AppFilter, AppPolicy};
use anet_common::consts::COALESCE_BUDGET_BYTES;
use anet_common::protocol::{AuthResponse, BillingType as ProtoBillingType};
use anet_common::stream_framing::{frame_packet_into, read_next_packet};

use crate::config::{CoreConfig, PerAppMode, ServerConfig};
use crate::dns::{get_dns_manager, DnsManager};
use crate::events::{client_state, status, warn, ClientState};
use crate::statistic::{
    start_stats_monitor, QuicStatsProvider, StatsProvider, StreamStatsProvider,
};
use crate::traits::{RouteManager, TunFactory};
use crate::transport::factory::create_transport;

struct RunningSession {
    endpoint: Option<Endpoint>,
    shutdown_notify: Arc<Notify>,
    reconnect_signal: Arc<Notify>,
    main_task: JoinHandle<()>,
    stats_task: Option<JoinHandle<()>>,
    iface_name: String,
}

pub struct AnetClient {
    config: CoreConfig,
    tun_factory: Box<dyn TunFactory>,
    route_manager: Box<dyn RouteManager>,
    dns_manager: Box<dyn DnsManager>,
    session: Mutex<Option<RunningSession>>,
    stop_requested: AtomicBool,
}

impl AnetClient {
    pub fn new(
        config: CoreConfig,
        tun_factory: Box<dyn TunFactory>,
        route_manager: Box<dyn RouteManager>,
    ) -> Self {
        let dns_manager = get_dns_manager();
        Self {
            config,
            tun_factory,
            route_manager,
            dns_manager,
            session: Mutex::new(None),
            stop_requested: AtomicBool::new(false),
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
            if let Ok(net) = IpNet::from_str(target) {
                result.push(net);
                continue;
            }
            if let Ok(ip) = IpAddr::from_str(target) {
                result.push(IpNet::from(ip));
                continue;
            }
            match resolver.lookup_ip(target).await {
                Ok(lookup) => {
                    for ip in lookup.iter() {
                        if ip.is_ipv4() {
                            result.push(IpNet::from(ip));
                        }
                    }
                }
                Err(e) => warn!("[Core] Failed to resolve {}: {}", target, e),
            }
        }
        result
    }

    pub fn is_running(&self) -> bool {
        let state = self.session.lock().unwrap();
        state.is_some()
    }

    /// Главный метод запуска VPN. Управляет циклом каскадного переподключения серверов.
    pub async fn start(&self) -> Result<()> {
        if self.is_running() {
            return Err(anyhow!("VPN tunnel is already active"));
        }

        self.stop_requested.store(false, Ordering::SeqCst);

        let mut config_clone = self.config.clone();
        config_clone.sanitize()?;

        info!("[Core] Starting failover connection loop...");
        warn("[Core] Starting connection loop...");
        client_state(ClientState::Connecting, "Starting connection loop", None);

        let reconnect_signal = Arc::new(Notify::new());
        let mut current_server_index = 0;

        loop {
            let server = &config_clone.servers[current_server_index];

            let server_name = server.get_name();
            info!("[Core] Connecting to server '{}' ({})", server_name, server.dsn);
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
                        status("VPN Stopped");
                        client_state(ClientState::Stopped, "VPN stopped", None);
                        break;
                    }

                    warn!(
                        "[Core] Connection with server '{}' lost. Switching to the next node...",
                        server_name
                    );
                    status("Connection lost. Reconnecting...");
                    client_state(
                        ClientState::Reconnecting,
                        "Connection lost; reconnecting",
                        Some(server_name.clone()),
                    );

                    current_server_index = (current_server_index + 1) % config_clone.servers.len();
                    sleep(Duration::from_secs(2)).await;
                }
                Err(e) => {
                    if self.stop_requested.load(Ordering::SeqCst) {
                        info!("[Core] Stop requested by user. Exiting connection loop.");
                        status("VPN Stopped");
                        client_state(ClientState::Stopped, "VPN stopped", None);
                        break;
                    }

                    error!(
                        "[Core] Connection failed or timed out for server '{}': {}",
                        server_name, e
                    );
                    status(format!("Node error: {}", e));
                    client_state(
                        ClientState::Reconnecting,
                        format!("Node error: {e}"),
                        Some(server_name.clone()),
                    );

                    current_server_index = (current_server_index + 1) % config_clone.servers.len();
                    sleep(Duration::from_secs(2)).await;
                }
            }
        }

        Ok(())
    }

    #[cfg(all(windows, feature = "per-app"))]
    async fn acquire_packet_source(
        &self,
        _server: &ServerConfig,
        auth: &AuthResponse,
    ) -> Result<(Sender<Bytes>, Receiver<Bytes>, String, Option<AppFilter>)> {
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
            PerAppMode::Exclude => AppPolicy::exclude(self.config.main.per_app.clone()),
            PerAppMode::Include => AppPolicy::include(self.config.main.per_app.clone()),
            PerAppMode::All => AppPolicy::exclude(Vec::<String>::new()),
        };

        let vpn_ip = IpAddr::from_str(&auth.ip).context("Failed to parse assigned VPN IP")?;
        let (filter, tx, rx) = AppFilter::start(policy, initial_bypass, vpn_ip)?;

        let (server_host, server_port) = _server.host_port()?;
        if let Ok(ip) = IpAddr::from_str(&server_host) {
            filter.add_bypass(ip).await;
        } else if let Ok(mut addrs) = lookup_host((server_host.as_str(), server_port)).await {
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
            apps_names, mode_str
        );
        status(format!(
            "[Core] Per-app mode active, apps: [{}], mode: [{}]",
            apps_names, mode_str
        ));

        spawn(async move {
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

    /// Внутренний метод, который держит активную сессию и мониторит её здоровье
    async fn connect_and_run(
        &self,
        server: &ServerConfig,
        reconnect_signal: Arc<Notify>,
    ) -> Result<()> {
        let mut config_clone = self.config.clone();
        config_clone.sanitize()?;

        let transport = create_transport(&config_clone, server)?;
        let conn_timeout = Duration::from_secs(server.timeout_secs);

        let result = tokio::time::timeout(conn_timeout, transport.connect())
            .await
            .map_err(|_| anyhow!("Connection handshake timed out"))??;

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
            self.route_manager.add_bypass_route(server_ip, prefix).await?;
        }

        let (tx_to_tun, mut rx_from_tun, iface_name, _app_filter) =
            self.acquire_packet_source(server, &result.auth_response).await?;

        let last_rx_time = Arc::new(Mutex::new(Instant::now()));
        let last_tx_time = Arc::new(Mutex::new(Instant::now()));

        let total_rx_bytes = Arc::new(AtomicU64::new(0));
        let total_tx_bytes = Arc::new(AtomicU64::new(0));
        let total_rx_packets = Arc::new(AtomicU64::new(0));
        let total_tx_packets = Arc::new(AtomicU64::new(0));

        let shutdown_notify = Arc::new(Notify::new());
        let notify_tx = shutdown_notify.clone();
        let notify_rx = shutdown_notify.clone();

        let (mut stream_reader, mut stream_writer) = io_split(result.vpn_stream);

        // Задача TUN -> NETWORK (Отправка пакетов)
        let tx_time = last_tx_time.clone();
        let tx_bytes = total_tx_bytes.clone();
        let tx_packets = total_tx_packets.clone();
        let sig_t1 = reconnect_signal.clone();
        let t1 = spawn(async move {
            let mut write_buf = BytesMut::with_capacity(COALESCE_BUDGET_BYTES);

            loop {
                let packet = select! {
                    pkt = rx_from_tun.recv() => {
                        match pkt {
                            Some(p) => p,
                            None => break,
                        }
                    }
                    _ = notify_tx.notified() => {
                        break;
                    }
                };

                write_buf.clear();
                *tx_time.lock().unwrap() = Instant::now();

                let len = packet.len() as u64;
                tx_bytes.fetch_add(len, Ordering::Relaxed);
                tx_packets.fetch_add(1, Ordering::Relaxed);

                frame_packet_into(&mut write_buf, &packet);

                while write_buf.len() < COALESCE_BUDGET_BYTES {
                    match rx_from_tun.try_recv() {
                        Ok(p) => {
                            let len = p.len() as u64;
                            tx_bytes.fetch_add(len, Ordering::Relaxed);
                            tx_packets.fetch_add(1, Ordering::Relaxed);
                            frame_packet_into(&mut write_buf, &p);
                        }
                        Err(_) => break,
                    }
                }

                if write_buf.is_empty() {
                    continue;
                }

                if stream_writer.write_all(&write_buf).await.is_err()
                    || stream_writer.flush().await.is_err()
                {
                    sig_t1.notify_one();
                    break;
                }
            }
        });

        // Задача NETWORK -> TUN (Прием пакетов)
        let rx_time = last_rx_time.clone();
        let rx_bytes = total_rx_bytes.clone();
        let rx_packets = total_rx_packets.clone();
        let sig_t2 = reconnect_signal.clone();
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

                                if tx_to_tun.send(packet).await.is_err() {
                                    sig_t2.notify_one();
                                    break;
                                }
                            }
                            _ => {
                                sig_t2.notify_one();
                                break;
                            }
                        }
                    }
                    _ = notify_rx.notified() => { break; }
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
                            net.addr(),
                            net.prefix_len(),
                            &result.auth_response.gateway,
                            &iface_name,
                        )
                        .await?;
                }
            } else {
                if !config_clone.main.exclude_route_for.is_empty() {
                    let exclude_routes =
                        self.resolve_list(&config_clone.main.exclude_route_for).await;
                    for net in exclude_routes.iter() {
                        self.route_manager
                            .add_bypass_route(net.addr(), net.prefix_len())
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

        // Монитор активности и блокировок
        let monitor_shutdown = shutdown_notify.clone();
        let monitor_reconnect = reconnect_signal.clone();
        let rx_check = last_rx_time.clone();
        let tx_check = last_tx_time.clone();

        let health_pause = result.health_pause.clone();
        let health_task = spawn(async move {
            let check_interval = Duration::from_secs(4);
            let mut is_initial_phase = true;

            loop {
                select! {
                    _ = sleep(check_interval) => {}
                    _ = monitor_shutdown.notified() => {
                        break;
                    }
                }

                let elapsed_rx = rx_check.lock().unwrap().elapsed();
                let elapsed_tx = tx_check.lock().unwrap().elapsed();

                if health_pause.as_ref().is_some_and(|pause| pause.load(Ordering::Acquire)) {
                    *rx_check.lock().unwrap() = Instant::now();
                    *tx_check.lock().unwrap() = Instant::now();
                    continue;
                }

                if is_initial_phase {
                    if elapsed_rx > Duration::from_secs(8) && elapsed_tx < Duration::from_secs(4) {
                        warn!("[Health] CASE 1 Detected: Connection established, but payload traffic is blocked!");
                        warn("[Health] CASE 1 Detected: Connection established, but payload traffic is blocked!");
                        monitor_reconnect.notify_one();
                        break;
                    }
                    is_initial_phase = false;
                }
            }
        });

        // Сборщик статистики сессии
        let stats_shutdown = shutdown_notify.clone();
        let stats_task = if config_clone.stats.enabled {
            let provider: Arc<dyn StatsProvider> = if let Some(ref conn) = result.connection {
                Arc::new(QuicStatsProvider::new(conn.clone()))
            } else {
                Arc::new(StreamStatsProvider::new(
                    total_rx_bytes.clone(),
                    total_tx_bytes.clone(),
                    total_rx_packets.clone(),
                    total_tx_packets.clone(),
                ))
            };
            Some(start_stats_monitor(
                provider,
                config_clone.stats.interval_minutes,
                stats_shutdown,
            ))
        } else {
            None
        };

        {
            let mut state = self.session.lock().unwrap();
            *state = Some(RunningSession {
                endpoint: result.endpoint,
                shutdown_notify: shutdown_notify.clone(),
                reconnect_signal: reconnect_signal.clone(),
                main_task: spawn(async move {
                    let _ = tokio::join!(t1, t2);
                }),
                stats_task,
                iface_name: iface_name.clone(),
            });
        }

        // =========================================================================
        // ВЫВОД ИНФОРМАЦИИ О ТАРИФЕ И АККАУНТЕ
        // =========================================================================
        let billing_str = match ProtoBillingType::from_i32(result.auth_response.billing_type) {
            Some(ProtoBillingType::NoTariffNoGroup) => "Без тарифа и группы",
            Some(ProtoBillingType::Group) => "Группа",
            Some(ProtoBillingType::Individual) => "Индивидуальный тариф",
            Some(ProtoBillingType::GroupAndIndividual) => "Группа + индивидуальный тариф",
            _ => "Не указан",
        };

        let group_str = result
            .auth_response
            .group_name
            .as_deref()
            .unwrap_or("—");

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

        let sessions_str = if result.auth_response.allowed_sessions > 0 {
            format!(
                "{} / {}",
                result.auth_response.active_sessions, result.auth_response.allowed_sessions
            )
        } else {
            format!("{} / Безлимит", result.auth_response.active_sessions)
        };

        info!(
            "\n╔═══════════════════════════════════════════════════════════════════════════════╗\n\
             ║                          ACCOUNT & TARIFF INFO                                ║\n\
             ╠═══════════════════════════════════════════════════════════════════════════════╣\n\
             ║  Тарификация:      {:<56} ║\n\
             ║  Группа:           {:<56} ║\n\
             ║  Сессии:           {:<56} ║\n\
             ║  Трафик за период: {:<56} ║\n\
             ║  Лимит трафика:    {:<56} ║\n\
             ╚═══════════════════════════════════════════════════════════════════════════════╝",
            billing_str, group_str, sessions_str, consumed_str, limit_str,
        );

        status(format!(
            "Тариф: {} | Группа: {} | Трафик: {} / {}",
            billing_str, group_str, consumed_str, limit_str
        ));

        info!(
            "[Core] VPN interface configured. Tunnel UP. Active node: {}",
            server.get_name()
        );
        status(format!(
            "[Core] VPN interface configured. Tunnel UP. Active node: {}",
            server.get_name()
        ));
        status(format!("Connected. Local IP: {}", result.auth_response.ip));
        status("VPN Tunnel UP");
        client_state(
            ClientState::Connected,
            format!("Connected. Local IP: {}", result.auth_response.ip),
            Some(server.get_name()),
        );

        // Ожидание сигнала перезапуска сессии
        reconnect_signal.notified().await;

        info!("[Core] Cleaning up dead session...");
        status("[Core] Cleaning up dead session...");
        shutdown_notify.notify_waiters();
        health_task.abort();

        let session_to_clean = {
            let mut state = self.session.lock().unwrap();
            state.take()
        };
        if let Some(sess) = session_to_clean {
            if let Some(task) = sess.stats_task {
                task.abort();
            }
            let _ = sess.main_task.await;
        }

        let _ = self.dns_manager.restore_dns(&iface_name);
        let _ = self.route_manager.restore_routes().await;

        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        self.stop_requested.store(true, Ordering::SeqCst);

        let session = {
            let mut state = self.session.lock().unwrap();
            state.take()
        };

        if let Some(running) = session {
            info!("[Core] Stopping VPN...");
            status("[Core] Stopping VPN...");
            client_state(ClientState::Stopping, "Stopping VPN", None);
            running.shutdown_notify.notify_waiters();
            running.reconnect_signal.notify_one();

            if let Some(task) = running.stats_task {
                task.abort();
            }

            let _ = running.main_task.await;

            if let Some(endpoint) = running.endpoint {
                endpoint.close(0u32.into(), b"Disconnected by user");
            }

            let _ = self.dns_manager.restore_dns(&running.iface_name);
            let _ = self.route_manager.restore_routes().await;
            info!("[Core] VPN Stopped.");
            status("[Core] VPN Stopped.");
            client_state(ClientState::Stopped, "VPN stopped", None);
        }
        Ok(())
    }
}

/// Вспомогательная функция форматирования байт в читаемые единицы
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