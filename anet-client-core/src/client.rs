use crate::config::{CoreConfig, ServerConfig};
use crate::dns::{DnsManager, get_dns_manager};
use crate::events::{status, warn};
use crate::traits::{RouteManager, TunFactory};
use crate::statistic;
use crate::transport::factory::create_transport;
use anet_common::stream_framing::{frame_packet_into, read_next_packet};
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use ipnet::IpNet;
use log::{error, info, warn};
use quinn::Endpoint;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

/// Бюджет коалесценции для группировки мелких IP-пакетов перед записью в сокет.
const COALESCE_BUDGET_BYTES: usize = 64 * 1024;

struct RunningSession {
    endpoint: Option<Endpoint>,
    shutdown_notify: Arc<Notify>,
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
    pub async fn start(&self) -> anyhow::Result<()> {
        if self.is_running() {
            return Err(anyhow::anyhow!("VPN tunnel is already active"));
        }

        let mut config_clone = self.config.clone();
        config_clone.sanitize()?;

        info!("[Core] Starting failover connection loop...");
        warn("[Core] Starting connection loop...");

        let reconnect_signal = Arc::new(Notify::new());
        let mut current_server_index = 0;

        loop {
            let server = &config_clone.servers[current_server_index];

            let server_name = server.get_name();
            info!("[Core] Connecting to server '{}' ({}) via {:?}", server_name, server.address, server.mode);
            status(format!("Connecting to '{}'...", server_name));

            match self.connect_and_run(server, reconnect_signal.clone()).await {
                Ok(()) => {
                    warn!("[Core] Connection with server '{}' lost. Switching to the next node...", server_name);
                    status("Connection lost. Reconnecting...");

                    current_server_index = (current_server_index + 1) % config_clone.servers.len();
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                Err(e) => {
                    error!("[Core] Connection failed or timed out for server '{}': {}", server_name, e);
                    status(format!("Node error: {}", e));

                    current_server_index = (current_server_index + 1) % config_clone.servers.len();
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }

    /// Внутренний метод, который держит активную сессию и мониторит её здоровье
    async fn connect_and_run(&self, server: &ServerConfig, reconnect_signal: Arc<Notify>) -> anyhow::Result<()> {
        let mut config_clone = self.config.clone();
        config_clone.sanitize()?;

        let transport = create_transport(&config_clone, server);
        let conn_timeout = Duration::from_secs(server.timeout_secs);

        let result = tokio::time::timeout(conn_timeout, transport.connect())
            .await
            .map_err(|_| anyhow::anyhow!("Connection handshake timed out"))??;

        info!("[Core] Authentication successful. Configuring tunnel interface...");
        status("[Core] Authentication successful. Configuring tunnel interface...");

        self.route_manager.backup_routes().await?;

        let server_host = server.address.split(':').next().unwrap();
        if let Ok(server_ip) = IpAddr::from_str(server_host) {
            self.route_manager.add_bypass_route(server_ip, 32).await?;
        }

        let (tx_to_tun, mut rx_from_tun, iface_name) =
            self.tun_factory.create_tun(&result.auth_response).await?;

        let last_rx_time = Arc::new(Mutex::new(Instant::now()));
        let last_tx_time = Arc::new(Mutex::new(Instant::now()));

        let total_rx_bytes = Arc::new(AtomicU64::new(0));
        let total_tx_bytes = Arc::new(AtomicU64::new(0));
        let total_rx_packets = Arc::new(AtomicU64::new(0));
        let total_tx_packets = Arc::new(AtomicU64::new(0));

        let shutdown_notify = Arc::new(Notify::new());
        let notify_tx = shutdown_notify.clone();
        let notify_rx = shutdown_notify.clone();

        let (mut stream_reader, mut stream_writer) = tokio::io::split(result.vpn_stream);

        // =========================================================================
        // Задача TUN -> NETWORK (Отправка пакетов) с КOАЛЕСЦЕНЦИЕЙ и СИГНАЛОМ ОТМЕНЫ
        // =========================================================================
        let tx_time = last_tx_time.clone();
        let tx_bytes = total_tx_bytes.clone();
        let tx_packets = total_tx_packets.clone();
        let sig_t1 = reconnect_signal.clone();
        let t1 = tokio::spawn(async move {
            let mut write_buf = bytes::BytesMut::with_capacity(COALESCE_BUDGET_BYTES);

            loop {
                // ИССПРАВЛЕНИЕ ДЕДЛОКА: Асинхронно ждем либо пакет из TUN, либо сигнал отмены сессии
                let packet = tokio::select! {
                    pkt = rx_from_tun.recv() => {
                        match pkt {
                            Some(p) => p,
                            None => break, // Канал закрылся
                        }
                    }
                    _ = notify_tx.notified() => {
                        // Получен сигнал отмены сессии при очистке — немедленно выходим!
                        break;
                    }
                };

                write_buf.clear();
                *tx_time.lock().unwrap() = Instant::now();

                let len = packet.len() as u64;
                tx_bytes.fetch_add(len, Ordering::Relaxed);
                tx_packets.fetch_add(1, Ordering::Relaxed);

                frame_packet_into(&mut write_buf, &packet);

                // Пакетная выгрузка без ожидания (выгребаем готовое)
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

                if stream_writer.write_all(&write_buf).await.is_err() || stream_writer.flush().await.is_err() {
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
        let t2 = tokio::spawn(async move {
            loop {
                tokio::select! {
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

        if !config_clone.main.route_for.is_empty() {
            let include_routes = self.resolve_list(&config_clone.main.route_for).await;
            for net in include_routes.iter() {
                self.route_manager.add_specific_route(
                    net.addr(),
                    net.prefix_len(),
                    &result.auth_response.gateway,
                    &iface_name,
                ).await?;
            }
        } else {
            if !config_clone.main.exclude_route_for.is_empty() {
                let exclude_routes = self.resolve_list(&config_clone.main.exclude_route_for).await;
                for net in exclude_routes.iter() {
                    self.route_manager.add_bypass_route(net.addr(), net.prefix_len()).await?;
                }
            }
            self.route_manager.set_default_route(&result.auth_response.gateway, &iface_name).await?;
        }

        if !config_clone.main.dns_server_list.is_empty() {
            let dns_ips: Vec<IpAddr> = config_clone.main.dns_server_list.iter()
                .filter_map(|s| IpAddr::from_str(s).ok()).collect();
            let dns_ipv4: Vec<std::net::Ipv4Addr> = dns_ips.iter().filter_map(|ip| match ip {
                IpAddr::V4(addr) => Some(*addr),
                _ => None,
            }).collect();

            if !dns_ipv4.is_empty() {
                let _ = self.dns_manager.set_dns(&iface_name, &dns_ipv4);
            }
        }

        // =========================================================================
        // АКТИВНЫЙ ВОРКЕР КОНТРОЛЯ ЗДОРОВЬЯ (HEALTH MONITOR)
        // =========================================================================
        let monitor_shutdown = shutdown_notify.clone();
        let monitor_reconnect = reconnect_signal.clone();
        let rx_check = last_rx_time.clone();

        let health_task = tokio::spawn(async move {
            let check_interval = Duration::from_secs(4);
            let mut is_initial_phase = true;

            loop {
                tokio::select! {
                    _ = tokio::time::sleep(check_interval) => {}
                    _ = monitor_shutdown.notified() => {
                        break;
                    }
                }

                let elapsed_rx = rx_check.lock().unwrap().elapsed();

                if is_initial_phase {
                    if elapsed_rx > Duration::from_secs(8) {
                        warn!("[Health] CASE 1 Detected: Connection established, but payload traffic is blocked!");
                        warn("[Health] CASE 1 Detected: Connection established, but payload traffic is blocked!");
                        monitor_reconnect.notify_one();
                        break;
                    }
                    is_initial_phase = false;
                } else {
                    if elapsed_rx > Duration::from_secs(15) {
                        warn!("[Health] CASE 2 Detected: Active tunnel lost traffic flow (15s inactivity timeout)!");
                        warn("[Health] CASE 2 Detected: Active tunnel lost traffic flow (15s inactivity timeout)!");
                        monitor_reconnect.notify_one();
                        break;
                    }
                }
            }
        });

        // =========================================================================
        // УНИВЕРСАЛЬНЫЙ СБОРЩИК СТАТИСТИКИ
        // =========================================================================
        let stats_shutdown = shutdown_notify.clone();
        let stats_task = if config_clone.stats.enabled {
            let provider: Arc<dyn statistic::StatsProvider> = if let Some(ref conn) = result.connection {
                Arc::new(statistic::QuicStatsProvider::new(conn.clone()))
            } else {
                Arc::new(statistic::StreamStatsProvider::new(
                    total_rx_bytes.clone(),
                    total_tx_bytes.clone(),
                    total_rx_packets.clone(),
                    total_tx_packets.clone(),
                ))
            };
            Some(statistic::start_stats_monitor(
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
                main_task: tokio::spawn(async move {
                    let _ = tokio::join!(t1, t2);
                }),
                stats_task,
                iface_name: iface_name.clone(),
            });
        }

        info!("[Core] VPN interface configured. Tunnel UP. Active node: {}", server.get_name());
        status(format!("[Core] VPN interface configured. Tunnel UP. Active node: {}", server.get_name()));
        status(format!("Connected. Local IP: {}", result.auth_response.ip));
        status("VPN Tunnel UP");

        // Засыпаем и ждем сигнала о необходимости реконнекта от воркера здоровья или задач t1/t2
        reconnect_signal.notified().await;

        // Очистка текущей нерабочей сессии
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
            // Теперь main_task разрешится за доли миллисекунды без зависания!
            let _ = sess.main_task.await;
        }

        let _ = self.dns_manager.restore_dns(&iface_name);
        let _ = self.route_manager.restore_routes().await;

        Ok(())
    }

    pub async fn stop(&self) -> anyhow::Result<()> {
        let session = {
            let mut state = self.session.lock().unwrap();
            state.take()
        };

        if let Some(running) = session {
            info!("[Core] Stopping VPN...");
            status("[Core] Stopping VPN...");
            running.shutdown_notify.notify_waiters();

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
        }
        Ok(())
    }
}
