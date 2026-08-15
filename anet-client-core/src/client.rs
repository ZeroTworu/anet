use crate::config::{CoreConfig, ServerConfig};
use crate::dns::{DnsManager, get_dns_manager};
use crate::events::{ClientState, client_state, status, warn};
use crate::traits::{RouteManager, TunFactory};
use crate::statistic;
use crate::transport::factory::create_transport;
use anet_common::stream_framing::{frame_packet_into, read_next_packet};
use anet_common::consts::COALESCE_BUDGET_BYTES;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use ipnet::IpNet;
use log::{error, info, warn};
use quinn::Endpoint;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
#[cfg(all(windows, feature = "per-app"))]
use anyhow::Context;


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
    // Взводится в stop(): цикл переподключения в start() использует этот
    // флаг, чтобы отличить "пользователь нажал disconnect" от "сессия
    // умерла сама" — оба случая возвращаются из connect_and_run() одним и
    // тем же путём (через reconnect_signal), поэтому раньше stop() всегда
    // трактовался как обрыв связи и немедленно вызывал реконнект.
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
    pub async fn start(&self) -> anyhow::Result<()> {
        if self.is_running() {
            return Err(anyhow::anyhow!("VPN tunnel is already active"));
        }

        // Свежий цикл подключения — сбрасываем флаг от возможного
        // предыдущего stop().
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
            info!("[Core] Connecting to server '{}' ({}) via {:?}", server_name, server.address, server.mode);
            status(format!("Connecting to '{}'...", server_name));
            client_state(ClientState::Connecting, format!("Connecting to '{}'", server_name), Some(server_name.clone()));

            match self.connect_and_run(server, reconnect_signal.clone()).await {
                Ok(()) => {
                    // connect_and_run() возвращается через reconnect_signal и
                    // при обрыве сессии, и при вызове stop() — различаем эти
                    // случаи флагом, иначе disconnect всегда трактовался как
                    // "связь потеряна" и тут же запускал реконнект.
                    if self.stop_requested.load(Ordering::SeqCst) {
                        info!("[Core] Stop requested by user. Exiting connection loop.");
                        status("VPN Stopped");
                        client_state(ClientState::Stopped, "VPN stopped", None);
                        break;
                    }

                    warn!("[Core] Connection with server '{}' lost. Switching to the next node...", server_name);
                    status("Connection lost. Reconnecting...");
                    client_state(ClientState::Reconnecting, "Connection lost; reconnecting", Some(server_name.clone()));

                    current_server_index = (current_server_index + 1) % config_clone.servers.len();
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                Err(e) => {
                    if self.stop_requested.load(Ordering::SeqCst) {
                        info!("[Core] Stop requested by user. Exiting connection loop.");
                        status("VPN Stopped");
                        client_state(ClientState::Stopped, "VPN stopped", None);
                        break;
                    }

                    error!("[Core] Connection failed or timed out for server '{}': {}", server_name, e);
                    status(format!("Node error: {}", e));
                    client_state(ClientState::Reconnecting, format!("Node error: {e}"), Some(server_name.clone()));

                    current_server_index = (current_server_index + 1) % config_clone.servers.len();
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }

        Ok(())
    }

    /// Получает источник IP-пакетов для сессии.
    ///
    /// Возвращает `(tx_to_source, rx_from_source, iface_name, filter_handle)`,
    /// где `filter_handle` держит WinDivert-фильтр живым (None для TUN-режима).
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
        // МЫ ВСЕГДА создаем TUN-интерфейс (Wintun), чтобы операционная система зарегистрировала
        // выделенный виртуальный IP-адрес на хосте.
        let (tun_tx, tun_rx, iface_name) = self.tun_factory.create_tun(auth).await?;

        // Проверяем режим работы через обновленный enum
        let mode = self.config.main.per_app_mode;

        if mode == crate::config::PerAppMode::All || (mode == crate::config::PerAppMode::Include && self.config.main.per_app.is_empty()) {
            info!("[Core] Per-app mode is disabled (All applications)");
            status("[Core] Per-app mode is disabled (All applications)");
            // Обычный полнотуннельный режим через TUN для всех приложений
            return Ok((tun_tx, tun_rx, iface_name, None));
        }

        // Статический bypass: IP-литералы всех серверов из конфига.
        let initial_bypass: Vec<IpAddr> = self
            .config
            .servers
            .iter()
            .filter_map(|s| s.address.split(':').next())
            .filter_map(|host| IpAddr::from_str(host).ok())
            .collect();

        // Формируем политику на основе enum с явным указанием типов для пустых векторов
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

        // Парсим выданный VPN IP
        let vpn_ip = IpAddr::from_str(&auth.ip).context("Failed to parse assigned VPN IP")?;

        let (filter, tx, rx) = anet_appfilter::AppFilter::start(policy, initial_bypass, vpn_ip)?;

        // Динамический bypass: фактический адрес текущего сервера.
        let server_host = _server.address.split(':').next().unwrap_or_default();
        if let Ok(ip) = IpAddr::from_str(server_host) {
            filter.add_bypass(ip).await;
        } else if let Ok(mut addrs) =
            tokio::net::lookup_host(_server.address.as_str()).await
        {
            if let Some(sa) = addrs.next() {
                filter.add_bypass(sa.ip()).await;
            }
        }

        let apps_names = self.config.main.per_app.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
        let mode_str = match mode {
            crate::config::PerAppMode::All => "all",
            crate::config::PerAppMode::Include => "include",
            crate::config::PerAppMode::Exclude => "exclude",
        };

        info!(
            "[Core] Per-app mode active, apps: [{}], mode: [{}]",
            apps_names,
            mode_str
        );
        status(format!(
            "[Core] Per-app mode active, apps: [{}], mode: [{}]",
            apps_names,
            mode_str
        ));

        // Утилизируем входящий канал TUN (tun_rx) в фоновом режиме
        tokio::spawn(async move {
            let mut rx = tun_rx;
            while rx.recv().await.is_some() {}
        });

        Ok((tx, rx, iface_name, Some(filter)))
    }

    /// Fallback: per-app недоступен (не Windows, либо фича `per-app`
    /// выключена) — всегда обычный TUN. Тип хэндла — (), чтобы сигнатура
    /// вызова совпадала на всех платформах.
    #[cfg(not(all(windows, feature = "per-app")))]
    async fn acquire_packet_source(
        &self,
        _server: &ServerConfig,
        auth: &anet_common::protocol::AuthResponse,
    ) -> anyhow::Result<(
        tokio::sync::mpsc::Sender<bytes::Bytes>,
        tokio::sync::mpsc::Receiver<bytes::Bytes>,
        String,
        Option<()>,
    )> {
        let (tx, rx, iface) = self.tun_factory.create_tun(auth).await?;
        Ok((tx, rx, iface, None))
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

        let (server_host, server_port) = if server.mode == crate::config::TransportMode::Websocket {
            let uri: http::Uri = server.websocket_url.parse()?;
            let host = uri.host().ok_or_else(|| anyhow::anyhow!("websocket_url has no host"))?;
            let port = uri.port_u16().unwrap_or(if uri.scheme_str() == Some("wss") { 443 } else { 80 });
            (host.to_string(), port)
        } else {
            let address = server.address.rsplit_once(':').unwrap_or((&server.address, "0"));
            (address.0.trim_matches(['[', ']']).to_string(), address.1.parse().unwrap_or(0))
        };
        let mut bypass_ips = Vec::new();
        if let Ok(server_ip) = IpAddr::from_str(&server_host) {
            bypass_ips.push(server_ip);
        } else if let Ok(resolved) = tokio::net::lookup_host((server_host.as_str(), server_port)).await {
            bypass_ips.extend(resolved.map(|addr| addr.ip()));
            bypass_ips.sort_unstable();
            bypass_ips.dedup();
        }
        for server_ip in bypass_ips {
            let prefix = if server_ip.is_ipv4() { 32 } else { 128 };
            self.route_manager.add_bypass_route(server_ip, prefix).await?;
        }

        // Источник/приёмник IP-пакетов. Обычно это TUN. На Windows, если задан
        // per-app список, вместо TUN поднимаем WinDivert-фильтр, который отдаёт
        // ту же пару каналов (Sender/Receiver<Bytes>) — транспорт не меняется.
        //
        // `_app_filter` держит хэндл фильтра живым на всё время сессии; при
        // выходе из функции он дропается и рабочие потоки WinDivert
        // останавливаются вместе с закрытием каналов.
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

        // В per-app режиме (Windows/WinDivert) маршрутизацией управляет сам
        // фильтр на уровне пакетов: нет реального интерфейса, дефолтный маршрут
        // и системный DNS трогать нельзя. `_app_filter.is_some()` == per-app.
        let per_app_active = _app_filter.is_some();

        if !per_app_active {
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
        }

        // АКТИВНЫЙ ВОРКЕР КОНТРОЛЯ ЗДОРОВЬЯ (HEALTH MONITOR)
        // =========================================================================
        let monitor_shutdown = shutdown_notify.clone();
        let monitor_reconnect = reconnect_signal.clone();
        let rx_check = last_rx_time.clone();

        //  Забираем время последней отправки пакета!
        let tx_check = last_tx_time.clone();

        let health_pause = result.health_pause.clone();
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
                let elapsed_tx = tx_check.lock().unwrap().elapsed();

                if health_pause.as_ref().is_some_and(|pause| pause.load(Ordering::Acquire)) {
                    *rx_check.lock().unwrap() = Instant::now();
                    *tx_check.lock().unwrap() = Instant::now();
                    continue;
                }

                if is_initial_phase {
                    // Если мы отправляли данные в последние 4 сек, но ответа нет 8 сек -> Блокировка
                    if elapsed_rx > Duration::from_secs(8) && elapsed_tx < Duration::from_secs(4) {
                        warn!("[Health] CASE 1 Detected: Connection established, but payload traffic is blocked!");
                        warn("[Health] CASE 1 Detected: Connection established, but payload traffic is blocked!");
                        monitor_reconnect.notify_one();
                        break;
                    }
                    is_initial_phase = false;
                } else {
                    // После успешного старта отсутствие входящих IP-пакетов не
                    // доказывает разрыв туннеля: трафик может быть асимметричным,
                    // идти пакетами, не попадающими в TUN, или временно не иметь
                    // обратного направления. Реальный обрыв определяется
                    // сетевыми worker-ами по EOF/ошибке чтения или записи.
                    // Поэтому payload inactivity больше не вызывает реконнект.
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
                reconnect_signal: reconnect_signal.clone(),
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
        client_state(ClientState::Connected, format!("Connected. Local IP: {}", result.auth_response.ip), Some(server.get_name()));

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
        // Взводим ДО notify_one() ниже — start() должен увидеть флаг сразу,
        // как только проснётся от сигнала reconnect_signal.
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
            running.reconnect_signal.notify_one(); // <-- Сигнализируем выходу из connect_and_run!

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
