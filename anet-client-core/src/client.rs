use crate::config::CoreConfig;
use crate::dns::{DnsManager, get_dns_manager};
use crate::events::status;
use crate::traits::{RouteManager, TunFactory};
use crate::statistic;
use crate::transport::factory::create_transport;
use anet_common::stream_framing::{frame_packet, read_next_packet};
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use ipnet::IpNet;
use log::{error, info, warn};
use quinn::Endpoint;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt; // Для write_all
use tokio::sync::Notify;
use tokio::task::JoinHandle;

/// Хранит "живые" объекты запущенной сессии.
struct RunningSession {
    /// QUIC Endpoint (только для QUIC, нужно для отправки close frame)
    endpoint: Option<Endpoint>,
    /// Сигнал для остановки фоновых задач пересылки байт
    shutdown_notify: Arc<Notify>,
    /// Хендл главной задачи, чтобы подождать её завершения
    main_task: JoinHandle<()>,
    /// Имя интерфейса (нужно для очистки DNS/маршрутов)
    iface_name: String,
}

/// Thread-safe, можно шарить между потоками GUI.
pub struct AnetClient {
    config: CoreConfig,
    /// Фабрика TUN (платформо-зависимая)
    tun_factory: Box<dyn TunFactory>,
    /// Менеджер маршрутов (платформо-зависимый)
    route_manager: Box<dyn RouteManager>,
    /// Менеджер DNS (платформо-зависимый)
    dns_manager: Box<dyn DnsManager>,
    /// Состояние: Запущен или нет?
    /// Когда это поле None - VPN выключен.
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

    /// Резолвинг доменов и парсинг IP из конфига
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

            // Domain resolution
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

    /// Проверяет, запущен ли клиент
    pub fn is_running(&self) -> bool {
        let state = self.session.lock().unwrap();
        state.is_some()
    }

    /// Запуск VPN
    pub async fn start(&self) -> anyhow::Result<()> {
        // 1. Защита от двойного запуска
        if self.is_running() {
            return Err(anyhow::anyhow!("VPN is already running"));
        }

        info!("[Core] Starting...");
        status("[Core] Starting...");

        // --- НОВАЯ ЛОГИКА ТРАНСПОРТА ---
        status(format!("[CORE] Connecting to {}", self.config.main.address));
        info!("[CORE] Connecting to {}", self.config.main.address);
        let transport = create_transport(&self.config);

        info!("[Core] Transport mode: [{:?}]", self.config.transport.mode);
        status(format!("[Core] Transport mode: [{:?}]", self.config.transport.mode));

        // Connect возвращает AuthResponse (настройки сети) и VpnStream (трубу данных)
        // Если это QUIC - stream это обертка над QUIC стримами.
        // Если это SSH - stream это обертка над SSH каналом.
        let result  = transport.connect().await?;

        info!("[Core] Authenticated. VPN IP: {}", result.auth_response.ip);
        status(format!("[Core] Authenticated. VPN IP: {}", result.auth_response.ip));

        // =========================================================================
        // ПРЕ-РЕЗОЛВИНГ: Собираем IP-адреса ДО того, как сломаем сеть адаптерами
        // =========================================================================
        status("Resolving domain routes...");
        let include_routes = self.resolve_list(&self.config.main.route_for).await;
        let exclude_routes = self.resolve_list(&self.config.main.exclude_route_for).await;

        // --- НАСТРОЙКА СЕТИ ---

        // Бэкапим маршруты
        self.route_manager.backup_routes().await?;

        // Добавляем маршрут до VPN-сервера (Bypass), чтобы не зациклить трафик
        let server_host = self.config.main.address.split(':').next().unwrap();

        // Пытаемся распарсить как IP, если не выйдет - надо резолвить (но пока считаем что там IP)
        if let Ok(server_ip) = IpAddr::from_str(server_host) {
            self.route_manager.add_bypass_route(server_ip, 32).await?;
        } else {
            warn!(
                "[Core] Server address is domain, skipping bypass route (TODO: implement resolve)"
            );
        }

        // Поднимаем TUN интерфейс
        let (tx_to_tun, mut rx_from_tun, iface_name) =
            self.tun_factory.create_tun(&result.auth_response).await?;

        // --- ЗАПУСК МОСТА (BRIDGE) ---

        let shutdown_notify = Arc::new(Notify::new());
        let notify_tx = shutdown_notify.clone();
        let notify_rx = shutdown_notify.clone();

        // Разделяем VpnStream на Reader и Writer
        let (mut stream_reader, mut stream_writer) = tokio::io::split(result.vpn_stream);

        // Task 1: TUN -> NETWORK (Пишем в транспорт)
        let t1 = tokio::spawn(async move {
            loop {
                tokio::select! {
                    pkt = rx_from_tun.recv() => {
                        if let Some(packet) = pkt {
                            // ВАЖНО: Всегда используем frame_packet (u16 length prefix).
                            // Это нужно для SSH (TCP) и не вредит QUIC (просто overhead 2 байта).
                            let framed = frame_packet(packet);
                            if stream_writer.write_all(&framed).await.is_err() {
                                error!("[Bridge] Write to transport failed");
                                break;
                            }
                            // Flush может быть дорогим, но для SSH/TCP он нужен, чтобы протолкнуть буфер
                            let _ = stream_writer.flush().await;
                        } else {
                            break;
                        }
                    }
                    _ = notify_tx.notified() => { break; }
                }
            }
        });

        // Task 2: NETWORK -> TUN (Читаем из транспорта)
        let t2 = tokio::spawn(async move {
            loop {
                tokio::select! {
                    // read_next_packet читает u16 length, потом данные
                    res = read_next_packet(&mut stream_reader) => {
                        match res {
                            Ok(Some(packet)) => {
                                if tx_to_tun.send(packet).await.is_err() { break; }
                            }
                            Ok(None) => {
                                info!("[Bridge] Transport closed (EOF)");
                                break;
                            }
                            Err(e) => {
                                error!("[Bridge] Read from transport error: {}", e);
                                break;
                            }
                        }
                    }
                    _ = notify_rx.notified() => { break; }
                }
            }
        });

        let main_task = tokio::spawn(async move {
            let _ = tokio::join!(t1, t2);
            info!("[Core] Bridge tasks finished");
        });

        // --- ЛОГИКА МАРШРУТИЗАЦИИ (Split / Global) ---

        if !self.config.main.route_for.is_empty() {
            // MODE 1: INCLUDE (Whitelist)
            info!("[Core] Mode: Split Tunneling (INCLUDE).");

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
            // MODE 2: GLOBAL VPN
            info!("[Core] Mode: Global VPN.");

            // Исключения
            if !self.config.main.exclude_route_for.is_empty() {
                info!(
                    "[Core] Found {} exclusion rules.",
                    self.config.main.exclude_route_for.len()
                );

                for net in exclude_routes.iter() {
                    self.route_manager
                        .add_bypass_route(net.addr(), net.prefix_len())
                        .await?;
                }
            }

            // Весь трафик в туннель
            self.route_manager
                .set_default_route(&result.auth_response.gateway, &iface_name)
                .await?;
        }

        // --- DNS ---
        if !self.config.main.dns_server_list.is_empty() {
            // Преобразуем строки в IP
            let dns_ips: Vec<IpAddr> = self
                .config
                .main
                .dns_server_list
                .iter()
                .filter_map(|s| IpAddr::from_str(s).ok())
                .collect();

            // Фильтруем IPv4 (для текущего менеджера)
            let dns_ipv4: Vec<std::net::Ipv4Addr> = dns_ips
                .iter()
                .filter_map(|ip| match ip {
                    IpAddr::V4(addr) => Some(*addr),
                    _ => None,
                })
                .collect();

            if !dns_ipv4.is_empty() {
                if let Err(e) = self.dns_manager.set_dns(&iface_name, &dns_ipv4) {
                    warn!("[Core] Failed to configure DNS: {}", e);
                }
            }
        }

        info!("[Core] VPN Tunnel UP.");
        status("[Core] VPN UP");
        status("VPN Tunnel UP");

        if self.config.stats.enabled {
            if let Some(conn) = result.connection {
                statistic::start_stats_monitor(conn, self.config.stats.interval_minutes);
            } else {
                info!("Stats are not available for this transport mode.");
            }
        }


        // 5. Сохраняем сессию
        let mut state = self.session.lock().unwrap();
        *state = Some(RunningSession {
            endpoint: result.endpoint,
            shutdown_notify,
            main_task,
            iface_name: iface_name.clone(),
        });

        Ok(())
    }

    /// Остановка VPN
    pub async fn stop(&self) -> anyhow::Result<()> {
        let session = {
            let mut state = self.session.lock().unwrap();
            state.take()
        };

        if let Some(running) = session {
            info!("[Core] Stopping VPN...");

            // 1. Говорим задачам остановиться
            running.shutdown_notify.notify_waiters();

            // 2. Ждем пока байты перестанут летать
            let _ = running.main_task.await;

            // 3. Если есть QUIC Endpoint - закрываем
            if let Some(endpoint) = running.endpoint {
                endpoint.close(0u32.into(), b"Disconnected by user");
            }

            // 4. Restore DNS
            if let Err(e) = self.dns_manager.restore_dns(&running.iface_name) {
                error!("Failed to restore DNS: {}", e);
            }

            // 5. Restore routes
            if let Err(e) = self.route_manager.restore_routes().await {
                error!("Failed to restore routes: {}", e);
            }

            info!("[Core] VPN Stopped.");
        }
        Ok(())
    }

}
