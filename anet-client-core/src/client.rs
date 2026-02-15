use crate::auth::AuthHandler;
use crate::config::CoreConfig;
use crate::dns::{DnsManager, create_dns_manager};
use crate::events::status;
use crate::traits::{RouteManager, TunFactory};
use crate::vpn::VpnHandler;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use ipnet::IpNet;
use log::{error, info, warn};
use quinn::{Connection, Endpoint};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

/// Хранит "живые" объекты запущенной сессии.
struct RunningSession {
    /// QUIC Endpoint
    endpoint: Endpoint,
    /// Сигнал для остановки фоновых задач пересылки байт
    shutdown_notify: Arc<Notify>,
    /// Хендл главной задачи, чтобы подождать её завершения
    main_task: JoinHandle<()>,
    /// Имя интерфейса (нужно для очистки маршрутов)
    connection: Connection,
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
        Self {
            config,
            tun_factory,
            route_manager,
            dns_manager: create_dns_manager(),
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
        status("Connecting");

        // 2. Логика подключения (Auth -> QUIC -> TUN)
        let auth_handler = AuthHandler::new(&self.config)?;
        // Стучимся на сервер
        let (auth_response, shared_key) = auth_handler.authenticate().await?;

        info!("[Core] Authenticated. Assigned IP: {}", auth_response.ip);
        status(format!("[Core] IP: {}", auth_response.ip));

        // Бэкапим маршруты
        self.route_manager.backup_routes().await?;

        // Добавляем маршрут до VPN-сервера
        let server_ip = self.config.main.address.split(':').next().unwrap();
        self.route_manager
            .add_bypass_route(IpAddr::from_str(server_ip).unwrap(), 32)
            .await?;

        // Поднимаем QUIC
        let vpn_handler = VpnHandler::new(self.config.clone());
        let (endpoint, connection, tx_to_quic, mut rx_from_quic) =
            vpn_handler.connect(&auth_response, shared_key).await?;

        let (tx_to_tun, mut rx_from_tun, iface_name) =
            self.tun_factory.create_tun(&auth_response).await?;

        // 3. Запуск пересылки данных
        let shutdown_notify = Arc::new(Notify::new());
        let notify_tx = shutdown_notify.clone();
        let notify_rx = shutdown_notify.clone();

        // TUN -> QUIC
        let t1 = tokio::spawn(async move {
            loop {
                tokio::select! {
                    pkt = rx_from_tun.recv() => {
                        if let Some(p) = pkt { let _ = tx_to_quic.send(p).await; } else { break; }
                    }
                    _ = notify_tx.notified() => { break; }
                }
            }
        });

        // QUIC -> TUN
        let t2 = tokio::spawn(async move {
            loop {
                tokio::select! {
                    pkt = rx_from_quic.recv() => {
                        if let Some(p) = pkt { let _ = tx_to_tun.send(p).await; } else { break; }
                    }
                    _ = notify_rx.notified() => { break; }
                }
            }
        });

        let main_task = tokio::spawn(async move {
            let _ = tokio::join!(t1, t2);
        });

        // ЛОГИКА МАРШРУТИЗАЦИИ
        if !self.config.main.route_for.is_empty() {
            // MODE 1: INCLUDE (Whitelist)
            // VPN выключен по умолчанию, включаем только для списка.
            // exclude_route_for игнорируется (логически не имеет смысла).

            info!("[Core] Mode: Split Tunneling (INCLUDE).");
            let routes = self.resolve_list(&self.config.main.route_for).await;

            for net in routes {
                self.route_manager
                    .add_specific_route(
                        net.addr(),
                        net.prefix_len(),
                        &auth_response.gateway,
                        &iface_name,
                    )
                    .await?;
            }
        } else {
            // MODE 2: GLOBAL VPN + EXCLUDE (Blacklist)
            info!("[Core] Mode: Global VPN.");

            // Если есть исключения - добавляем их ПЕРЕД установкой дефолтного шлюза
            if !self.config.main.exclude_route_for.is_empty() {
                info!(
                    "[Core] Found {} exclusion rules.",
                    self.config.main.exclude_route_for.len()
                );
                let bypass_routes = self.resolve_list(&self.config.main.exclude_route_for).await;

                for net in bypass_routes {
                    self.route_manager
                        .add_bypass_route(net.addr(), net.prefix_len())
                        .await?;
                }
            }

            // Включаем перенаправление всего трафика
            // Благодаря Longest Prefix Match, наши bypass маршруты (/32 или /24)
            // будут приоритетнее дефолтного (/0 или /1)
            self.route_manager
                .set_default_route(&auth_response.gateway, &iface_name)
                .await?;
        }

        // Configure DNS servers
        if !self.config.main.dns_server_list.is_empty() {
            if let Err(e) = self.dns_manager.set_dns(&self.config.main.dns_server_list) {
                warn!("[Core] Failed to configure DNS: {}", e);
                // Continue anyway - VPN can still work without custom DNS
            }
        }

        info!("[Core] VPN Tunnel UP.");
        status("[Core] VPN UP");
        status("VPN Tunnel UP"); // Типо сигнал

        // 5. Сохраняем сессию
        let mut state = self.session.lock().unwrap();
        *state = Some(RunningSession {
            endpoint,
            shutdown_notify,
            main_task,
            connection,
        });

        Ok(())
    }

    /// Остановка VPN
    pub async fn stop(&self) -> anyhow::Result<()> {
        // Забираем сессию (Option::take), освобождая Mutex
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

            // 3. Отправляем серверу "Good bye"
            running.endpoint.close(0u32.into(), b"Disconnected by user");

            // 4. Restore DNS configuration
            if let Err(e) = self.dns_manager.restore_dns() {
                error!("Failed to restore DNS: {}", e);
            }

            // 5. Restore routes (ОЧЕНЬ ВАЖНО ДЛЯ CLI)
            if let Err(e) = self.route_manager.restore_routes().await {
                error!("Failed to restore routes: {}", e);
            }

            info!("[Core] VPN Stopped.");
        }
        Ok(())
    }

    /// Получение статистики
    pub fn get_stats(&self) -> Option<Connection> {
        let state = self.session.lock().unwrap();
        if let Some(s) = &*state {
            // Переделать на структуру
            Some(s.connection.clone())
        } else {
            None
        }
    }
}
