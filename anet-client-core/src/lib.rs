pub mod auth;
pub mod config;
pub mod events;
pub mod socket;
pub mod traits;
pub mod vpn;

use crate::auth::AuthHandler;
use crate::config::CoreConfig;
use crate::events::status;
use crate::traits::{RouteManager, TunFactory};
use crate::vpn::VpnHandler;
use anyhow::Result;
use log::{error, info};
use quinn::{Connection, Endpoint};
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
            session: Mutex::new(None),
        }
    }

    /// Проверяет, запущен ли клиент
    pub fn is_running(&self) -> bool {
        let state = self.session.lock().unwrap();
        state.is_some()
    }

    /// Запуск VPN
    pub async fn start(&self) -> Result<()> {
        // 1. Защита от двойного запуска
        if self.is_running() {
            return Err(anyhow::anyhow!("VPN is already running"));
        }

        info!("[Core] Starting...");
        status("[Core] Starting...");

        // 2. Логика подключения (Auth -> QUIC -> TUN)
        let auth_handler = AuthHandler::new(&self.config)?;
        // Стучимся на сервер
        let (auth_response, shared_key) = auth_handler.authenticate().await?;

        info!("[Core] Authenticated. Assigned IP: {}", auth_response.ip);
        status(format!("[Core] IP: {}", auth_response.ip));

        // Бэкапим маршруты
        self.route_manager.backup_routes()?;

        // Добавляем маршрут до VPN-сервера
        let server_ip = self.config.main.address.split(':').next().unwrap();
        self.route_manager.add_exclusion_route(server_ip)?;

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

        // 4. Меняем дефолтный шлюз
        self.route_manager
            .set_default_route(&auth_response.gateway, &iface_name)?;

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
    pub async fn stop(&self) -> Result<()> {
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

            // 4. Чиним маршруты (ОЧЕНЬ ВАЖНО ДЛЯ CLI)
            if let Err(e) = self.route_manager.restore_routes() {
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
