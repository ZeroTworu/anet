use crate::auth_handler::AuthHandler;
use crate::config::Config;
use crate::router::RouteManager;
use crate::vpn_handler::VpnHandler;
use anyhow::Result;
use log::{error, info};

pub struct ANetClient {
    cfg: Config,
}

impl ANetClient {
    pub fn new(cfg: Config) -> Self {
        Self { cfg }
    }

    pub async fn run(&self) -> Result<()> {
        info!("[ANet] Client starting...");

        // --- ЭТАП 1: Аутентификация ---
        let auth_handler = AuthHandler::new(&self.cfg)?;
        let (auth_response, shared_key) = auth_handler.authenticate().await?;

        // --- ЭТАП 2: Настройка маршрутизации ---
        let server_ip_str = self.cfg.main.address.split(':').next().unwrap().to_string();
        let mut router = RouteManager::new(server_ip_str);

        #[cfg(unix)]
        router.backup_original_routes()?;
        router.setup_exclusion_route()?;

        // --- ЭТАП 3: Запуск VPN ---
        let vpn_handler = VpnHandler::new(&self.cfg)?;
        let endpoint_result = vpn_handler.run(&auth_response, shared_key).await;

        if endpoint_result.is_ok() {
            #[cfg(unix)]
            {
                router
                    .set_vpn_as_default_gateway(&auth_response.gateway, &self.cfg.main.tun_name)?;
            }
        }

        // --- ЭТАП 4: Основной цикл работы и ожидание завершения ---
        match endpoint_result {
            Ok(endpoint) => {
                info!("[ANet] VPN is running. Press Ctrl-C to exit.");
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => info!("[ANet] Ctrl-C received. Shutting down."),
                    _ = endpoint.wait_idle() => info!("[ANet] Connection lost. Exiting."),
                }
            }
            Err(e) => {
                error!("[ANet] Failed to start VPN operation: {}", e);
            }
        }

        // --- ЭТАП 5: Восстановление маршрутизации ---
        router.restore_routing()?;
        info!("[ANet] Shutdown complete.");
        Ok(())
    }
}
