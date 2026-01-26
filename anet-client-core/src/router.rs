
#[cfg(any(target_os = "windows", target_os = "linux"))]
pub mod desktop {
    use crate::traits::RouteManager;
    use anyhow::Result;
    use async_trait::async_trait;
    use anyhow::Context;
    use log::{debug, error, info, warn};
    use net_route::{Handle, Route};
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::sync::Mutex;

    #[derive(Default)]
    struct RouteState {
        original_gateway: Option<IpAddr>,
        original_ifindex: Option<u32>,
        added_routes: Vec<Route>, // Список всех добавленных маршрутов для очистки
    }

    pub struct DesktopRouteManager {
        handle: Handle,
        state: Mutex<RouteState>,
    }

    impl DesktopRouteManager {
        pub fn new() -> Result<Self> {
            Ok(Self {
                handle: Handle::new()?,
                state: Mutex::new(RouteState::default()),
            })
        }

        // Хелпер для получения индекса интерфейса
        fn get_iface_index(name: &str) -> Result<u32> {
            let interfaces = netdev::get_interfaces();
            let iface = interfaces
                .iter()
                .find(|i| i.name == name || i.friendly_name.as_deref() == Some(name))
                .context(format!("Interface '{}' not found", name))?;
            Ok(iface.index)
        }
    }

    #[async_trait]
    impl RouteManager for DesktopRouteManager {
        async fn backup_routes(&self) -> Result<()> {
            let default_route = self
                .handle
                .default_route()
                .await?
                .context("No default route found in system table")?;

            let gateway = default_route
                .gateway
                .context("Default route has no gateway")?;
            let ifindex = default_route.ifindex;

            info!("Backup: Gateway {} on iface {:?}", gateway, ifindex);

            let mut state = self.state.lock().await;
            state.original_gateway = Some(gateway);
            state.original_ifindex = ifindex;

            Ok(())
        }

        async fn add_bypass_route(&self, target: IpAddr, prefix: u8) -> Result<()> {
            let mut state = self.state.lock().await;

            let gateway = state.original_gateway.context("Gateway not backed up")?;
            let ifindex = state
                .original_ifindex
                .context("Interface index not backed up")?;

            info!(
                "Adding BYPASS route for {}/{} via physical gateway {}",
                target, prefix, gateway
            );

            let route = Route::new(target, prefix)
                .with_gateway(gateway)
                .with_ifindex(ifindex)
                .with_metric(1); // Низкая метрика (высокий приоритет)

            // Удаляем старый если был
            let _ = self.handle.delete(&route).await;

            // Добавляем
            self.handle
                .add(&route)
                .await
                .context("Failed to add bypass route")?;

            // Сохраняем в список, чтобы потом удалить при выключении VPN
            // (хотя для server_ip мы раньше использовали отдельное поле,
            // теперь можно всё хранить в added_routes, если мы корректно чистим LIFO)
            state.added_routes.push(route);

            Ok(())
        }

        async fn set_default_route(&self, _gateway: &str, interface_name: &str) -> Result<()> {
            let tun_index = Self::get_iface_index(interface_name)?;
            info!("Redirecting ALL traffic to TUN (index: {})", tun_index);

            let routes_to_add = vec![
                Route::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1)
                    .with_ifindex(tun_index)
                    .with_metric(1),
                Route::new(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1)
                    .with_ifindex(tun_index)
                    .with_metric(1),
            ];

            let mut state = self.state.lock().await;
            for route in routes_to_add {
                let _ = self.handle.delete(&route).await;
                if let Err(e) = self.handle.add(&route).await {
                    warn!("Failed to add redirect route {:?}: {}", route, e);
                } else {
                    state.added_routes.push(route);
                }
            }
            Ok(())
        }

        async fn add_specific_route(
            &self,
            target: IpAddr,
            prefix: u8,
            _gateway: &str,
            interface_name: &str,
        ) -> Result<()> {
            let tun_index = Self::get_iface_index(interface_name)?;

            let route = Route::new(target, prefix)
                .with_ifindex(tun_index)
                .with_metric(1);

            let mut state = self.state.lock().await;

            // Пытаемся удалить старый маршрут, если он есть (игнорируем ошибку)
            let _ = self.handle.delete(&route).await;

            match self.handle.add(&route).await {
                Ok(_) => {
                    info!("Added split-tunnel route: {}/{} via TUN", target, prefix);
                    state.added_routes.push(route);
                    Ok(())
                }
                Err(e) => {
                    error!("Failed to add route {}/{}: {}", target, prefix, e);
                    Err(anyhow::anyhow!(e))
                }
            }
        }

        async fn restore_routes(&self) -> Result<()> {
            info!("Restoring original routing...");
            let mut state = self.state.lock().await;

            // Удаляем все маршруты (Global, Specific, Bypass) в обратном порядке
            while let Some(route) = state.added_routes.pop() {
                debug!("Removing route to {}/{}", route.destination, route.prefix);
                let _ = self.handle.delete(&route).await;
            }

            info!("Routing restored.");
            Ok(())
        }
    }
}
