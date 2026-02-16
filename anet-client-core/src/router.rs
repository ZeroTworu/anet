#[cfg(target_os = "macos")]
pub mod macos {
    pub use crate::router_macos::MacOSRouteManager;
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub mod desktop {
    use crate::traits::RouteManager;
    use anyhow::Context;
    use anyhow::Result;
    use async_trait::async_trait;
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

        /// Fallback: parse /proc/net/route to get default gateway
        /// Used when net_route crate returns None for gateway (OpenWRT compatibility)
        #[cfg(target_os = "linux")]
        fn parse_proc_route_gateway() -> Option<(IpAddr, u32)> {
            use std::fs::File;
            use std::io::{BufRead, BufReader};

            let file = File::open("/proc/net/route").ok()?;
            let reader = BufReader::new(file);

            for line in reader.lines().skip(1) {
                let line = line.ok()?;
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 8 {
                    continue;
                }

                let dest = fields[1];
                let gateway_hex = fields[2];
                let iface_name = fields[0];

                // Match default route (dest=00000000) with non-zero gateway
                if dest == "00000000" && gateway_hex != "00000000" {
                    if let Ok(gw_u32) = u32::from_str_radix(gateway_hex, 16) {
                        // Convert from little-endian hex to IP address
                        let gw_bytes = gw_u32.to_le_bytes();
                        let gateway = IpAddr::V4(Ipv4Addr::new(
                            gw_bytes[0],
                            gw_bytes[1],
                            gw_bytes[2],
                            gw_bytes[3],
                        ));

                        // Try to get interface index
                        let ifindex = Self::get_iface_index(iface_name).ok();

                        info!(
                            "Fallback: parsed gateway {} from /proc/net/route (iface: {})",
                            gateway, iface_name
                        );
                        return Some((gateway, ifindex.unwrap_or(0)));
                    }
                }
            }
            None
        }

        #[cfg(not(target_os = "linux"))]
        fn parse_proc_route_gateway() -> Option<(IpAddr, u32)> {
            None
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

            // Try to get gateway from net_route crate first
            // If it returns None (OpenWRT issue), fall back to /proc/net/route parsing
            let (gateway, ifindex) = if let Some(gw) = default_route.gateway {
                (gw, default_route.ifindex)
            } else {
                warn!("net_route returned None for gateway, trying /proc/net/route fallback...");
                if let Some((gw, idx)) = Self::parse_proc_route_gateway() {
                    (gw, Some(idx))
                } else {
                    return Err(anyhow::anyhow!(
                        "Default route has no gateway (net_route and /proc/net/route both failed)"
                    ));
                }
            };

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
