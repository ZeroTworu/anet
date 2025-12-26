use anet_client_core::traits::RouteManager;
use anyhow::{Context, Result};
use async_trait::async_trait;
use log::{info, warn, debug};
use net_route::{Handle, Route};
use std::net::{IpAddr, Ipv4Addr};
use tokio::sync::Mutex;

#[derive(Default)]
struct RouteState {
    original_gateway: Option<IpAddr>,
    original_ifindex: Option<u32>,
    server_ip_cache: Option<IpAddr>,
    added_default_routes: Vec<Route>,
}

pub struct DesktopRouteManager {
    handle: Handle,
    state: Mutex<RouteState>, // <-- Tokio Mutex
}

impl DesktopRouteManager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            handle: Handle::new()?,
            state: Mutex::new(RouteState::default()),
        })
    }
}

#[async_trait]
impl RouteManager for DesktopRouteManager {
    async fn backup_routes(&self) -> Result<()> {
        let default_route = self.handle.default_route().await?
            .context("No default route found in system table")?;

        let gateway = default_route.gateway.context("Default route has no gateway")?;
        let ifindex = default_route.ifindex;

        info!("Backup: Gateway {} on iface {}", gateway, ifindex.unwrap());

        // Tokio Mutex: lock().await
        let mut state = self.state.lock().await;
        state.original_gateway = Some(gateway);
        state.original_ifindex = ifindex;

        Ok(())
    }

    async fn add_exclusion_route(&self, server_ip: &str) -> Result<()> {
        let server_ipv4: Ipv4Addr = server_ip.parse().context("Invalid server IP")?;
        let server_ip = IpAddr::V4(server_ipv4);

        // Держим лок через await - теперь это легально!
        let mut state = self.state.lock().await;

        let gateway = state.original_gateway.context("Gateway not backed up")?;
        let ifindex = state.original_ifindex.context("Interface index not backed up")?;

        info!("Setting exclusion route to VPN server: {} via {}", server_ip, gateway);

        let route = Route::new(server_ip, 32)
            .with_gateway(gateway)
            .with_ifindex(ifindex)
            .with_metric(1);

        // Мы держим state, но вызываем self.handle. Это безопасно.
        let _ = self.handle.delete(&route).await;
        self.handle.add(&route).await.context("Failed to add exclusion route via API")?;

        state.server_ip_cache = Some(server_ip);

        Ok(())
    }

    async fn set_default_route(&self, _gateway: &str, interface_name: &str) -> Result<()> {
        let interfaces = netdev::get_interfaces();
        let tun_iface = interfaces.iter()
            .find(|i| i.name == interface_name || i.friendly_name.as_deref() == Some(interface_name))
            .context("TUN interface not found")?;

        let tun_index = tun_iface.index;
        info!("Redirecting all traffic to TUN (index: {})", tun_index);

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
                state.added_default_routes.push(route);
            }
        }

        Ok(())
    }

    async fn restore_routes(&self) -> Result<()> {
        info!("Restoring original routing...");
        let mut state = self.state.lock().await;

        // Удаляем маршруты-перенаправления
        // Идем с конца, как настоящие самураи (LIFO)
        while let Some(route) = state.added_default_routes.pop() {
            debug!("Removing redirect route...");
            let _ = self.handle.delete(&route).await;
        }

        // Удаляем маршрут к серверу
        if let Some(server_ip) = state.server_ip_cache.take() {
            if let (Some(gw), Some(idx)) = (state.original_gateway, state.original_ifindex) {
                let route = Route::new(server_ip, 32)
                    .with_gateway(gw)
                    .with_ifindex(idx)
                    .with_metric(1);

                info!("Removing exclusion route to {}", server_ip);
                let _ = self.handle.delete(&route).await;
            }
        }

        info!("Routing restored.");
        Ok(())
    }
}