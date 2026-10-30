//! # anet-appfilter
//! Per-app split tunneling для Windows

pub mod flow_map;
pub mod policy;
pub mod proc_name;

#[cfg(all(windows, feature = "windivert"))]
mod windivert_backend;

pub use flow_map::{BypassSet, FlowKey, FlowMap, FlowOwner};
pub use policy::AppPolicy;

use anyhow::Result;
use bytes::Bytes;
use ipnet::IpNet;
use std::net::IpAddr;
use tokio::sync::mpsc;

#[cfg(all(windows, feature = "windivert"))]
use anyhow::Context;
#[cfg(all(windows, feature = "windivert"))]
use std::sync::Arc;

#[cfg(all(windows, feature = "windivert"))]
use windivert::layer::{NetworkLayer, SocketLayer};
#[cfg(all(windows, feature = "windivert"))]
use windivert::prelude::*;
#[cfg(all(windows, feature = "windivert"))]
use windivert::{ShutdownHandle, WinDivert};

#[cfg(all(windows, feature = "windivert"))]
use anet_common::consts::CHANNEL_BUFFER_SIZE;

pub struct AppFilter {
    _map: FlowMap,
    bypass: BypassSet,
    #[cfg(all(windows, feature = "windivert"))]
    socket_shutdown: ShutdownHandle,
    #[cfg(all(windows, feature = "windivert"))]
    network_shutdown: ShutdownHandle,
}

// Безопасно: FlowMap и BypassSet являются Send + Sync, а ShutdownHandle содержит Weak<HANDLE>
// (в windows 0.62 HANDLE — это *mut c_void, а в windivert 0.7.0-beta.4 для ShutdownHandle
// реализован только unsafe impl Send, но пропущен Sync) и используется исключительно в Drop (&mut self).
unsafe impl Send for AppFilter {}
unsafe impl Sync for AppFilter {}

impl AppFilter {
    #[cfg(all(windows, feature = "windivert"))]
    pub fn start(
        policy: AppPolicy,
        initial_bypass: impl IntoIterator<Item = IpAddr>,
        vpn_ip: IpAddr,
    ) -> Result<(Self, mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>)> {
        let map = FlowMap::new();
        let bypass = BypassSet::with_initial(initial_bypass);
        let nat_map: windivert_backend::NatMap = Arc::new(dashmap::DashMap::new());
        let decisions: windivert_backend::DecisionSet = Arc::new(dashmap::DashMap::new());
        let logged_bypass: windivert_backend::LoggedBypass = Arc::new(dashmap::DashMap::new());

        let (uplink_tx, uplink_rx) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
        let (downlink_tx, downlink_rx) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);

        let socket_flags = WinDivertFlags::new().set_sniff();
        let socket_handle = Arc::new(
            WinDivert::<SocketLayer>::socket(
                "(protocol == 6 || protocol == 17) \
                 && localPort != 1900 \
                 && localPort != 5353 \
                 && localPort != 137 \
                 && localPort != 138 \
                 && localPort != 139",
                0,
                socket_flags,
            )
            .context("failed to open WinDivert socket layer")?,
        );
        let socket_shutdown = socket_handle.shutdown_handle();

        // Сразу после открытия SocketLayer снимаем снимок уже открытых в системе TCP/UDP сокетов
        // (чтобы приложения, запущенные до включения VPN, такие как BitTorrent, игры или браузеры,
        // были известны до старта перехвата пакетов в NetworkLayer).
        map.populate_initial_sockets();

        // ВАЖНО: Флаг !impostor.
        // Когда мы возвращаем пакет из туннеля в Windows, он помечается как "impostor" (самозванец).
        // Этот флаг в правиле гарантирует, что мы не будем перехватывать собственные реинжектированные пакеты по бесконечному кругу.
        let network_handle = Arc::new(
            WinDivert::<NetworkLayer>::network(
                "(ip || ipv6) && !impostor",
                0,
                WinDivertFlags::new(),
            )
            .context("failed to open WinDivert network layer")?,
        );
        let network_shutdown = network_handle.shutdown_handle();

        // Поток 1: Отслеживание сокетов (Строгий контроль открытий/закрытий портов)
        {
            let map = map.clone();
            let handle = socket_handle.clone();
            let nat_map_clone = nat_map.clone();
            let decisions_clone = decisions.clone();
            let logged_bypass_clone = logged_bypass.clone();
            tokio::task::spawn_blocking(move || {
                if let Err(e) = windivert_backend::run_socket_tracker(
                    handle,
                    map,
                    nat_map_clone,
                    decisions_clone,
                    logged_bypass_clone,
                ) {
                    log::error!("appfilter: socket tracker exited: {e:#}");
                }
            });
        }

        // Поток 2: Роутер пакетов (Перехват, SNAT/DNAT и отправка в туннель)
        {
            let map = map.clone();
            let bypass = bypass.clone();
            let handle = network_handle.clone();
            let nat_map_clone = nat_map.clone();
            let decisions_clone = decisions.clone();
            let logged_bypass_clone = logged_bypass.clone();

            tokio::task::spawn_blocking(move || {
                if let Err(e) = windivert_backend::run_packet_router(
                    handle,
                    map,
                    bypass,
                    policy,
                    uplink_tx,
                    downlink_rx,
                    vpn_ip,
                    nat_map_clone,
                    decisions_clone,
                    logged_bypass_clone,
                ) {
                    log::error!("appfilter: packet router exited: {e:#}");
                }
            });
        }

        Ok((
            Self {
                _map: map,
                bypass,
                socket_shutdown,
                network_shutdown,
            },
            downlink_tx,
            uplink_rx,
        ))
    }

    pub async fn add_bypass(&self, ip: IpAddr) {
        self.bypass.add(ip).await;
    }

    pub fn add_bypass_sync(&self, ip: IpAddr) {
        self.bypass.add_sync(ip);
    }

    pub fn add_bypass_net(&self, net: IpNet) {
        self.bypass.add_net_sync(net);
    }

    pub fn bypass_set(&self) -> BypassSet {
        self.bypass.clone()
    }

    #[cfg(not(all(windows, feature = "windivert")))]
    pub fn start(
        _policy: AppPolicy,
        _initial_bypass: impl IntoIterator<Item = IpAddr>,
        _vpn_ip: IpAddr,
    ) -> Result<(Self, mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>)> {
        anyhow::bail!("anet-appfilter is only supported on Windows")
    }
}

#[cfg(all(windows, feature = "windivert"))]
impl Drop for AppFilter {
    fn drop(&mut self) {
        log::info!("AppFilter: shutting down WinDivert handles via ShutdownHandle...");
        if let Err(e) = self.socket_shutdown.shutdown() {
            log::debug!("AppFilter: socket shutdown returned: {e}");
        }
        if let Err(e) = self.network_shutdown.shutdown() {
            log::debug!("AppFilter: network shutdown returned: {e}");
        }
    }
}