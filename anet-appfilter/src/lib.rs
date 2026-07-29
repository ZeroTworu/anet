//! # anet-appfilter
//! Per-app split tunneling для Windows

pub mod flow_map;
pub mod policy;
pub mod proc_name;

#[cfg(all(windows, feature = "windivert"))]
mod windivert_backend;

pub use flow_map::{BypassSet, FlowKey, FlowMap, FlowOwner};
pub use policy::AppPolicy;

use anyhow::{Context, Result};
use bytes::Bytes;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

#[cfg(all(windows, feature = "windivert"))]
use windivert::layer::{NetworkLayer, SocketLayer};
#[cfg(all(windows, feature = "windivert"))]
use windivert::prelude::*;
#[cfg(all(windows, feature = "windivert"))]
use windivert::WinDivert;

#[cfg(all(windows, feature = "windivert"))]
use anet_common::consts::CHANNEL_BUFFER_SIZE;
#[cfg(all(windows, feature = "windivert"))]
use windows::Win32::Foundation::HANDLE;

pub struct AppFilter {
    _map: FlowMap,
    bypass: BypassSet,
    #[cfg(all(windows, feature = "windivert"))]
    socket_handle: Arc<WinDivert<SocketLayer>>,
    #[cfg(all(windows, feature = "windivert"))]
    network_handle: Arc<WinDivert<NetworkLayer>>,
}

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
            ).context("failed to open WinDivert socket layer")?
        );

        // ВАЖНО: Флаг !impostor.
        // Когда мы возвращаем пакет из туннеля в Windows, он помечается как "impostor" (самозванец).
        // Этот флаг в правиле гарантирует, что мы не будем перехватывать собственные реинжектированные пакеты по бесконечному кругу.
        let network_handle = Arc::new(
            WinDivert::<NetworkLayer>::network("(ip || ipv6) && !impostor", 0, WinDivertFlags::new())
                .context("failed to open WinDivert network layer")?
        );

        // Поток 1: Отслеживание сокетов (Строгий контроль открытий/закрытий портов)
        {
            let map = map.clone();
            let handle = socket_handle.clone();
            let nat_map_clone = nat_map.clone();
            let decisions_clone = decisions.clone();
            tokio::task::spawn_blocking(move || {
                if let Err(e) = windivert_backend::run_socket_tracker(handle, map, nat_map_clone, decisions_clone) {
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

            tokio::task::spawn_blocking(move || {
                if let Err(e) = windivert_backend::run_packet_router(
                    handle, map, bypass, policy, uplink_tx, downlink_rx, vpn_ip, nat_map_clone, decisions_clone
                ) {
                    log::error!("appfilter: packet router exited: {e:#}");
                }
            });
        }

        Ok((
            Self {
                _map: map,
                bypass,
                socket_handle,
                network_handle,
            },
            downlink_tx,
            uplink_rx,
        ))
    }

    pub async fn add_bypass(&self, ip: IpAddr) {
        self.bypass.add(ip).await;
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
        log::info!("AppFilter: dropping, forcing shutdown of WinDivert handles via memory layout cast...");
        let socket_raw = unsafe { *(&*self.socket_handle as *const WinDivert<SocketLayer> as *const HANDLE) };
        let network_raw = unsafe { *(&*self.network_handle as *const WinDivert<NetworkLayer> as *const HANDLE) };
        unsafe {
            windivert_sys::WinDivertShutdown(socket_raw, windivert_sys::WinDivertShutdownMode::Both);
            windivert_sys::WinDivertShutdown(network_raw, windivert_sys::WinDivertShutdownMode::Both);
        }
    }
}
