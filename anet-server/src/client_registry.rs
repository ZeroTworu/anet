use crate::ip_pool::IpPool;
use crate::multikey_udp_socket::StreamSender;
use anet_common::encryption::Cipher;
use arc_swap::ArcSwap;
use bytes::Bytes;
use dashmap::DashMap;
use log::{info, warn};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

pub struct ClientTransportInfo {
    pub cipher: Arc<Cipher>,
    pub sequence: Arc<AtomicU64>,
    pub assigned_ip: String,
    pub session_id: String,
    pub nonce_prefix: [u8; 4],
    pub remote_addr: ArcSwap<SocketAddr>,
}

#[derive(Clone)]
pub struct ClientRegistry {
    clients_by_prefix: Arc<DashMap<[u8; 4], Arc<ClientTransportInfo>>>,
    clients_by_addr: Arc<DashMap<SocketAddr, Arc<ClientTransportInfo>>>,
    quic_router: Arc<DashMap<String, StreamSender>>,
    ip_pool: IpPool,
}

impl ClientRegistry {
    pub fn new(ip_pool: IpPool) -> Self {
        Self {
            clients_by_prefix: Arc::new(DashMap::new()),
            clients_by_addr: Arc::new(DashMap::new()),
            quic_router: Arc::new(DashMap::new()),
            ip_pool,
        }
    }

    pub fn get_network_params(&self) -> (String, String, i32) {
        (
            self.ip_pool.netmask.to_string(),
            self.ip_pool.gateway.to_string(),
            self.ip_pool.mtu as i32,
        )
    }

    pub fn pre_register_client(&self, client_info: Arc<ClientTransportInfo>) {
        let remote_addr = **client_info.remote_addr.load();
        info!(
            "[Registry] Pre-registered client {} for address {}",
            client_info.assigned_ip, remote_addr
        );
        self.clients_by_prefix
            .insert(client_info.nonce_prefix, client_info.clone());
        self.clients_by_addr.insert(remote_addr, client_info);
    }

    pub fn finalize_client(&self, client_ip: &str, router_sender: StreamSender) {
        self.quic_router
            .insert(client_ip.to_string(), router_sender);
        info!(
            "[Registry] Finalized client {}. Total active clients: {}",
            client_ip,
            self.quic_router.len()
        );
    }

    pub fn remove_client(&self, client_info: &ClientTransportInfo) {
        let client_ip = &client_info.assigned_ip;
        let remote_addr = **client_info.remote_addr.load();

        self.quic_router.remove(client_ip);
        self.clients_by_prefix.remove(&client_info.nonce_prefix);
        self.clients_by_addr.remove(&remote_addr);

        if let Ok(ip_addr) = client_ip.parse::<Ipv4Addr>() {
            self.ip_pool.release(ip_addr);
        }
        info!("[Registry] Client {} removed.", client_ip);
    }

    pub fn allocate_ip(&self) -> Option<Ipv4Addr> {
        self.ip_pool.allocate()
    }

    pub fn get_by_addr(&self, remote_addr: &SocketAddr) -> Option<Arc<ClientTransportInfo>> {
        self.clients_by_addr
            .get(remote_addr)
            .map(|entry| entry.value().clone())
    }

    pub fn get_by_prefix(&self, nonce_prefix: &[u8; 4]) -> Option<Arc<ClientTransportInfo>> {
        self.clients_by_prefix
            .get(nonce_prefix)
            .map(|entry| entry.value().clone())
    }

    pub fn update_client_addr(&self, client_info: &Arc<ClientTransportInfo>, new_addr: SocketAddr) {
        let old_addr_arc = client_info.remote_addr.swap(Arc::new(new_addr));
        // ИСПРАВЛЕНИЕ: Разыменовываем Arc<SocketAddr>
        let old_addr = *old_addr_arc;

        if old_addr == new_addr {
            return;
        }

        if let Some((_, client)) = self.clients_by_addr.remove(&old_addr) {
            self.clients_by_addr.insert(new_addr, client);
            info!(
                "[Registry] Client {} roamed from {} to {}",
                client_info.assigned_ip, old_addr, new_addr
            );
        }
    }

    pub async fn route_packet_to_client(&self, dst_ip: &str, packet: Bytes) {
        if let Some(sender) = self.quic_router.get(dst_ip) {
            if sender.send(packet).await.is_err() {
                warn!("[Registry] Failed to route to {}: channel closed.", dst_ip);
            }
        }
    }
}
