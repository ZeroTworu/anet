use crate::auth_provider::AuthProvider;
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
use std::time::{Duration, Instant};

pub struct ClientTransportInfo {
    pub cipher: Arc<Cipher>,
    pub sequence: Arc<AtomicU64>,
    pub assigned_ip: String,
    pub session_id: String,
    pub nonce_prefix: [u8; 4],
    pub remote_addr: ArcSwap<SocketAddr>,
    pub fingerprint: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_provider::AuthProvider;
    use tokio::sync::mpsc;

    fn registry() -> ClientRegistry {
        ClientRegistry::new(
            IpPool::new(
                "10.0.0.0".parse().unwrap(),
                "255.255.255.0".parse().unwrap(),
                "10.0.0.1".parse().unwrap(),
                "10.0.0.2".parse().unwrap(),
                1400,
            ),
            Arc::new(AuthProvider::new(vec![], vec![], String::new())),
        )
    }

    fn client(session_id: &str, fingerprint: &str) -> Arc<ClientTransportInfo> {
        Arc::new(ClientTransportInfo {
            cipher: Arc::new(Cipher::new(&[7u8; 32])),
            sequence: Arc::new(AtomicU64::new(0)),
            assigned_ip: "10.0.0.3".to_string(),
            session_id: session_id.to_string(),
            nonce_prefix: [1, 2, 3, 4],
            remote_addr: ArcSwap::new(Arc::new("127.0.0.1:12345".parse().unwrap())),
            fingerprint: fingerprint.to_string(),
        })
    }

    #[tokio::test]
    async fn suspended_session_resumes_only_for_same_identity() {
        let registry = registry();
        let client = client("session-1", "fingerprint-1");
        let (router, _receiver) = mpsc::channel(1);
        registry.pre_register_client(client.clone());
        registry.finalize_client(&client.assigned_ip, router);
        registry.suspend_client(client);

        assert!(!registry.can_resume("session-1", "somebody-else"));
        assert!(
            registry
                .take_suspended("session-1", "somebody-else")
                .is_none()
        );
        assert!(registry.can_resume("session-1", "fingerprint-1"));
        let resumed = registry
            .take_suspended("session-1", "fingerprint-1")
            .expect("session must resume");
        assert_eq!(resumed.assigned_ip, "10.0.0.3");
        assert!(!registry.can_resume("session-1", "fingerprint-1"));
    }
}

struct SuspendedSession {
    client_info: Arc<ClientTransportInfo>,
    expires_at: Instant,
}

const RESUME_WINDOW: Duration = Duration::from_secs(45);

#[derive(Clone)]
pub struct ClientRegistry {
    clients_by_prefix: Arc<DashMap<[u8; 4], Arc<ClientTransportInfo>>>,
    clients_by_addr: Arc<DashMap<SocketAddr, Arc<ClientTransportInfo>>>,
    quic_router: Arc<DashMap<String, StreamSender>>,
    suspended_sessions: Arc<DashMap<String, SuspendedSession>>,
    auth_provider: Arc<AuthProvider>,
    ip_pool: IpPool,
}

impl ClientRegistry {
    pub fn new(ip_pool: IpPool, auth_provider: Arc<AuthProvider>) -> Self {
        Self {
            clients_by_prefix: Arc::new(DashMap::new()),
            clients_by_addr: Arc::new(DashMap::new()),
            quic_router: Arc::new(DashMap::new()),
            suspended_sessions: Arc::new(DashMap::new()),
            auth_provider,
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

        // dec sessions
        let ap = self.auth_provider.clone();
        let fp = client_info.fingerprint.clone();

        tokio::spawn(async move {
            ap.report_session_stop(fp).await;
        });

        info!("[Registry] Client {} removed.", client_ip);
    }

    pub fn suspend_client(&self, client_info: Arc<ClientTransportInfo>) {
        let client_ip = client_info.assigned_ip.clone();
        let remote_addr = **client_info.remote_addr.load();
        self.quic_router.remove(&client_ip);
        self.clients_by_prefix.remove(&client_info.nonce_prefix);
        self.clients_by_addr.remove(&remote_addr);
        self.suspended_sessions.insert(
            client_info.session_id.clone(),
            SuspendedSession {
                client_info,
                expires_at: Instant::now() + RESUME_WINDOW,
            },
        );
        info!("[Registry] Session {} suspended for WS resume", client_ip);
    }

    pub fn take_suspended(
        &self,
        session_id: &str,
        fingerprint: &str,
    ) -> Option<Arc<ClientTransportInfo>> {
        if session_id.is_empty() {
            return None;
        }
        let valid = self
            .suspended_sessions
            .get(session_id)
            .is_some_and(|entry| {
                entry.expires_at > Instant::now() && entry.client_info.fingerprint == fingerprint
            });
        if !valid {
            return None;
        }
        self.suspended_sessions
            .remove(session_id)
            .map(|(_, session)| session.client_info)
    }

    pub fn can_resume(&self, session_id: &str, fingerprint: &str) -> bool {
        !session_id.is_empty()
            && self
                .suspended_sessions
                .get(session_id)
                .is_some_and(|entry| {
                    entry.expires_at > Instant::now()
                        && entry.client_info.fingerprint == fingerprint
                })
    }

    pub fn cleanup_suspended(&self) {
        let expired: Vec<String> = self
            .suspended_sessions
            .iter()
            .filter(|entry| entry.expires_at <= Instant::now())
            .map(|entry| entry.key().clone())
            .collect();
        for session_id in expired {
            if let Some((_, session)) = self.suspended_sessions.remove(&session_id) {
                self.finish_suspended(session.client_info);
            }
        }
    }

    fn finish_suspended(&self, client_info: Arc<ClientTransportInfo>) {
        if let Ok(ip_addr) = client_info.assigned_ip.parse::<Ipv4Addr>() {
            self.ip_pool.release(ip_addr);
        }
        let auth_provider = self.auth_provider.clone();
        let fingerprint = client_info.fingerprint.clone();
        tokio::spawn(async move {
            auth_provider.report_session_stop(fingerprint).await;
        });
        info!(
            "[Registry] Suspended session {} expired",
            client_info.session_id
        );
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
        // NAT rebinding is rare. Keep the common path read-only and allocation-free instead of
        // swapping a new Arc for every received QUIC datagram.
        if **client_info.remote_addr.load() == new_addr {
            return;
        }

        let old_addr_arc = client_info.remote_addr.swap(Arc::new(new_addr));
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
