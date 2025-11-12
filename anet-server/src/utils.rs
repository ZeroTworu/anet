use crate::multikey_udp_socket::ClientTransportInfo;
use base64::{Engine as _, engine::general_purpose};
use chacha20poly1305::aead::rand_core::RngCore;
use dashmap::DashMap;
use rand::rngs::OsRng;
use std::net::Ipv4Addr;
use std::sync::Arc;

#[inline]
pub fn generate_seid() -> String {
    let mut rng = rand::thread_rng();
    let mut session_id = [0u8; 16];
    rng.fill_bytes(&mut session_id);
    general_purpose::STANDARD.encode(session_id)
}

#[inline]
pub fn extract_ip_dst(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < 20 {
        return None;
    }

    if (pkt[0] >> 4) != 4 {
        return None;
    }

    Some(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
}

#[inline]
pub fn generate_unique_nonce_prefix(
    clients_by_prefix: Arc<DashMap<[u8; 4], Arc<ClientTransportInfo>>>,
) -> [u8; 4] {
    let mut rng = OsRng;
    loop {
        let mut prefix = [0u8; 4];
        rng.fill_bytes(&mut prefix);
        // Обеспечение уникальности в DashMap (для O(1) Rx)
        if !clients_by_prefix.contains_key(&prefix) {
            return prefix;
        }
    }
}
