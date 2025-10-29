use base64::{
    Engine as _, alphabet,
    engine::{self, general_purpose},
};
use chacha20poly1305::aead::rand_core::RngCore;
use rand;
use std::net::Ipv4Addr;

#[inline]
pub fn generate_crypto_key() -> [u8; 32] {
    let mut rng = rand::thread_rng();
    let mut crypto_key = [0u8; 32];
    rng.fill_bytes(&mut crypto_key);
    crypto_key
}

#[inline]
pub fn generate_seid() -> String {
    let mut rng = rand::thread_rng();
    let mut client_id = [0u8; 16];
    rng.fill_bytes(&mut client_id);
    engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD).encode(client_id)
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
