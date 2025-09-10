use base64::{
    Engine as _, alphabet,
    engine::{self, general_purpose},
};
use rand::Rng;
use std::net::Ipv4Addr;

pub fn generate_crypto_key() -> String {
    let mut rng = rand::rng();
    let key: [u8; 32] = rng.random();
    engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD).encode(key)
}

pub fn generate_uid() -> String {
    let mut rng = rand::rng();
    format!("{:x}", rng.random::<u64>())
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
