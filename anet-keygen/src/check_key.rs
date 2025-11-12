use base64::prelude::*;
use ed25519_dalek::VerifyingKey;
use sha2::{Sha256, Digest};

pub fn check_key_fingerprint(public_key_b64: &str) -> Result<String, Box<dyn std::error::Error>> {
    let public_key_bytes = BASE64_STANDARD.decode(public_key_b64)?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes.try_into()?)?;

    let mut hasher = Sha256::new();
    hasher.update(verifying_key.to_bytes());
    let hash = hasher.finalize();
    let fingerprint = BASE64_STANDARD.encode(&hash[..16]);

    Ok(fingerprint)
}
