
use base64::prelude::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

pub struct GeneratedIdentity {
    pub private_key: String,
    pub public_key: String,
    pub fingerprint: String,
}

pub fn generate_identity() -> GeneratedIdentity {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let private_key = BASE64_STANDARD.encode(signing_key.to_bytes());
    let public_key = BASE64_STANDARD.encode(verifying_key.to_bytes());
    let fingerprint = generate_fingerprint(&verifying_key);

    GeneratedIdentity {
        private_key,
        public_key,
        fingerprint,
    }
}

fn generate_fingerprint(public_key: &VerifyingKey) -> String {
    let key_bytes = public_key.to_bytes();
    let mut hasher = Sha256::new();
    hasher.update(&key_bytes);
    let hash = hasher.finalize();
    BASE64_STANDARD.encode(&hash[..16])
}
