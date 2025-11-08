use aead::{Aead, KeyInit, Nonce};
use aes_gcm::Key;
use bytes::Bytes;
use chacha20poly1305::ChaCha20Poly1305;
use std::sync::Arc;

// Заменить на `ChaCha20Poly1305` при необходимости.
type CryptoAlgorithm = ChaCha20Poly1305;

#[derive(Clone)]
pub struct Cipher {
    cipher: Arc<CryptoAlgorithm>,
}

impl Cipher {
    pub fn new(key: &[u8]) -> Self {
        if key.len() != 32 {
            panic!("Invalid key length for AES-256-GCM. Must be 32 bytes.");
        }

        let key_generic: &Key<CryptoAlgorithm> = key.try_into().expect("Key must be 32 bytes");

        Self {
            cipher: Arc::new(CryptoAlgorithm::new(key_generic)),
        }
    }

    #[inline]
    pub fn encrypt(&self, nonce_bytes: &[u8], data: Bytes) -> Result<Bytes, EncryptionError> {
        let nonce = Nonce::<CryptoAlgorithm>::from_slice(nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, data.as_ref())
            .map_err(|_| EncryptionError::EncryptionFailed)?;

        Ok(Bytes::from(ciphertext))
    }

    #[inline]
    pub fn decrypt(&self, nonce_bytes: &[u8], data: Bytes) -> Result<Bytes, EncryptionError> {
        let nonce = Nonce::<CryptoAlgorithm>::from_slice(nonce_bytes);

        let plaintext = self
            .cipher
            .decrypt(nonce, data.as_ref())
            .map_err(|_| EncryptionError::DecryptionFailed)?;

        Ok(Bytes::from(plaintext))
    }
    pub fn generate_nonce(sequence: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&sequence.to_be_bytes());
        nonce
    }
}

#[derive(Debug)]
pub enum EncryptionError {
    EncryptionFailed,
    DecryptionFailed,
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionError::EncryptionFailed => write!(f, "Encryption failed"),
            EncryptionError::DecryptionFailed => write!(f, "Decryption failed"),
        }
    }
}

impl std::error::Error for EncryptionError {}
