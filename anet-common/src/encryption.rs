use aead::{Aead, AeadInPlace, KeyInit, Nonce, Tag}; // <--- Добавили AeadInPlace
use aes_gcm::Key;
// use aes_gcm::Aes256Gcm;
use bytes::Bytes;
use chacha20poly1305::ChaCha20Poly1305;
use std::sync::Arc;

// Заменить на `ChaCha20Poly1305` / `Aes256Gcm` при необходимости.
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

    /// Расшифровывает данные прямо в переданном буфере.
    /// Буфер должен содержать [Ciphertext + Tag].
    /// После успеха буфер будет содержать [Plaintext], а "хвост" (где был тег) станет мусором.
    #[inline]
    pub fn decrypt_in_place(&self, nonce_bytes: &[u8], buffer: &mut [u8]) -> Result<(), EncryptionError> {
        let nonce = Nonce::<CryptoAlgorithm>::from_slice(nonce_bytes);
        let len = buffer.len();

        // 16 байт - размер тега Poly1305 для ChaCha20Poly1305
        if len < 16 {
            return Err(EncryptionError::DecryptionFailed);
        }

        // Разделяем буфер на сообщение и тег
        let (msg, tag_bytes) = buffer.split_at_mut(len - 16);
        let tag = Tag::<CryptoAlgorithm>::from_slice(tag_bytes);

        // Используем detached версию, которая работает с сырыми слайсами
        self.cipher
            .decrypt_in_place_detached(nonce, &[], msg, tag)
            .map_err(|_| EncryptionError::DecryptionFailed)?;

        Ok(())
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