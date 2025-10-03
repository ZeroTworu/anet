use bytes::{Bytes, BytesMut};
use ring::aead;
use std::convert::TryInto;
use std::sync::Arc;

#[derive(Clone)]
pub struct Cipher {
    key: Arc<aead::LessSafeKey>,
}

impl Cipher {
    pub fn new(key: &[u8]) -> Self {
        let unbound_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key)
            .expect("Invalid key length");
        let key = aead::LessSafeKey::new(unbound_key);
        Self { key: Arc::new(key) }
    }

    #[inline]
    pub fn encrypt(&self, nonce: &[u8], data: Bytes) -> Result<Bytes, EncryptionError> {
        let nonce = aead::Nonce::assume_unique_for_key(nonce.try_into().unwrap());

        // Конвертируем Bytes в BytesMut для in-place шифрования
        let mut buffer = BytesMut::from(data.as_ref());

        // Шифруем данные
        self.key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut buffer)
            .map_err(|_| EncryptionError::EncryptionFailed)?;

        Ok(buffer.freeze())
    }

    #[inline]
    pub fn decrypt(&self, nonce: &[u8], data: Bytes) -> Result<Bytes, EncryptionError> {
        let nonce = aead::Nonce::assume_unique_for_key(nonce.try_into().unwrap());

        // Конвертируем Bytes в BytesMut для in-place дешифрования
        let mut buffer = BytesMut::from(data.as_ref());

        // Дешифруем данные
        self.key.open_in_place(nonce, aead::Aad::empty(), &mut buffer)
            .map_err(|_| EncryptionError::DecryptionFailed)?;

        // Убираем тег аутентификации
        buffer.truncate(buffer.len() - aead::CHACHA20_POLY1305.tag_len());

        Ok(buffer.freeze())
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