use anet_common::encryption::Cipher;
use base64::prelude::*;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::env;

/// крипто-слой для бесшовной защиты конфиденциальных полей в PostgreSQL
pub struct DbEncryptor {
    cipher: Cipher,
}

impl DbEncryptor {
    pub fn new() -> Self {
        // Читаем ключ шифрования СУБД из конфига докера
        let master_key = env::var("DB_ENCRYPTION_KEY")
            .unwrap_or_else(|_| "secret_na_chushpana_encryption_key_change_me_123".to_string());

        // Хешируем мастер-ключ через SHA256, чтобы получить ровно 32 байта для шифра ChaCha20
        let mut hasher = Sha256::new();
        hasher.update(master_key.as_bytes());
        let derived_key: [u8; 32] = hasher.finalize().into();

        Self {
            cipher: Cipher::new(&derived_key),
        }
    }

    /// Шифрует строку и возвращает Base64-строку вида: [nonce_12_bytes][ciphertext]
    pub fn encrypt(&self, plaintext: &str) -> anyhow::Result<String> {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let ciphertext = self
            .cipher
            .encrypt(&nonce, bytes::Bytes::copy_from_slice(plaintext.as_bytes()))
            .map_err(|e| anyhow::anyhow!("Encryption error: {}", e))?;

        let mut combined = Vec::with_capacity(12 + ciphertext.len());
        combined.extend_from_slice(&nonce);
        combined.extend_from_slice(&ciphertext);

        Ok(BASE64_STANDARD.encode(combined))
    }

    /// Дешифрует Base64-строку из БД обратно в читаемый плейн-текст
    pub fn decrypt(&self, ciphertext_b64: &str) -> anyhow::Result<String> {
        let decoded = BASE64_STANDARD
            .decode(ciphertext_b64)
            .map_err(|e| anyhow::anyhow!("Base64 decode failed: {}", e))?;

        if decoded.len() < 12 {
            anyhow::bail!("Invalid encrypted payload: too short");
        }

        let (nonce, ciphertext) = decoded.split_at(12);
        let decrypted_bytes = self
            .cipher
            .decrypt(nonce, bytes::Bytes::copy_from_slice(ciphertext))
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        String::from_utf8(decrypted_bytes.to_vec())
            .map_err(|e| anyhow::anyhow!("UTF-8 conversion failed: {}", e))
    }
}