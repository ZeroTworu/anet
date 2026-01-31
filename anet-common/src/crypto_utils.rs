use crate::encryption::Cipher;
use base64::prelude::*;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use x25519_dalek::SharedSecret;

/// Создает Cipher для шифрования/дешифрования ПЕРВОГО пакета (Handshake).
/// В качестве ключа используется SHA256 от публичного ключа сервера (Ed25519).
/// Обеспечивает обфускацию: пакет выглядит как шум для любого, кто не знает PubKey сервера.
pub fn create_handshake_cipher(server_pub_key_bytes: &[u8]) -> Cipher {
    let mut hasher = Sha256::new();
    hasher.update(server_pub_key_bytes);
    let key: [u8; 32] = hasher.finalize().into();
    Cipher::new(&key)
}

/// Выведение симметричного ключа из DH Shared Secret
pub fn derive_shared_key(shared_secret: &SharedSecret) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(shared_secret.as_bytes());
    let output: [u8; 32] = hasher.finalize().into();
    output
}

/// Подписывает данные личным ключом клиента
pub fn sign_data(signing_key: &SigningKey, data: &[u8]) -> Vec<u8> {
    let signature: Signature = signing_key.sign(data);
    signature.to_bytes().to_vec()
}

/// Проверяет подпись с помощью публичного ключа
pub fn verify_signature(
    verifying_key: &VerifyingKey,
    data: &[u8],
    signature: &[u8],
) -> Result<(), anyhow::Error> {
    let signature = Signature::from_bytes(signature.try_into()?);
    verifying_key.verify(data, &signature)?;
    Ok(())
}

/// Генерирует fingerprint публичного ключа для идентификации клиента
pub fn generate_key_fingerprint(public_key: &VerifyingKey) -> String {
    let key_bytes = public_key.to_bytes();
    let mut hasher = Sha256::new();
    hasher.update(&key_bytes);
    let hash = hasher.finalize();
    BASE64_STANDARD.encode(&hash[..16])
}
