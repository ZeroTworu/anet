use crate::consts::{AUTH_MAGIC_ID_BASE, AUTH_PREFIX_LEN, AUTH_SALT_LEN};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{Rng, rngs::OsRng};
use sha2::{Digest, Sha256};
use x25519_dalek::SharedSecret;

/// Выполняет XOR [a] ^ [b]
fn xor_arrays(a: &[u8; 4], b: &[u8; 4]) -> [u8; 4] {
    let mut result = [0u8; 4];
    for i in 0..4 {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// Клиент: генерирует 8-байтный обфусцированный префикс Auth (Salt + MAGIC^Salt)
pub fn generate_auth_prefix() -> [u8; AUTH_PREFIX_LEN] {
    let mut rng = OsRng;
    let mut salt = [0u8; AUTH_SALT_LEN];
    rng.fill(&mut salt);

    let obfuscated_magic = xor_arrays(&AUTH_MAGIC_ID_BASE, &salt);

    let mut prefix = [0u8; AUTH_PREFIX_LEN];
    prefix[0..AUTH_SALT_LEN].copy_from_slice(&salt);
    prefix[AUTH_SALT_LEN..AUTH_PREFIX_LEN].copy_from_slice(&obfuscated_magic);
    prefix
}

/// Сервер: проверяет, соответствует ли полученный префикс (8 байт) ожидаемому Magic ID
pub fn check_auth_prefix(prefix: &[u8]) -> bool {
    if prefix.len() < AUTH_PREFIX_LEN {
        return false;
    }
    let salt: &[u8; AUTH_SALT_LEN] = match prefix[0..AUTH_SALT_LEN].try_into() {
        Ok(s) => s,
        Err(_) => return false,
    };

    let received_obf: &[u8; AUTH_SALT_LEN] = match prefix[AUTH_SALT_LEN..AUTH_PREFIX_LEN].try_into()
    {
        Ok(r) => r,
        Err(_) => return false,
    };

    let derived_base = xor_arrays(salt, received_obf);
    derived_base == AUTH_MAGIC_ID_BASE
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
    base64::encode(&hash[..16]) // Берем первые 16 байт для короткого fingerprint
}
