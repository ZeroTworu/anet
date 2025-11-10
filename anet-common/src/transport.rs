use crate::consts::{NONCE_LEN, NONCE_PREFIX_LEN};
use crate::encryption::{Cipher, EncryptionError};
use anyhow::{Result, anyhow};
use bytes::{BufMut, Bytes, BytesMut};

/// Упаковывает и шифрует QUIC-пакет с новым протоколом
pub fn wrap_packet(
    cipher: &Cipher,
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    sequence: u64,
    quic_payload: Bytes,
) -> Result<Bytes, EncryptionError> {
    // Plaintext = [sequence][quic_payload]
    let mut plaintext = BytesMut::with_capacity(8 + quic_payload.len());
    plaintext.put_u64(sequence);
    plaintext.put(quic_payload);

    // Nonce = [prefix][sequence]
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(nonce_prefix);
    // Последние 8 байт nonce - это сам sequence, для уникальности
    nonce[NONCE_PREFIX_LEN..].copy_from_slice(&sequence.to_be_bytes());

    // Шифруем
    let ciphertext = cipher.encrypt(&nonce, plaintext.freeze())?;

    // Финальный пакет = [полный nonce][зашифрованные данные]
    // Nonce теперь идет в открытом виде для O(1) поиска на сервере
    let mut final_packet = BytesMut::with_capacity(NONCE_LEN + ciphertext.len());
    final_packet.put_slice(&nonce);
    final_packet.put(ciphertext);

    Ok(final_packet.freeze())
}

/// Расшифровывает пакет, полученный от сервера
pub fn unwrap_packet(cipher: &Cipher, raw_packet: &[u8]) -> Result<Bytes> {
    if raw_packet.len() < NONCE_LEN + 1 {
        // Nonce + минимум 1 байт payload
        return Err(anyhow!("Packet too short"));
    }

    // Извлекаем nonce и зашифрованные данные
    let (nonce, ciphertext) = raw_packet.split_at(NONCE_LEN);

    // Расшифровываем
    let plaintext = cipher.decrypt(nonce, Bytes::copy_from_slice(ciphertext))?;

    if plaintext.len() < 8 {
        // Должен быть как минимум sequence
        return Err(anyhow!("Decrypted payload too short"));
    }

    // Извлекаем QUIC-пакет (все что после 8 байт sequence)
    Ok(plaintext.slice(8..))
}
