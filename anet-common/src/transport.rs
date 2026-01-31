use crate::consts::{NONCE_LEN, NONCE_PREFIX_LEN};
use crate::encryption::{Cipher, EncryptionError};
use anyhow::{Result, anyhow};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Упаковывает и шифрует QUIC-пакет с новым протоколом
pub fn wrap_packet(
    cipher: &Cipher,
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    sequence: u64,
    quic_payload: Bytes,
    padding_size: u16,
) -> Result<Bytes, EncryptionError> {
    let payload_len = quic_payload.len();
    let total_capacity = 8 + 2 + payload_len + padding_size as usize;

    let mut plaintext = BytesMut::with_capacity(total_capacity);
    plaintext.put_u64(sequence);
    plaintext.put_u16(payload_len as u16); // Записываем длину данных
    plaintext.put(quic_payload);
    plaintext.put_bytes(0u8, padding_size as usize); // Добиваем нулями (станут шумом)

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
    let mut plaintext = cipher.decrypt(nonce, Bytes::copy_from_slice(ciphertext))?;

    if plaintext.len() < 10 {
        return Err(anyhow!("Payload too short"));
    }

    let _seq = plaintext.get_u64();
    let data_len = plaintext.get_u16() as usize; // Читаем длину

    if data_len > plaintext.remaining() {
        return Err(anyhow!("Malformed packet length"));
    }
    // Обрезаем паддинг
    Ok(plaintext.copy_to_bytes(data_len))
}

/// Расшифровывает пакет на месте (без выделения памяти).
/// buffer: полный пакет (Nonce + Ciphertext + Tag).
/// Возвращает срез с полезной нагрузкой (Quic Payload).
pub fn unwrap_packet_in_place<'a>(
    cipher: &Cipher,
    buffer: &'a mut [u8]
) -> Result<&'a [u8]> {
    // 16 байт - размер тега Poly1305
    if buffer.len() < NONCE_LEN + 16 {
        return Err(anyhow!("Packet too short"));
    }

    // 1. Копируем Nonce (12 байт), так как decrypt_in_place будет менять buffer
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&buffer[..NONCE_LEN]);

    // 2. Берем срез данных (включая Tag в конце)
    let payload_buffer = &mut buffer[NONCE_LEN..];

    // 3. Расшифровываем на месте
    cipher.decrypt_in_place(&nonce, payload_buffer)?;

    // 4. Отрезаем тег (логически).
    // Реальная длина данных теперь меньше на 16 байт.
    let plaintext_len = payload_buffer.len() - 16;
    let plaintext = &payload_buffer[..plaintext_len];

    // 5. Парсим заголовок ANet: [Seq (8)] [Len (2)] [Payload...] [Padding...]
    if plaintext.len() < 10 {
        return Err(anyhow!("Payload too short (header missing)"));
    }

    // Читаем длину (offset 8, 2 байта) вручную, чтобы не использовать Buf
    let data_len = u16::from_be_bytes([plaintext[8], plaintext[9]]) as usize;

    if 10 + data_len > plaintext.len() {
        return Err(anyhow!("Malformed packet length"));
    }

    // Возвращаем срез чистого пейлоуда
    Ok(&plaintext[10..10 + data_len])
}