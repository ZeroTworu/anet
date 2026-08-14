use crate::consts::{NONCE_LEN, NONCE_PREFIX_LEN, PADDING_MTU, TRANSPORT_ENVELOPE_OVERHEAD};
use crate::encryption::{Cipher, EncryptionError};
use crate::padding_utils::calculate_padding_needed;
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
    wrap_packet_slice(cipher, nonce_prefix, sequence, &quic_payload, padding_size)
}

/// Packs and encrypts a packet using a single output allocation.
pub fn wrap_packet_slice(
    cipher: &Cipher,
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    sequence: u64,
    payload: &[u8],
    padding_size: u16,
) -> Result<Bytes, EncryptionError> {
    let payload_len = payload.len();

    // Nonce = [prefix][sequence]
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(nonce_prefix);
    // Последние 8 байт nonce - это сам sequence, для уникальности
    nonce[NONCE_PREFIX_LEN..].copy_from_slice(&sequence.to_be_bytes());

    // Reserve the final wire buffer once: nonce + plaintext + authentication tag.
    let mut final_packet =
        BytesMut::with_capacity(NONCE_LEN + 10 + payload_len + padding_size as usize + 16);
    final_packet.put_slice(&nonce);
    final_packet.put_u64(sequence);
    final_packet.put_u16(payload_len as u16);
    final_packet.put_slice(payload);
    final_packet.put_bytes(0, padding_size as usize);

    let tag = {
        let plaintext = &mut final_packet[NONCE_LEN..];
        cipher.encrypt_in_place_detached(&nonce, plaintext)?
    };
    final_packet.put_slice(&tag);

    Ok(final_packet.freeze())
}

/// Applies the configured transport padding and encrypts an owned packet.
#[inline]
pub fn wrap_packet_padded(
    cipher: &Cipher,
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    sequence: u64,
    payload: Bytes,
    padding_step: u16,
) -> Result<Bytes, EncryptionError> {
    let wire_len_without_padding = payload.len() + TRANSPORT_ENVELOPE_OVERHEAD;
    let requested_padding = calculate_padding_needed(wire_len_without_padding, padding_step);
    let padding = if wire_len_without_padding + usize::from(requested_padding) <= PADDING_MTU {
        requested_padding
    } else {
        0
    };
    wrap_packet_slice(cipher, nonce_prefix, sequence, &payload, padding)
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
pub fn unwrap_packet_in_place<'a>(cipher: &Cipher, buffer: &'a mut [u8]) -> Result<&'a [u8]> {
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

/// Decrypts an owned packet in place and returns a zero-copy view of its IP payload.
///
/// Unlike [`unwrap_packet`], this reuses the receive buffer for both ciphertext and
/// plaintext. `Bytes` produced directly from a freshly read `Vec` is normally unique;
/// a shared buffer is rejected rather than silently copied.
pub fn unwrap_packet_bytes_in_place(cipher: &Cipher, raw_packet: Bytes) -> Result<Bytes> {
    let mut buffer = raw_packet
        .try_into_mut()
        .map_err(|_| anyhow!("Encrypted packet buffer is unexpectedly shared"))?;

    let payload = unwrap_packet_in_place(cipher, &mut buffer)?;
    let payload_len = payload.len();
    let payload_start = NONCE_LEN + 10;
    let payload_end = payload_start + payload_len;
    buffer.truncate(payload_end);
    Ok(buffer.freeze().slice(payload_start..payload_end))
}

/// Decrypts an owned packet in place when its buffer is unique and falls back to the
/// allocating path for shared buffers such as slices owned by a WebSocket frame parser.
pub fn unwrap_packet_bytes(cipher: &Cipher, raw_packet: Bytes) -> Result<Bytes> {
    let mut buffer = match raw_packet.try_into_mut() {
        Ok(buffer) => buffer,
        Err(shared) => return unwrap_packet(cipher, &shared),
    };

    let payload = unwrap_packet_in_place(cipher, &mut buffer)?;
    let payload_len = payload.len();
    let payload_start = NONCE_LEN + 10;
    let payload_end = payload_start + payload_len;
    buffer.truncate(payload_end);
    Ok(buffer.freeze().slice(payload_start..payload_end))
}

#[cfg(test)]
mod in_place_tests {
    use super::*;

    #[test]
    fn owned_in_place_unwrap_matches_allocating_path() {
        let cipher = Cipher::new(&[9; 32]);
        let payload = Bytes::from_static(b"test IP packet payload");
        let encrypted = wrap_packet(&cipher, &[1, 2, 3, 4], 7, payload.clone(), 13).unwrap();

        let allocating = unwrap_packet(&cipher, &encrypted).unwrap();
        let in_place = unwrap_packet_bytes_in_place(&cipher, encrypted).unwrap();

        assert_eq!(allocating, payload);
        assert_eq!(in_place, payload);
    }

    #[test]
    fn padded_wrap_round_trips_without_changing_payload() {
        let cipher = Cipher::new(&[3; 32]);
        let payload = Bytes::from(vec![7; 1400]);
        let encrypted = wrap_packet_padded(&cipher, &[4, 3, 2, 1], 9, payload.clone(), 64)
            .expect("packet must encrypt");

        assert!(encrypted.len() <= PADDING_MTU);
        assert_eq!(unwrap_packet(&cipher, &encrypted).unwrap(), payload);
    }

    #[test]
    fn owned_unwrap_falls_back_for_shared_buffers() {
        let cipher = Cipher::new(&[8; 32]);
        let payload = Bytes::from_static(b"shared WebSocket frame payload");
        let encrypted = wrap_packet(&cipher, &[9, 8, 7, 6], 11, payload.clone(), 0).unwrap();
        let shared = encrypted.clone();

        assert_eq!(unwrap_packet_bytes(&cipher, encrypted).unwrap(), payload);
        assert!(!shared.is_empty());
    }
}
