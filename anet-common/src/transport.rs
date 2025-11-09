use crate::consts::{PACKET_TYPE_DATA, PACKET_TYPE_HANDSHAKE};
use crate::encryption::Cipher;
use anyhow::{Result, anyhow};
use bytes::{BufMut, Bytes, BytesMut};
use rand::RngCore;

#[derive(Debug)]
pub struct AnetVpnPacket {
    pub packet_type: u8,
    pub session_id: [u8; 16],
    pub sequence: u64,
    pub payload: Bytes,
}

impl AnetVpnPacket {
    /// Создает новый пакет данных
    pub fn new_data(session_id: [u8; 16], sequence: u64, quic_payload: Bytes) -> Self {
        Self {
            packet_type: PACKET_TYPE_DATA,
            session_id,
            sequence,
            payload: quic_payload,
        }
    }

    /// Создает handshake пакет для initial connection
    pub fn new_handshake(session_id: [u8; 16], client_id: [u8; 16], timestamp: u64) -> Self {
        let mut payload = Vec::with_capacity(24);
        payload.extend_from_slice(&client_id);
        payload.extend_from_slice(&timestamp.to_be_bytes());

        Self {
            packet_type: PACKET_TYPE_HANDSHAKE,
            session_id,
            sequence: 0,
            payload: Bytes::from(payload),
        }
    }

    /// Сериализует и шифрует пакет (полностью зашифрованный формат)
    pub fn wrap_and_encrypt(&self, cipher: &Cipher) -> Result<Bytes> {
        // Генерируем случайный паддинг
        let padding = generate_random_padding();

        // Создаем plaintext: packet_type + payload_length + payload + padding
        let payload_length = self.payload.len() as u16;
        let mut plaintext = BytesMut::with_capacity(1 + 2 + self.payload.len() + padding.len());

        plaintext.put_u8(self.packet_type);           // 1 byte
        plaintext.put_u16(payload_length);            // 2 bytes
        plaintext.put_slice(&self.payload);           // N bytes
        plaintext.put_slice(&padding);                // 0-127 bytes

        let nonce = Cipher::generate_nonce(self.sequence);
        let encrypted_data = cipher.encrypt(&nonce, plaintext.freeze())?;

        // Формат: session_id + sequence + encrypted_data
        let mut final_packet = BytesMut::with_capacity(16 + 8 + encrypted_data.len());
        final_packet.put_slice(&self.session_id);     // 16 bytes
        final_packet.put_u64(self.sequence);          // 8 bytes
        final_packet.put_slice(&encrypted_data);      // encrypted: [type][length][payload][padding] + AEAD тег

        Ok(final_packet.freeze())
    }

    /// Десериализует и расшифровывает пакет (полностью зашифрованный формат)
    pub fn unwrap_and_decrypt(
        cipher: &Cipher,
        session_id: [u8; 16],
        transport_packet: &[u8],
    ) -> Result<Self> {
        if transport_packet.len() < 25 { // 16 (session_id) + 8 (sequence) + 1 (минимальные зашифрованные данные)
            return Err(anyhow!("Transport packet too short"));
        }

        let received_session_id = &transport_packet[..16];
        if received_session_id != session_id {
            return Err(anyhow!("Session ID mismatch"));
        }

        let sequence = u64::from_be_bytes(transport_packet[16..24].try_into()?);
        let encrypted_data = &transport_packet[24..];

        let nonce = Cipher::generate_nonce(sequence);
        let plaintext = cipher.decrypt(&nonce, Bytes::copy_from_slice(encrypted_data))?;

        if plaintext.len() < 3 { // минимум: packet_type (1) + payload_length (2)
            return Err(anyhow!("Decrypted data too short"));
        }

        // Извлекаем данные из расшифрованного plaintext
        let packet_type = plaintext[0];
        let payload_length = u16::from_be_bytes([plaintext[1], plaintext[2]]) as usize;

        if plaintext.len() < 3 + payload_length {
            return Err(anyhow!("Payload length exceeds decrypted data"));
        }

        let payload = Bytes::from(plaintext[3..3 + payload_length].to_vec());
        // Паддинг (plaintext[3 + payload_length..]) игнорируем

        Ok(Self {
            packet_type,
            session_id,
            sequence,
            payload,
        })
    }

    pub fn get_client_id(&self) -> Result<[u8; 16]> {
        if self.packet_type != PACKET_TYPE_HANDSHAKE || self.payload.len() < 16 {
            return Err(anyhow!("Not a handshake packet or invalid length"));
        }

        let mut client_id = [0u8; 16];
        client_id.copy_from_slice(&self.payload[..16]);
        Ok(client_id)
    }

    pub fn get_timestamp(&self) -> Result<u64> {
        if self.packet_type != PACKET_TYPE_HANDSHAKE || self.payload.len() < 24 {
            return Err(anyhow!("Not a handshake packet or invalid length"));
        }

        Ok(u64::from_be_bytes(self.payload[16..24].try_into()?))
    }
}

/// Генерирует случайный паддинг переменной длины
fn generate_random_padding() -> Bytes {
    let mut rng = rand::rng();
    let padding_len = rng.next_u32() as usize % 128;
    let mut random_padding = vec![0u8; padding_len];
    rng.fill_bytes(&mut random_padding);
    Bytes::from(random_padding)
}

/// Публичные функции-обертки для удобства

pub fn wrap_handshake(
    cipher: &Cipher,
    session_id: [u8; 16],
    client_id: [u8; 16],
    timestamp: u64,
) -> Result<Bytes> {
    AnetVpnPacket::new_handshake(session_id, client_id, timestamp).wrap_and_encrypt(cipher)
}

pub fn wrap_packet(
    cipher: &Cipher,
    session_id: [u8; 16],
    sequence: u64,
    payload: Bytes,
) -> Result<Bytes> {
    AnetVpnPacket::new_data(session_id, sequence, payload).wrap_and_encrypt(cipher)
}

pub fn unwrap_packet(
    cipher: &Cipher,
    session_id: [u8; 16],
    transport_packet: &[u8],
) -> Result<Bytes> {
    match AnetVpnPacket::unwrap_and_decrypt(cipher, session_id, transport_packet) {
        Ok(wrapped) => {
            if wrapped.packet_type != PACKET_TYPE_DATA {
                return Err(anyhow!("Expected data packet, got type: {}", wrapped.packet_type));
            }
            Ok(wrapped.payload)
        }
        Err(e) => Err(e),
    }
}

pub fn unwrap_handshake(
    cipher: &Cipher,
    session_id: [u8; 16],
    transport_packet: &[u8],
) -> Result<([u8; 16], u64)> {
    match AnetVpnPacket::unwrap_and_decrypt(cipher, session_id, transport_packet) {
        Ok(wrapped) => {
            if wrapped.packet_type != PACKET_TYPE_HANDSHAKE {
                return Err(anyhow!("Expected handshake packet, got type: {}", wrapped.packet_type));
            }
            let client_id = wrapped.get_client_id()?;
            let timestamp = wrapped.get_timestamp()?;
            Ok((client_id, timestamp))
        }
        Err(e) => Err(e),
    }
}
