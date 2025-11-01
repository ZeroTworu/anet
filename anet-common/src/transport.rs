use crate::consts::{
    PACKET_TYPE_DATA, PACKET_TYPE_HANDSHAKE, PACKET_TYPE_AUTH_REQUEST, PACKET_TYPE_AUTH_RESPONSE,
    SESSION_ID_LENGTH, CLIENT_ID_LENGTH, TIMESTAMP_LENGTH, MAX_PACKET_SIZE
};
use crate::encryption::Cipher;
use anyhow::{Result, anyhow};
use bytes::{BufMut, Bytes, BytesMut};
use rand::RngCore;

#[derive(Debug)]
pub struct AnetVpnPacket {
    pub packet_type: u8,
    pub session_id: [u8; SESSION_ID_LENGTH],
    pub sequence: u64,
    pub payload: Bytes,
    pub random_padding: Bytes,
}

impl AnetVpnPacket {
    /// Создает новый пакет данных
    pub fn new_data(session_id: [u8; SESSION_ID_LENGTH], sequence: u64, quic_payload: Bytes) -> Self {
        let mut rng = rand::rng();
        let padding_len = rng.next_u32() as usize % 64;
        let mut random_padding = vec![0u8; padding_len];
        rng.fill_bytes(&mut random_padding);

        Self {
            packet_type: PACKET_TYPE_DATA,
            session_id,
            sequence,
            payload: quic_payload,
            random_padding: Bytes::from(random_padding),
        }
    }

    /// Создает handshake пакет для initial connection
    pub fn new_handshake(session_id: [u8; SESSION_ID_LENGTH], client_id: [u8; CLIENT_ID_LENGTH], timestamp: u64) -> Self {
        let mut rng = rand::rng();
        let padding_len = rng.next_u32() as usize % 128;
        let mut random_padding = vec![0u8; padding_len];
        rng.fill_bytes(&mut random_padding);

        let mut payload = Vec::with_capacity(CLIENT_ID_LENGTH + TIMESTAMP_LENGTH);
        payload.extend_from_slice(&client_id);
        payload.extend_from_slice(&timestamp.to_be_bytes());

        Self {
            packet_type: PACKET_TYPE_HANDSHAKE,
            session_id,
            sequence: 0,
            payload: Bytes::from(payload),
            random_padding: Bytes::from(random_padding),
        }
    }

    /// Создает пакет аутентификационного запроса
    pub fn new_auth_request(auth_phrase: String, client_random: [u8; 32]) -> Self {
        let mut rng = rand::rng();
        let padding_len = rng.next_u32() as usize % 256;
        let mut random_padding = vec![0u8; padding_len];
        rng.fill_bytes(&mut random_padding);

        let mut payload = Vec::with_capacity(auth_phrase.len() + 32);
        payload.extend_from_slice(auth_phrase.as_bytes());
        payload.extend_from_slice(&client_random);

        Self {
            packet_type: PACKET_TYPE_AUTH_REQUEST,
            session_id: [0u8; SESSION_ID_LENGTH], // пока не известен
            sequence: 0,
            payload: Bytes::from(payload),
            random_padding: Bytes::from(random_padding),
        }
    }

    /// Создает пакет аутентификационного ответа
    pub fn new_auth_response(
        session_id: [u8; SESSION_ID_LENGTH],
        crypto_key: Vec<u8>,
        udp_port: u32,
        gateway: String,
        netmask: String,
        client_ip: String,
        mtu: i32,
    ) -> Self {
        let mut rng = rand::rng();
        let padding_len = rng.next_u32() as usize % 256;
        let mut random_padding = vec![0u8; padding_len];
        rng.fill_bytes(&mut random_padding);

        let mut payload = Vec::new();
        payload.extend_from_slice(&crypto_key);
        payload.extend_from_slice(&udp_port.to_be_bytes());
        payload.extend_from_slice(gateway.as_bytes());
        payload.push(0); // разделитель
        payload.extend_from_slice(netmask.as_bytes());
        payload.push(0); // разделитель
        payload.extend_from_slice(client_ip.as_bytes());
        payload.extend_from_slice(&mtu.to_be_bytes());

        Self {
            packet_type: PACKET_TYPE_AUTH_RESPONSE,
            session_id,
            sequence: 0,
            payload: Bytes::from(payload),
            random_padding: Bytes::from(random_padding),
        }
    }

    /// Сериализует и шифрует пакет
    pub fn wrap_and_encrypt(&self, cipher: &Cipher) -> Result<Bytes> {
        let nonce = Cipher::generate_nonce(self.sequence);

        // Собираем полные данные для шифрования: payload + padding
        let mut full_data = BytesMut::with_capacity(self.payload.len() + self.random_padding.len());
        full_data.put(self.payload.clone());
        full_data.put(self.random_padding.clone());

        let encrypted_data = cipher.encrypt(&nonce, full_data.freeze())?;

        // Фиксированная структура: [session_id][type][sequence][encrypted]
        let mut final_packet = BytesMut::with_capacity(SESSION_ID_LENGTH + 1 + 8 + encrypted_data.len());
        final_packet.put_slice(&self.session_id);
        final_packet.put_u8(self.packet_type);
        final_packet.put_u64(self.sequence);
        final_packet.put_slice(&encrypted_data);

        Ok(final_packet.freeze())
    }

    /// Десериализует и расшифровывает пакет
    pub fn unwrap_and_decrypt(
        cipher: &Cipher,
        session_id: [u8; SESSION_ID_LENGTH],
        transport_packet: &[u8],
    ) -> Result<Self> {
        let min_packet_size = SESSION_ID_LENGTH + 1 + 8;
        if transport_packet.len() < min_packet_size {
            return Err(anyhow!("Transport packet too short"));
        }

        // Фиксированная структура: [session_id][type][sequence][encrypted]
        let received_session_id = &transport_packet[..SESSION_ID_LENGTH];
        if received_session_id != session_id {
            return Err(anyhow!("Session ID mismatch"));
        }

        let packet_type = transport_packet[SESSION_ID_LENGTH];
        let sequence = u64::from_be_bytes(transport_packet[SESSION_ID_LENGTH + 1..SESSION_ID_LENGTH + 9].try_into()?);
        let encrypted_data = &transport_packet[SESSION_ID_LENGTH + 9..];

        let nonce = Cipher::generate_nonce(sequence);
        let plaintext = cipher.decrypt(&nonce, Bytes::copy_from_slice(encrypted_data))?;

        // Эвристика для извлечения payload
        const MIN_QUIC_SIZE: usize = 20;
        if plaintext.len() < MIN_QUIC_SIZE {
            return Err(anyhow!("Plaintext too short for QUIC packet"));
        }

        let payload = plaintext;
        let random_padding = Bytes::new();

        Ok(Self {
            packet_type,
            session_id,
            sequence,
            payload,
            random_padding,
        })
    }

    /// Извлекает данные из аутентификационного запроса
    pub fn get_auth_data(&self) -> Result<(String, [u8; 32])> {
        if self.packet_type != PACKET_TYPE_AUTH_REQUEST {
            return Err(anyhow!("Not an auth request packet"));
        }

        // Ищем конец auth phrase (первый нулевой байт или конец данных)
        let mut auth_end = 0;
        for (i, &byte) in self.payload.iter().enumerate() {
            if byte == 0 || i >= 256 {
                auth_end = i;
                break;
            }
        }

        if auth_end == 0 {
            auth_end = self.payload.len().min(256);
        }

        let auth_phrase = String::from_utf8(self.payload[..auth_end].to_vec())
            .map_err(|_| anyhow!("Invalid auth phrase encoding"))?;

        // client_random - следующие 32 байта
        if self.payload.len() < auth_end + 32 {
            return Err(anyhow!("Auth packet too short"));
        }

        let mut client_random = [0u8; 32];
        client_random.copy_from_slice(&self.payload[auth_end..auth_end + 32]);

        Ok((auth_phrase, client_random))
    }

    /// Извлекает данные из аутентификационного ответа
    pub fn get_auth_response_data(&self) -> Result<(Vec<u8>, u32, String, String, String, i32)> {
        if self.packet_type != PACKET_TYPE_AUTH_RESPONSE {
            return Err(anyhow!("Not an auth response packet"));
        }

        let mut cursor = 0;

        // crypto_key (32 байта)
        if self.payload.len() < cursor + 32 {
            return Err(anyhow!("Auth response too short for crypto key"));
        }
        let crypto_key = self.payload[cursor..cursor + 32].to_vec();
        cursor += 32;

        // udp_port (4 байта)
        if self.payload.len() < cursor + 4 {
            return Err(anyhow!("Auth response too short for UDP port"));
        }
        let udp_port = u32::from_be_bytes(self.payload[cursor..cursor + 4].try_into()?);
        cursor += 4;

        // gateway (до первого нуля)
        let gateway_end = self.payload[cursor..].iter()
            .position(|&b| b == 0)
            .ok_or_else(|| anyhow!("Invalid gateway format"))?;
        let gateway = String::from_utf8(self.payload[cursor..cursor + gateway_end].to_vec())?;
        cursor += gateway_end + 1;

        // netmask (до первого нуля)
        let netmask_end = self.payload[cursor..].iter()
            .position(|&b| b == 0)
            .ok_or_else(|| anyhow!("Invalid netmask format"))?;
        let netmask = String::from_utf8(self.payload[cursor..cursor + netmask_end].to_vec())?;
        cursor += netmask_end + 1;

        // client_ip (оставшиеся байты до последних 4)
        if self.payload.len() < cursor + 5 {
            return Err(anyhow!("Auth response too short for IP and MTU"));
        }
        let ip_len = self.payload.len() - cursor - 4;
        let client_ip = String::from_utf8(self.payload[cursor..cursor + ip_len].to_vec())?;
        cursor += ip_len;

        // mtu (4 байта)
        let mtu = i32::from_be_bytes(self.payload[cursor..cursor + 4].try_into()?);

        Ok((crypto_key, udp_port, gateway, netmask, client_ip, mtu))
    }

    pub fn get_client_id(&self) -> Result<[u8; CLIENT_ID_LENGTH]> {
        if self.packet_type != PACKET_TYPE_HANDSHAKE || self.payload.len() < CLIENT_ID_LENGTH {
            return Err(anyhow!("Not a handshake packet or invalid length"));
        }

        let mut client_id = [0u8; CLIENT_ID_LENGTH];
        client_id.copy_from_slice(&self.payload[..CLIENT_ID_LENGTH]);
        Ok(client_id)
    }

    pub fn get_timestamp(&self) -> Result<u64> {
        let timestamp_start = CLIENT_ID_LENGTH;
        let timestamp_end = timestamp_start + TIMESTAMP_LENGTH;

        if self.packet_type != PACKET_TYPE_HANDSHAKE || self.payload.len() < timestamp_end {
            return Err(anyhow!("Not a handshake packet or invalid length"));
        }

        Ok(u64::from_be_bytes(self.payload[timestamp_start..timestamp_end].try_into()?))
    }
}

// Функции-обертки
pub fn wrap_handshake(
    cipher: &Cipher,
    session_id: [u8; SESSION_ID_LENGTH],
    client_id: [u8; CLIENT_ID_LENGTH],
    timestamp: u64,
) -> Result<Bytes> {
    AnetVpnPacket::new_handshake(session_id, client_id, timestamp).wrap_and_encrypt(cipher)
}

pub fn wrap_packet(
    cipher: &Cipher,
    session_id: [u8; SESSION_ID_LENGTH],
    sequence: u64,
    payload: Bytes,
) -> Result<Bytes> {
    AnetVpnPacket::new_data(session_id, sequence, payload).wrap_and_encrypt(cipher)
}

pub fn wrap_auth_request(
    cipher: &Cipher,
    session_id: [u8; SESSION_ID_LENGTH],
    auth_phrase: String,
    client_random: [u8; 32],
) -> Result<Bytes> {
    AnetVpnPacket::new_auth_request(auth_phrase, client_random).wrap_and_encrypt(cipher)
}

pub fn wrap_auth_response(
    cipher: &Cipher,
    session_id: [u8; SESSION_ID_LENGTH],
    crypto_key: Vec<u8>,
    udp_port: u32,
    gateway: String,
    netmask: String,
    client_ip: String,
    mtu: i32,
) -> Result<Bytes> {
    AnetVpnPacket::new_auth_response(
        session_id,
        crypto_key,
        udp_port,
        gateway,
        netmask,
        client_ip,
        mtu,
    ).wrap_and_encrypt(cipher)
}

pub fn unwrap_packet(
    cipher: &Cipher,
    session_id: [u8; SESSION_ID_LENGTH],
    transport_packet: &[u8],
) -> Result<Bytes> {
    match AnetVpnPacket::unwrap_and_decrypt(cipher, session_id, transport_packet) {
        Ok(wrapped) => Ok(wrapped.payload),
        Err(e) => Err(e),
    }
}

pub fn unwrap_handshake(
    cipher: &Cipher,
    session_id: [u8; SESSION_ID_LENGTH],
    transport_packet: &[u8],
) -> Result<([u8; CLIENT_ID_LENGTH], u64)> {
    match AnetVpnPacket::unwrap_and_decrypt(cipher, session_id, transport_packet) {
        Ok(wrapped) => {
            let client_id = wrapped.get_client_id()?;
            let timestamp = wrapped.get_timestamp()?;
            Ok((client_id, timestamp))
        }
        Err(e) => Err(e),
    }
}

pub fn unwrap_auth_request(
    cipher: &Cipher,
    session_id: [u8; SESSION_ID_LENGTH],
    transport_packet: &[u8],
) -> Result<(String, [u8; 32])> {
    match AnetVpnPacket::unwrap_and_decrypt(cipher, session_id, transport_packet) {
        Ok(wrapped) => wrapped.get_auth_data(),
        Err(e) => Err(e),
    }
}

pub fn unwrap_auth_response(
    cipher: &Cipher,
    session_id: [u8; SESSION_ID_LENGTH],
    transport_packet: &[u8],
) -> Result<(Vec<u8>, u32, String, String, String, i32)> {
    match AnetVpnPacket::unwrap_and_decrypt(cipher, session_id, transport_packet) {
        Ok(wrapped) => wrapped.get_auth_response_data(),
        Err(e) => Err(e),
    }
}
