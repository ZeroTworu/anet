use std::sync::Arc;
// anet-common/src/transport.rs
use crate::consts::PACKET_TYPE_DATA;
use crate::encryption::Cipher;
use bytes::{BufMut, Bytes, BytesMut};
use anyhow::{anyhow, Result};
use log::trace;

/// Структура, инкапсулирующая пакет ANET VPN транспортного уровня.
/// [Тип пакета (u8)][Sequence (u64)][Зашифрованные данные (QUIC/Protobuf)]
pub struct AnetVpnPacket {
    pub packet_type: u8,
    pub sequence: u64,
    pub payload: Bytes, // Исходные данные (QUIC или Handshake Protobuf)
}

impl AnetVpnPacket {
    /// Создает новый пакет данных (для QUIC).
    pub fn new_data(sequence: u64, quic_payload: Bytes) -> Self {
        Self {
            packet_type: PACKET_TYPE_DATA,
            sequence,
            payload: quic_payload,
        }
    }

    /// Сериализует и шифрует полезную нагрузку.
    pub fn wrap_and_encrypt(&self, cipher: &Cipher) -> Result<Bytes> {
        if self.packet_type != PACKET_TYPE_DATA {
            // Для QUIC мы всегда используем PACKET_TYPE_DATA
            return Err(anyhow!("Attempted to wrap non-DATA packet as QUIC data"));
        }

        let nonce = Cipher::generate_nonce(self.sequence);
        let encrypted_data = cipher.encrypt(&nonce, self.payload.clone())?;

        let mut final_packet = BytesMut::with_capacity(1 + 8 + encrypted_data.len());
        final_packet.put_u8(self.packet_type);
        final_packet.put_u64(self.sequence);
        final_packet.put_slice(&encrypted_data);

        Ok(final_packet.freeze())
    }

    /// Десериализует и расшифровывает транспортный пакет. Возвращает AnetVpnPacket.
    pub fn unwrap_and_decrypt(cipher: &Cipher, transport_packet: &[u8]) -> Result<Self> {
        if transport_packet.len() < 1 + 8 {
            trace!("Packet too short.");
            return Err(anyhow!("Transport packet too short"));
        }

        let packet_type = transport_packet[0];
        if packet_type != PACKET_TYPE_DATA {
            // Если пакет не типа DATA, мы его игнорируем, т.к. QUIC работает только с DATA
            trace!("Non-QUIC packet type received: {}", packet_type);
            return Err(anyhow!("Non-QUIC transport packet type received: {}", packet_type));
        }

        let sequence = u64::from_be_bytes(transport_packet[1..9].try_into()?);
        let encrypted_data = Bytes::copy_from_slice(&transport_packet[9..]);
        let nonce = Cipher::generate_nonce(sequence);

        let decrypted_payload = cipher.decrypt(&nonce, encrypted_data)?;

        Ok(AnetVpnPacket {
            packet_type,
            sequence,
            payload: decrypted_payload, // Это QUIC payload
        })
    }

}

pub fn wrap_packet(cipher: &Cipher, sequence: u64, payload: Bytes) -> Result<Bytes> {
    AnetVpnPacket::new_data(sequence, payload).wrap_and_encrypt(cipher)
}

pub fn unwrap_packet(cipher: &Cipher, transport_packet: &[u8]) -> Result<Bytes> {
    let wrapped = AnetVpnPacket::unwrap_and_decrypt(cipher, transport_packet)?;
    Ok(wrapped.payload)
}