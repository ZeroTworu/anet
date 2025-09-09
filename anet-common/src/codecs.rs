use bytes::{Buf, BytesMut};
use log::{error, warn};
use std::io;
use tokio_util::codec::{Decoder, Encoder};

pub struct RawIpCodec {
    max_packet_size: usize,
}

impl RawIpCodec {
    pub fn new() -> Self {
        Self {
            max_packet_size: 65536, // 64KB по умолчанию
        }
    }

    pub fn with_max_packet_size(max_packet_size: usize) -> Self {
        Self { max_packet_size }
    }
}

impl Decoder for RawIpCodec {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, io::Error> {
        if src.is_empty() {
            return Ok(None);
        }

        // Проверяем, не превышает ли пакет максимальный размер
        if src.len() > self.max_packet_size {
            warn!(
                "Packet too large: {} bytes, truncating to {}",
                src.len(),
                self.max_packet_size
            );
            let data = src.split_to(self.max_packet_size).to_vec();
            src.clear();
            return Ok(Some(data));
        }

        let data = src.split_to(src.len()).to_vec();
        src.clear();
        Ok(Some(data))
    }
}

impl Encoder<Vec<u8>> for RawIpCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Vec<u8>, dst: &mut BytesMut) -> Result<(), io::Error> {
        if item.len() > self.max_packet_size {
            error!("Packet too large to send: {} bytes", item.len());
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Packet too large: {} bytes", item.len()),
            ));
        }

        dst.extend_from_slice(&item);
        Ok(())
    }
}

pub struct AnetCodec;

impl Decoder for AnetCodec {
    type Item = BytesMut;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            return Ok(None);
        }

        // Читаем длину сообщения
        let len = {
            let mut len_bytes = [0u8; 4];
            len_bytes.copy_from_slice(&src[0..4]);
            u32::from_be_bytes(len_bytes) as usize
        };

        // Проверяем, есть ли полное сообщение
        if src.len() < 4 + len {
            src.reserve(4 + len - src.len());
            return Ok(None);
        }

        // Пропускаем байты длины
        src.advance(4);

        // Возвращаем данные сообщения
        Ok(Some(src.split_to(len)))
    }
}
