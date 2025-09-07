use std::io;
use tokio_util::codec::{Decoder, Encoder};
use bytes::BytesMut;
use log::{error, warn};

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
            warn!("Packet too large: {} bytes, truncating to {}", src.len(), self.max_packet_size);
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
                format!("Packet too large: {} bytes", item.len())
            ));
        }

        dst.extend_from_slice(&item);
        Ok(())
    }
}
