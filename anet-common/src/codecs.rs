use bytes::{Bytes, BytesMut};
use std::io;
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug, Clone)]
pub struct TunCodec {
    mtu: usize,
}

impl TunCodec {
    pub fn new(mtu: usize) -> Self {
        Self { mtu }
    }
}

impl Decoder for TunCodec {
    type Item = Bytes;
    type Error = io::Error;

    #[inline]
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }

        let data = src.split_to(src.len()).freeze();
        Ok(Some(data))
    }
}

impl Encoder<Bytes> for TunCodec {
    type Error = io::Error;

    #[inline]
    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        // Проверяем, что пакет не превышает MTU
        if item.len() > self.mtu {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Packet exceeds MTU: {} > {}", item.len(), self.mtu),
            ));
        }

        // Добавляем данные в буфер
        dst.extend_from_slice(&item);
        Ok(())
    }
}
