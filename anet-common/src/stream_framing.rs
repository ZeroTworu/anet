use crate::consts::MAX_PACKET_SIZE;
use bytes::{BufMut, Bytes, BytesMut};
use log::error;
use std::io;

const LENGTH_PREFIX_SIZE: usize = 2; // u16 длина префикса

/// Создает сегмент потока: [u16 length][payload]
/// Используется в QUIC TX задаче.
pub fn frame_packet(payload: Bytes) -> Bytes {
    let len = payload.len() as u16;
    let mut framed_data = BytesMut::with_capacity(LENGTH_PREFIX_SIZE + payload.len());

    // 1. Добавляем u16 длины (Big Endian)
    framed_data.put_u16(len);
    // 2. Добавляем полезную нагрузку (IP пакет)
    framed_data.put(payload);

    framed_data.freeze()
}

/// Читает ровно один IP-пакет из QUIC стрима.
/// Возвращает None, если стрим закрыт, или Result<Bytes, io::Error>
/// Используется в QUIC RX задаче.
#[inline]
pub async fn read_next_packet<R: tokio::io::AsyncRead + tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
) -> io::Result<Option<Bytes>> {
    let mut len_buf = [0u8; LENGTH_PREFIX_SIZE];

    // 1. Считываем префикс длины (2 байта)
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {
            let len = u16::from_be_bytes(len_buf) as usize;

            if len == 0 {
                // Пакет нулевой длины игнорируем, но продолжаем читать
                error!("Received packet with zero length prefix.");
                return Ok(None);
            }
            if len > MAX_PACKET_SIZE {
                error!(
                    "Received oversized packet length: {}. Max allowed: {}",
                    len, MAX_PACKET_SIZE
                );
                // Критическая ошибка фрейминга, разрываем соединение
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Oversized packet received",
                ));
            }

            // 2. Считываем полный пакет данных
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).await?;

            Ok(Some(Bytes::from(buf)))
        }
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
            // EOF при чтении префикса
            Ok(None)
        }
        Err(e) => Err(e),
    }
}
