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

/// Дописывает сегмент [u16 length][payload] в существующий буфер.
/// В отличие от `frame_packet` не выделяет память на каждый пакет —
/// используется для коалесценции нескольких пакетов в одну запись стрима.
#[inline]
pub fn frame_packet_into(buf: &mut BytesMut, payload: &Bytes) {
    buf.reserve(LENGTH_PREFIX_SIZE + payload.len());
    buf.put_u16(payload.len() as u16);
    buf.put_slice(payload);
}

/// Читает ровно один IP-пакет из QUIC стрима.
/// Возвращает None, если стрим закрыт, или Result<Bytes, io::Error>
/// Используется в QUIC RX задаче.
#[inline]
pub async fn read_next_packet<R: tokio::io::AsyncRead + tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
) -> io::Result<Option<Bytes>> {
    loop {
        let mut len_buf = [0u8; LENGTH_PREFIX_SIZE];

        // 1. Считываем префикс длины (2 байта)
        match reader.read_exact(&mut len_buf).await {
            Ok(_) => {
                let len = u16::from_be_bytes(len_buf) as usize;

                if len == 0 {
                    // Пакет нулевой длины игнорируем, но продолжаем читать.
                    // ВАЖНО: раньше тут возвращался Ok(None), который все вызывающие
                    // трактуют как EOF и рвут туннель. Теперь честно пропускаем фрейм.
                    error!("Received packet with zero length prefix, skipping frame.");
                    continue;
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

                return Ok(Some(Bytes::from(buf)));
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // EOF при чтении префикса
                return Ok(None);
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_read_normal_packet() {
        let payload = vec![0xAB; 100];
        let mut data = vec![0u8, 100]; // длина 100 BE
        data.extend_from_slice(&payload);
        let mut reader = std::io::Cursor::new(data);

        let pkt = read_next_packet(&mut reader).await.unwrap().unwrap();
        assert_eq!(pkt.len(), 100);
        assert_eq!(pkt[0], 0xAB);
    }

    #[tokio::test]
    async fn test_zero_length_frame_is_skipped_not_eof() {
        // [len=0][len=3][3 байта] — нулевой фрейм должен быть пропущен,
        // а следующий пакет — прочитан (раньше тут возвращался Ok(None) => разрыв туннеля)
        let data = vec![0, 0, 0, 3, 1, 2, 3];
        let mut reader = std::io::Cursor::new(data);

        let pkt = read_next_packet(&mut reader).await.unwrap().unwrap();
        assert_eq!(&pkt[..], &[1, 2, 3]);
    }

    #[tokio::test]
    async fn test_eof_returns_none() {
        let mut reader = std::io::Cursor::new(Vec::<u8>::new());
        assert!(read_next_packet(&mut reader).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_oversized_frame_is_error() {
        let len = (MAX_PACKET_SIZE + 1) as u16;
        let data = len.to_be_bytes().to_vec();
        let mut reader = std::io::Cursor::new(data);
        assert!(read_next_packet(&mut reader).await.is_err());
    }

    #[test]
    fn test_frame_packet_into_matches_frame_packet() {
        let payload = Bytes::from_static(&[9, 8, 7, 6]);
        let framed = frame_packet(payload.clone());

        let mut buf = BytesMut::new();
        frame_packet_into(&mut buf, &payload);
        assert_eq!(&framed[..], &buf[..]);
    }
}
