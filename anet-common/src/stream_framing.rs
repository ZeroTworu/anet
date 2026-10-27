use crate::consts::{COALESCE_BUDGET_BYTES, MAX_PACKET_SIZE};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use log::error;
use std::io;
use tokio::io::AsyncReadExt;

const LENGTH_PREFIX_SIZE: usize = 2; // u16 длина префикса

/// Буферизованный декодер сегментов потока `[u16 length][payload]`.
/// Читает из `AsyncRead` крупными блоками через `read_buf` в переиспользуемый `BytesMut`,
/// исключая аллокацию `vec![0u8; len]` и двойной `.await` на каждый пакет.
pub struct FrameReader {
    buf: BytesMut,
}

impl Default for FrameReader {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameReader {
    #[inline]
    pub fn new() -> Self {
        Self::with_capacity(COALESCE_BUDGET_BYTES + MAX_PACKET_SIZE)
    }

    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: BytesMut::with_capacity(capacity),
        }
    }

    /// Пытается синхронно извлечь следующий уже полностью загруженный в буфер фрейм без I/O.
    #[inline]
    pub fn try_next_packet(&mut self) -> io::Result<Option<Bytes>> {
        loop {
            if self.buf.len() < LENGTH_PREFIX_SIZE {
                return Ok(None);
            }

            let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
            if len == 0 {
                self.buf.advance(LENGTH_PREFIX_SIZE);
                error!("Received packet with zero length prefix, skipping frame.");
                continue;
            }
            if len > MAX_PACKET_SIZE {
                error!(
                    "Received oversized packet length: {}. Max allowed: {}",
                    len, MAX_PACKET_SIZE
                );
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Oversized packet received",
                ));
            }

            if self.buf.len() < LENGTH_PREFIX_SIZE + len {
                return Ok(None);
            }

            self.buf.advance(LENGTH_PREFIX_SIZE);
            let pkt = self.buf.split_to(len).freeze();
            return Ok(Some(pkt));
        }
    }

    /// Читает следующий фрейм из `reader`, подгружая данные крупными порциями при необходимости.
    #[inline]
    pub async fn read_next_packet<R: tokio::io::AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> io::Result<Option<Bytes>> {
        loop {
            if let Some(pkt) = self.try_next_packet()? {
                return Ok(Some(pkt));
            }

            if self.buf.capacity().saturating_sub(self.buf.len()) < COALESCE_BUDGET_BYTES {
                self.buf.reserve(COALESCE_BUDGET_BYTES + MAX_PACKET_SIZE);
            }

            let n = reader.read_buf(&mut self.buf).await?;
            if n == 0 {
                if self.buf.is_empty() {
                    return Ok(None);
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "EOF in the middle of a framed packet",
                    ));
                }
            }
        }
    }
}

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
                let mut buf = BytesMut::zeroed(len);
                reader.read_exact(&mut buf).await?;

                return Ok(Some(buf.freeze()));
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
    async fn test_frame_reader_coalesced_batch() {
        let mut batch = BytesMut::new();
        let p1 = Bytes::from_static(&[1, 2, 3, 4]);
        let p2 = Bytes::from_static(&[5, 6, 7]);
        frame_packet_into(&mut batch, &p1);
        frame_packet_into(&mut batch, &p2);

        let mut cursor = std::io::Cursor::new(batch.freeze());
        let mut frame_reader = FrameReader::new();

        let out1 = frame_reader.read_next_packet(&mut cursor).await.unwrap().unwrap();
        assert_eq!(out1, p1);
        // Второй пакет уже должен быть в буфере без дополнительного чтения из сокета
        let out2 = frame_reader.try_next_packet().unwrap().unwrap();
        assert_eq!(out2, p2);
        assert!(frame_reader.read_next_packet(&mut cursor).await.unwrap().is_none());
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


/// Результат ожидания завершения одного из двух воркеров двунаправленного потока (inbound / outbound).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinishedWorker {
    Inbound,
    Outbound,
}

/// Выполняет синхронное ожидание первого завершившегося воркера (`inbound` или `outbound`),
/// после чего корректно абортит и очищает оставшийся воркер, устраняя дублирование логики в SSH/VNC серверах.
pub async fn supervise_bidirectional_workers(
    mut inbound: tokio::task::JoinHandle<anyhow::Result<()>>,
    mut outbound: tokio::task::JoinHandle<anyhow::Result<()>>,
    transport_name: &str,
) -> (FinishedWorker, anyhow::Result<()>) {
    let (finished_worker, result) = tokio::select! {
        result = &mut inbound => (
            FinishedWorker::Inbound,
            result.map_err(|e| anyhow::anyhow!("{transport_name} reader task panicked: {e}")).and_then(|r| r)
        ),
        result = &mut outbound => (
            FinishedWorker::Outbound,
            result.map_err(|e| anyhow::anyhow!("{transport_name} writer task panicked: {e}")).and_then(|r| r)
        ),
    };

    if finished_worker != FinishedWorker::Inbound {
        inbound.abort();
        let _ = inbound.await;
    }
    if finished_worker != FinishedWorker::Outbound {
        outbound.abort();
        let _ = outbound.await;
    }

    (finished_worker, result)
}
