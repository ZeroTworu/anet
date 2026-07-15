use crate::config::StealthConfig;
use crate::stream_framing::frame_packet_into;
use bytes::{Bytes, BytesMut};
use log::{error, info, warn};
use rand::Rng;
use rand::rngs::OsRng;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::time::sleep;
use crate::consts::CHANNEL_BUFFER_SIZE;
use crate::encryption::Cipher;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use crate::padding_utils::calculate_padding_needed;



/// Читает пакеты из канала `rx`, добавляет случайную задержку (parallel jitter),
/// и пишет их в QUIC стрим `stream`.
///
/// * `rx`: Источник пакетов (например, из TUN).
/// * `stream`: QUIC SendStream.
/// * `min_jitter`: Минимальная задержка (ns).
/// * `max_jitter`: Максимальная задержка (ns).
/// Максимальный размер буфера коалесценции (байт) перед сбросом в стрим.
/// ~44 пакета по 1450 байт. Держим заметно меньше stream receive window,
/// чтобы не вносить лишнюю задержку.
const COALESCE_BUDGET_BYTES: usize = 64 * 1024;

/// Цикл отправки с коалесценцией: берём первый пакет блокирующе,
/// затем выгребаем всё, что уже накопилось в канале, через `try_recv()`,
/// и пишем одним `write_all` с одним `flush`.
///
/// На высоких PPS это уменьшает число операций записи в стрим (и, как следствие,
/// syscalls/QUIC-пакетов на выходе) на порядок, сохраняя порядок пакетов.
async fn coalesced_sender_loop<S>(
    rx_ready: &mut mpsc::Receiver<Bytes>,
    stream: &mut S,
) -> anyhow::Result<()>
where
    S: AsyncWriteExt + Unpin + Send,
{
    let mut buf = BytesMut::with_capacity(COALESCE_BUDGET_BYTES);

    while let Some(packet) = rx_ready.recv().await {
        buf.clear();

        // Фильтр мусора: минимальный IPv4-заголовок — 20 байт
        if packet.len() >= 20 {
            frame_packet_into(&mut buf, &packet);
        }

        // Выгребаем всё, что уже готово, без ожидания
        while buf.len() < COALESCE_BUDGET_BYTES {
            match rx_ready.try_recv() {
                Ok(p) if p.len() >= 20 => frame_packet_into(&mut buf, &p),
                Ok(_) => continue,
                Err(_) => break,
            }
        }

        if buf.is_empty() {
            continue;
        }

        if stream.write_all(&buf).await.is_err() || stream.flush().await.is_err() {
            error!("Stream write failed");
            break;
        }
    }
    Ok(())
}

pub async fn bridge_with_jitter<S>(
    mut rx: mpsc::Receiver<Bytes>,
    mut stream: S,
    config: StealthConfig,
) -> anyhow::Result<()>
where
    S: AsyncWriteExt + Unpin + Send + 'static,
{
    let jitter_enabled = config.max_jitter_ns > config.min_jitter_ns;

    // --- Быстрый путь: джиттер выключен (дефолт) ---
    // Без диспетчера, без spawn на каждый пакет, без второго канала.
    // Пакеты идут напрямую: rx -> коалесценция -> стрим. Порядок сохраняется.
    if !jitter_enabled {
        let result = coalesced_sender_loop(&mut rx, &mut stream).await;
        let _ = stream.shutdown().await;
        return result;
    }

    // --- Путь с джиттером ---
    // Промежуточный канал для пакетов, которые "проснулись" после джиттера
    let (tx_ready, mut rx_ready) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);

    // Задача 1: Диспетчер (Прием -> Sleep -> ReadyChannel)
    let dispatch_task = tokio::spawn(async move {
        let mut rng = OsRng;
        while let Some(packet) = rx.recv().await {
            if packet.len() < 20 {
                continue;
            } // Фильтр мусора (опционально)

            let tx = tx_ready.clone();
            let delay = rng.gen_range(config.min_jitter_ns..=config.max_jitter_ns);

            // Спавним микро-задачу на каждый пакет
            tokio::spawn(async move {
                if delay > 0 {
                    sleep(Duration::from_nanos(delay)).await;
                }
                // Если получатель умер, просто выходим
                let _ = tx.send(packet).await;
            });
        }
    });

    // Задача 2: Отправщик (ReadyChannel -> QUIC Stream)
    // Этот цикл работает в текущем таске и ждет завершения
    let result = coalesced_sender_loop(&mut rx_ready, &mut stream).await;

    // Закрываем стрим корректно
    let _ = stream.shutdown().await;

    // Ждем завершения диспетчера (хотя он скорее всего уже умер из-за закрытия канала)
    dispatch_task.abort();

    result
}


/// Читает IP-пакеты, применяет Jitter, шифрует XChaCha20, добавляет фрейминг длины и пишет в TCP-Стрим.
/// Используется для SSH, VNC и других стримовых протоколов.
pub async fn bridge_crypto_stream_with_jitter<S>(
    mut rx: mpsc::Receiver<Bytes>,
    mut stream: S,
    config: StealthConfig,
    cipher: Arc<Cipher>,
    sequence: Arc<AtomicU64>,
    nonce_prefix: [u8; 4],
) -> anyhow::Result<()>
where
    S: AsyncWriteExt + Unpin + Send + 'static,
{
    let (tx_ready, mut rx_ready) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);

    let stealth_cfg = config.clone();
    let dispatch_task = tokio::spawn(async move {
        let mut rng = OsRng;
        while let Some(packet) = rx.recv().await {
            if packet.len() < 20 { continue; }

            let tx = tx_ready.clone();
            let delay = if stealth_cfg.max_jitter_ns > stealth_cfg.min_jitter_ns {
                rng.gen_range(stealth_cfg.min_jitter_ns..=stealth_cfg.max_jitter_ns)
            } else { 0 };

            tokio::spawn(async move {
                if delay > 0 { tokio::time::sleep(Duration::from_nanos(delay)).await; }
                let _ = tx.send(packet).await;
            });
        }
    });

    let padding_step = config.padding_step;
    let mut buf = BytesMut::with_capacity(COALESCE_BUDGET_BYTES);

    // Шифруем пакет и дописываем его фрейм в буфер коалесценции
    let encrypt_into = |packet: Bytes, buf: &mut BytesMut| {
        let seq = sequence.fetch_add(1, Ordering::Relaxed);
        let total_len = packet.len() + 38;
        let pad = calculate_padding_needed(total_len, padding_step);
        let safe_pad = if total_len + (pad as usize) > crate::consts::PADDING_MTU { 0 } else { pad };

        if let Ok(crypted) = crate::transport::wrap_packet(&cipher, &nonce_prefix, seq, packet, safe_pad) {
            frame_packet_into(buf, &crypted);
        }
    };

    while let Some(packet) = rx_ready.recv().await {
        buf.clear();
        encrypt_into(packet, &mut buf);

        // Выгребаем всё, что уже готово, и пишем одним вызовом
        while buf.len() < COALESCE_BUDGET_BYTES {
            match rx_ready.try_recv() {
                Ok(p) => encrypt_into(p, &mut buf),
                Err(_) => break,
            }
        }

        if buf.is_empty() {
            continue;
        }

        if stream.write_all(&buf).await.is_err() || stream.flush().await.is_err() {
            break;
        }
    }

    let _ = stream.shutdown().await;
    dispatch_task.abort();
    Ok(())
}


pub async fn receive_crypto_stream<R>(
    mut reader: R,
    tx: mpsc::Sender<Bytes>,
    cipher: Arc<Cipher>,
) -> anyhow::Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    loop {
        match crate::stream_framing::read_next_packet(&mut reader).await {
            Ok(Some(framed_packet)) => {
                match crate::transport::unwrap_packet(&cipher, &framed_packet) {
                    Ok(tun_data) => {
                        if tx.send(tun_data).await.is_err() {
                            error!("[Crypto Stream RX] Failed to send to TUN queue. Inner router channel closed!");
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("[Crypto Stream RX] Packet Decryption Failed (Dropped): {}", e);
                        // Продолжаем читать, не убиваем туннель из-за одного битого пакета
                    }
                }
            }
            Ok(None) => {
                info!("[Crypto Stream RX] Clean EOF received. Remote peer closed connection.");
                break;
            }
            Err(e) => {
                error!("[Crypto Stream RX] Frame Reader Fault: {}", e);
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// Быстрый путь (джиттер выключен): все пакеты доходят, порядок сохранён,
    /// фрейминг корректен.
    #[tokio::test]
    async fn test_fast_path_preserves_order_and_framing() {
        let (tx, rx) = mpsc::channel::<Bytes>(64);
        let (writer, mut read_half) = tokio::io::duplex(1 << 20);

        for i in 0..50u8 {
            tx.send(Bytes::from(vec![i; 24])).await.unwrap();
        }
        drop(tx);

        let bridge = tokio::spawn(bridge_with_jitter(rx, writer, StealthConfig::default()));

        let mut data = Vec::new();
        read_half.read_to_end(&mut data).await.unwrap();
        bridge.await.unwrap().unwrap();

        let mut reader = std::io::Cursor::new(data);
        for i in 0..50u8 {
            let pkt = crate::stream_framing::read_next_packet(&mut reader)
                .await
                .unwrap()
                .expect("packet missing");
            assert_eq!(pkt.len(), 24);
            assert_eq!(pkt[0], i, "packet order violated");
        }
        assert!(
            crate::stream_framing::read_next_packet(&mut reader)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Мусор (<20 байт) отфильтровывается и в быстром пути.
    #[tokio::test]
    async fn test_fast_path_filters_garbage() {
        let (tx, rx) = mpsc::channel::<Bytes>(8);
        let (writer, mut read_half) = tokio::io::duplex(1 << 16);

        tx.send(Bytes::from_static(&[1, 2, 3])).await.unwrap(); // мусор
        tx.send(Bytes::from(vec![7u8; 32])).await.unwrap(); // нормальный
        drop(tx);

        let bridge = tokio::spawn(bridge_with_jitter(rx, writer, StealthConfig::default()));

        let mut data = Vec::new();
        read_half.read_to_end(&mut data).await.unwrap();
        bridge.await.unwrap().unwrap();

        let mut reader = std::io::Cursor::new(data);
        let pkt = crate::stream_framing::read_next_packet(&mut reader)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pkt.len(), 32);
        assert!(
            crate::stream_framing::read_next_packet(&mut reader)
                .await
                .unwrap()
                .is_none()
        );
    }
}
