use crate::config::StealthConfig;
use crate::stream_framing::frame_packet;
use bytes::Bytes;
use log::error;
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
use crate::transport::unwrap_packet;
use crate::stream_framing::read_next_packet;



/// Читает пакеты из канала `rx`, добавляет случайную задержку (parallel jitter),
/// и пишет их в QUIC стрим `stream`.
///
/// * `rx`: Источник пакетов (например, из TUN).
/// * `stream`: QUIC SendStream.
/// * `min_jitter`: Минимальная задержка (ns).
/// * `max_jitter`: Максимальная задержка (ns).
pub async fn bridge_with_jitter<S>(
    mut rx: mpsc::Receiver<Bytes>,
    mut stream: S,
    config: StealthConfig,
) -> anyhow::Result<()>
where
    S: AsyncWriteExt + Unpin + Send + 'static,
{
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
            let delay = if config.max_jitter_ns > config.min_jitter_ns {
                rng.gen_range(config.min_jitter_ns..=config.max_jitter_ns)
            } else {
                0
            };

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
    while let Some(packet) = rx_ready.recv().await {
        let framed = frame_packet(packet);
        if stream.write_all(&framed).await.is_err() || stream.flush().await.is_err() {
            error!("Stream write failed");
            break;
        }
    }

    // Закрываем стрим корректно
    let _ = stream.shutdown().await;

    // Ждем завершения диспетчера (хотя он скорее всего уже умер из-за закрытия канала)
    dispatch_task.abort();

    Ok(())
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
    while let Some(packet) = rx_ready.recv().await {
        let seq = sequence.fetch_add(1, Ordering::Relaxed);
        let total_len = packet.len() + 38;
        let pad = calculate_padding_needed(total_len, padding_step);
        let safe_pad = if total_len + (pad as usize) > crate::consts::PADDING_MTU { 0 } else { pad };

        if let Ok(crypted) = crate::transport::wrap_packet(&cipher, &nonce_prefix, seq, packet, safe_pad) {
            let framed = frame_packet(crypted);
            if stream.write_all(&framed).await.is_err() || stream.flush().await.is_err() {
                break;
            }
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
    while let Ok(Some(framed_packet)) = read_next_packet(&mut reader).await {
        if let Ok(tun_data) = unwrap_packet(&cipher, &framed_packet) {
            if tx.send(tun_data).await.is_err() {
                break;
            }
        }
    }
    Ok(())
}
