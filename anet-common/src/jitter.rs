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
    let (tx_ready, mut rx_ready) = mpsc::channel::<Bytes>(1024);

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
