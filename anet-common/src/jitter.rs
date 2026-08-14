use crate::config::StealthConfig;
use crate::consts::{CHANNEL_BUFFER_SIZE, COALESCE_BUDGET_BYTES, CRYPTO_COALESCE_BUDGET_BYTES};
use crate::encryption::Cipher;
use crate::padding_utils::calculate_padding_needed;
use crate::stream_framing::frame_packet_into;
use bytes::{Bytes, BytesMut};
use futures::future::BoxFuture;
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use log::error;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::OsRng;
use rand::rngs::StdRng;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::time::sleep;

const MAX_PENDING_JITTER_PACKETS: usize = 256;

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

        if packet.len() >= 20 {
            frame_packet_into(&mut buf, &packet);
        }

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

    if !jitter_enabled {
        let result = coalesced_sender_loop(&mut rx, &mut stream).await;
        let _ = stream.shutdown().await;
        return result;
    }

    let (tx_ready, mut rx_ready) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);

    let dispatch_task = tokio::spawn(async move {
        let mut rng = OsRng;
        while let Some(packet) = rx.recv().await {
            if packet.len() < 20 {
                continue;
            }

            let tx = tx_ready.clone();
            let delay = rng.gen_range(config.min_jitter_ns..=config.max_jitter_ns);

            tokio::spawn(async move {
                if delay > 0 {
                    sleep(Duration::from_nanos(delay)).await;
                }
                let _ = tx.send(packet).await;
            });
        }
    });

    let result = coalesced_sender_loop(&mut rx_ready, &mut stream).await;
    let _ = stream.shutdown().await;
    dispatch_task.abort();

    result
}

/// Шифрует и объединяет пакеты потокового SSH-транспорта с ограниченным джиттером.
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
    let padding_step = config.padding_step;
    let jitter_enabled = config.max_jitter_ns > config.min_jitter_ns;
    let mut rng = StdRng::from_entropy();
    let mut pending = FuturesUnordered::<BoxFuture<'static, Bytes>>::new();
    let mut input_open = true;
    let mut buf = BytesMut::with_capacity(CRYPTO_COALESCE_BUDGET_BYTES);

    let encrypt_into = |packet: Bytes, buf: &mut BytesMut| -> anyhow::Result<()> {
        let seq = sequence.fetch_add(1, Ordering::Relaxed);
        let total_len = packet.len() + 38;
        let pad = calculate_padding_needed(total_len, padding_step);
        let safe_pad = if total_len + (pad as usize) > crate::consts::PADDING_MTU {
            0
        } else {
            pad
        };

        let encrypted =
            crate::transport::wrap_packet(&cipher, &nonce_prefix, seq, packet, safe_pad)?;
        frame_packet_into(buf, &encrypted);
        Ok(())
    };

    while input_open || !pending.is_empty() {
        let packet = if !jitter_enabled {
            match rx.recv().await {
                Some(packet) => packet,
                None => break,
            }
        } else if pending.is_empty() {
            match rx.recv().await {
                Some(packet) => {
                    schedule_with_jitter(&mut pending, packet, &config, &mut rng);
                    continue;
                }
                None => {
                    input_open = false;
                    continue;
                }
            }
        } else if !input_open || pending.len() >= MAX_PENDING_JITTER_PACKETS {
            pending.next().await.expect("очередь джиттера не пуста")
        } else {
            tokio::select! {
                packet = rx.recv() => {
                    match packet {
                        Some(packet) => {
                            schedule_with_jitter(&mut pending, packet, &config, &mut rng);
                            continue;
                        }
                        None => {
                            input_open = false;
                            continue;
                        }
                    }
                }
                packet = pending.next() => packet.expect("очередь джиттера не пуста"),
            }
        };
        if packet.len() < 20 {
            continue;
        }

        buf.clear();
        encrypt_into(packet, &mut buf)?;

        // При выключенном джиттере объединяем уже ожидающие пакеты в одну SSH-запись.
        while !jitter_enabled && buf.len() < CRYPTO_COALESCE_BUDGET_BYTES {
            match rx.try_recv() {
                Ok(packet) if packet.len() >= 20 => encrypt_into(packet, &mut buf)?,
                Ok(_) => continue,
                Err(_) => break,
            }
        }

        if buf.is_empty() {
            continue;
        }

        stream.write_all(&buf).await?;
        stream.flush().await?;
    }

    stream.shutdown().await?;
    Ok(())
}

fn schedule_with_jitter(
    pending: &mut FuturesUnordered<BoxFuture<'static, Bytes>>,
    packet: Bytes,
    config: &StealthConfig,
    rng: &mut StdRng,
) {
    let delay = rng.gen_range(config.min_jitter_ns..=config.max_jitter_ns);
    pending.push(
        async move {
            if delay > 0 {
                sleep(Duration::from_nanos(delay)).await;
            }
            packet
        }
        .boxed(),
    );
}

pub async fn receive_crypto_stream<R>(
    mut reader: R,
    tx: mpsc::Sender<Bytes>,
    cipher: Arc<Cipher>,
) -> anyhow::Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    while let Some(encrypted) = crate::stream_framing::read_next_packet(&mut reader).await? {
        let packet = crate::transport::unwrap_packet_bytes_in_place(&cipher, encrypted)?;
        tx.send(packet)
            .await
            .map_err(|_| anyhow::anyhow!("очередь входящих пакетов закрыта"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

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

    #[tokio::test]
    async fn crypto_stream_fast_path_round_trip() {
        let cipher = Arc::new(Cipher::new(&[5; 32]));
        let sequence = Arc::new(AtomicU64::new(0));
        let nonce_prefix = [1, 2, 3, 4];
        let rx = {
            let (tx, rx) = mpsc::channel::<Bytes>(64);
            for value in 0..32u8 {
                tx.send(Bytes::from(vec![value; 64])).await.unwrap();
            }
            rx
        };
        let (writer, mut reader) = tokio::io::duplex(1 << 20);

        bridge_crypto_stream_with_jitter(
            rx,
            writer,
            StealthConfig::default(),
            cipher.clone(),
            sequence,
            nonce_prefix,
        )
        .await
        .unwrap();

        for value in 0..32u8 {
            let encrypted = crate::stream_framing::read_next_packet(&mut reader)
                .await
                .unwrap()
                .expect("зашифрованный пакет отсутствует");
            let packet = crate::transport::unwrap_packet_bytes_in_place(&cipher, encrypted)
                .expect("пакет должен расшифровываться");
            assert_eq!(packet, Bytes::from(vec![value; 64]));
        }
        assert!(
            crate::stream_framing::read_next_packet(&mut reader)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_fast_path_filters_garbage() {
        let (tx, rx) = mpsc::channel::<Bytes>(8);
        let (writer, mut read_half) = tokio::io::duplex(1 << 16);

        tx.send(Bytes::from_static(&[1, 2, 3])).await.unwrap();
        tx.send(Bytes::from(vec![7u8; 32])).await.unwrap();
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
