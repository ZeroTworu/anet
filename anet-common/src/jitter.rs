use crate::config::StealthConfig;
use crate::consts::{COALESCE_BUDGET_BYTES, CRYPTO_COALESCE_BUDGET_BYTES};
use crate::encryption::Cipher;
use crate::padding_utils::calculate_padding_needed;
use crate::stream_framing::frame_packet_into;
use bytes::{Bytes, BytesMut};
use futures::future::BoxFuture;
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::time::sleep;

const MAX_PENDING_JITTER_PACKETS: usize = 256;

pub async fn bridge_with_jitter<S>(
    mut rx: mpsc::Receiver<Bytes>,
    mut stream: S,
    config: StealthConfig,
) -> anyhow::Result<()>
where
    S: AsyncWriteExt + Unpin + Send + 'static,
{
    let jitter_enabled = config.max_jitter_ns > config.min_jitter_ns;
    let mut rng = StdRng::from_entropy();
    let mut pending = FuturesUnordered::<BoxFuture<'static, Bytes>>::new();
    let mut input_open = true;
    let mut buf = BytesMut::with_capacity(COALESCE_BUDGET_BYTES);

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
            pending.next().await.expect("jitter queue is not empty")
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
                packet = pending.next() => packet.expect("jitter queue is not empty"),
            }
        };

        if packet.len() < 20 {
            continue;
        }

        buf.clear();
        frame_packet_into(&mut buf, &packet);

        while !jitter_enabled && buf.len() < COALESCE_BUDGET_BYTES {
            match rx.try_recv() {
                Ok(packet) if packet.len() >= 20 => frame_packet_into(&mut buf, &packet),
                Ok(_) => continue,
                Err(_) => break,
            }
        }

        if !buf.is_empty() {
            stream.write_all(&buf).await?;
            // FLUSH УДАЛЕН
        }
    }

    stream.shutdown().await?;
    Ok(())
}

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
        crate::stream_framing::frame_packet_into(buf, &encrypted);
        Ok(())
    };

    while input_open || !pending.is_empty() {
        let mut packet = if !jitter_enabled {
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

        buf.clear();

        loop {
            if packet.len() >= 20 {
                encrypt_into(packet, &mut buf)?;
            }

            if buf.len() >= CRYPTO_COALESCE_BUDGET_BYTES {
                break;
            }

            packet = match rx.try_recv() {
                Ok(p) => p,
                Err(_) => break,
            };
        }

        if !buf.is_empty() {
            stream.write_all(&buf).await?;
            // FLUSH УДАЛЕН
        }
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
