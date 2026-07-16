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

/// Максимальный размер буфера коалесценции для QUIC (64 KB)
const COALESCE_BUDGET_BYTES: usize = 64 * 1024;

/// Безопасный бюджет коалесценции для SSH/VNC (16 KB)
/// Гарантирует, что размер пакета никогда не превысит стандартное окно SSH-канала (32 KB),
/// предотвращая переполнение буферов и панику CryptoVec::resize.
const CRYPTO_COALESCE_BUDGET_BYTES: usize = 16 * 1024;

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

/// Адаптированная функция для SSH и VNC транспортов с безопасным лимитом 16 KB
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
    // Используем безопасную емкость буфера для крипто-потоков
    let mut buf = BytesMut::with_capacity(CRYPTO_COALESCE_BUDGET_BYTES);

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

        // Группируем, строго ограничивая размер буфера лимитом CRYPTO_COALESCE_BUDGET_BYTES (16 KB)
        while buf.len() < CRYPTO_COALESCE_BUDGET_BYTES {
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
