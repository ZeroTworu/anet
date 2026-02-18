//! Unified transport abstraction for all VPN protocols

mod ssh_client;
mod tcp_ssh;
mod tcp_tls;

use crate::config::StealthConfig;
use crate::encryption::Cipher;
use crate::protocol::AuthResponse;
use anyhow::Result;
use bytes::Bytes;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

/// Unique connection identifier
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub String);

/// Transport-agnostic VPN stream
pub trait VpnStream: AsyncRead + AsyncWrite + Send + Unpin {
    /// Get peer address
    fn peer_addr(&self) -> Result<SocketAddr>;

    /// Get connection ID for logging/registry
    fn connection_id(&self) -> ConnectionId;

    /// Graceful shutdown
    fn shutdown(&mut self) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>>;
}

/// Factory for creating transport-specific VPN connections
#[async_trait::async_trait]
pub trait TransportConnector: Send + Sync {
    /// Connect and perform full authentication
    async fn connect(
        &self,
    ) -> Result<(
        Box<dyn VpnStream>,
        AuthResponse,
        Cipher,
    )>;
}

/// Server-side transport acceptor
#[async_trait::async_trait]
pub trait TransportAcceptor: Send + Sync + Clone {
    /// Accept incoming connection and perform authentication
    async fn accept(
        &self,
    ) -> Result<(
        Box<dyn VpnStream>,
        AuthResponse,
        Cipher,
        ConnectionId,
    )>;
}

/// Unified packet framing - reused across all transports
pub use crate::stream_framing::{frame_packet, read_next_packet};

/// Bridge TUN channel to any VpnStream with stealth features
/// Reuses existing bridge_with_jitter logic exactly as-is
pub async fn bridge_tun_to_stream<S>(
    tun_rx: mpsc::Receiver<Bytes>,
    stream: S,
    stealth: StealthConfig,
) -> Result<()>
where
    S: AsyncWrite + Unpin + Send + 'static,
{
    use crate::jitter::bridge_with_jitter;

    // Reuse existing jitter implementation exactly as-is
    bridge_with_jitter(tun_rx, stream, stealth).await
}

/// Bridge VpnStream to TUN channel
pub async fn bridge_stream_to_tun<S>(
    mut stream: S,
    tun_tx: mpsc::Sender<Bytes>,
) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    loop {
        match read_next_packet(&mut stream).await {
            Ok(Some(packet)) => {
                if tun_tx.send(packet).await.is_err() {
                    break;
                }
            }
            Ok(None) => break, // EOF
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

// === EncryptedStream wrapper for post-auth encryption ===

pin_project_lite::pin_project! {
    /// Wrapper to add post-auth encryption layer to any stream
    pub struct EncryptedStream<S> {
        #[pin]
        inner: S,
        cipher: Cipher,
        nonce_counter: u64,
        read_buffer: Vec<u8>,
        write_buffer: Vec<u8>,
    }
}

impl<S> EncryptedStream<S> {
    pub fn new(inner: S, cipher: Cipher) -> Self {
        Self {
            inner,
            cipher,
            nonce_counter: 0,
            read_buffer: Vec::with_capacity(65535),
            write_buffer: Vec::with_capacity(65535),
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead> AsyncRead for EncryptedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();

        // Try to serve from decrypted buffer first
        if !this.read_buffer.is_empty() {
            let to_copy = std::cmp::min(buf.remaining(), this.read_buffer.len());
            buf.put_slice(&this.read_buffer[..to_copy]);
            this.read_buffer.drain(..to_copy);
            return Poll::Ready(Ok(()));
        }

        // Need to read and decrypt more data
        let mut temp = vec![0u8; 65535];
        let mut temp_buf = ReadBuf::new(&mut temp);

        match this.inner.poll_read(cx, &mut temp_buf) {
            Poll::Ready(Ok(())) => {
                let filled = temp_buf.filled().len();
                if filled == 0 {
                    return Poll::Ready(Ok(()));
                }

                // Decrypt: nonce (12) + ciphertext + tag (16)
                if filled < 28 {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "packet too short",
                    )));
                }

                let nonce: [u8; 12] = temp[..12].try_into().unwrap();
                let ciphertext = &temp[12..filled];

                match this.cipher.decrypt(&nonce, Bytes::copy_from_slice(ciphertext)) {
                    Ok(plaintext) => {
                        let to_copy = std::cmp::min(buf.remaining(), plaintext.len());
                        buf.put_slice(&plaintext[..to_copy]);
                        if plaintext.len() > to_copy {
                            this.read_buffer.extend_from_slice(&plaintext[to_copy..]);
                        }
                        Poll::Ready(Ok(()))
                    }
                    Err(_) => Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "decryption failed",
                    ))),
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncWrite> AsyncWrite for EncryptedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();

        // Encrypt with fresh nonce
        let nonce = Cipher::generate_nonce(*this.nonce_counter);
        *this.nonce_counter += 1;

        let plaintext = Bytes::copy_from_slice(buf);
        match this.cipher.encrypt(&nonce, plaintext) {
            Ok(ciphertext) => {
                // Build packet: [nonce][ciphertext]
                this.write_buffer.clear();
                this.write_buffer.extend_from_slice(&nonce);
                this.write_buffer.extend_from_slice(&ciphertext);

                // Write all to inner
                let mut written = 0;
                while written < this.write_buffer.len() {
                    match this.inner.poll_write(cx, &this.write_buffer[written..]) {
                        Poll::Ready(Ok(n)) => written += n,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => {
                            this.write_buffer.drain(..written);
                            return Poll::Pending;
                        }
                    }
                }

                this.write_buffer.clear();
                Poll::Ready(Ok(buf.len()))
            }
            Err(_) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "encryption failed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}
