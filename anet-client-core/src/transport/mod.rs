pub(crate) mod factory;
pub(crate) mod quic;
pub(crate) mod ssh;
pub(crate) mod vnc;

use anet_common::protocol::AuthResponse;
use anet_common::transport_trait::VpnStream;
use anyhow::Result;
use async_trait::async_trait;
use quinn::{Endpoint, Connection};

use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;

pub struct ConnectionResult {
    pub auth_response: AuthResponse,
    pub vpn_stream: Box<dyn VpnStream>,
    pub endpoint: Option<Endpoint>,
    pub connection: Option<Connection>,
}

#[async_trait]
pub trait ClientTransport: Send + Sync {
    async fn connect(&self) -> Result<ConnectionResult>;
}

// ------------------------------------------------------------------
// Shared Stream Adapter
// ------------------------------------------------------------------
pub struct MutexVpnStream<S>(pub Arc<Mutex<S>>);

impl<S: AsyncRead + Unpin + Send> AsyncRead for MutexVpnStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        let mut guard = futures::ready!(Box::pin(self.0.lock()).as_mut().poll(cx));
        Pin::new(&mut *guard).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin + Send> AsyncWrite for MutexVpnStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        let mut guard = futures::ready!(Box::pin(self.0.lock()).as_mut().poll(cx));
        Pin::new(&mut *guard).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        let mut guard = futures::ready!(Box::pin(self.0.lock()).as_mut().poll(cx));
        Pin::new(&mut *guard).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        let mut guard = futures::ready!(Box::pin(self.0.lock()).as_mut().poll(cx));
        Pin::new(&mut *guard).poll_shutdown(cx)
    }
}
