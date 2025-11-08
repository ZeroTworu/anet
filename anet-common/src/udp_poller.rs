use quinn::UdpPoller;
use std::fmt::Debug;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::net::UdpSocket;

#[derive(Debug)]
pub struct TokioUdpPoller {
    pub io: Arc<UdpSocket>,
}

impl Future for TokioUdpPoller {
    type Output = io::Result<()>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.io.poll_send_ready(cx).map(|res| res.map(|_| ()))
    }
}

impl UdpPoller for TokioUdpPoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self).poll(cx)
    }
}
