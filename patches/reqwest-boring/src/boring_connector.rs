//! Hyper I/O adapter for the BoringSSL transport.
use crate::boring_tls::Config;
use crate::error::BoxError;
use http::Uri;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower_service::Service;

#[derive(Clone)]
pub(crate) struct HttpsConnector<T> {
    http: T,
    tls: Arc<Config>,
}
impl<T> From<(T, Arc<Config>)> for HttpsConnector<T> {
    fn from((http, tls): (T, Arc<Config>)) -> Self {
        Self { http, tls }
    }
}
impl<T, S> Service<Uri> for HttpsConnector<T>
where
    T: Service<Uri, Response = S>,
    T::Future: Send + 'static,
    T::Error: Into<BoxError>,
    S: Read + Write + Connection + Unpin + Send + Sync + std::fmt::Debug + 'static,
{
    type Response = MaybeHttpsStream<S>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, BoxError>> + Send>>;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }
    fn call(&mut self, dst: Uri) -> Self::Future {
        let connect = self.http.call(dst.clone());
        let tls = self.tls.clone();
        Box::pin(async move {
            let io = connect.await.map_err(Into::into)?;
            if dst.scheme_str() != Some("https") {
                return Ok(MaybeHttpsStream::Http(io));
            }
            let host = dst
                .host()
                .ok_or("missing host")?
                .trim_start_matches('[')
                .trim_end_matches(']');
            let io = tokio_boring::connect(
                tls.configure(host, dst.port_u16().unwrap_or(443))?,
                host,
                TokioIo::new(io),
            )
            .await?;
            Ok(MaybeHttpsStream::Https(TokioIo::new(io)))
        })
    }
}

#[derive(Debug)]
pub(crate) enum MaybeHttpsStream<T> {
    Http(T),
    Https(TokioIo<tokio_boring::SslStream<TokioIo<T>>>),
}
impl<T: Read + Write + Connection + Unpin> Connection for MaybeHttpsStream<T> {
    fn connected(&self) -> Connected {
        match self {
            Self::Http(io) => io.connected(),
            Self::Https(io) => {
                let connected = io.inner().get_ref().inner().connected();
                if io.inner().ssl().selected_alpn_protocol() == Some(b"h2") {
                    connected.negotiated_h2()
                } else {
                    connected
                }
            }
        }
    }
}
impl<T: Read + Write + Unpin> Read for MaybeHttpsStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Http(io) => Pin::new(io).poll_read(cx, buf),
            Self::Https(io) => Pin::new(io).poll_read(cx, buf),
        }
    }
}
impl<T: Read + Write + Unpin> Write for MaybeHttpsStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Http(io) => Pin::new(io).poll_write(cx, buf),
            Self::Https(io) => Pin::new(io).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Http(io) => Pin::new(io).poll_flush(cx),
            Self::Https(io) => Pin::new(io).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Http(io) => Pin::new(io).poll_shutdown(cx),
            Self::Https(io) => Pin::new(io).poll_shutdown(cx),
        }
    }
}
