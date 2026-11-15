//! Hyper I/O adapter for the BoringSSL transport.
use crate::boring_tls::{Config, TlsHelloFragConfig};
use crate::error::BoxError;
use http::Uri;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;
use std::{
    fmt,
    future::Future,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tower_service::Service;

fn next_rand_range(lo: u64, hi: u64) -> u64 {
    if hi <= lo {
        return lo;
    }
    static STATE: AtomicU64 = AtomicU64::new(0x9e37_79b9_7f4a_7c15);
    let mut prev = STATE.load(Ordering::Relaxed);
    if prev == 0x9e37_79b9_7f4a_7c15 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1);
        prev ^= nanos.rotate_left(17);
    }
    let mut z = prev.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    let out = z ^ (z >> 31);
    STATE.store(out, Ordering::Relaxed);
    let span = (hi - lo).saturating_add(1);
    lo + (out % span)
}

enum FragPhase {
    Armed(TlsHelloFragConfig),
    Fragmenting {
        cfg: TlsHelloFragConfig,
        remaining: usize,
        chunk_rem: usize,
        sleep: Option<Pin<Box<tokio::time::Sleep>>>,
        yield_next: bool,
    },
    Done,
}

pub(crate) struct FragStream<S> {
    inner: S,
    phase: FragPhase,
}

impl<S: fmt::Debug> fmt::Debug for FragStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FragStream")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S> FragStream<S> {
    pub(crate) fn new(inner: S, cfg: Option<TlsHelloFragConfig>) -> Self {
        let phase = match cfg {
            Some(c) if c.enabled => FragPhase::Armed(c),
            _ => FragPhase::Done,
        };
        Self { inner, phase }
    }

    pub(crate) fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FragStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FragStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }

        if let FragPhase::Armed(cfg) = self.phase {
            if cfg.enabled && buf.len() >= 5 && buf[0] == 0x16 && buf[1] == 0x03 {
                let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
                self.phase = FragPhase::Fragmenting {
                    cfg,
                    remaining: 5 + record_len,
                    chunk_rem: 0,
                    sleep: None,
                    yield_next: false,
                };
            } else {
                self.phase = FragPhase::Done;
            }
        }

        match &mut self.phase {
            FragPhase::Done | FragPhase::Armed(_) => Pin::new(&mut self.inner).poll_write(cx, buf),
            FragPhase::Fragmenting {
                cfg,
                remaining,
                chunk_rem,
                sleep,
                yield_next,
            } => {
                if let Some(s) = sleep.as_mut() {
                    match s.as_mut().poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(()) => *sleep = None,
                    }
                }

                if *yield_next {
                    *yield_next = false;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }

                if *chunk_rem == 0 {
                    let lo = cfg.min_len.max(1) as u64;
                    let hi = cfg.max_len.max(lo as usize) as u64;
                    *chunk_rem = next_rand_range(lo, hi) as usize;
                }

                let to_write = buf.len().min(*remaining).min(*chunk_rem).max(1);
                match Pin::new(&mut self.inner).poll_write(cx, &buf[..to_write]) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Ready(Ok(0)) => Poll::Ready(Ok(0)),
                    Poll::Ready(Ok(n)) => {
                        *remaining = remaining.saturating_sub(n);
                        *chunk_rem = chunk_rem.saturating_sub(n);
                        if *remaining == 0 {
                            self.phase = FragPhase::Done;
                        } else if *chunk_rem == 0 {
                            let delay = next_rand_range(
                                cfg.min_delay_ms,
                                cfg.max_delay_ms.max(cfg.min_delay_ms),
                            );
                            if delay > 0 {
                                *sleep =
                                    Some(Box::pin(tokio::time::sleep(Duration::from_millis(delay))));
                            } else {
                                *yield_next = true;
                            }
                        }
                        Poll::Ready(Ok(n))
                    }
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

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

            let is_ip = host.parse::<std::net::IpAddr>().is_ok();
            let mut ssl_config = tls.configure(host, dst.port_u16().unwrap_or(443))?;

            if is_ip {
                ssl_config.set_use_server_name_indication(false);
                ssl_config.set_verify_hostname(false);
            }

            let io = tokio_boring::connect(
                ssl_config,
                host,
                FragStream::new(TokioIo::new(io), tls.tls_frag),
            )
            .await?;
            Ok(MaybeHttpsStream::Https(TokioIo::new(io)))
        })
    }
}

#[derive(Debug)]
pub(crate) enum MaybeHttpsStream<T> {
    Http(T),
    Https(TokioIo<tokio_boring::SslStream<FragStream<TokioIo<T>>>>),
}
impl<T: Read + Write + Connection + Unpin> Connection for MaybeHttpsStream<T> {
    fn connected(&self) -> Connected {
        match self {
            Self::Http(io) => io.connected(),
            Self::Https(io) => {
                let connected = io.inner().get_ref().inner().inner().connected();
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
