//! Tokio driver for Quiche. Each connection owns its UDP socket and multiplexes
//! request streams; bounded body channels propagate application backpressure.
use super::connect::H3ClientConfig;
use crate::async_impl::body::ResponseBody;
use crate::error::BoxError;
use bytes::Bytes;
use http::{Request, Response};
use http_body::{Body as _, Frame, SizeHint};
use http_body_util::BodyExt;
use quiche::h3::NameValue;
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot, Notify},
};

type BodyFrame = Result<Frame<Bytes>, crate::Error>;
type Reply = oneshot::Sender<Result<Response<ResponseBody>, BoxError>>;

pub(super) enum Command {
    Request(Box<Request<crate::Body>>, Reply),
    Data(u64, Bytes, bool, oneshot::Sender<Result<(), BoxError>>),
    Cancel(u64),
    Abort(u64, BoxError),
}

#[derive(Clone)]
pub(crate) struct Sender {
    tx: mpsc::UnboundedSender<Command>,
    accepting: Arc<std::sync::atomic::AtomicBool>,
    wake: Arc<Notify>,
}
impl Sender {
    pub(super) fn is_closed(&self) -> bool {
        self.tx.is_closed() || !self.accepting.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub async fn send_request(
        &self,
        request: Request<crate::Body>,
    ) -> Result<Response<ResponseBody>, BoxError> {
        let _wake_on_drop = WakeOnDrop(self.wake.clone());
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Command::Request(Box::new(request), tx))
            .map_err(|_| "HTTP/3 connection closed")?;
        rx.await.map_err(|_| "HTTP/3 connection closed")?
    }
}

type PendingData = (Bytes, bool, oneshot::Sender<Result<(), BoxError>>);

struct Stream {
    reply: Option<Reply>,
    body_tx: mpsc::Sender<BodyFrame>,
    body_rx: Option<mpsc::Receiver<BodyFrame>>,
    failure: Arc<Mutex<Option<BoxError>>>,
    readable: bool,
    finished: bool,
    trailers: Option<http::HeaderMap>,
    peer_stop: Option<u64>,
    pending: Option<PendingData>,
    upload: Option<tokio::task::JoinHandle<()>>,
}
impl Drop for Stream {
    fn drop(&mut self) {
        if let Some(task) = self.upload.take() {
            task.abort();
        }
    }
}

pub(crate) struct Driver {
    conn: quiche::Connection,
    h3: quiche::h3::Connection,
    socket: UdpSocket,
    local: SocketAddr,
    commands: mpsc::UnboundedReceiver<Command>,
    sender: mpsc::WeakUnboundedSender<Command>,
    wake: Arc<Notify>,
    streams: HashMap<u64, Stream>,
    send_window: u64,
    tls: crate::boring_tls::Config,
    session_key: String,
    accepting: Arc<std::sync::atomic::AtomicBool>,
    queued: VecDeque<(Box<Request<crate::Body>>, Reply)>,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn connect(
    peer: SocketAddr,
    local: SocketAddr,
    host: &str,
    mut config: quiche::Config,
    h3_config: H3ClientConfig,
    send_window: u64,
    tls: crate::boring_tls::Config,
) -> Result<(Driver, Sender), BoxError> {
    let socket = UdpSocket::bind(local).await?;
    socket.connect(peer).await?;
    let local = socket.local_addr()?;
    let mut id = [0; quiche::MAX_CONN_ID_LEN];
    boring::rand::rand_bytes(&mut id)?;
    let mut conn = quiche::connect(
        None,
        &quiche::ConnectionId::from_ref(&id),
        local,
        peer,
        &mut config,
    )?;
    {
        let ssl: &mut boring::ssl::SslRef = conn.as_mut();
        let ip = host.parse::<std::net::IpAddr>().ok();
        if tls.enable_sni && ip.is_none() {
            ssl.set_hostname(host)?;
        }
        if tls.verify_hostname {
            if let Some(ip) = ip {
                ssl.param_mut().set_ip(ip)?;
            } else {
                ssl.param_mut().set_host(host)?;
            }
        }
        #[cfg(target_vendor = "apple")]
        ssl.set_ex_data(crate::boring_tls::hostname_index()?, host.to_owned());
    }
    let session_key = format!("{host}:{}", peer.port());
    if let Some(session) = tls.quic_sessions.lock().unwrap().get(&session_key) {
        conn.set_session(session)?;
    }
    let mut buf = vec![0; 65535];
    loop {
        flush(&mut conn, &socket).await?;
        if conn.is_established() || conn.is_in_early_data() {
            break;
        }
        if conn.is_closed() {
            return Err(connection_error(&conn));
        }
        receive(&mut conn, &socket, local, &mut buf).await?;
    }
    let mut config = quiche::h3::Config::new()?;
    if let Some(max) = h3_config.max_field_section_size {
        config.set_max_field_section_size(max);
    }
    // Quiche uses the QUIC grease setting for HTTP/3 grease as well.
    let h3 = quiche::h3::Connection::with_transport(&mut conn, &config)?;
    let (tx, commands) = mpsc::unbounded_channel();
    let sender = tx.downgrade();
    let accepting = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let wake = Arc::new(Notify::new());
    Ok((
        Driver {
            conn,
            h3,
            socket,
            local,
            commands,
            sender,
            wake: wake.clone(),
            accepting: accepting.clone(),
            streams: HashMap::new(),
            send_window,
            tls,
            session_key,
            queued: VecDeque::new(),
        },
        Sender {
            tx,
            accepting,
            wake,
        },
    ))
}

fn connection_error(conn: &quiche::Connection) -> BoxError {
    if conn.is_timed_out() {
        Box::new(crate::error::TimedOut)
    } else {
        format!(
            "QUIC connection closed: {:?} {:?}",
            conn.local_error(),
            conn.peer_error()
        )
        .into()
    }
}
async fn flush(conn: &mut quiche::Connection, socket: &UdpSocket) -> Result<(), BoxError> {
    let mut out = [0; 1350];
    loop {
        match conn.send(&mut out) {
            Ok((len, info)) => {
                tokio::time::sleep_until(info.at.into()).await;
                match socket.send(&out[..len]).await {
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {}
                    result => {
                        result?;
                    }
                }
            }
            Err(quiche::Error::Done) => return Ok(()),
            Err(e) => return Err(e.into()),
        }
    }
}
async fn receive(
    conn: &mut quiche::Connection,
    socket: &UdpSocket,
    local: SocketAddr,
    buf: &mut [u8],
) -> Result<(), BoxError> {
    let timeout = conn.timeout().unwrap_or(Duration::from_secs(60));
    tokio::select! {
        result = socket.recv_from(buf) => {
            let (len, from) = match result {
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => return Ok(()),
                result => result?,
            };
            match conn.recv(&mut buf[..len], quiche::RecvInfo { from, to: local }) {
                Ok(_) | Err(quiche::Error::Done) => {},
                Err(e) => return Err(e.into()),
            }
        }
        _ = tokio::time::sleep(timeout) => conn.on_timeout(),
    }
    Ok(())
}

impl Driver {
    pub async fn run(mut self) -> Result<(), BoxError> {
        let result = self.drive().await;
        let reason = result
            .as_ref()
            .err()
            .map(ToString::to_string)
            .unwrap_or_else(|| "HTTP/3 connection closed".into());
        for (_, mut stream) in self.streams.drain() {
            if let Some(reply) = stream.reply.take() {
                let error: BoxError = if self.conn.is_timed_out() {
                    Box::new(crate::error::TimedOut)
                } else {
                    reason.clone().into()
                };
                let _ = reply.send(Err(error));
            }
            *stream.failure.lock().unwrap() = Some(if self.conn.is_timed_out() {
                Box::new(crate::error::TimedOut)
            } else {
                reason.clone().into()
            });
        }
        result
    }
    async fn drive(&mut self) -> Result<(), BoxError> {
        let mut buf = vec![0; 65535];
        loop {
            self.process_streams()?;
            for _ in 0..self.queued.len() {
                if let Some((request, reply)) = self.queued.pop_front() {
                    self.command(Command::Request(request, reply))?;
                }
            }
            if let Some(session) = self.conn.session() {
                let mut cache = self.tls.quic_sessions.lock().unwrap();
                if cache.get(&self.session_key).map(Vec::as_slice) != Some(session) {
                    if cache.len() >= 64 {
                        cache.clear();
                    }
                    cache.insert(self.session_key.clone(), session.to_vec());
                }
            }
            flush(&mut self.conn, &self.socket).await?;
            if self.conn.is_closed() {
                return Err(connection_error(&self.conn));
            }
            tokio::select! {
                cmd = self.commands.recv() => match cmd {
                    Some(cmd) => self.command(cmd)?,
                    None => { let _ = self.conn.close(true, 0x100, b"client dropped"); flush(&mut self.conn, &self.socket).await?; return Ok(()); }
                },
                result = receive(&mut self.conn, &self.socket, self.local, &mut buf) => result?,
                _ = self.wake.notified() => {},
            }
        }
    }
    fn command(&mut self, cmd: Command) -> Result<(), BoxError> {
        match cmd {
            Command::Request(req, reply) => {
                if reply.is_closed() {
                    return Ok(());
                }
                if !self.accepting.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = reply.send(Err(Box::new(GoAway)));
                    return Ok(());
                }
                let (mut parts, mut body) = req.into_parts();
                let fin = body.is_end_stream();
                if let Some(n) = body.size_hint().exact().filter(|n| *n > 0) {
                    parts.headers.insert(http::header::CONTENT_LENGTH, n.into());
                }
                let mut headers = vec![
                    quiche::h3::Header::new(b":method", parts.method.as_str().as_bytes()),
                    quiche::h3::Header::new(b":scheme", b"https"),
                    quiche::h3::Header::new(
                        b":authority",
                        parts
                            .uri
                            .authority()
                            .ok_or("missing authority")?
                            .as_str()
                            .as_bytes(),
                    ),
                    quiche::h3::Header::new(
                        b":path",
                        parts
                            .uri
                            .path_and_query()
                            .map_or("/", |p| p.as_str())
                            .as_bytes(),
                    ),
                ];
                for (name, value) in &parts.headers {
                    if name == http::header::HOST {
                        continue;
                    }
                    headers.push(quiche::h3::Header::new(
                        name.as_str().as_bytes(),
                        value.as_bytes(),
                    ));
                }
                let id = match self.h3.send_request(&mut self.conn, &headers, fin) {
                    Ok(id) => id,
                    Err(
                        quiche::h3::Error::StreamBlocked
                        | quiche::h3::Error::Done
                        | quiche::h3::Error::TransportError(quiche::Error::StreamLimit),
                    ) => {
                        self.queued
                            .push_back((Box::new(Request::from_parts(parts, body)), reply));
                        return Ok(());
                    }
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                        return Ok(());
                    }
                };
                let (body_tx, body_rx) = mpsc::channel(8);
                let tx = self.sender.upgrade().ok_or("client dropped")?;
                let chunk_size = usize::try_from(self.send_window.clamp(1, 65536)).unwrap();
                let upload = if fin {
                    None
                } else {
                    Some(tokio::spawn(async move {
                        while let Some(frame) = body.frame().await {
                            let frame = match frame {
                                Ok(frame) => frame,
                                Err(e) => {
                                    let _ = tx.send(Command::Abort(id, Box::new(e)));
                                    return;
                                }
                            };
                            if let Ok(data) = frame.into_data() {
                                for chunk in data.chunks(chunk_size) {
                                    let (ack, rx) = oneshot::channel();
                                    if tx
                                        .send(Command::Data(
                                            id,
                                            Bytes::copy_from_slice(chunk),
                                            false,
                                            ack,
                                        ))
                                        .is_err()
                                    {
                                        return;
                                    }
                                    if !matches!(rx.await, Ok(Ok(()))) {
                                        return;
                                    }
                                }
                            }
                        }
                        let (ack, rx) = oneshot::channel();
                        let _ = tx.send(Command::Data(id, Bytes::new(), true, ack));
                        let _ = rx.await;
                    }))
                };
                self.streams.insert(
                    id,
                    Stream {
                        failure: Arc::new(Mutex::new(None)),
                        reply: Some(reply),
                        body_tx,
                        body_rx: Some(body_rx),
                        readable: false,
                        finished: false,
                        trailers: None,
                        peer_stop: None,
                        pending: None,
                        upload,
                    },
                );
            }
            Command::Data(id, data, fin, ack) => {
                if let Some(stream) = self.streams.get_mut(&id) {
                    stream.pending = Some((data, fin, ack));
                }
            }
            Command::Abort(id, error) => {
                if let Some(stream) = self.streams.get_mut(&id) {
                    if let Some(reply) = stream.reply.take() {
                        let _ = reply.send(Err(error));
                    } else {
                        *stream.failure.lock().unwrap() = Some(error);
                        let _ = stream
                            .body_tx
                            .try_send(Err(crate::error::body("request body failed")));
                    }
                }
                let _ = self
                    .conn
                    .stream_shutdown(id, quiche::Shutdown::Write, 0x102);
            }
            Command::Cancel(id) => {
                let _ = self.conn.stream_shutdown(id, quiche::Shutdown::Read, 0x10c);
                let _ = self
                    .conn
                    .stream_shutdown(id, quiche::Shutdown::Write, 0x10c);
                self.streams.remove(&id);
            }
        }
        Ok(())
    }
    fn process_streams(&mut self) -> Result<(), BoxError> {
        for (&id, stream) in &mut self.streams {
            if let Err(quiche::Error::StreamStopped(code)) = self.conn.stream_capacity(id) {
                stream.peer_stop = Some(code);
            }
            if let Some((mut data, fin, ack)) = stream.pending.take() {
                match self.h3.send_body(&mut self.conn, id, &data, fin) {
                    Ok(n) => {
                        data = data.slice(n..);
                        if data.is_empty() {
                            let _ = ack.send(Ok(()));
                        } else {
                            stream.pending = Some((data, fin, ack));
                        }
                    }
                    Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => {
                        stream.pending = Some((data, fin, ack))
                    }
                    Err(quiche::h3::Error::TransportError(quiche::Error::StreamStopped(0x100))) => {
                        let _ = ack.send(Err("peer finished reading request".into()));
                    }
                    Err(e) => {
                        *stream.failure.lock().unwrap() = Some(e.into());
                        let _ = stream
                            .body_tx
                            .try_send(Err(crate::error::body("request upload failed")));
                        let _ = ack.send(Err("request upload failed".into()));
                    }
                }
            }
        }
        loop {
            match self.h3.poll(&mut self.conn) {
                Ok((id, quiche::h3::Event::Headers { list, .. })) => {
                    if let Some(stream) = self.streams.get_mut(&id) {
                        if let Some(reply) = stream.reply.take() {
                            let mut response = Response::builder().version(http::Version::HTTP_3);
                            let mut status = None;
                            for header in list {
                                if header.name() == b":status" {
                                    status = Some(http::StatusCode::from_bytes(header.value())?);
                                } else {
                                    response = response.header(header.name(), header.value());
                                }
                            }
                            let status = status.ok_or("missing HTTP/3 status")?;
                            if status.is_informational() {
                                stream.reply = Some(reply);
                                continue;
                            }
                            let body = Incoming {
                                failure: stream.failure.clone(),
                                rx: stream.body_rx.take().unwrap(),
                                wake: self.wake.clone(),
                                sender: self.sender.clone(),
                                id,
                                remaining: None,
                                done: false,
                            };
                            let mut response = response.status(status).body(body)?;
                            response.body_mut().remaining = response
                                .headers()
                                .get(http::header::CONTENT_LENGTH)
                                .and_then(|h| h.to_str().ok())
                                .and_then(|h| h.parse().ok());
                            let _ = reply.send(Ok(response.map(crate::async_impl::body::boxed)));
                        } else {
                            let mut trailers = http::HeaderMap::new();
                            for header in list {
                                trailers.append(
                                    http::HeaderName::from_bytes(header.name())?,
                                    http::HeaderValue::from_bytes(header.value())?,
                                );
                            }
                            stream.trailers = Some(trailers);
                        }
                    }
                }
                Ok((id, quiche::h3::Event::Data)) => {
                    if let Some(stream) = self.streams.get_mut(&id) {
                        stream.readable = true;
                    }
                }
                Ok((id, quiche::h3::Event::Finished)) => {
                    if let Some(stream) = self.streams.get_mut(&id) {
                        stream.finished = true;
                    }
                }
                Ok((id, quiche::h3::Event::Reset(code))) => {
                    if let Some(mut stream) = self.streams.remove(&id) {
                        let msg = format!("HTTP/3 stream reset: {code}");
                        if let Some(reply) = stream.reply.take() {
                            let _ = reply.send(Err(msg.clone().into()));
                        }
                        *stream.failure.lock().unwrap() = Some(msg.into());
                    }
                }
                Ok((first_rejected, quiche::h3::Event::GoAway)) => {
                    self.accepting
                        .store(false, std::sync::atomic::Ordering::Relaxed);
                    let rejected: Vec<_> = self
                        .streams
                        .keys()
                        .copied()
                        .filter(|id| *id >= first_rejected)
                        .collect();
                    for id in rejected {
                        if let Some(mut stream) = self.streams.remove(&id) {
                            if let Some(reply) = stream.reply.take() {
                                let _ = reply.send(Err(Box::new(GoAway)));
                            }
                            *stream.failure.lock().unwrap() = Some(Box::new(GoAway));
                        }
                    }
                }
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(e) => return Err(e.into()),
            }
        }
        let mut remove = Vec::new();
        for (&id, stream) in &mut self.streams {
            if stream.reply.as_ref().is_some_and(|r| r.is_closed()) || stream.body_tx.is_closed() {
                remove.push(id);
                continue;
            }
            while stream.readable && stream.body_tx.capacity() > 0 {
                let mut buf = vec![0; 16384];
                match self.h3.recv_body(&mut self.conn, id, &mut buf) {
                    Ok(n) => {
                        buf.truncate(n);
                        let _ = stream.body_tx.try_send(Ok(Frame::data(Bytes::from(buf))));
                    }
                    Err(quiche::h3::Error::Done) => {
                        stream.readable = false;
                        break;
                    }
                    Err(e) => {
                        *stream.failure.lock().unwrap() = Some(e.into());
                        remove.push(id);
                        break;
                    }
                }
            }
            if !stream.readable && stream.body_tx.capacity() > 0 {
                if let Some(trailers) = stream.trailers.take() {
                    let _ = stream.body_tx.try_send(Ok(Frame::trailers(trailers)));
                }
            }
            if stream.finished && !stream.readable && stream.trailers.is_none() {
                remove.push(id);
            }
        }
        for id in remove {
            if let Some(stream) = self.streams.remove(&id) {
                if let Some(code) = stream.peer_stop.filter(|code| *code != 0x100) {
                    *stream.failure.lock().unwrap() = Some(
                        quiche::h3::Error::TransportError(quiche::Error::StreamStopped(code))
                            .into(),
                    );
                }
            }
            let _ = self.conn.stream_shutdown(id, quiche::Shutdown::Read, 0x10c);
            let _ = self
                .conn
                .stream_shutdown(id, quiche::Shutdown::Write, 0x10c);
        }
        Ok(())
    }
}

struct Incoming {
    rx: mpsc::Receiver<BodyFrame>,
    wake: Arc<Notify>,
    sender: mpsc::WeakUnboundedSender<Command>,
    id: u64,
    failure: Arc<Mutex<Option<BoxError>>>,
    remaining: Option<u64>,
    done: bool,
}
impl http_body::Body for Incoming {
    type Data = Bytes;
    type Error = crate::Error;
    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<BodyFrame>> {
        if self.done {
            return Poll::Ready(None);
        }
        let failure = self.failure.lock().unwrap().take();
        if let Some(error) = failure {
            self.done = true;
            return Poll::Ready(Some(Err(crate::error::body(error))));
        }
        let result = self.rx.poll_recv(cx);
        if result.is_ready() {
            self.wake.notify_one();
        }
        if let Poll::Ready(Some(Ok(frame))) = &result {
            if let Some(data) = frame.data_ref() {
                self.remaining = self.remaining.map(|n| n.saturating_sub(data.len() as u64));
            }
        }
        if let Poll::Ready(None) = result {
            self.done = true;
        }
        result
    }
    fn size_hint(&self) -> SizeHint {
        self.remaining.map(SizeHint::with_exact).unwrap_or_default()
    }
    fn is_end_stream(&self) -> bool {
        self.done
    }
}
impl Drop for Incoming {
    fn drop(&mut self) {
        if !self.done {
            if let Some(tx) = self.sender.upgrade() {
                let _ = tx.send(Command::Cancel(self.id));
            }
        }
    }
}

struct WakeOnDrop(Arc<Notify>);
impl Drop for WakeOnDrop {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}

/// The peer guarantees requests at or above its GOAWAY stream ID were not processed.
#[derive(Debug)]
pub(crate) struct GoAway;
impl std::fmt::Display for GoAway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HTTP/3 connection is draining")
    }
}
impl std::error::Error for GoAway {}
