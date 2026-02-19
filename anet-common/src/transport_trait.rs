use tokio::io::{AsyncRead, AsyncWrite};

// Маркерный трейт для стрима, который можно читать/писать и отправлять между потоками
pub trait VpnStream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}

// Авто-реализация для всего, что подходит (TcpStream, QuicStream, SshChannelStream)
impl<T> VpnStream for T where T: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
