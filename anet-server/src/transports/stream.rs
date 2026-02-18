use crate::transports::handshake::{HandshakeTransport};
use anet_common::protocol::Message as AnetMessage;
use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const LENGTH_PREFIX_SIZE: usize = 4; // u32 для длины сообщения

pub struct StreamHandshakeTransport<S> {
    stream: S,
}

impl<S> StreamHandshakeTransport<S> {
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

#[async_trait]
impl<S: AsyncReadExt + AsyncWriteExt + Unpin + Send> HandshakeTransport for StreamHandshakeTransport<S> {
    async fn send_message(&mut self, msg: &AnetMessage) -> Result<()> {
        let mut buf = Vec::new();
        msg.encode(&mut buf)?;
        let len = buf.len() as u32;
        self.stream.write_u32(len).await?;
        self.stream.write_all(&buf).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn receive_message(&mut self) -> Result<AnetMessage> {
        let len = self.stream.read_u32().await?;
        if len == 0 || len > 1024 * 1024 { // ограничим 1 МБ
            anyhow::bail!("Invalid message length: {}", len);
        }
        let mut buf = vec![0u8; len as usize];
        self.stream.read_exact(&mut buf).await?;
        let msg = AnetMessage::decode(buf.as_slice())?;
        Ok(msg)
    }
}
