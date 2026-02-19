use super::ClientTransport;
use crate::auth::{AuthHandler, UdpAuthChannel}; // Импорт
use crate::config::CoreConfig;
use crate::socket::AnetUdpSocket;
use anet_common::encryption::Cipher;
use anet_common::protocol::AuthResponse;
use anet_common::quic_settings::build_transport_config;
use anet_common::transport_trait::VpnStream;
use anyhow::Result;
use async_trait::async_trait;
use log::info;
use quinn::{ClientConfig, Endpoint, EndpointConfig, RecvStream, SendStream, TokioRuntime};
use rustls::RootCertStore;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;

pub struct QuicDuplexStream {
    send: SendStream,
    recv: RecvStream,
}
// ... (impl AsyncRead/Write те же) ...
impl AsyncRead for QuicDuplexStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}
impl AsyncWrite for QuicDuplexStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut self.send).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut self.send).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut self.send).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct QuicTransport {
    config: CoreConfig,
}

impl QuicTransport {
    pub fn new(config: CoreConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ClientTransport for QuicTransport {
    async fn connect(&self) -> Result<(AuthResponse, Box<dyn VpnStream>)> {
        // 1. Создаем канал
        let server_addr: SocketAddr = self.config.main.address.parse()?;
        let udp_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let channel = UdpAuthChannel::new(udp_socket.clone(), server_addr);

        // 2. Аутентификация
        let auth_handler = AuthHandler::new(&self.config)?;
        let (auth_response, shared_key) = auth_handler.authenticate(&channel).await?;

        // 3. QUIC
        let transport_config =
            build_transport_config(&self.config.quic_transport, auth_response.mtu as u16)?;

        let cipher = Arc::new(Cipher::new(&shared_key));
        let nonce_prefix: [u8; 4] = auth_response
            .nonce_prefix
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid nonce prefix len"))?;

        let anet_socket = Arc::new(AnetUdpSocket::new(
            udp_socket, // Используем тот же сокет
            cipher,
            nonce_prefix,
            self.config.stealth.clone(),
        ));

        let mut endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            anet_socket,
            Arc::new(TokioRuntime),
        )?;

        let mut root_store = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut auth_response.quic_cert.as_slice()) {
            root_store.add(cert?)?;
        }

        let client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let mut client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
        ));
        client_config.transport_config(Arc::new(transport_config));
        endpoint.set_default_client_config(client_config);

        info!("[QUIC] Connecting to {}...", server_addr);
        let connection = endpoint.connect(server_addr, "alco")?.await?;

        info!(
            "[QUIC] Connection established. SEID: {}",
            auth_response.session_id
        );

        let (send, recv) = connection.open_bi().await?;
        let stream = QuicDuplexStream { send, recv };

        Ok((auth_response, Box::new(stream)))
    }
}
