use super::{ClientTransport, ConnectionResult, MutexVpnStream};
use crate::auth::{AuthHandler, StreamAuthChannel};
use crate::config::{CoreConfig, ServerConfig};
use anet_common::consts::{CHANNEL_BUFFER_SIZE, MAX_PACKET_SIZE};
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use log::{info, warn};
use russh::client::Handler;
use std::future::ready;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};

const SSH_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const SSH_CHANNEL_WINDOW_SIZE: u32 = 4 * 1024 * 1024;
const SSH_MAX_PACKET_SIZE: u32 = 32 * 1024;

struct ClientHandler;

impl Handler for ClientHandler {
    type Error = russh::Error;

    fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        // Подлинность конечного узла дополнительно проверяется подписанным ASTP DH-обменом.
        ready(Ok(true))
    }
}

pub struct SshTransport {
    config: CoreConfig,
    server: ServerConfig,
}

impl SshTransport {
    pub fn new(config: CoreConfig, server: ServerConfig) -> Self {
        Self { config, server }
    }
}

#[async_trait]
impl ClientTransport for SshTransport {
    async fn connect(&self) -> Result<ConnectionResult> {
        let address = resolve_address(&self.server.address)?;
        let user = self
            .server
            .ssh_user
            .as_deref()
            .or(self.config.transport.ssh_user.as_deref())
            .unwrap_or("root");

        let ssh_config = Arc::new(russh::client::Config {
            window_size: SSH_CHANNEL_WINDOW_SIZE,
            maximum_packet_size: SSH_MAX_PACKET_SIZE,
            channel_buffer_size: CHANNEL_BUFFER_SIZE,
            nodelay: true,
            ..Default::default()
        });

        let stream = tokio::time::timeout(SSH_CONNECT_TIMEOUT, TcpStream::connect(address))
            .await
            .context("timed out connecting to the SSH endpoint")??;
        stream.set_nodelay(true)?;
        let mut session = russh::client::connect_stream(ssh_config, stream, ClientHandler).await?;

        anyhow::ensure!(
            session.authenticate_none(user).await?.success(),
            "SSH none authentication was rejected"
        );
        info!("[SSH] Authenticated; opening the VPN channel");

        let channel = session.channel_open_session().await?;
        channel.exec(true, "anet-vpn").await?;
        let channel_stream = channel.into_stream();
        let stream = Arc::new(Mutex::new(channel_stream));

        let (auth_response, shared_key) = {
            let auth_channel = StreamAuthChannel::new(stream.clone());
            let auth_handler =
                AuthHandler::new(&self.config, self.server.server_pub_key.as_deref())?;
            auth_handler.authenticate(&auth_channel).await?
        };
        info!("[SSH] ASTP authenticated; assigned IP {}", auth_response.ip);

        let stream = Arc::try_unwrap(stream)
            .map_err(|_| anyhow::anyhow!("SSH authentication stream is still shared"))?
            .into_inner();
        let (reader, writer) = tokio::io::split(stream);
        let (client_stream, internal_stream) = tokio::io::duplex(MAX_PACKET_SIZE * 10);
        let (tunnel_reader, tunnel_writer) = tokio::io::split(internal_stream);

        let cipher = Arc::new(anet_common::encryption::Cipher::new(&shared_key));
        let nonce_prefix = auth_response
            .nonce_prefix
            .as_slice()
            .try_into()
            .context("server returned an invalid nonce prefix")?;
        let sequence = Arc::new(AtomicU64::new(0));
        let stealth = self.config.stealth.clone();

        tokio::spawn(async move {
            let (packet_tx, packet_rx) = mpsc::channel(CHANNEL_BUFFER_SIZE);
            let (network_tx, mut network_rx) = mpsc::channel(CHANNEL_BUFFER_SIZE);
            let mut tunnel_input = tokio::spawn(read_tunnel_packets(tunnel_reader, packet_tx));
            let mut outbound = tokio::spawn(anet_common::jitter::bridge_crypto_stream_with_jitter(
                packet_rx,
                writer,
                stealth,
                cipher.clone(),
                sequence,
                nonce_prefix,
            ));
            let mut inbound = tokio::spawn(anet_common::jitter::receive_crypto_stream(
                reader, network_tx, cipher,
            ));
            let mut tunnel_output = tokio::spawn(async move {
                let mut tunnel_writer = tunnel_writer;
                while let Some(packet) = network_rx.recv().await {
                    tunnel_writer.write_all(&frame_packet(packet)).await?;
                }
                tunnel_writer.shutdown().await?;
                Result::<()>::Ok(())
            });

            // `select!` уже забирает результат одной из задач. Её JoinHandle
            // нельзя повторно poll-ить через `.await`: Tokio завершает процесс
            // с "JoinHandle polled after completion". Запоминаем победителя,
            // отменяем только остальные задачи и ждём только их.
            enum FinishedWorker {
                TunnelInput,
                Outbound,
                Inbound,
                TunnelOutput,
            }

            let (finished_worker, result) = tokio::select! {
                result = &mut tunnel_input => (
                    FinishedWorker::TunnelInput,
                    flatten_worker_result("TUN reader", result),
                ),
                result = &mut outbound => (
                    FinishedWorker::Outbound,
                    flatten_worker_result("network writer", result),
                ),
                result = &mut inbound => (
                    FinishedWorker::Inbound,
                    flatten_worker_result("network reader", result),
                ),
                result = &mut tunnel_output => (
                    FinishedWorker::TunnelOutput,
                    flatten_worker_result("TUN writer", result),
                ),
            };

            if !matches!(finished_worker, FinishedWorker::TunnelInput) {
                tunnel_input.abort();
                let _ = tunnel_input.await;
            }
            if !matches!(finished_worker, FinishedWorker::Outbound) {
                outbound.abort();
                let _ = outbound.await;
            }
            if !matches!(finished_worker, FinishedWorker::Inbound) {
                inbound.abort();
                let _ = inbound.await;
            }
            if !matches!(finished_worker, FinishedWorker::TunnelOutput) {
                tunnel_output.abort();
                let _ = tunnel_output.await;
            }

            match result {
                Ok(()) => info!("[SSH] Tunnel closed"),
                Err(error) => warn!("[SSH] Tunnel stopped: {error:#}"),
            }
        });

        Ok(ConnectionResult {
            auth_response,
            vpn_stream: Box::new(MutexVpnStream(Arc::new(Mutex::new(client_stream)))),
            endpoint: None,
            connection: None,
            health_pause: None,
        })
    }
}

fn resolve_address(address: &str) -> Result<SocketAddr> {
    address
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve SSH endpoint {address}"))?
        .next()
        .with_context(|| format!("SSH endpoint {address} resolved to no addresses"))
}

fn flatten_worker_result(
    worker: &'static str,
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> Result<()> {
    result.with_context(|| format!("SSH {worker} task failed"))?
}

async fn read_tunnel_packets(
    mut tunnel_reader: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    packet_tx: mpsc::Sender<Bytes>,
) -> Result<()> {
    while let Some(packet) = read_next_packet(&mut tunnel_reader).await? {
        packet_tx
            .send(packet)
            .await
            .context("SSH packet queue closed")?;
    }
    Ok(())
}
