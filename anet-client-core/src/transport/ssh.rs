use super::{ClientTransport, ConnectionResult};
use crate::auth::{AuthHandler, StreamAuthChannel};
use crate::config::{CoreConfig, ServerConfig};
use anet_common::consts::{
    CHANNEL_BUFFER_SIZE, COALESCE_BUDGET_BYTES, CRYPTO_COALESCE_BUDGET_BYTES,
    MAX_PENDING_JITTER_PACKETS, PADDING_MTU, SSH_CHANNEL_WINDOW_SIZE, SSH_MAX_PACKET_SIZE,
};
use anet_common::padding_utils::calculate_padding_needed;
use anet_common::stream_framing::{FrameReader, frame_packet_into, supervise_bidirectional_workers, FinishedWorker};
use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures::future::BoxFuture;
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use log::{info, warn};
use rand::{Rng, SeedableRng, rngs::StdRng};
use russh::client::Handler;
use std::future::ready;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

const SSH_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);


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
        let address = resolve_address(&self.server.endpoint()?)?;
        let user = self
            .server
            .ssh_user
            .as_deref()
            .or(self.config.transport.ssh_user.as_deref())
            .unwrap_or("root");

        let banner = anet_common::consts::normalize_ssh_banner(
            self.server
                .ssh_banner
                .as_deref()
                .or(self.config.transport.ssh_banner.as_deref()),
        );

        let ssh_config = Arc::new(russh::client::Config {
            client_id: russh::SshId::Standard(banner.into()),
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
        info!(
            "[SSH] TCP socket connected to {address} (local: {:?}, nodelay: true)",
            stream.local_addr().ok()
        );
        info!("[SSH] Initiating SSH handshake with user '{user}'");
        let mut session = russh::client::connect_stream(ssh_config, stream, ClientHandler).await?;

        anyhow::ensure!(
            session.authenticate_none(user).await?.success(),
            "SSH none authentication was rejected"
        );
        info!("[SSH] Authenticated; opening the VPN channel with exec 'anet-vpn'");

        let channel = session.channel_open_session().await?;
        channel.exec(true, "anet-vpn").await?;
        info!("[SSH] Exec 'anet-vpn' accepted by server; channel stream opened");
        let channel_stream = channel.into_stream();
        let stream = Arc::new(Mutex::new(channel_stream));

        let (auth_response, shared_key) = {
            let auth_channel = StreamAuthChannel::new(stream.clone());
            let auth_handler =
                AuthHandler::new(&self.config, self.server.server_pub_key.as_deref())?;
            auth_handler.authenticate_once(&auth_channel).await?
        };
        info!("[SSH] ASTP authenticated; assigned IP {}", auth_response.ip);

        let stream = Arc::try_unwrap(stream)
            .map_err(|_| anyhow::anyhow!("SSH authentication stream is still shared"))?
            .into_inner();
        let (reader, writer) = tokio::io::split(stream);
        let (client_stream, internal_stream) = tokio::io::duplex(512 * 1024);
        let (tunnel_reader, tunnel_writer) = tokio::io::split(internal_stream);

        let cipher = Arc::new(anet_common::encryption::Cipher::new(&shared_key));
        let nonce_prefix = auth_response
            .nonce_prefix
            .as_slice()
            .try_into()
            .context("server returned an invalid nonce prefix")?;
        let sequence = Arc::new(AtomicU64::new(0));
        let stealth = self.config.stealth.clone();

        let ssh_session = session;

        tokio::spawn(async move {
            let tunnel_start = std::time::Instant::now();
            let _session_guard = ssh_session;
            let outbound = tokio::spawn(send_to_server(
                tunnel_reader,
                writer,
                stealth,
                cipher.clone(),
                sequence,
                nonce_prefix,
            ));
            let inbound = tokio::spawn(receive_from_server(reader, tunnel_writer, cipher));

            let (finished_worker, result) =
                supervise_bidirectional_workers(inbound, outbound, "SSH").await;

            let duration = tunnel_start.elapsed().as_secs_f64();
            match result {
                Ok(()) => match finished_worker {
                    FinishedWorker::Inbound => info!(
                        "[SSH] Tunnel closed: remote SSH server closed channel/connection (EOF / session limit or idle timeout). Duration: {:.1}s ({:.2} min)",
                        duration, duration / 60.0
                    ),
                    FinishedWorker::Outbound => info!(
                        "[SSH] Tunnel closed: client TUN stream or outbound network queue closed. Duration: {:.1}s",
                        duration
                    ),
                },
                Err(error) => warn!(
                    "[SSH] Tunnel stopped on {:?}: {error:#}. Duration: {:.1}s",
                    finished_worker, duration
                ),
            }
        });

        Ok(ConnectionResult {
            auth_response,
            vpn_stream: Box::new(client_stream),
            endpoint: None,
            connection: None,
            health_pause: None,
            remote_ip: Some(address.ip()),
            bypass_ips: Vec::new(),
            effective_mode: None,
            shutdown_hook: None,
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



async fn send_to_server<W>(
    mut tunnel_reader: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    mut writer: W,
    stealth: anet_common::config::StealthConfig,
    cipher: Arc<anet_common::encryption::Cipher>,
    sequence: Arc<AtomicU64>,
    nonce_prefix: [u8; 4],
) -> Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let padding_step = stealth.padding_step;
    let jitter_enabled = stealth.max_jitter_ns > stealth.min_jitter_ns;
    let mut rng = StdRng::from_entropy();
    let mut pending = FuturesUnordered::<BoxFuture<'static, Bytes>>::new();
    let mut input_open = true;
    let mut frame_reader = FrameReader::new();
    let mut buf = BytesMut::with_capacity(CRYPTO_COALESCE_BUDGET_BYTES);

    let encrypt_into = |packet: Bytes, buf: &mut BytesMut| -> Result<()> {
        let seq = sequence.fetch_add(1, Ordering::Relaxed);
        let total_len = packet.len() + 38;
        let pad = calculate_padding_needed(total_len, padding_step);
        let safe_pad = if total_len + usize::from(pad) > PADDING_MTU {
            0
        } else {
            pad
        };
        let encrypted =
            anet_common::transport::wrap_packet(&cipher, &nonce_prefix, seq, packet, safe_pad)?;
        frame_packet_into(buf, &encrypted);
        Ok(())
    };

    while input_open || !pending.is_empty() {
        let mut packet = if !jitter_enabled {
            match frame_reader.read_next_packet(&mut tunnel_reader).await? {
                Some(packet) => packet,
                None => break,
            }
        } else if pending.is_empty() {
            match frame_reader.read_next_packet(&mut tunnel_reader).await? {
                Some(packet) => {
                    schedule_with_jitter(&mut pending, packet, &stealth, &mut rng);
                    while let Some(next_pkt) = frame_reader.try_next_packet()? {
                        schedule_with_jitter(&mut pending, next_pkt, &stealth, &mut rng);
                    }
                    continue;
                }
                None => {
                    input_open = false;
                    continue;
                }
            }
        } else if !input_open || pending.len() >= MAX_PENDING_JITTER_PACKETS {
            pending.next().await.expect("pending jitter queue is not empty")
        } else {
            tokio::select! {
                res = frame_reader.read_next_packet(&mut tunnel_reader) => {
                    match res? {
                        Some(packet) => {
                            schedule_with_jitter(&mut pending, packet, &stealth, &mut rng);
                            while let Some(next_pkt) = frame_reader.try_next_packet()? {
                                schedule_with_jitter(&mut pending, next_pkt, &stealth, &mut rng);
                            }
                            continue;
                        }
                        None => {
                            input_open = false;
                            continue;
                        }
                    }
                }
                packet = pending.next() => packet.expect("pending jitter queue is not empty"),
            }
        };

        buf.clear();

        loop {
            if packet.len() >= 20 {
                encrypt_into(packet, &mut buf)?;
            }

            if buf.len() >= CRYPTO_COALESCE_BUDGET_BYTES {
                break;
            }

            if !jitter_enabled {
                match frame_reader.try_next_packet()? {
                    Some(p) => packet = p,
                    None => break,
                }
            } else {
                match pending.next().now_or_never().flatten() {
                    Some(p) => packet = p,
                    None => break,
                }
            }
        }

        if !buf.is_empty() {
            writer.write_all(&buf).await?;
        }
    }

    writer.shutdown().await?;
    Ok(())
}

async fn receive_from_server<R>(
    mut reader: R,
    mut tunnel_writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    cipher: Arc<anet_common::encryption::Cipher>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let mut frame_reader = FrameReader::new();
    let mut write_buf = BytesMut::with_capacity(COALESCE_BUDGET_BYTES);

    while let Some(encrypted) = frame_reader.read_next_packet(&mut reader).await? {
        write_buf.clear();
        let packet = anet_common::transport::unwrap_packet_bytes_in_place(&cipher, encrypted)?;
        frame_packet_into(&mut write_buf, &packet);

        while write_buf.len() < COALESCE_BUDGET_BYTES {
            match frame_reader.try_next_packet()? {
                Some(next_enc) => {
                    let next_pkt =
                        anet_common::transport::unwrap_packet_bytes_in_place(&cipher, next_enc)?;
                    frame_packet_into(&mut write_buf, &next_pkt);
                }
                None => break,
            }
        }

        tunnel_writer.write_all(&write_buf).await?;
    }

    tunnel_writer.shutdown().await?;
    Ok(())
}

fn schedule_with_jitter(
    pending: &mut FuturesUnordered<BoxFuture<'static, Bytes>>,
    packet: Bytes,
    stealth: &anet_common::config::StealthConfig,
    rng: &mut StdRng,
) {
    let delay = rng.gen_range(stealth.min_jitter_ns..=stealth.max_jitter_ns);
    pending.push(
        async move {
            if delay > 0 {
                tokio::time::sleep(Duration::from_nanos(delay)).await;
            }
            packet
        }
        .boxed(),
    );
}

#[cfg(test)]
mod tests {
    use anet_common::consts::{DEFAULT_SSH_BANNER, normalize_ssh_banner};

    #[test]
    fn ssh_banner_masks_russh_signature() {
        let default_banner = normalize_ssh_banner(None);
        assert_eq!(default_banner, DEFAULT_SSH_BANNER);
        assert!(default_banner.starts_with("SSH-2.0-OpenSSH_"));
        assert!(!default_banner.contains("russh"));

        let custom_without_prefix = normalize_ssh_banner(Some("OpenSSH_9.2p1 Debian-2+deb12u3\r\n"));
        assert_eq!(custom_without_prefix, "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3");
    }
}
