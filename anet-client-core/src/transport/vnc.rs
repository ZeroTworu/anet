use super::{ClientTransport, ConnectionResult, MutexVpnStream};
use crate::auth::{AuthChannel, AuthHandler};
use crate::config::{CoreConfig, ServerConfig};
use anet_common::consts::{MAX_PACKET_SIZE, PADDING_MTU};
use anet_common::handshake_fragmentation::{FragmentConfig, write_fragmented};
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anet_common::vnc::{
    CLIENT_CUT_TEXT, RFB_VERSION, SECURITY_TYPE_NONE, SERVER_CUT_TEXT, encode_cut_text,
    read_cut_text, write_cut_text,
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use futures::future::BoxFuture;
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use log::{info, warn};
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};

const RFB_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_PENDING_JITTER_PACKETS: usize = 256;

struct VncAuthChannel {
    stream: Mutex<TcpStream>,
}

#[async_trait]
impl AuthChannel for VncAuthChannel {
    async fn send(&self, data: Bytes, fragmentation: &FragmentConfig) -> Result<()> {
        let frame = encode_cut_text(CLIENT_CUT_TEXT, &data)?;
        let mut stream = self.stream.lock().await;
        write_fragmented(&mut *stream, &frame, fragmentation).await?;
        Ok(())
    }

    async fn recv(&self, timeout: Duration) -> Result<Bytes> {
        let mut stream = self.stream.lock().await;
        tokio::time::timeout(timeout, read_cut_text(&mut *stream, SERVER_CUT_TEXT))
            .await
            .context("timed out waiting for the VNC authentication response")??
            .context("VNC server closed during authentication")
    }
}

pub struct VncTransport {
    config: CoreConfig,
    server: ServerConfig,
}

impl VncTransport {
    pub fn new(config: CoreConfig, server: ServerConfig) -> Self {
        Self { config, server }
    }
}

#[async_trait]
impl ClientTransport for VncTransport {
    async fn connect(&self) -> Result<ConnectionResult> {
        let addr = resolve_address(&self.server.address)?;
        info!("[VNC] Connecting to RFB endpoint {addr}");

        let mut stream = tokio::time::timeout(RFB_HANDSHAKE_TIMEOUT, TcpStream::connect(addr))
            .await
            .context("timed out connecting to the VNC endpoint")??;
        stream.set_nodelay(true)?;
        tokio::time::timeout(
            RFB_HANDSHAKE_TIMEOUT,
            emulate_rfb_client_handshake(&mut stream),
        )
        .await
        .context("timed out during the VNC handshake")??;

        info!("[VNC] RFB handshake complete; starting ASTP authentication");
        let auth_channel = VncAuthChannel {
            stream: Mutex::new(stream),
        };
        let auth_handler = AuthHandler::new(&self.config, self.server.server_pub_key.as_deref())?;
        let (auth_response, shared_key) = auth_handler.authenticate(&auth_channel).await?;
        info!("[VNC] ASTP authenticated; assigned IP {}", auth_response.ip);

        let stream = auth_channel.stream.into_inner();
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
            let (packet_tx, packet_rx) = mpsc::channel(anet_common::consts::CHANNEL_BUFFER_SIZE);
            let mut tunnel_input = tokio::spawn(read_tunnel_packets(tunnel_reader, packet_tx));
            let mut inbound =
                tokio::spawn(receive_from_server(reader, tunnel_writer, cipher.clone()));
            let mut outbound = tokio::spawn(send_to_server(
                packet_rx,
                writer,
                cipher,
                sequence,
                nonce_prefix,
                stealth,
            ));

            let result = tokio::select! {
                result = &mut tunnel_input => flatten_worker_result("TUN reader", result),
                result = &mut inbound => flatten_worker_result("network reader", result),
                result = &mut outbound => flatten_worker_result("network writer", result),
            };
            tunnel_input.abort();
            inbound.abort();
            outbound.abort();
            let _ = tunnel_input.await;
            let _ = inbound.await;
            let _ = outbound.await;
            match result {
                Ok(()) => info!("[VNC] Tunnel closed"),
                Err(error) => warn!("[VNC] Tunnel stopped: {error:#}"),
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

fn flatten_worker_result(
    worker: &'static str,
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> Result<()> {
    result.with_context(|| format!("VNC {worker} task failed"))?
}

fn resolve_address(address: &str) -> Result<SocketAddr> {
    address
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve VNC endpoint {address}"))?
        .next()
        .with_context(|| format!("VNC endpoint {address} resolved to no addresses"))
}

async fn emulate_rfb_client_handshake(stream: &mut TcpStream) -> Result<()> {
    let mut version = [0; 12];
    stream.read_exact(&mut version).await?;
    anyhow::ensure!(&version == RFB_VERSION, "server does not speak RFB 3.8");
    stream.write_all(RFB_VERSION).await?;

    let security_count = stream.read_u8().await?;
    anyhow::ensure!(security_count > 0, "VNC server offered no security types");
    let mut security_types = vec![0; usize::from(security_count)];
    stream.read_exact(&mut security_types).await?;
    anyhow::ensure!(
        security_types.contains(&SECURITY_TYPE_NONE),
        "VNC server did not offer the negotiated security type"
    );
    stream.write_u8(SECURITY_TYPE_NONE).await?;

    let security_result = stream.read_u32().await?;
    anyhow::ensure!(
        security_result == 0,
        "VNC server rejected security negotiation"
    );
    stream.write_u8(1).await?;

    read_server_init(stream).await
}

async fn read_server_init(stream: &mut TcpStream) -> Result<()> {
    let mut fixed = [0; 24];
    stream.read_exact(&mut fixed).await?;
    let width = u16::from_be_bytes(fixed[0..2].try_into().expect("fixed-size field"));
    let height = u16::from_be_bytes(fixed[2..4].try_into().expect("fixed-size field"));
    anyhow::ensure!(
        width > 0 && height > 0,
        "VNC server returned an invalid desktop size"
    );

    let name_len = u32::from_be_bytes(fixed[20..24].try_into().expect("fixed-size field")) as usize;
    anyhow::ensure!(name_len <= 1024, "VNC desktop name is too large");
    let mut name = vec![0; name_len];
    stream.read_exact(&mut name).await?;
    Ok(())
}

async fn send_to_server(
    mut packet_rx: mpsc::Receiver<Bytes>,
    mut writer: tokio::io::WriteHalf<TcpStream>,
    cipher: Arc<anet_common::encryption::Cipher>,
    sequence: Arc<AtomicU64>,
    nonce_prefix: [u8; 4],
    stealth: anet_common::config::StealthConfig,
) -> Result<()> {
    let mut rng = StdRng::from_entropy();
    let jitter_enabled = stealth.max_jitter_ns > stealth.min_jitter_ns;
    let mut pending = FuturesUnordered::<BoxFuture<'static, Bytes>>::new();
    let mut input_open = true;

    while input_open || !pending.is_empty() {
        let packet = if !jitter_enabled {
            match packet_rx.recv().await {
                Some(packet) => packet,
                None => break,
            }
        } else if pending.is_empty() {
            match packet_rx.recv().await {
                Some(packet) => {
                    schedule_with_jitter(&mut pending, packet, &stealth, &mut rng);
                    continue;
                }
                None => {
                    input_open = false;
                    continue;
                }
            }
        } else if !input_open || pending.len() >= MAX_PENDING_JITTER_PACKETS {
            pending
                .next()
                .await
                .expect("pending jitter queue is not empty")
        } else {
            tokio::select! {
                packet = packet_rx.recv() => {
                    match packet {
                        Some(packet) => {
                            schedule_with_jitter(&mut pending, packet, &stealth, &mut rng);
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
        if packet.len() < 20 {
            continue;
        }
        let sequence = sequence.fetch_add(1, Ordering::Relaxed);
        let total_len = packet.len() + 38;
        let padding =
            anet_common::padding_utils::calculate_padding_needed(total_len, stealth.padding_step);
        let safe_padding = if total_len + usize::from(padding) > PADDING_MTU {
            0
        } else {
            padding
        };
        let encrypted = anet_common::transport::wrap_packet(
            &cipher,
            &nonce_prefix,
            sequence,
            packet,
            safe_padding,
        )?;
        write_cut_text(&mut writer, CLIENT_CUT_TEXT, &encrypted).await?;
    }
    writer.shutdown().await?;
    Ok(())
}

async fn read_tunnel_packets(
    mut tunnel_reader: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    packet_tx: mpsc::Sender<Bytes>,
) -> Result<()> {
    while let Some(packet) = read_next_packet(&mut tunnel_reader).await? {
        packet_tx
            .send(packet)
            .await
            .context("VNC packet queue closed")?;
    }
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

async fn receive_from_server(
    mut reader: tokio::io::ReadHalf<TcpStream>,
    mut tunnel_writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    cipher: Arc<anet_common::encryption::Cipher>,
) -> Result<()> {
    while let Some(encrypted) = read_cut_text(&mut reader, SERVER_CUT_TEXT).await? {
        let packet = anet_common::transport::unwrap_packet_bytes_in_place(&cipher, encrypted)?;
        tunnel_writer.write_all(&frame_packet(packet)).await?;
    }
    tunnel_writer.shutdown().await?;
    Ok(())
}
