use super::{ClientTransport, ConnectionResult};
use crate::auth::{AuthChannel, AuthHandler};
use crate::config::{CoreConfig, ServerConfig};
use anet_common::consts::{
    COALESCE_BUDGET_BYTES, CRYPTO_COALESCE_BUDGET_BYTES, MAX_PENDING_JITTER_PACKETS, PADDING_MTU,
    RFB_HANDSHAKE_TIMEOUT,
};
use anet_common::handshake_fragmentation::{FragmentConfig, write_fragmented};
use anet_common::stream_framing::{FrameReader, frame_packet_into, supervise_bidirectional_workers, FinishedWorker};
use anet_common::vnc::{
    CLIENT_CUT_TEXT, RFB_VERSION, SECURITY_TYPE_NONE, SERVER_CUT_TEXT, encode_cut_text,
    read_cut_text,
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures::future::BoxFuture;
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use log::{info, warn};
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;



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
        let addr = resolve_address(&self.server.endpoint()?)?;
        info!("[VNC] Connecting to RFB endpoint {addr}");

        let mut stream = tokio::time::timeout(RFB_HANDSHAKE_TIMEOUT, TcpStream::connect(addr))
            .await
            .context("timed out connecting to the VNC endpoint")??;
        stream.set_nodelay(true)?;
        info!(
            "[VNC] TCP socket connected to {addr} (local: {:?}, nodelay: true)",
            stream.local_addr().ok()
        );
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
        let (auth_response, shared_key) = auth_handler.authenticate_once(&auth_channel).await?;
        info!("[VNC] ASTP authenticated; assigned IP {}", auth_response.ip);

        let stream = auth_channel.stream.into_inner();
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

        tokio::spawn(async move {
            let tunnel_start = std::time::Instant::now();
            let inbound =
                tokio::spawn(receive_from_server(reader, tunnel_writer, cipher.clone()));
            let outbound = tokio::spawn(send_to_server(
                tunnel_reader,
                writer,
                cipher,
                sequence,
                nonce_prefix,
                stealth,
            ));

            let (finished_worker, result) =
                supervise_bidirectional_workers(inbound, outbound, "VNC").await;

            let duration = tunnel_start.elapsed().as_secs_f64();
            match result {
                Ok(()) => match finished_worker {
                    FinishedWorker::Inbound => info!(
                        "[VNC] Tunnel closed: remote VNC server closed TCP connection (EOF / session limit reached). Duration: {:.1}s ({:.2} min)",
                        duration, duration / 60.0
                    ),
                    FinishedWorker::Outbound => info!(
                        "[VNC] Tunnel closed: client TUN stream or outbound packet queue closed. Duration: {:.1}s",
                        duration
                    ),
                },
                Err(error) => warn!(
                    "[VNC] Tunnel stopped on {:?}: {error:#}. Duration: {:.1}s",
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
            remote_ip: Some(addr.ip()), // Передаем IP в bypass
            bypass_ips: Vec::new(),
            effective_mode: None,
            shutdown_hook: None,
        })
    }
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
    mut tunnel_reader: tokio::io::ReadHalf<tokio::io::DuplexStream>,
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
    let mut frame_reader = FrameReader::new();

    let mut batch_buf = BytesMut::with_capacity(CRYPTO_COALESCE_BUDGET_BYTES);
    let mut pkt_count = 0u64;
    let mut byte_count = 0u64;
    let start = std::time::Instant::now();

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
            pending
                .next()
                .await
                .expect("pending jitter queue is not empty")
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

        batch_buf.clear();

        loop {
            if packet.len() >= 20 {
                pkt_count += 1;
                let seq = sequence.fetch_add(1, Ordering::Relaxed);
                let total_len = packet.len() + 38;
                let padding = anet_common::padding_utils::calculate_padding_needed(total_len, stealth.padding_step);
                let safe_padding = if total_len + usize::from(padding) > PADDING_MTU { 0 } else { padding };

                let encrypted = anet_common::transport::wrap_packet(
                    &cipher,
                    &nonce_prefix,
                    seq,
                    packet,
                    safe_padding,
                )?;

                if let Ok(frame) = encode_cut_text(CLIENT_CUT_TEXT, &encrypted) {
                    batch_buf.extend_from_slice(&frame);
                }
            }

            if batch_buf.len() >= CRYPTO_COALESCE_BUDGET_BYTES {
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

        if !batch_buf.is_empty() {
            byte_count += batch_buf.len() as u64;
            if let Err(e) = writer.write_all(&batch_buf).await {
                warn!(
                    "[VNC/Tx] TCP write failed on batch ({} bytes): {e:#}. Sent so far: {} packets, {} bytes in {:.1}s",
                    batch_buf.len(), pkt_count, byte_count, start.elapsed().as_secs_f64()
                );
                return Err(e.into());
            }
        }
    }
    info!(
        "[VNC/Tx] Finished outbound stream. Total sent: {} packets, {} bytes in {:.1}s",
        pkt_count, byte_count, start.elapsed().as_secs_f64()
    );
    writer.shutdown().await?;
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
    reader: tokio::io::ReadHalf<TcpStream>,
    mut tunnel_writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    cipher: Arc<anet_common::encryption::Cipher>,
) -> Result<()> {
    let mut reader = BufReader::with_capacity(64 * 1024, reader);
    let mut write_buf = BytesMut::with_capacity(COALESCE_BUDGET_BYTES);
    let mut pkt_count = 0u64;
    let mut byte_count = 0u64;
    let start = std::time::Instant::now();
    let mut last_rx = start;

    while let Some(encrypted) = read_cut_text(&mut reader, SERVER_CUT_TEXT).await? {
        write_buf.clear();
        pkt_count += 1;
        byte_count += encrypted.len() as u64;
        last_rx = std::time::Instant::now();

        let packet = match anet_common::transport::unwrap_packet_bytes_in_place(&cipher, encrypted) {
            Ok(p) => p,
            Err(e) => {
                warn!("[VNC/Rx] Failed to unwrap/decrypt frame #{pkt_count}: {e:#}");
                return Err(e.into());
            }
        };
        frame_packet_into(&mut write_buf, &packet);

        while !reader.buffer().is_empty() && write_buf.len() < COALESCE_BUDGET_BYTES {
            match read_cut_text(&mut reader, SERVER_CUT_TEXT).await? {
                Some(next_enc) => {
                    pkt_count += 1;
                    byte_count += next_enc.len() as u64;
                    last_rx = std::time::Instant::now();
                    let next_pkt = match anet_common::transport::unwrap_packet_bytes_in_place(
                        &cipher, next_enc,
                    ) {
                        Ok(p) => p,
                        Err(e) => {
                            warn!("[VNC/Rx] Failed to unwrap/decrypt frame #{pkt_count}: {e:#}");
                            return Err(e.into());
                        }
                    };
                    frame_packet_into(&mut write_buf, &next_pkt);
                }
                None => break,
            }
        }

        tunnel_writer.write_all(&write_buf).await?;
    }

    info!(
        "[VNC/Rx] Server closed RFB connection (clean TCP EOF / FIN). Total received: {} frames, {} bytes in {:.1}s (last frame was {:.3}s ago)",
        pkt_count, byte_count, start.elapsed().as_secs_f64(), last_rx.elapsed().as_secs_f64()
    );
    tunnel_writer.shutdown().await?;
    Ok(())
}
