use crate::auth_handler::ServerAuthHandler;
use crate::client_registry::ClientRegistry;
use crate::config::Config;
use anet_common::consts::{CHANNEL_BUFFER_SIZE, COALESCE_BUDGET_BYTES};
use anyhow::{Context, Result};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use log::{debug, info, warn};
use rand::Rng;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::accept_hdr_async_with_config;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

const MAX_WS_MESSAGE_SIZE: usize = 64 * 1024;

async fn upgrade(
    stream: TcpStream,
    expected_path: String,
) -> Result<tokio_tungstenite::WebSocketStream<TcpStream>> {
    let callback = move |request: &Request,
                         mut response: Response|
          -> std::result::Result<Response, ErrorResponse> {
        if request.uri().path() != expected_path {
            let mut rejected = ErrorResponse::new(Some("Not Found".to_string()));
            *rejected.status_mut() = StatusCode::NOT_FOUND;
            return Err(rejected);
        }
        // A small, ordinary-looking response surface instead of a protocol brand.
        response
            .headers_mut()
            .insert("cache-control", HeaderValue::from_static("no-store"));
        Ok(response)
    };
    let ws_config = WebSocketConfig::default()
        .read_buffer_size(16 * 1024)
        .write_buffer_size(16 * 1024)
        .max_write_buffer_size(128 * 1024)
        .max_message_size(Some(MAX_WS_MESSAGE_SIZE))
        .max_frame_size(Some(MAX_WS_MESSAGE_SIZE));
    Ok(accept_hdr_async_with_config(stream, callback, Some(ws_config)).await?)
}

async fn handle_session(
    stream: TcpStream,
    remote_addr: SocketAddr,
    registry: Arc<ClientRegistry>,
    config: Arc<Config>,
    tun_tx: mpsc::Sender<Bytes>,
    auth_handler: ServerAuthHandler,
) -> Result<()> {
    let mut socket = upgrade(stream, config.server.websocket_path.clone()).await?;
    info!("ASTP[WebSocket] HTTP upgrade complete: {}", remote_addr);

    let mut handshake_phase = 1u8;
    loop {
        let payload = loop {
            match socket.next().await {
                Some(Ok(Message::Binary(data))) => break data,
                Some(Ok(Message::Ping(data))) => socket.send(Message::Pong(data)).await?,
                Some(Ok(Message::Close(_))) | None => return Ok(()),
                Some(Err(error)) => return Err(error.into()),
                _ => {}
            }
        };

        let (response, result) = auth_handler
            .process_handshake_packet(payload, remote_addr)
            .await
            .with_context(|| format!("WebSocket ASTP handshake phase {}", handshake_phase))?;
        if let Some(response) = response {
            socket.send(Message::Binary(response)).await?;
        }

        if let Some((client_info, _)) = result {
            let assigned_ip = client_info.assigned_ip.clone();
            let (tx_router, mut rx_router) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
            registry.finalize_client(&assigned_ip, tx_router);

            let cipher = client_info.cipher.clone();
            let sequence = client_info.sequence.clone();
            let nonce_prefix = client_info.nonce_prefix;
            let padding_step = config.stealth.padding_step;
            let mut ping_timer = Box::pin(tokio::time::sleep(random_ping_interval()));

            loop {
                tokio::select! {
                    incoming = socket.next() => {
                        match incoming {
                            Some(Ok(Message::Binary(data))) => {
                                match anet_common::transport::unwrap_packet_bytes(&cipher, data) {
                                    Ok(packet) => {
                                        if tun_tx.send(packet).await.is_err() { break; }
                                    }
                                    Err(error) => debug!("[WebSocket] Dropped invalid message from {remote_addr}: {error}"),
                                }
                            }
                            Some(Ok(Message::Ping(data))) => {
                                if socket.send(Message::Pong(data)).await.is_err() { break; }
                            }
                            Some(Ok(Message::Pong(_))) => {}
                            Some(Ok(Message::Close(_))) => {
                                // Reserve the logical VPN session before the
                                // close acknowledgement reaches the client.
                                registry.suspend_client(client_info.clone());
                                let _ = socket.close(None).await;
                                return Ok(());
                            }
                            None | Some(Err(_)) => break,
                            _ => {}
                        }
                    }
                    packet = rx_router.recv() => {
                        let Some(mut raw) = packet else { break; };
                        let mut batch_bytes = 0usize;
                        loop {
                            if raw.len() >= 20 {
                                let seq = sequence.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                let encrypted = match anet_common::transport::wrap_packet_padded(
                                    &cipher,
                                    &nonce_prefix,
                                    seq,
                                    raw,
                                    padding_step,
                                ) {
                                    Ok(encrypted) => encrypted,
                                    Err(error) => {
                                        warn!("[WebSocket] Failed to encrypt packet for {remote_addr}: {error}");
                                        return Err(error.into());
                                    }
                                };
                                batch_bytes += encrypted.len();
                                if socket.feed(Message::Binary(encrypted)).await.is_err() {
                                    break;
                                }
                            }
                            if batch_bytes >= COALESCE_BUDGET_BYTES {
                                break;
                            }
                            raw = match rx_router.try_recv() {
                                Ok(packet) => packet,
                                Err(_) => break,
                            };
                        }
                        if socket.flush().await.is_err() {
                            break;
                        }
                    }
                    _ = &mut ping_timer => {
                        let ping_payload = rand::rngs::OsRng.r#gen::<u32>().to_be_bytes().to_vec();
                        if socket.send(Message::Ping(ping_payload.into())).await.is_err() { break; }
                        ping_timer.as_mut().reset(tokio::time::Instant::now() + random_ping_interval());
                    }
                }
            }

            info!("[WebSocket] Client disconnected: {}", assigned_ip);
            registry.suspend_client(client_info);
            return Ok(());
        }
        handshake_phase = 3;
    }
}

fn random_ping_interval() -> Duration {
    Duration::from_secs(rand::rngs::OsRng.gen_range(22..=52))
}

pub async fn run_websocket_server(
    config: Arc<Config>,
    registry: Arc<ClientRegistry>,
    tun_tx: mpsc::Sender<Bytes>,
    auth_handler: ServerAuthHandler,
) -> Result<()> {
    info!(
        "Initializing Transport Port [WebSocket ASTP] TCP: {}{}",
        config.server.websocket_bind_to, config.server.websocket_path
    );
    let listener = TcpListener::bind(&config.server.websocket_bind_to).await?;
    loop {
        let (stream, remote_addr) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let (cfg, reg, tx, auth) = (
            config.clone(),
            registry.clone(),
            tun_tx.clone(),
            auth_handler.clone(),
        );
        tokio::spawn(async move {
            if let Err(error) = handle_session(stream, remote_addr, reg, cfg, tx, auth).await {
                warn!("[WebSocket] Session {} stopped: {}", remote_addr, error);
            }
        });
    }
}
