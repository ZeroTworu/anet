use super::{ClientTransport, ConnectionResult};
use crate::auth::{AuthHandler, UdpAuthChannel};
use crate::config::{CoreConfig, ServerConfig};
use anet_common::astpl::{
    unwrap_astpl_packet_in_place, wrap_astpl_packet, ASTPL_HEADER_LEN, ASTPL_MIN_PACKET_LEN,
};
use anet_common::consts::MAX_PACKET_SIZE;
use anet_common::crypto_utils::derive_astpl_seed;
use anet_common::stream_framing::{frame_packet_into, read_next_packet};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::BytesMut;
use log::{debug, info, warn};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;

pub struct AstplTransport {
    config: CoreConfig,
    server: ServerConfig,
}

impl AstplTransport {
    pub fn new(config: CoreConfig, server: ServerConfig) -> Self {
        Self { config, server }
    }
}

#[async_trait]
impl ClientTransport for AstplTransport {
    async fn connect(&self) -> Result<ConnectionResult> {
        let addr_str = self.server.endpoint()?;
        let server_addr: SocketAddr = addr_str
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow!("Invalid ASTP-L server address '{}'", addr_str))?;

        let udp_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let channel = UdpAuthChannel::new(udp_socket.clone(), server_addr);

        let auth_handler = AuthHandler::new(&self.config, self.server.server_pub_key.as_deref())?;
        let (auth_response, shared_key) = auth_handler.authenticate(&channel).await?;

        let nonce_prefix: [u8; 4] = auth_response
            .nonce_prefix
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Invalid nonce_prefix length in AuthResponse"))?;
        let crypto_seed = derive_astpl_seed(&shared_key);

        info!(
            "[ASTP-L] Handshake complete with {}. SEID: {}, Assigned IP: {}",
            server_addr, auth_response.session_id, auth_response.ip
        );

        let (client_stream, tunnel_stream) = tokio::io::duplex(256 * 1024);
        let (mut tunnel_read, mut tunnel_write) = tokio::io::split(tunnel_stream);

        let assigned_ipv4: Option<std::net::Ipv4Addr> = auth_response.ip.parse().ok();
        let tx_socket = udp_socket.clone();
        let tx_task = tokio::spawn(async move {
            let mut tx_seq: u32 = 0;
            while let Ok(Some(packet)) = read_next_packet(&mut tunnel_read).await {
                if packet.len() < 20 || (packet[0] >> 4) != 4 {
                    continue;
                }
                if let Some(expected_src) = assigned_ipv4 {
                    let pkt_src = std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
                    if pkt_src != expected_src {
                        continue;
                    }
                }
                tx_seq = tx_seq.wrapping_add(1);
                if tx_seq == 0 {
                    tx_seq = 1;
                }
                let datagram = wrap_astpl_packet(&nonce_prefix, tx_seq, crypto_seed, &packet);
                if let Err(e) = tx_socket.send_to(&datagram, server_addr).await {
                    warn!("[ASTP-L/TX] UDP send_to {} failed: {}", server_addr, e);
                    break;
                }
            }
            debug!("[ASTP-L/TX] Uplink task finished.");
        });

        let rx_socket = udp_socket.clone();
        let rx_task = tokio::spawn(async move {
            let mut recv_buf = vec![0u8; MAX_PACKET_SIZE];
            let mut frame_buf = BytesMut::with_capacity(MAX_PACKET_SIZE);

            loop {
                let (len, remote) = match rx_socket.recv_from(&mut recv_buf).await {
                    Ok(res) => res,
                    Err(e) => {
                        warn!("[ASTP-L/RX] UDP recv_from failed: {}", e);
                        break;
                    }
                };

                if remote != server_addr || len < ASTPL_HEADER_LEN {
                    continue;
                }

                if recv_buf[0..4] != nonce_prefix {
                    continue;
                }

                if len < ASTPL_MIN_PACKET_LEN {
                    // Управляющий пакет (Seq == 0) без полезной нагрузки
                    continue;
                }

                match unwrap_astpl_packet_in_place(crypto_seed, &mut recv_buf[..len], None) {
                    Ok((_, 0, _control_payload)) => {
                        debug!("[ASTP-L/RX] Received control packet (Seq=0)");
                    }
                    Ok((_, _seq, inner_ipv4)) => {
                        frame_buf.clear();
                        frame_packet_into(&mut frame_buf, inner_ipv4);
                        if tunnel_write.write_all(&frame_buf).await.is_err() {
                            debug!("[ASTP-L/RX] Tunnel stream closed.");
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("[ASTP-L/RX] Dropped invalid ASTP-L packet: {}", e);
                    }
                }
            }
            debug!("[ASTP-L/RX] Downlink task finished.");
        });

        let shutdown_hook: super::ShutdownHook = Box::pin(async move {
            tx_task.abort();
            rx_task.abort();
        });

        Ok(ConnectionResult {
            auth_response,
            vpn_stream: Box::new(client_stream),
            endpoint: None,
            connection: None,
            health_pause: None,
            remote_ip: Some(server_addr.ip()),
            bypass_ips: Vec::new(),
            effective_mode: Some("ASTP-L".to_string()),
            shutdown_hook: Some(shutdown_hook),
        })
    }
}
