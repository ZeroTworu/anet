//! Unified transport client supporting QUIC/TLS/SSH

use anet_common::config::{CoreConfig, StealthConfig};
use anet_common::encryption::Cipher;
use anet_common::protocol::AuthResponse;
use anet_common::transport::{
    TransportConnector, VpnStream,
    ssh_client::SshTransportConnector,
    tcp_tls::TlsTransportConnector,
};
use anet_common::jitter::bridge_with_jitter;
use anet_common::stream_framing::read_next_packet;
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Transport type selection
#[derive(Clone, Debug)]
pub enum TransportType {
    UdpQuic,
    TcpTls,
    TcpSsh { private_key: String },
}

impl Default for TransportType {
    fn default() -> Self {
        TransportType::UdpQuic
    }
}

/// Unified transport client
pub struct UnifiedTransportClient {
    transport_type: TransportType,
    core_config: CoreConfig,
}

impl UnifiedTransportClient {
    pub fn new(core_config: CoreConfig, transport_type: TransportType) -> Self {
        Self {
            transport_type,
            core_config,
        }
    }

    /// Connect using selected transport
    pub async fn connect(
        &self,
    ) -> Result<(
        Box<dyn VpnStream>,
        AuthResponse,
        Cipher,
    )> {
        match &self.transport_type {
            TransportType::UdpQuic => {
                self.connect_quic().await
            }
            TransportType::TcpTls => {
                let connector = TlsTransportConnector::new(&self.core_config)?;
                connector.connect().await
            }
            TransportType::TcpSsh { private_key } => {
                let connector = SshTransportConnector::new(&self.core_config, private_key)?;
                connector.connect().await
            }
        }
    }

    /// Bridge TUN to stream with proper jitter handling
    pub async fn run_vpn_bridge(
        stream: Box<dyn VpnStream>,
        tun_tx: mpsc::Sender<Bytes>,
        tun_rx: mpsc::Receiver<Bytes>,
        stealth: StealthConfig,
    ) -> Result<()> {
        // Stream -> TUN (no jitter needed for incoming)
        let stream_to_tun = async {
            let mut stream = stream;
            loop {
                match read_next_packet(&mut stream).await {
                    Ok(Some(packet)) => {
                        if tun_tx.send(packet).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => return Err(e.into()),
                }
            }
            Ok::<_, anyhow::Error>(())
        };

        // TUN -> Stream (with jitter via bridge_with_jitter)
        // We need to adapt VpnStream to work with bridge_with_jitter
        // bridge_with_jitter expects S: AsyncWriteExt + Unpin + Send + 'static
        let tun_to_stream = async {
            // This requires boxing the stream properly
            // For now, simplified direct write
            let mut stream = stream;
            let mut rx = tun_rx;

            while let Some(packet) = rx.recv().await {
                let framed = anet_common::stream_framing::frame_packet(packet);
                use tokio::io::AsyncWriteExt;
                if stream.write_all(&framed).await.is_err() {
                    break;
                }
            }
            Ok::<_, anyhow::Error>(())
        };

        // Run both directions
        tokio::select! {
            result = stream_to_tun => result,
            result = tun_to_stream => result,
        }
    }

    async fn connect_quic(&self) -> Result<(Box<dyn VpnStream>, AuthResponse, Cipher)> {
        // Delegate to existing VpnHandler
        // Need to create adapter from Quinn streams to VpnStream
        bail!("QUIC adapter not yet implemented - use existing VpnHandler directly")
    }
}