use crate::client_udp_socket::AnetUdpSocket;
use crate::config::{Config, StatsConfig};
use anet_common::atun::TunManager;
use anet_common::config::StealthConfig;
use anet_common::encryption::Cipher;
use anet_common::jitter::bridge_with_jitter;
use anet_common::protocol::AuthResponse;
use anet_common::quic_settings::QuicConfig;
use anet_common::quic_settings::build_transport_config;
use anet_common::stream_framing::read_next_packet;
use anet_common::tun_params::TunParams;
use anyhow::Result;
use log::{error, info};
use quinn::{
    ClientConfig as QuinnClientConfig, Connection, Endpoint, EndpointConfig, TokioRuntime,
    crypto::rustls::QuicClientConfig,
};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore};
use rustls_pemfile::certs;
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::sleep;

const KIB: f64 = 1024.0;
const MIB: f64 = 1024.0 * 1024.0;
const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

fn format_bytes(bytes: u64) -> String {
    let bytes_f = bytes as f64;
    if bytes_f < KIB {
        format!("{} B", bytes)
    } else if bytes_f < MIB {
        format!("{:.2} KiB", bytes_f / KIB)
    } else if bytes_f < GIB {
        format!("{:.2} MiB", bytes_f / MIB)
    } else {
        format!("{:.2} GiB", bytes_f / GIB)
    }
}

pub struct VpnHandler {
    server_addr: SocketAddr,
    tun_name: String,
    stats_config: StatsConfig,
    quic_config: QuicConfig,
    stealth_config: StealthConfig,
}

impl VpnHandler {
    pub fn new(cfg: &Config) -> Result<Self> {
        Ok(Self {
            server_addr: cfg.main.address.parse()?,
            tun_name: cfg.main.tun_name.clone(),
            stats_config: cfg.stats.clone(),
            quic_config: cfg.quic_transport.clone(),
            stealth_config: cfg.stealth.clone(),
        })
    }

    pub async fn run(
        &self,
        auth_response: &AuthResponse,
        shared_key: [u8; 32],
    ) -> Result<Endpoint> {
        let transport_config = build_transport_config(&self.quic_config, auth_response.mtu as u16)?;

        let real_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let cipher = Arc::new(Cipher::new(&shared_key));
        let nonce_prefix: [u8; 4] = auth_response.nonce_prefix.as_slice().try_into()?;
        let anet_socket = Arc::new(AnetUdpSocket::new(
            real_socket,
            cipher,
            nonce_prefix,
            self.stealth_config.clone(),
        ));

        let mut endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            anet_socket,
            Arc::new(TokioRuntime),
        )?;
        let mut client_config = self.build_quinn_client_config(auth_response)?;
        client_config.transport_config(Arc::new(transport_config));
        endpoint.set_default_client_config(client_config);

        info!(
            "[VPN] Connecting to QUIC endpoint [{}]...",
            self.server_addr
        );
        let server_name = ServerName::try_from("alco").expect("Invalid server name");
        let connection = endpoint
            .connect(self.server_addr, server_name.to_str().deref())?
            .await?;
        info!(
            "[VPN] QUIC connection established with {}, SEID: {}",
            connection.remote_address(),
            auth_response.session_id
        );

        if self.stats_config.enabled {
            self.start_stats_monitor(connection.clone());
        }

        let (send_stream, recv_stream) = connection.open_bi().await?;
        let tun_params = TunParams::from_auth_response(auth_response, &self.tun_name);
        let mut tun_manager = TunManager::new(tun_params)?;
        let (tx_to_tun, rx_from_tun) = tun_manager.run().await?;

        let quic_sender = send_stream;
        let stealth_config = self.stealth_config.clone(); // Клонируем конфиг

        // TUN -> QUIC (TX)
        tokio::spawn(async move {
            if let Err(e) = bridge_with_jitter(rx_from_tun, quic_sender, stealth_config).await {
                error!("[VPN] TX task failed: {}", e);
            } else {
                info!("[VPN] TX task finished.");
            }
        });

        // QUIC -> TUN (RX)
        let mut quic_receiver = recv_stream;
        tokio::spawn(async move {
            loop {
                match read_next_packet(&mut quic_receiver).await {
                    Ok(Some(packet)) => {
                        if tx_to_tun.send(packet).await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
            info!("[VPN] RX task finished.");
        });

        Ok(endpoint)
    }

    fn build_quinn_client_config(&self, auth_response: &AuthResponse) -> Result<QuinnClientConfig> {
        let mut root_store = RootCertStore::empty();
        let certs = certs(&mut auth_response.quic_cert.as_slice())
            .collect::<Result<Vec<CertificateDer>, _>>()?;
        for cert in certs {
            root_store.add(cert)?;
        }
        let client_crypto = RustlsClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let quic_crypto_config = QuicClientConfig::try_from(client_crypto)?;

        Ok(QuinnClientConfig::new(Arc::new(quic_crypto_config)))
    }

    fn start_stats_monitor(&self, connection: Connection) {
        let interval_minutes = self.stats_config.interval_minutes;
        info!(
            "[STATS] Monitor enabled. Interval: {} minute(s).",
            interval_minutes
        );
        tokio::spawn(async move {
            let interval = Duration::from_secs(interval_minutes * 60);
            let mut last_stats = connection.stats();
            let start_time = std::time::Instant::now();
            loop {
                sleep(interval).await;
                if connection.close_reason().is_some() {
                    break;
                }

                let current_stats = connection.stats();
                let elapsed_since_start = (std::time::Instant::now() - start_time)
                    .as_secs_f64()
                    .max(1.0);

                let rx_bytes_delta = current_stats
                    .udp_rx
                    .bytes
                    .saturating_sub(last_stats.udp_rx.bytes);
                let tx_bytes_delta = current_stats
                    .udp_tx
                    .bytes
                    .saturating_sub(last_stats.udp_tx.bytes);
                let interval_secs = interval.as_secs_f64();
                let rx_mbps = if interval_secs > 0.0 {
                    (rx_bytes_delta * 8) as f64 / (1000.0 * 1000.0 * interval_secs)
                } else {
                    0.0
                };
                let tx_mbps = if interval_secs > 0.0 {
                    (tx_bytes_delta * 8) as f64 / (1000.0 * 1000.0 * interval_secs)
                } else {
                    0.0
                };

                let path = &current_stats.path;

                info!(
                    "\n\
                    [STATS] Session time: {:.1} min\n\
                    [+] Path: RTT: {:>6.2}ms | Cwnd: {:>9} | Lost (Tx): {:<5} | MTU: {} B\n\
                    [+] Speed (Rx/Tx): {:>6.2} / {:>6.2} Mbps (avg for last interval)\n\
                    [+] Total Rx: {:>12} | Datagrams: {}\n\
                    [+] Total Tx: {:>12} | Datagrams: {}",
                    elapsed_since_start / 60.0,
                    path.rtt.as_secs_f64() * 1000.0,
                    format_bytes(path.cwnd),
                    path.lost_packets - last_stats.path.lost_packets,
                    path.current_mtu,
                    rx_mbps.max(0.0),
                    tx_mbps.max(0.0),
                    format_bytes(current_stats.udp_rx.bytes),
                    current_stats.udp_rx.datagrams,
                    format_bytes(current_stats.udp_tx.bytes),
                    current_stats.udp_tx.datagrams,
                );
                last_stats = current_stats;
            }
            info!("[STATS] Connection closed, stopping stats monitor.");
        });
    }
}
