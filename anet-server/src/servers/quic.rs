use crate::client_registry::ClientRegistry;
use crate::config::Config;
use crate::auth_handler::ServerAuthHandler;
use crate::multikey_udp_socket::{HandshakeData, MultiKeyAnetUdpSocket};
use anet_common::consts::CHANNEL_BUFFER_SIZE;
use anet_common::jitter::bridge_with_jitter;
use anet_common::quic_settings::build_transport_config;
use anet_common::stream_framing::read_next_packet;
use anyhow::{Context, Result};
use bytes::Bytes;
use log::{error, info, warn};
use quinn::{Endpoint, EndpointConfig, ServerConfig as QuinnServerConfig, TokioRuntime};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig as RustlsServerConfig;
use std::io::BufReader;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

fn load_cert_and_key(cert_pem: &str, key_pem: &str) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(cert_pem.as_bytes())).collect::<Result<_, _>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_pem.as_bytes()))?.context("No quic private key found")?;
    Ok((certs, key.into()))
}

fn build_quinn_config(cfg: &Config) -> Result<QuinnServerConfig> {
    let (certs, key) = load_cert_and_key(&cfg.crypto.quic_cert, &cfg.crypto.quic_key)?;
    let server_crypto = RustlsServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)?;
    let mut s_cfg = QuinnServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?));
    let t_cfg = build_transport_config(&cfg.quic_transport, cfg.network.mtu)?;
    s_cfg.transport_config(Arc::new(t_cfg));
    Ok(s_cfg)
}

async fn serve_udp_auth_layer(auth_core: ServerAuthHandler, socket: Arc<UdpSocket>, mut rx_from_auth: mpsc::Receiver<HandshakeData>) {
    info!("[QUIC Auth Worker] Running isolated UDP DHCP acceptor");
    while let Some((packet, remote_addr)) = rx_from_auth.recv().await {
        let handler = auth_core.clone();
        let s = socket.clone();
        tokio::spawn(async move {
            match handler.process_handshake_packet(packet, remote_addr).await {
                Ok((Some(resp), _)) => { let _ = s.send_to(&resp, remote_addr).await; }
                Err(e) => { error!("[QUIC Handshake fail] {}: {}", remote_addr, e); }
                _ => {}
            }
        });
    }
}

pub async fn run_quic_server(
    config: Arc<Config>,
    registry: Arc<ClientRegistry>,
    tun_tx: mpsc::Sender<Bytes>,
    auth_handler: ServerAuthHandler,
) -> Result<()> {
    let bind_to = &config.server.quic_bind_to;
    let s_cfg = build_quinn_config(&config)?;
    let real_socket = Arc::new(UdpSocket::bind(bind_to).await?);

    let (tx_auth, rx_auth) = mpsc::channel::<HandshakeData>(CHANNEL_BUFFER_SIZE);

    // Передаем провайдера в стейт мультисокетного транспорта
    let socket_wrapper = Arc::new(MultiKeyAnetUdpSocket::new(
        real_socket.clone(), registry.clone(), tx_auth, config.stealth.clone()
    ));

    // Стартуем асинхронную ловушку DH Хендшейка UDP (Только для этого сокета)
    tokio::spawn(serve_udp_auth_layer(auth_handler.clone(), real_socket, rx_auth));

    info!("Starting ASTP_UDP(QUIC) Proxy Layer on {}", bind_to);

    let endpoint = Endpoint::new_with_abstract_socket(EndpointConfig::default(), Some(s_cfg), socket_wrapper, Arc::new(TokioRuntime))?;

    while let Some(incoming) = endpoint.accept().await {
        let r = registry.clone();
        let c = config.clone();
        let t_tx = tun_tx.clone();

        tokio::spawn(async move {
            let conn = match incoming.await { Ok(con) => con, Err(_) => return };
            let addr = conn.remote_address();
            let c_info = match r.get_by_addr(&addr) { Some(ci) => ci, None => { conn.close(0u32.into(), b"401"); return; }};

            let client_ip = c_info.assigned_ip.clone();
            info!("QUIC Connected. Routed IP: {}", client_ip);

            if let Ok((send, mut recv)) = conn.accept_bi().await {
                let (tx_router, rx_router) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
                r.finalize_client(&client_ip, tx_router);

                let stealth_c = c.stealth.clone();

                let ci_tx = c_info.clone();
                tokio::spawn(async move {
                    if bridge_with_jitter(rx_router, send, stealth_c).await.is_err() { warn!("Client {} tx abort", ci_tx.assigned_ip); }
                });

                let ci_rx = c_info.clone();
                tokio::spawn(async move {
                    while let Ok(Some(pkt)) = read_next_packet(&mut recv).await { if t_tx.send(pkt).await.is_err() { break; } }
                    warn!("Client {} rx abort", ci_rx.assigned_ip);
                });
            } else { r.remove_client(&c_info); }
        });
    }
    Ok(())
}
