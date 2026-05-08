use crate::auth_handler::ServerAuthHandler;
use crate::client_registry::ClientRegistry;
use crate::config::Config;
use crate::multikey_udp_socket::{HandshakeData, MultiKeyAnetUdpSocket};
use crate::anet_af_xdp_socket::AnetAfXdpSocket;
use anet_common::consts::CHANNEL_BUFFER_SIZE;
use anet_common::jitter::bridge_with_jitter;
use anet_common::quic_settings::build_transport_config;
use anet_common::stream_framing::read_next_packet;
use anyhow::{Context, Result};
use bytes::Bytes;
use log::{error, info, warn};
use quinn::{Endpoint, EndpointConfig, ServerConfig as QuinnServerConfig, TokioRuntime};
use rustls::ServerConfig as RustlsServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io::BufReader;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use crate::ebpf::EbpfManager;
use aya_log::EbpfLogger;

fn load_cert_and_key(
    cert_pem: &str,
    key_pem: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(cert_pem.as_bytes()))
        .collect::<Result<_, _>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_pem.as_bytes()))?
        .context("No quic private key found")?;
    Ok((certs, key.into()))
}

fn build_quinn_config(cfg: &Config) -> Result<QuinnServerConfig> {
    let (certs, key) = load_cert_and_key(&cfg.crypto.quic_cert, &cfg.crypto.quic_key)?;
    let server_crypto = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let mut s_cfg = QuinnServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));
    let t_cfg = build_transport_config(&cfg.quic_transport, cfg.network.mtu)?;
    s_cfg.transport_config(Arc::new(t_cfg));
    Ok(s_cfg)
}

async fn serve_udp_auth_layer(
    auth_core: ServerAuthHandler,
    af_xdp_socket: Arc<AnetAfXdpSocket>,
    mut rx_from_auth: mpsc::Receiver<HandshakeData>,
) {
    info!("[QUIC Auth Worker] Running isolated UDP DHCP acceptor via AF_XDP");
    while let Some((packet, remote_addr)) = rx_from_auth.recv().await {
        let handler = auth_core.clone();
        let s = af_xdp_socket.clone();
        tokio::spawn(async move {
            match handler.process_handshake_packet(packet, remote_addr).await {
                Ok((Some(resp), _)) => {
                    // Отвечаем через ядерный TX-ринг
                    if let Err(e) = s.send_raw_to(&resp, remote_addr) {
                        error!("[QUIC Auth] Failed to send response via AF_XDP: {}", e);
                    }
                }
                Err(e) => {
                    error!("[QUIC Handshake fail] {}: {}", remote_addr, e);
                }
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

    let iface_name = "ens3"; // Убедись, что это имя твоего интерфейса

    let bind_addr: std::net::SocketAddr = bind_to.parse()?;
    let port = bind_addr.port();
    let ebpf_manager = Arc::new(EbpfManager::load_and_attach(iface_name, port).await?);
    let (tx_auth, rx_auth) = mpsc::channel::<HandshakeData>(CHANNEL_BUFFER_SIZE);

    // 1. Создаем AF_XDP сокет
    let socket_wrapper = Arc::new(AnetAfXdpSocket::new(
        iface_name,
        port,
        registry.clone(),
        tx_auth,
        config.stealth.clone(),
    )?);

    // 2. Регистрируем сокет в eBPF карте!
    // Без этого XDP_REDIRECT не будет работать
    ebpf_manager.set_xsk(0, socket_wrapper.fd())?;

    EbpfLogger::init(&mut *ebpf_manager.bpf.lock())?;

    info!("[AF_XDP] Registered FD {} in XSK_MAP", socket_wrapper.fd());
    // 3. Исправляем Auth Worker: он должен отвечать через AF_XDP
    tokio::spawn(serve_udp_auth_layer(
        auth_handler.clone(),
        socket_wrapper.clone(),
        rx_auth,
    ));

    info!("Starting ASTP[Nuclear AF_XDP] Proxy Layer on {} ({})", bind_to, iface_name);

    let endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(s_cfg),
        socket_wrapper,
        Arc::new(TokioRuntime),
    )?;

    while let Some(incoming) = endpoint.accept().await {
        let r = registry.clone();
        let c = config.clone();
        let t_tx = tun_tx.clone();

        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(con) => con,
                Err(_) => return,
            };
            let addr = conn.remote_address();
            let client_info = match r.get_by_addr(&addr) {
                Some(ci) => ci,
                None => {
                    conn.close(0u32.into(), b"401");
                    return;
                }
            };

            let client_ip = client_info.assigned_ip.clone();
            info!("QUIC Connected. Routed IP: {}", client_ip);

            if let Ok((send, mut recv)) = conn.accept_bi().await {
                let (tx_router, rx_router) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
                r.finalize_client(&client_ip, tx_router);

                let stealth_c = c.stealth.clone();

                let ci_tx = client_info.clone();
                let writer_task = tokio::spawn(async move {
                    if bridge_with_jitter(rx_router, send, stealth_c)
                        .await
                        .is_err()
                    {
                        warn!("Client {} tx abort", ci_tx.assigned_ip);
                    }
                });

                let ci_rx = client_info.clone();
                let reader_task  = tokio::spawn(async move {
                    while let Ok(Some(pkt)) = read_next_packet(&mut recv).await {
                        if t_tx.send(pkt).await.is_err() {
                            break;
                        }
                    }
                    warn!("Client {} rx abort", ci_rx.assigned_ip);
                });
                let _ = tokio::select! {
                _ = reader_task => info!("QUIC Reader task finished for {}", client_info.assigned_ip),
                _ = writer_task => info!("QUIC Writer task finished for {}", client_info.assigned_ip),
            };

                info!("[QUIC] Client disconnected and wiped: {}", client_info.assigned_ip);

                r.remove_client(&client_info);
            } else {
                r.remove_client(&client_info);
            }
        });
    }
    Ok(())
}
