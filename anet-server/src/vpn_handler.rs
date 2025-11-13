use crate::ip_pool::IpPool;
use crate::multikey_udp_socket::{ClientTransportInfo, StreamSender};
use crate::utils::extract_ip_dst;
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anyhow::Result;
use bytes::Bytes;
use dashmap::DashMap;
use log::{error, info, warn};
use quinn::{Endpoint, Incoming};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

/// Главная функция-обработчик, которая запускает все задачи, связанные с VPN.
pub async fn run_vpn_handler(
    endpoint: Endpoint,
    tx_to_tun: StreamSender,
    rx_from_tun: mpsc::Receiver<Bytes>,
    quic_router: Arc<DashMap<String, StreamSender>>,
    ip_pool: IpPool,
    clients_by_prefix: Arc<DashMap<[u8; 4], Arc<ClientTransportInfo>>>,
    clients_by_addr: Arc<DashMap<SocketAddr, Arc<ClientTransportInfo>>>,
) -> Result<()> {
    info!("ANet VPN Handler task started.");

    // Запускаем две основные задачи: прием новых соединений и маршрутизацию трафика из TUN.
    let incoming_quic_task = handle_incoming_quic(
        endpoint,
        tx_to_tun,
        quic_router.clone(),
        ip_pool,
        clients_by_prefix,
        clients_by_addr,
    );
    let router_task = route_tun_to_quic(rx_from_tun, quic_router);

    // Ожидаем завершения обеих задач.
    tokio::try_join!(incoming_quic_task, router_task)?;

    Ok(())
}

/// Принимает новые QUIC-соединения и для каждого запускает `handle_connection`.
async fn handle_incoming_quic(
    endpoint: Endpoint,
    tx_to_tun: StreamSender,
    quic_router: Arc<DashMap<String, StreamSender>>,
    ip_pool: IpPool,
    clients_by_prefix: Arc<DashMap<[u8; 4], Arc<ClientTransportInfo>>>,
    clients_by_addr: Arc<DashMap<SocketAddr, Arc<ClientTransportInfo>>>,
) -> Result<()> {
    while let Some(conn) = endpoint.accept().await {
        let fut = handle_connection(
            conn,
            tx_to_tun.clone(),
            quic_router.clone(),
            ip_pool.clone(),
            clients_by_prefix.clone(),
            clients_by_addr.clone(),
        );
        tokio::spawn(async move {
            if let Err(e) = fut.await {
                error!("QUIC connection failed: {}", e);
            }
        });
    }
    Ok(())
}

/// Обрабатывает одно установленное QUIC-соединение: настраивает потоки и маршрутизацию.
async fn handle_connection(
    incoming: Incoming,
    tx_to_tun: StreamSender,
    quic_router: Arc<DashMap<String, StreamSender>>,
    ip_pool: IpPool,
    clients_by_prefix: Arc<DashMap<[u8; 4], Arc<ClientTransportInfo>>>,
    clients_by_addr: Arc<DashMap<SocketAddr, Arc<ClientTransportInfo>>>,
) -> Result<()> {
    let connection = incoming.await?;
    let remote_addr = connection.remote_address();
    info!("QUIC negotiation started with peer: {}", remote_addr);

    let client = clients_by_addr
        .get(&remote_addr)
        .map(|entry| entry.value().clone())
        .ok_or_else(|| {
            connection.close(0u32.into(), b"Transport layer association failed");
            anyhow::anyhow!("QUIC connection from {} but no associated client info found", remote_addr)
        })?;

    let client_ip = client.assigned_ip.clone();
    info!("QUIC session accepted for client VPN IP: {} ({}), SEID: {}", client_ip, remote_addr, client.session_id);

    let (send_stream, recv_stream) = connection.accept_bi().await?;

    let (tx_router, mut rx_router) = mpsc::channel::<Bytes>(1024);
    quic_router.insert(client_ip.clone(), tx_router);
    info!("Client {} added to QUIC router. Total clients: {}", client_ip, quic_router.len());

    let tx_task = tokio::spawn(async move {
        let mut stream = send_stream;
        while let Some(packet) = rx_router.recv().await {
            let framed_packet = frame_packet(packet);
            if stream.write_all(&framed_packet).await.is_err() || stream.flush().await.is_err() {
                break;
            }
        }
        let _ = stream.finish();
    });

    let rx_task = tokio::spawn(async move {
        let mut stream = recv_stream;
        loop {
            match read_next_packet(&mut stream).await {
                Ok(Some(packet)) => {
                    if tx_to_tun.send(packet).await.is_err() { break; }
                }
                _ => break, // Ошибка или стрим закрыт
            }
        }
    });

    tokio::select! {
        _ = tx_task => {},
        _ = rx_task => {},
        _ = connection.closed() => {},
    }

    info!("Cleaning up resources for client {}.", client_ip);
    quic_router.remove(&client_ip);
    clients_by_prefix.remove(&client.nonce_prefix);
    clients_by_addr.remove(&remote_addr);
    if let Ok(ip_addr) = client_ip.parse() {
        ip_pool.release(ip_addr);
    }
    info!("Client {} removed. Remaining clients: {}", client_ip, quic_router.len());

    Ok(())
}

/// Читает пакеты из TUN, определяет IP назначения и отправляет в нужный QUIC-поток.
async fn route_tun_to_quic(
    mut rx_from_tun: mpsc::Receiver<Bytes>,
    quic_router: Arc<DashMap<String, StreamSender>>,
) -> Result<()> {
    while let Some(packet) = rx_from_tun.recv().await {
        if packet.len() < 20 { continue; }
        let version = packet[0] >> 4;
        if version != 4 && version != 6 { continue; }

        let dst_ip_str = match extract_ip_dst(&packet) {
            Some(ip) => ip.to_string(),
            None => {
                warn!("Cannot extract destination IP from packet");
                continue;
            }
        };

        if let Some(sender) = quic_router.get(&dst_ip_str) {
            if sender.send(packet).await.is_err() {
                warn!("Failed to route packet to {}: QUIC channel closed.", dst_ip_str);
            }
        } else {
            // Это нормальная ситуация, если пакет пришел для клиента, который уже отключился
        }
    }
    Ok(())
}