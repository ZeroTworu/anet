use crate::client_registry::ClientRegistry;
use crate::config::Config;
use crate::utils::extract_ip_dst;
use anet_common::consts::MAX_PACKET_SIZE;
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anyhow::Result;
use bytes::Bytes;
use log::{error, info, warn};
use quinn::{Endpoint, Incoming};
use rand::Rng;
use rand::rngs::OsRng;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::time::sleep;

pub struct ServerVpnHandler {
    endpoint: Endpoint,
    registry: Arc<ClientRegistry>,
    server_config: Arc<Config>,
}

impl ServerVpnHandler {
    pub fn new(
        endpoint: Endpoint,
        registry: Arc<ClientRegistry>,
        server_config: Arc<Config>,
    ) -> Self {
        Self {
            endpoint,
            registry,
            server_config,
        }
    }

    pub async fn run(
        &self,
        tx_to_tun: mpsc::Sender<Bytes>,
        rx_from_tun: mpsc::Receiver<Bytes>,
    ) -> Result<()> {
        info!("ANet VPN Handler task started.");

        let endpoint = self.endpoint.clone();
        let registry = self.registry.clone();
        let config = self.server_config.clone();

        // Task 1:Route QUIC -> TUN
        let incoming_quic_task = tokio::spawn(async move {
            while let Some(conn) = endpoint.accept().await {
                let reg = registry.clone();
                let cfg = config.clone();
                let tx = tx_to_tun.clone();

                tokio::spawn(async move {
                    if let Err(e) = Self::handle_connection(conn, tx, reg, cfg).await {
                        error!("QUIC connection failed: {}", e);
                    }
                });
            }
        });

        // Task 2: Route TUN -> QUIC
        let router_registry = self.registry.clone();
        let router_task =
            tokio::spawn(
                async move { Self::route_tun_to_quic(rx_from_tun, router_registry).await },
            );

        let _ = tokio::try_join!(incoming_quic_task, router_task)?;
        Ok(())
    }

    async fn handle_connection(
        incoming: Incoming,
        tx_to_tun: mpsc::Sender<Bytes>,
        registry: Arc<ClientRegistry>,
        server_config: Arc<Config>,
    ) -> Result<()> {
        let connection = incoming.await?;
        let remote_addr = connection.remote_address();
        info!("QUIC negotiation started with peer: {}", remote_addr);

        let client_info = registry.get_by_addr(&remote_addr).ok_or_else(|| {
            connection.close(0u32.into(), b"Transport layer association failed");
            anyhow::anyhow!(
                "QUIC connection from {} but no associated client info found",
                remote_addr
            )
        })?;

        let client_ip = client_info.assigned_ip.clone();
        info!(
            "QUIC session accepted for client VPN IP: {} ({}), SEID: {}",
            client_ip, remote_addr, client_info.session_id
        );

        let (send_stream, recv_stream) = connection.accept_bi().await?;
        let (tx_router, mut rx_router) = mpsc::channel::<Bytes>(MAX_PACKET_SIZE);

        registry.finalize_client(&client_ip, tx_router);

        let stealth_config = server_config.stealth.clone();

        let client_info_for_tx = client_info.clone();
        let tx_task = tokio::spawn(async move {
            let mut stream = send_stream;

            // 1. Создаем промежуточный канал для пакетов, которые "проснулись"
            // Размер буфера определяет, сколько пакетов может быть "в полете" (спать) одновременно
            let (tx_ready, mut rx_ready) = mpsc::channel::<Bytes>(MAX_PACKET_SIZE);

            // 2. Задача-Диспетчер: Читает из TUN, назначает задержку и спавнит ожидание
            let mut rx_from_router = rx_router; // Твой входящий канал
            let config_jitter = stealth_config.clone();

            tokio::spawn(async move {
                let mut rng = OsRng;
                let min_jitter = config_jitter.min_jitter_ns;
                let max_jitter = config_jitter.max_jitter_ns;

                while let Some(packet) = rx_from_router.recv().await {
                    let tx = tx_ready.clone();

                    // Вычисляем задержку тут
                    let delay_ns = if max_jitter > min_jitter {
                        rng.gen_range(min_jitter..=max_jitter)
                    } else {
                        0
                    };

                    // Спавним задачу на каждый пакет
                    // Это дешево в Tokio. Это позволяет пакетам обгонять друг друга.
                    tokio::spawn(async move {
                        if delay_ns > 0 {
                            sleep(Duration::from_nanos(delay_ns)).await;
                        }
                        // Если канал полон (backpressure), мы подождем тут, не блокируя чтение новых
                        if let Err(_) = tx.send(packet).await {
                            // Канал закрыт (соединение разорвано), просто выходим
                        }
                    });
                }
            });

            // 3. Задача-Отправщик: Читает готовые пакеты и пишет в QUIC
            // Пакеты приходят сюда уже после сна, возможно, в другом порядке
            while let Some(packet) = rx_ready.recv().await {
                let framed_packet = frame_packet(packet);

                if stream.write_all(&framed_packet).await.is_err() || stream.flush().await.is_err()
                {
                    break;
                }
            }

            let _ = stream.finish();
            info!(
                "[VPN] Client {} TUN->QUIC task finished.",
                client_info_for_tx.assigned_ip
            );
        });

        let client_info_for_rx = client_info.clone();
        let rx_task = tokio::spawn(async move {
            let mut stream = recv_stream;
            loop {
                match read_next_packet(&mut stream).await {
                    Ok(Some(packet)) => {
                        if tx_to_tun.send(packet).await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
            info!(
                "[VPN] Client {} QUIC->TUN task finished.",
                client_info_for_rx.assigned_ip
            );
        });

        tokio::select! {
            _ = tx_task => {
                warn!("Client {} Tx closed unexpectedly", client_info.remote_addr.load());
            },
            _ = rx_task => {
                warn!("Client {} Rx closed unexpectedly", client_info.remote_addr.load());
            },
            _ = connection.closed() => {
                warn!("Client {} connection closed unexpectedly", client_info.remote_addr.load());
            },
        }

        info!("Cleaning up resources for client {}.", client_ip);
        registry.remove_client(&client_info);
        Ok(())
    }

    async fn route_tun_to_quic(
        mut rx_from_tun: mpsc::Receiver<Bytes>,
        registry: Arc<ClientRegistry>,
    ) -> Result<()> {
        while let Some(packet) = rx_from_tun.recv().await {
            if packet.len() < 20 {
                continue;
            }
            if let Some(dst_ip) = extract_ip_dst(&packet) {
                registry
                    .route_packet_to_client(&dst_ip.to_string(), packet)
                    .await;
            }
        }
        Ok(())
    }
}
