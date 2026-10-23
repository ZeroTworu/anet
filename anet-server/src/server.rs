use crate::auth_handler::ServerAuthHandler;
use crate::auth_provider::AuthProvider;
use crate::client_registry::ClientRegistry;
use crate::config::Config;
use crate::ip_pool::IpPool;
use crate::multikey_udp_socket::TempDHInfo;
use crate::servers::{astpl, http_stream, quic, ssh, vnc, websocket, wrtc};

use anet_common::atun::TunManager;
use anet_common::tun_params::TunParams;
use anyhow::Result;
use base64::prelude::*;
use bytes::Bytes;
use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use log::error;
use std::sync::Arc;
use std::time::Duration;

pub struct ANetServer {
    cfg: Arc<Config>,
    registry: Arc<ClientRegistry>,
    temp_dh_map: Arc<DashMap<std::net::SocketAddr, TempDHInfo>>,
    tun_manager: TunManager,
    auth_handler_core: ServerAuthHandler,
}

impl ANetServer {
    pub fn new(cfg_ref: &Config) -> Result<Self> {
        let t_prm = TunParams {
            netmask: cfg_ref.network.mask.parse()?, gateway: cfg_ref.network.gateway.parse()?,
            address: cfg_ref.network.self_ip.parse()?, name: cfg_ref.network.if_name.clone(),
            mtu: cfg_ref.network.mtu, network: Some(cfg_ref.network.net.parse()?),
        };

        let pl = IpPool::new(
            cfg_ref.network.net.parse()?, cfg_ref.network.mask.parse()?,
            cfg_ref.network.gateway.parse()?, cfg_ref.network.self_ip.parse()?, cfg_ref.network.mtu,
        );

        let sk_bytes = BASE64_STANDARD.decode(&cfg_ref.crypto.server_signing_key)?;
        let sign_key = SigningKey::from_bytes(&sk_bytes.try_into().unwrap());


        let reg = Arc::new(ClientRegistry::new(pl));
        let dh = Arc::new(DashMap::new());

        let node_id = (!cfg_ref.control_plane.node_id.trim().is_empty())
            .then(|| cfg_ref.control_plane.node_id.trim().to_string());
        let a_prov = Arc::new(
            AuthProvider::new(
                cfg_ref.authentication.allowed_clients.clone(),
                cfg_ref.authentication.auth_servers.clone(),
                cfg_ref.authentication.auth_server_token.clone(),
            )
            .with_node_id(node_id),
        );

        let ac = ServerAuthHandler::new(
            reg.clone(), dh.clone(), a_prov, sign_key,
            cfg_ref.crypto.quic_cert.clone(), cfg_ref.stealth.padding_step,
        );

        Ok(Self { cfg: Arc::new(cfg_ref.clone()), registry: reg, temp_dh_map: dh, tun_manager: TunManager::new(t_prm)?, auth_handler_core: ac })
    }

    pub async fn run(&mut self) -> Result<()> {
        let (tx_tun, mut rx_tun) = self.tun_manager.run().await?;
        let actual_tun_iface = self
            .tun_manager
            .get_actual_name()
            .unwrap_or(self.cfg.network.if_name.as_str())
            .to_string();

        // eBPF-шейпер (per-user speed_limit) вешается на TUN только после
        // того, как интерфейс реально поднят — имя может отличаться от
        // запрошенного (`get_actual_name()`), если ОС его переименовала.
        if self.cfg.shaper.enabled {
            match crate::shaper::Shaper::attach(&actual_tun_iface).await {
                Ok(shaper) => self.registry.set_shaper(Arc::new(shaper)),
                Err(e) => error!(
                    "[Shaper] Failed to attach eBPF shaper to '{}': {}. Speed limits will not be enforced.",
                    actual_tun_iface, e
                ),
            }
        }

        let control_config = self.cfg.control_plane.clone();
        let control_registry = self.registry.clone();
        tokio::spawn(async move {
            crate::control_plane::run_heartbeat(control_config, control_registry).await;
        });

        // 1. Дешифратор маршрутов: от ядра ОС к внутренним регистрам UDP/TCP транспорта.
        // Также перехватывает внутритуннельные ICMP-зонды (dst = gateway 10.0.0.1), которые
        // после XDP-декапсуляции ASTP-L были направлены ядром ОС в TUN-интерфейс.
        let rx_reg = self.registry.clone();
        tokio::spawn(async move {
            while let Some(packet) = rx_tun.recv().await {
                if packet.len() < 20 { continue; }
                if let Some(reply) = anet_common::icmp_probe::handle_in_tunnel_icmp_probe(&packet) {
                    if let Some(dst_ip) = crate::utils::extract_ip_dst(&reply) {
                        rx_reg.route_packet_to_client(&dst_ip.to_string(), reply).await;
                    }
                    continue;
                }
                if let Some(dst_ip) = crate::utils::extract_ip_dst(&packet) {
                    rx_reg.route_packet_to_ipv4(dst_ip, packet).await;
                }
            }
        });

        // 2. Демон очистки State (Очистка незаконченных DH транзакций по истечении тайминга)
        let gcx = self.temp_dh_map.clone();
        let gc_registry = self.registry.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                gcx.retain(|_, v| v.created_at.elapsed() <= Duration::from_secs(30));
                gc_registry.cleanup_suspended().await;
                gc_registry.cleanup_inactive_clients(30).await;
            }
        });

        // 3. Выборочная инъекция транспорта на основании конфигурационного манифеста
        // Канал входящих пакетов от клиентов (все транспорты шлют сюда).
        // Перехватываем внутритуннельные ICMP Echo Request зонды в userspace
        // и мгновенно отправляем ICMP Echo Reply клиенту через registry.route_packet_to_client.
        // Это гарантирует точный замер сквозного RTT на всех транспортах (WRTC/SSH/VNC/WS/AHTTP/QUIC/ASTP-L)
        // без зависимости от ядра ОС сервера, iptables, rp_filter или совпадения IP TUN.
        let (client_pkt_tx, mut client_pkt_rx) =
            tokio::sync::mpsc::channel::<Bytes>(anet_common::consts::CHANNEL_BUFFER_SIZE);

        let probe_registry = self.registry.clone();
        let tun_writer = tx_tun.clone();
        tokio::spawn(async move {
            while let Some(packet) = client_pkt_rx.recv().await {
                if let Some(reply) = anet_common::icmp_probe::handle_in_tunnel_icmp_probe(&packet) {
                    if let Some(dst_ip) = crate::utils::extract_ip_dst(&reply) {
                        probe_registry
                            .route_packet_to_ipv4(dst_ip, reply)
                            .await;
                    }
                    continue;
                }
                if let Err(tokio::sync::mpsc::error::TrySendError::Full(pkt)) =
                    tun_writer.try_send(packet)
                {
                    let _ = tun_writer.send(pkt).await;
                }
            }
        });

        let mut handle_collection = vec![];

        if !self.cfg.server.quic_bind_to.trim().is_empty() {
            let t_tx = client_pkt_tx.clone();
            let auth = self.auth_handler_core.clone();
            let rg = self.registry.clone();
            let c = self.cfg.clone();

            handle_collection.push(tokio::spawn(async move {
                if let Err(e) = quic::run_quic_server(c, rg, t_tx, auth).await {
                    error!("QUIC Interface execution halted: {}", e);
                }
            }));
        }

        if !self.cfg.server.astpl_bind_to.trim().is_empty() {
            let t_tx = tx_tun.clone();
            let auth = self.auth_handler_core.clone();
            let rg = self.registry.clone();
            let c = self.cfg.clone();
            let tun_if = actual_tun_iface.clone();

            handle_collection.push(tokio::spawn(async move {
                if let Err(e) = astpl::run_astpl_server(c, rg, t_tx, auth, tun_if).await {
                    error!("ASTP-L Interface execution halted: {}", e);
                }
            }));
        }

        if !self.cfg.server.ssh_bind_to.trim().is_empty() {
            let t_tx = client_pkt_tx.clone();
            let auth = self.auth_handler_core.clone();
            let rg = self.registry.clone();
            let c = self.cfg.clone();
            handle_collection.push(tokio::spawn(async move {
                if let Err(e) = ssh::run_ssh_server(c, rg, t_tx, auth).await {
                    error!("SSH Interface execution halted: {}", e);
                }
            }));
        }

        let bnd_vnc = self.cfg.server.vnc_bind_to.trim();
        if !bnd_vnc.is_empty() {
            let v_cfg = self.cfg.clone();
            let v_reg = self.registry.clone();
            let v_tx = client_pkt_tx.clone();
            let v_auth = self.auth_handler_core.clone();
            handle_collection.push(tokio::spawn(async move {
                if let Err(e) = vnc::run_vnc_server(v_cfg, v_reg, v_tx, v_auth).await {
                    error!("Fatal VNC Failure: {}", e);
                }
            }));
        }

        if !self.cfg.server.websocket_bind_to.trim().is_empty() {
            let c = self.cfg.clone();
            let rg = self.registry.clone();
            let tx = client_pkt_tx.clone();
            let auth = self.auth_handler_core.clone();
            handle_collection.push(tokio::spawn(async move {
                if let Err(e) = websocket::run_websocket_server(c, rg, tx, auth).await {
                    error!("WebSocket interface execution halted: {}", e);
                }
            }));
        }

        if !self.cfg.server.ahttp_bind_to.trim().is_empty() {
            let c = self.cfg.clone();
            let rg = self.registry.clone();
            let tx = client_pkt_tx.clone();
            let auth = self.auth_handler_core.clone();
            handle_collection.push(tokio::spawn(async move {
                if let Err(e) = http_stream::run_http_stream_server(c, rg, tx, auth).await {
                    error!("Fatal error: [AHTTP-Stream] Server halted: {}", e);
                }
            }));
        }

        if let Some(ref wrtc_url) = self.cfg.server.wrtc_room_url {
            if !wrtc_url.trim().is_empty() {
                let c = self.cfg.clone();
                let rg = self.registry.clone();
                let tx = client_pkt_tx.clone();
                let auth = self.auth_handler_core.clone();
                handle_collection.push(tokio::spawn(async move {
                    if let Err(e) = wrtc::run_wrtc_server(c, rg, tx, auth).await {
                        error!("Fatal error: [WRTC] Server halted: {}", e);
                    }
                }));
            }
        }

        futures::future::join_all(handle_collection).await;
        Ok(())
    }
}
