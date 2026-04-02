use crate::auth_handler::ServerAuthHandler;
use crate::auth_provider::AuthProvider;
use crate::client_registry::ClientRegistry;
use crate::config::Config;
use crate::ip_pool::IpPool;
use crate::multikey_udp_socket::TempDHInfo;
use crate::servers::{quic, ssh, vnc};

use anet_common::atun::TunManager;
use anet_common::tun_params::TunParams;
use anyhow::Result;
use base64::prelude::*;
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

        let a_prov = Arc::new(AuthProvider::new(
            cfg_ref.authentication.allowed_clients.clone(),
            cfg_ref.authentication.auth_servers.clone(),
            cfg_ref.authentication.auth_server_token.clone(),
        ));

        let ac = ServerAuthHandler::new(
            reg.clone(), dh.clone(), a_prov, sign_key,
            cfg_ref.crypto.quic_cert.clone(), cfg_ref.stealth.padding_step,
        );

        Ok(Self { cfg: Arc::new(cfg_ref.clone()), registry: reg, temp_dh_map: dh, tun_manager: TunManager::new(t_prm)?, auth_handler_core: ac })
    }

    pub async fn run(&mut self) -> Result<()> {
        let (tx_tun, mut rx_tun) = self.tun_manager.run().await?;

        // 1. Дешифратор маршрутов: от ядра ОС к внутренним регистрам UDP/TCP транспорта
        let rx_reg = self.registry.clone();
        tokio::spawn(async move {
            while let Some(packet) = rx_tun.recv().await {
                if packet.len() < 20 { continue; }
                if let Some(dst_ip) = crate::utils::extract_ip_dst(&packet) {
                    rx_reg.route_packet_to_client(&dst_ip.to_string(), packet).await;
                }
            }
        });

        // 2. Демон очистки State (Очистка незаконченных DH транзакций по истечении тайминга)
        let gcx = self.temp_dh_map.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                gcx.retain(|_, v| v.created_at.elapsed() <= Duration::from_secs(30));
            }
        });

        // 3. Выборочная инъекция транспорта на основании конфигурационного манифеста
        let mut handle_collection = vec![];

        if !self.cfg.server.quic_bind_to.trim().is_empty() {
            let t_tx = tx_tun.clone();
            let auth = self.auth_handler_core.clone();
            let rg = self.registry.clone();
            let c = self.cfg.clone();

            handle_collection.push(tokio::spawn(async move {
                if let Err(e) = quic::run_quic_server(c, rg, t_tx, auth).await {
                    error!("QUIC Interface execution halted: {}", e);
                }
            }));
        }

        if !self.cfg.server.ssh_bind_to.trim().is_empty() {
            let t_tx = tx_tun.clone();
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
            let v_tx = tx_tun.clone();
            let v_auth = self.auth_handler_core.clone();
            handle_collection.push(tokio::spawn(async move {
                if let Err(e) = vnc::run_vnc_server(v_cfg, v_reg, v_tx, v_auth).await {
                    error!("Fatal VNC Failure: {}", e);
                }
            }));
        }

        futures::future::join_all(handle_collection).await;
        Ok(())
    }
}
