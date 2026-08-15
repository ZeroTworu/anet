//! Исходящий control plane VPN-ноды.
//!
//! Нода сама обращается к панели управления: отправляет heartbeat и счётчики,
//! забирает команды и возвращает результат их выполнения. Входящий HTTP-сервер
//! для управления в `anet-server` намеренно отсутствует — это сохраняет data
//! plane закрытым и удобным для работы за NAT.

use crate::client_registry::ClientRegistry;
use crate::config::ControlPlaneConfig;
use anet_common::dto::{
    NodeCommand, NodeCommandResultRequest, NodeHeartbeatRequest, NodeTrafficReport,
};
use log::{info, warn};
use reqwest::Client;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Запускает бесконечный цикл обмена состоянием ноды с control plane.
pub async fn run_heartbeat(config: ControlPlaneConfig, registry: Arc<ClientRegistry>) {
    if config.node_id.trim().is_empty() || config.url.trim().is_empty() {
        info!("[ControlPlane] Heartbeat disabled: node_id or url is empty");
        return;
    }

    let client = match Client::builder().timeout(Duration::from_secs(5)).build() {
        Ok(client) => client,
        Err(error) => {
            warn!("[ControlPlane] Cannot create HTTP client: {error}");
            return;
        }
    };
    let endpoint = format!(
        "{}/control/nodes/heartbeat",
        config.url.trim_end_matches('/')
    );
    let commands_endpoint = format!(
        "{}/control/nodes/commands",
        config.url.trim_end_matches('/')
    );
    let interval = Duration::from_secs(config.heartbeat_interval_seconds.max(5));
    let started_at = Instant::now();
    let boot_id = crate::utils::generate_seid();

    loop {
        let heartbeat = NodeHeartbeatRequest {
            node_id: config.node_id.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: started_at.elapsed().as_secs(),
            active_connections: registry.active_connection_count() as u64,
            accepting_connections: registry.is_accepting_connections(),
        };

        match client
            .post(&endpoint)
            .header("X-Node-Token", &config.token)
            .json(&heartbeat)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => warn!(
                "[ControlPlane] Heartbeat rejected with status {}",
                response.status()
            ),
            Err(error) => warn!("[ControlPlane] Heartbeat failed: {error}"),
        }

        let samples = registry.traffic_snapshot();
        if !samples.is_empty() {
            let traffic_endpoint =
                format!("{}/control/nodes/traffic", config.url.trim_end_matches('/'));
            let report = NodeTrafficReport {
                node_id: config.node_id.clone(),
                boot_id: boot_id.clone(),
                samples,
            };
            match client
                .post(traffic_endpoint)
                .header("X-Node-Token", &config.token)
                .json(&report)
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {}
                Ok(response) => warn!(
                    "[ControlPlane] Traffic report rejected with status {}",
                    response.status()
                ),
                Err(error) => warn!("[ControlPlane] Traffic report failed: {error}"),
            }
        }

        match client
            .get(&commands_endpoint)
            .header("X-Node-Token", &config.token)
            .query(&[("node_id", &config.node_id)])
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                match response.json::<Vec<NodeCommand>>().await {
                    Ok(commands) => {
                        for command in commands {
                            execute_and_report_command(&client, &config, &registry, command).await;
                        }
                    }
                    Err(error) => warn!("[ControlPlane] Invalid commands response: {error}"),
                }
            }
            Ok(response) => warn!(
                "[ControlPlane] Command polling rejected with status {}",
                response.status()
            ),
            Err(error) => warn!("[ControlPlane] Command polling failed: {error}"),
        }

        tokio::time::sleep(interval).await;
    }
}

async fn execute_and_report_command(
    client: &Client,
    config: &ControlPlaneConfig,
    registry: &ClientRegistry,
    command: NodeCommand,
) {
    // Команды выполняются локально, после чего панель получает подтверждение.
    // Это позволяет UI показать реальное состояние, а не только факт постановки
    // записи в очередь.
    let result = match command.command_type.as_str() {
        "set_accepting_connections" => match command.accepting_connections {
            Some(accepting) => {
                registry.set_accepting_connections(accepting);
                Ok(())
            }
            None => Err("Command is missing accepting_connections".to_string()),
        },
        other => Err(format!("Unsupported command type: {other}")),
    };

    let endpoint = format!(
        "{}/control/nodes/commands/{}/result",
        config.url.trim_end_matches('/'),
        command.command_id
    );
    let report = NodeCommandResultRequest {
        node_id: config.node_id.clone(),
        succeeded: result.is_ok(),
        error: result.err(),
    };
    match client
        .post(endpoint)
        .header("X-Node-Token", &config.token)
        .json(&report)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {}
        Ok(response) => warn!(
            "[ControlPlane] Command result rejected with status {}",
            response.status()
        ),
        Err(error) => warn!("[ControlPlane] Command result report failed: {error}"),
    }
}
