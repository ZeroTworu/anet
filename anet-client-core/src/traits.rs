use anet_common::protocol::AuthResponse;
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use std::net::IpAddr;
use tokio::sync::mpsc;

/// Интерфейс для управления системной маршрутизацией.
/// На Linux/Windows это будет вызов `ip route`/`route`.
/// На Android это будет пустая заглушка (NoOp), т.к. Android делает это сам.
#[async_trait]
pub trait RouteManager: Send + Sync {
    /// Сохранить текущие маршруты (если нужно)
    async fn backup_routes(&self) -> Result<()>;

    /// Добавить маршрут, который идет МИМО туннеля (через физический шлюз).
    /// Используется для:
    /// 1. IP самого VPN сервера (чтобы не разорвать соединение).
    /// 2. Локальных сетей (192.168.x.x).
    /// 3. Ресурсов, которые нужно исключить из VPN.
    async fn add_bypass_route(&self, target: IpAddr, prefix: u8) -> Result<()>;

    /// Направить весь трафик в туннель
    async fn set_default_route(&self, gateway: &str, interface_name: &str) -> Result<()>;

    /// Добавить точечный маршрут (Split Tunneling)
    /// target: IP адрес или подсеть
    /// mask: маска (u8, например 32 для одного IP)
    async fn add_specific_route(
        &self,
        target: IpAddr,
        prefix: u8,
        gateway: &str,
        interface_name: &str,
    ) -> Result<()>;

    /// Восстановить маршрутизацию
    async fn restore_routes(&self) -> Result<()>;
}

/// Интерфейс для создания/настройки TUN устройства.
/// На Linux/Windows это использует crate `tun`.
/// На Android это получает `fd` от Java.
#[async_trait::async_trait]
pub trait TunFactory: Send + Sync {
    /// Создает интерфейс с полученными от сервера параметрами.
    /// Возвращает каналы для чтения и записи пакетов.
    async fn create_tun(
        &self,
        auth: &AuthResponse,
    ) -> Result<(mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>, String)>;
    // Возвращает: (Tx Channel, Rx Channel, Interface Name)
}
