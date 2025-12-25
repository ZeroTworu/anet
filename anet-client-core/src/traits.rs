use anet_common::protocol::AuthResponse;
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::mpsc;

/// Интерфейс для управления системной маршрутизацией.
/// На Linux/Windows это будет вызов `ip route`/`route`.
/// На Android это будет пустая заглушка (NoOp), т.к. Android делает это сам.
#[async_trait]
pub trait RouteManager: Send + Sync {
    /// Сохранить текущие маршруты (если нужно)
    async fn backup_routes(&self) -> Result<()>;

    /// Добавить маршрут до VPN сервера мимо туннеля
    async fn add_exclusion_route(&self, server_ip: &str) -> Result<()>;

    /// Направить весь трафик в туннель
    async fn set_default_route(&self, gateway: &str, interface_name: &str) -> Result<()>;

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
