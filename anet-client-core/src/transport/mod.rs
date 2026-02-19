pub(crate) mod factory;
pub(crate) mod quic;
pub(crate) mod ssh;

use anet_common::protocol::AuthResponse;
use anet_common::transport_trait::VpnStream;
use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait ClientTransport: Send + Sync {
    /// Подключается к серверу, проводит хендшейк и возвращает:
    /// 1. Параметры сети (AuthResponse) для настройки TUN.
    /// 2. Установленный поток данных (VpnStream).
    async fn connect(&self) -> Result<(AuthResponse, Box<dyn VpnStream>)>;
}
