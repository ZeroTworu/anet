pub(crate) mod factory;
pub(crate) mod quic;
pub(crate) mod ssh;
mod vnc;

use anet_common::protocol::AuthResponse;
use anet_common::transport_trait::VpnStream;
use anyhow::Result;
use async_trait::async_trait;
use quinn::{Endpoint, Connection};

pub struct ConnectionResult {
    pub auth_response: AuthResponse,
    pub vpn_stream: Box<dyn VpnStream>,
    pub endpoint: Option<Endpoint>,
    pub connection: Option<Connection>,

}

#[async_trait]
pub trait ClientTransport: Send + Sync {
    /// Подключается к серверу, проводит хендшейк и возвращает:
    /// 1. Параметры сети (AuthResponse) для настройки TUN.
    /// 2. Установленный поток данных (VpnStream).
    async fn connect(&self) -> Result<ConnectionResult>;
}
