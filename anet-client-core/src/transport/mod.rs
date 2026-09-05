pub(crate) mod factory;
pub(crate) mod quic;
pub(crate) mod ssh;
pub(crate) mod vnc;
pub (crate) mod websocket;
pub(crate) mod ahttp;

use anet_common::protocol::AuthResponse;
use anet_common::transport_trait::VpnStream;
use anyhow::Result;
use async_trait::async_trait;
use quinn::{Endpoint, Connection};

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

pub struct ConnectionResult {
    pub auth_response: AuthResponse,
    pub vpn_stream: Box<dyn VpnStream>,
    pub endpoint: Option<Endpoint>,
    pub connection: Option<Connection>,
    /// Set only while a transport performs a planned internal reconnect.
    pub health_pause: Option<Arc<AtomicBool>>,

}

#[async_trait]
pub trait ClientTransport: Send + Sync {
    async fn connect(&self) -> Result<ConnectionResult>;
}
