use anet_client_core::traits::TunFactory;
use anet_common::atun::TunManager;
use anet_common::protocol::AuthResponse;
use anet_common::tun_params::TunParams;
use anyhow::Result;
use bytes::Bytes;
use tokio::sync::mpsc;

pub struct DesktopTunFactory {
    tun_name: String,
    _per_app_mode: bool,
}

impl DesktopTunFactory {
    pub fn new(tun_name: String, per_app_mode: bool) -> Self {
        Self { tun_name, _per_app_mode: per_app_mode }
    }
}

#[async_trait::async_trait]
impl TunFactory for DesktopTunFactory {
    async fn create_tun(
        &self,
        auth: &AuthResponse,
    ) -> Result<(mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>, String)> {
        let params = TunParams::from_auth_response(auth, &self.tun_name);
        let mut manager = TunManager::new(params)?;
        let result = manager.run_with_name().await?;
        Ok((result.tx, result.rx, result.interface_name))
    }
}