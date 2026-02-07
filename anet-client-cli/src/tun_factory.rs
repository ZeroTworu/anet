use anet_client_core::traits::TunFactory;
use anet_common::atun::TunManager;
use anet_common::protocol::AuthResponse;
use anet_common::tun_params::TunParams;
use anyhow::Result;
use bytes::Bytes;
use tokio::sync::mpsc;

pub struct DesktopTunFactory {
    tun_name: String,
}

impl DesktopTunFactory {
    pub fn new(tun_name: String) -> Self {
        Self { tun_name }
    }
}

#[async_trait::async_trait]
impl TunFactory for DesktopTunFactory {
    async fn create_tun(
        &self,
        auth: &AuthResponse,
    ) -> Result<(mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>, String)> {
        let params = TunParams::from_auth_response(auth, &self.tun_name)?;

        let mut manager = TunManager::new(params)?;

        // Use run_with_name to get the actual interface name
        // This is important for macOS where utun names are assigned dynamically
        let result = manager.run_with_name().await?;

        Ok((result.tx, result.rx, result.interface_name))
    }
}
