use crate::consts::{CHANNEL_BUFFER_SIZE, MAX_PACKET_SIZE};
use crate::tun_params::TunParams;
use anyhow::Result;
use bytes::Bytes;
#[cfg(target_os = "macos")]
use log::warn;
use log::{error, info};
#[cfg(target_os = "macos")]
use tokio::process::Command;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tun::AbstractDevice;

#[derive(Debug)]
pub struct TunChannels {
    pub tx_to_tun: mpsc::Sender<Bytes>,
    pub rx_from_tun: mpsc::Receiver<Bytes>,
    pub tun_index: Option<u32>,
}

impl TunChannels {
    pub fn new(
        tx_to_tun: mpsc::Sender<Bytes>,
        rx_from_tun: mpsc::Receiver<Bytes>,
        tun_index: Option<u32>,
    ) -> Self {
        Self {
            tx_to_tun,
            rx_from_tun,
            tun_index,
        }
    }
}

/// Result of TUN device creation
pub struct TunCreationResult {
    pub tx: mpsc::Sender<Bytes>,
    pub rx: mpsc::Receiver<Bytes>,
    /// The actual interface name (may differ from requested on macOS)
    pub interface_name: String,
}

pub struct TunManager {
    params: TunParams,
    tun_index: Option<u32>,
    /// The actual interface name after creation
    actual_name: Option<String>,
}

impl Clone for TunManager {
    fn clone(&self) -> Self {
        Self {
            params: self.params.clone(),
            tun_index: self.tun_index,
            actual_name: self.actual_name.clone(),
        }
    }
}

impl TunManager {
    pub fn new(params: TunParams) -> Result<Self> {
        Ok(Self {
            params,
            tun_index: None,
            actual_name: None,
        })
    }

    pub fn get_tun_index(&self) -> u32 {
        if self.tun_index.is_none() {
            error!("Attempted to get tun index from a not created device!");
            return 0;
        }
        self.tun_index.unwrap()
    }

    /// Get the actual interface name after creation
    pub fn get_actual_name(&self) -> Option<&str> {
        self.actual_name.as_deref()
    }

    /// Run the TUN device and return channels + actual interface name
    pub async fn run_with_name(&mut self) -> Result<TunCreationResult> {
        let (tx, rx) = self.run().await?;
        let interface_name = self
            .actual_name
            .clone()
            .unwrap_or_else(|| self.params.name.clone());
        Ok(TunCreationResult {
            tx,
            rx,
            interface_name,
        })
    }

    pub async fn run(&mut self) -> Result<(mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>)> {
        let (tx_to_tun, mut rx_to_tun) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
        let (tx_from_tun, rx_from_tun) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);

        let config = self.params.create_config()?;
        let device = match tun::create_as_async(&config) {
            Ok(device) => device,
            Err(e) => anyhow::bail!("Failed to create async TUN device: {}", e),
        };

        // Get the TUN index
        self.tun_index = Some(device.tun_index()? as u32);

        // Get the actual interface name (important for macOS where names are dynamic)
        let actual_name = device
            .tun_name()
            .unwrap_or_else(|_| self.params.name.clone());

        self.actual_name = Some(actual_name.clone());

        // On macOS, we may need to configure the interface manually
        #[cfg(target_os = "macos")]
        self.configure_macos_interface(&actual_name).await?;

        let (mut reader, mut writer) = tokio::io::split(device);

        info!(
            "Created TUN with: [{}] (actual name: {})",
            self.params.get_info(),
            actual_name
        );

        // Task for reading from TUN
        tokio::spawn(async move {
            let mut buffer = vec![0u8; MAX_PACKET_SIZE];
            loop {
                match reader.read(&mut buffer).await {
                    Ok(0) => {
                        info!("TUN reader stream ended.");
                        break;
                    }
                    Ok(n) => {
                        let packet = Bytes::copy_from_slice(&buffer[..n]);
                        if let Err(e) = tx_from_tun.send(packet).await {
                            error!("Failed send to channel, error: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Failed to read from TUN: {}", e);
                        break;
                    }
                }
            }
        });

        // Task for writing to TUN
        tokio::spawn(async move {
            while let Some(packet) = rx_to_tun.recv().await {
                if let Err(e) = writer.write_all(&packet).await {
                    error!("Failed to write to TUN: {}, bytes: {:?}", e, packet);
                    break;
                }
            }
        });
        info!("TUN reader/writer stream started.");
        Ok((tx_to_tun, rx_from_tun))
    }

    /// Configure the macOS utun interface using ifconfig
    ///
    /// The tun crate may not fully configure the interface on macOS,
    /// so we use ifconfig to ensure proper configuration.
    #[cfg(target_os = "macos")]
    async fn configure_macos_interface(&self, interface_name: &str) -> Result<()> {
        use std::process::Stdio;

        // Configure IP address and peer (point-to-point)
        // ifconfig utunX inet <local_ip> <peer_ip> netmask <mask>
        let output = Command::new("ifconfig")
            .args([
                interface_name,
                "inet",
                &self.params.address.to_string(),
                &self.params.gateway.to_string(),
                "netmask",
                &self.params.netmask.to_string(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(
                "ifconfig inet configuration warning: {} (interface may already be configured)",
                stderr.trim()
            );
        }

        // Set MTU
        let output = Command::new("ifconfig")
            .args([interface_name, "mtu", &self.params.mtu.to_string()])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("ifconfig mtu configuration warning: {}", stderr.trim());
        }

        info!(
            "Configured macOS interface {}: {} -> {} netmask {} mtu {}",
            interface_name,
            self.params.address,
            self.params.gateway,
            self.params.netmask,
            self.params.mtu
        );

        Ok(())
    }
}
