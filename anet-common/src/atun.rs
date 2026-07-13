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

/// Результат успешного создания TUN устройства
pub struct TunCreationResult {
    pub tx: mpsc::Sender<Bytes>,
    pub rx: mpsc::Receiver<Bytes>,
    pub interface_name: String,
}

pub struct TunManager {
    params: TunParams,
    tun_index: Option<u32>,
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

    pub fn get_actual_name(&self) -> Option<&str> {
        self.actual_name.as_deref()
    }

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

        self.tun_index = Some(device.tun_index()? as u32);

        let actual_name = device
            .tun_name()
            .unwrap_or_else(|_| self.params.name.clone());

        self.actual_name = Some(actual_name.clone());

        #[cfg(target_os = "macos")]
        self.configure_macos_interface(&actual_name).await?;

        let (mut reader, mut writer) = tokio::io::split(device);

        info!(
            "Created TUN with: [{}] (actual name: {})",
            self.params.get_info(),
            actual_name
        );

        // Задача чтения из TUN устройства (TUN -> NETWORK)
        let tx_clone = tx_from_tun.clone();
        tokio::spawn(async move {
            let mut buffer = [0u8; MAX_PACKET_SIZE];
            loop {
                tokio::select! {
                    // Читаем входящие пакеты от операционной системы
                    res = reader.read(&mut buffer) => {
                        match res {
                            Ok(0) => {
                                info!("TUN reader stream ended.");
                                break;
                            }
                            Ok(n) => {
                                let packet = Bytes::copy_from_slice(&buffer[..n]);
                                if tx_clone.send(packet).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                error!("Failed to read from TUN: {}", e);
                                break;
                            }
                        }
                    }
                    // ВАЖНО: Мониторим закрытие канала на стороне клиента.
                    // Как только клиент дропнет приемник, этот фьючерс мгновенно разрешится,
                    // прервав висящий вызов read и освободив файловый дескриптор устройства.
                    _ = tx_clone.closed() => {
                        info!("TUN reader channel closed, stopping read task.");
                        break;
                    }
                }
            }
        });

        // Задача записи в TUN устройство (NETWORK -> TUN)
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

    #[cfg(target_os = "macos")]
    async fn configure_macos_interface(&self, interface_name: &str) -> Result<()> {
        use std::process::Stdio;

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
