use crate::consts::{CHANNEL_BUFFER_SIZE, MAX_PACKET_SIZE};
use crate::tun_params::TunParams;
use anyhow::{Context, Result};
use bytes::Bytes;
use log::{error, info};
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
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

pub struct TunManager {
    params: TunParams,
    tun_index: Option<u32>,
}

impl Clone for TunManager {
    fn clone(&self) -> Self {
        Self {
            params: self.params.clone(),
            tun_index: self.tun_index.clone(),
        }
    }
}

impl TunManager {
    pub fn new(params: TunParams) -> Result<Self> {
        Ok(Self {
            params,
            tun_index: None,
        })
    }

    pub fn get_tun_index(&self) -> u32 {
        if self.tun_index.is_none() {
            error!("Attempted to get tun index from a not created device!");
            return 0;
        }
        self.tun_index.unwrap()
    }

    pub async fn run(&mut self) -> Result<(mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>)> {
        let (tx_to_tun, mut rx_to_tun) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
        let (tx_from_tun, rx_from_tun) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);

        let config = self.params.create_config()?;
        let device = tun::create_as_async(&config).context("Failed to create async TUN device")?;
        self.tun_index = Some(device.tun_index()? as u32);
        let (mut reader, mut writer) = tokio::io::split(device);

        info!("Created TUN with: [{}]", self.params.get_info());

        // Задача для чтения из TUN
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

        // Задача для записи в TUN
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

    pub async fn setup_server_tun_routing(&self, external: &str) -> Result<()> {
        if self.params.network.is_none() {
            // Мы - не сервер.
            return Ok(());
        }
        Command::new("sysctl")
            .arg("-w")
            .arg("net.ipv4.ip_forward=1")
            .status()
            .await?;
        Command::new("iptables").args(&["-F"]).status().await?;
        Command::new("iptables")
            .args(&["-t", "nat", "-F"])
            .status()
            .await?;
        Command::new("iptables")
            .args(&["-P", "INPUT", "ACCEPT"])
            .status()
            .await?;
        Command::new("iptables")
            .args(&["-P", "FORWARD", "ACCEPT"])
            .status()
            .await?;
        Command::new("iptables")
            .args(&["-P", "OUTPUT", "ACCEPT"])
            .status()
            .await?;
        Command::new("iptables")
            .args(&[
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-o",
                external,
                "-j",
                "MASQUERADE",
            ])
            .status()
            .await?;
        Command::new("iptables")
            .args(&[
                "-A",
                "FORWARD",
                "-i",
                &self.params.name,
                "-o",
                external,
                "-j",
                "ACCEPT",
            ])
            .status()
            .await?;
        Command::new("iptables")
            .args(&[
                "-A",
                "FORWARD",
                "-i",
                external,
                "-o",
                &self.params.name,
                "-j",
                "ACCEPT",
            ])
            .status()
            .await?;
        let prefix = Self::netmask_to_prefix(self.params.netmask)?;
        let net = format!("{}/{}", self.params.network.unwrap(), prefix);
        Command::new("ip")
            .args(&["route", "replace", &net, "dev", &self.params.name])
            .status()
            .await?;
        info!("IP routing configured successfully");
        Ok(())
    }

    /// Преобразует маску в формате Ipv4Addr в префикс CIDR
    fn netmask_to_prefix(netmask: Ipv4Addr) -> Result<u8, anyhow::Error> {
        let octets = netmask.octets();
        let mask = u32::from_be_bytes(octets);

        // Проверяем что маска валидна (последовательность единиц followed by нулей)
        if !Self::is_valid_netmask(mask) {
            return Err(anyhow::anyhow!("Invalid netmask: {}", netmask));
        }

        // Считаем количество установленных битов
        Ok(mask.count_ones() as u8)
    }

    /// Проверяет что маска является валидной сетевой маской
    fn is_valid_netmask(mask: u32) -> bool {
        // Маска должна быть последовательностью единиц followed by нулей
        let inverted = !mask;
        inverted & (inverted + 1) == 0
    }
}
