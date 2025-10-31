use crate::consts::{CHANNEL_BUFFER_SIZE, MAX_PACKET_SIZE};
use crate::tun_params::TunParams;
use anyhow::{Context, Result};
use bytes::Bytes;
use log::{error, info};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::process::Command;
use tokio::sync::{Mutex, mpsc};
use tun::AsyncDevice;

pub struct TunManager {
    reader: Arc<Mutex<ReadHalf<AsyncDevice>>>,
    writer: Arc<Mutex<WriteHalf<AsyncDevice>>>,
    params: TunParams,
}

impl Clone for TunManager {
    fn clone(&self) -> Self {
        Self {
            reader: Arc::clone(&self.reader),
            writer: Arc::clone(&self.writer),
            params: self.params.clone(),
        }
    }
}

impl TunManager {
    pub fn new(params: TunParams) -> Result<Self> {
        let config = params.create_config()?;
        let device = tun::create_as_async(&config).context("Failed to create async TUN device")?;

        let (reader, writer) = tokio::io::split(device);
        info!("Created TUN with: [{}]", params.get_info());
        Ok(Self {
            reader: Arc::new(Mutex::new(reader)),
            writer: Arc::new(Mutex::new(writer)),
            params,
        })
    }

    pub async fn run(&self) -> Result<(mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>)> {
        let (tx_to_tun, mut rx_to_tun) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
        let (tx_from_tun, rx_from_tun) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);

        let reader_clone = Arc::clone(&self.reader);
        let writer_clone = Arc::clone(&self.writer);

        // Задача для чтения из TUN
        tokio::spawn(async move {
            let mut buffer = vec![0u8; MAX_PACKET_SIZE];
            loop {
                let mut reader_guard = reader_clone.lock().await;
                match reader_guard.read(&mut buffer).await {
                    Ok(0) => {
                        info!("TUN reader stream ended.");
                        break;
                    }
                    Ok(n) => {
                        let packet = Bytes::copy_from_slice(&buffer[..n]);
                        drop(reader_guard); // Освобождаем мьютекс перед отправкой
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
                let mut writer_guard = writer_clone.lock().await;
                if let Err(e) = writer_guard.write_all(&packet).await {
                    error!("Failed to write to TUN: {}, bytes: {:?}", e, packet);
                    break;
                }
            }
        });
        info!("TUN reader/writer stream started.");
        Ok((tx_to_tun, rx_from_tun))
    }

    pub async fn setup_tun_routing(&self, external: &str) -> anyhow::Result<()> {
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
