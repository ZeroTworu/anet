use crate::consts::{CHANNEL_BUFFER_SIZE, MAX_PACKET_SIZE};
use crate::tun_params::TunParams;
use anyhow::{Context, Result};
use bytes::Bytes;
use log::{error, info};
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::mpsc;
use tun::Configuration;

#[derive(Clone)]
pub struct TunManager {
    params: TunParams,
}

impl TunManager {
    pub fn new(params: TunParams) -> Self {
        Self { params }
    }

    fn create_config(&self) -> Result<Configuration> {
        let mut binding = Configuration::default();
        let config = binding
            .tun_name(&self.params.name)
            .mtu(self.params.mtu)
            .up()
            .address(self.params.address)
            .netmask(self.params.netmask)
            .destination(self.params.gateway);
        Ok(config.clone())
    }

    pub async fn run(&self) -> Result<(mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>)> {
        let config = self.create_config()?;
        let device = tun::create_as_async(&config).context("Failed to create async TUN device")?;

        info!("Created TUN [{}]", self.get_info());


        let (mut reader, mut writer) = tokio::io::split(device);

        let (tx_to_tun, mut rx_to_tun) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
        let (tx_from_tun, rx_from_tun) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);

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
                        match tx_from_tun.send(packet).await {
                            Ok(_) => {},
                            Err(e) => {
                                error!("Failed send to channel, error: {}", e);
                                break
                            },
                        }
                    }
                    Err(e) => {
                        error!("Failed to read from TUN: {}", e);
                        break;
                    }
                }
            }
        });

        tokio::spawn(async move {
            while let Some(packet) = rx_to_tun.recv().await {
                if let Err(e) = writer.write_all(&packet).await {
                    error!("Failed to write to TUN: {}", e);
                    break;
                }
            }
        });

        Ok((tx_to_tun, rx_from_tun))
    }

    pub fn get_info(&self) -> String {
        format!(
            "Address: {}, Netmask: {}, Destination: {}, Name: {}, MTU: {}",
            self.params.address,
            self.params.netmask,
            self.params.gateway,
            self.params.name,
            self.params.mtu
        )
    }

    // Нагенерено нейронкой
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
        let prefix = self.netmask_to_prefix(self.params.netmask)?;
        let net = format!("{}/{}", self.params.network.unwrap(), prefix);
        Command::new("ip")
            .args(&["route", "replace", &net, "dev", &self.params.name])
            .status()
            .await?;
        info!("IP routing configured successfully");
        Ok(())
    }

    /// Преобразует маску в формате Ipv4Addr в префикс CIDR
    fn netmask_to_prefix(&self, netmask: Ipv4Addr) -> Result<u8, anyhow::Error> {
        let octets = netmask.octets();
        let mask = u32::from_be_bytes(octets);

        // Проверяем что маска валидна (последовательность единиц followed by нулей)
        if !self.is_valid_netmask(mask) {
            return Err(anyhow::anyhow!("Invalid netmask: {}", netmask));
        }

        // Считаем количество установленных битов
        Ok(mask.count_ones() as u8)
    }

    /// Проверяет что маска является валидной сетевой маской
    fn is_valid_netmask(&self, mask: u32) -> bool {
        // Маска должна быть последовательностью единиц followed by нулей
        let inverted = !mask;
        inverted & (inverted + 1) == 0
    }
}
