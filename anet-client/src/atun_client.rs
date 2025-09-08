use anet_common::protocol::AssignedIp;
use anyhow::{Context, Result};
use log::{debug, error, info};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tun::{AsyncDevice, Configuration};

#[derive(Clone)]
pub struct TunParams {
    pub address: Option<Ipv4Addr>,
    pub netmask: Option<Ipv4Addr>,
    pub destination: Option<Ipv4Addr>,
    pub name: String,
    pub mtu: u16,
}

impl Default for TunParams {
    fn default() -> Self {
        Self {
            address: None,
            netmask: None,
            destination: None,
            name: "anet-client".to_string(),
            mtu: 1500,
        }
    }
}

#[derive(Clone)]
pub struct TunManager {
    params: TunParams,
}

impl TunManager {
    pub fn new() -> Self {
        Self {
            params: TunParams::default(),
        }
    }

    pub fn set_ip_network_params(&mut self, params: &AssignedIp) -> Result<()> {
        let address: Ipv4Addr = params.ip.parse().context("Invalid IP address format")?;
        let netmask: Ipv4Addr = params
            .netmask
            .parse()
            .context("Invalid NETMASK address format")?;
        let gateway: Ipv4Addr = params
            .gateway
            .parse()
            .context("Invalid GATEWAY address format")?;

        self.params.address = Some(address);
        self.params.netmask = Some(netmask);
        self.params.destination = Some(gateway);

        Ok(())
    }

    fn create_config(&self) -> Configuration {
        let mut binding = Configuration::default();
        let mut config = binding
            .tun_name(&self.params.name)
            .mtu(self.params.mtu)
            .up();

        if let Some(address) = self.params.address {
            config = config.address(address);
        }

        if let Some(netmask) = self.params.netmask {
            config = config.netmask(netmask);
        }

        if let Some(destination) = self.params.destination {
            config = config.destination(destination);
        }

        config.clone()
    }

    pub fn create_as_async(&self) -> AsyncDevice {
        let config = self.create_config();
        match tun::create_as_async(&config) {
            Ok(dev) => {
                info!("Device created");
                dev
            }
            Err(e) => {
                error!("Error creating device {:?}", e);
                panic!("Error creating device")
            }
        }
    }

    pub async fn start_processing(
        &mut self,
        tx_to_tls: mpsc::Sender<Vec<u8>>,
        mut rx_to_tun: mpsc::Receiver<Vec<u8>>,
    ) -> Result<()> {
        if self.params.address.is_none() {
            return Err(anyhow::anyhow!(
                "IP address must be set before starting processing"
            ));
        }

        let async_dev = Arc::new(self.create_as_async());
        let mut buffer = vec![0u8; 65536 * 10]; // 640KB буфер
        let cloned_async_dev = async_dev.clone();

        tokio::spawn(async move {
            loop {
                match async_dev.recv(&mut buffer).await {
                    Ok(n) => {
                        let packet = buffer[..n].to_vec();
                        if let Err(e) = tx_to_tls.send(packet).await {
                            error!("Failed to send to TLS channel: {}", e);
                            break;
                        }
                        debug!("TUN -> TLS: {} bytes", n);
                    }
                    Err(err) => {
                        error!("Error reading from TUN: {:?}", err);
                        break;
                    }
                }
            }
        });

        tokio::spawn(async move {
            loop {
                let packet = rx_to_tun.recv().await;
                match packet {
                    Some(pkt) => {
                        debug!("TLS -> TUN: {} bytes", pkt.len());
                        if let Err(e) = cloned_async_dev.send(&pkt).await {
                            error!("TLS -> TUN: {}", e);
                            break;
                        }
                    }
                    None => break,
                }
            }
        });

        info!("Starting TUN packet processing on client...");

        Ok(())
    }

    pub fn get_info(&self) -> String {
        format!(
            "Address: {:?}, Netmask: {:?}, Destination: {:?}, Name: {}, MTU: {}",
            self.params.address.unwrap(),
            self.params.netmask.unwrap(),
            self.params.destination.unwrap(),
            self.params.name,
            self.params.mtu
        )
    }
}
