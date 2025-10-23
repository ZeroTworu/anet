use anet_common::consts::MAX_PACKET_SIZE;
use anet_common::protocol::AuthResponse;
use anet_common::tun_params::TunParams;
use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use log::{error, info};
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tun::{AsyncDevice, Configuration};

#[derive(Clone)]
pub struct TunManager {
    pub params: TunParams,
    pub is_set: bool,
}

impl TunManager {
    pub fn new() -> Self {
        Self {
            params: TunParams::default_client(),
            is_set: false,
        }
    }

    pub fn set_ip_network_params(&mut self, params: &AuthResponse) -> Result<()> {
        let address: Ipv4Addr = params.ip.parse().context("Invalid IP address format")?;
        let netmask: Ipv4Addr = params
            .netmask
            .parse()
            .context("Invalid NETMASK address format")?;
        let gateway: Ipv4Addr = params
            .gateway
            .parse()
            .context("Invalid GATEWAY address format")?;
        self.params.address = address;
        self.params.netmask = netmask;
        self.params.gateway = gateway;
        self.params.mtu = params.mtu as u16;
        self.is_set = true;
        Ok(())
    }

    fn create_config(&self) -> Configuration {
        let mut binding = Configuration::default();
        let mut config = binding
            .tun_name(&self.params.name)
            .mtu(self.params.mtu)
            .up();

        config = config.address(&self.params.address);
        config = config.netmask(&self.params.netmask);
        config = config.destination(&self.params.gateway);

        #[cfg(windows)]
        {
            config = config.ring_capacity(67108864);
        }

        config.clone()
    }

    pub fn create_as_async(&self) -> AsyncDevice {
        let config = self.create_config();
        match tun::create_as_async(&config) {
            Ok(dev) => {
                info!("TUN Device created.");
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
        tx_to_tls: mpsc::Sender<Bytes>,
        mut rx_to_tun: mpsc::Receiver<Bytes>,
    ) -> Result<()> {
        info!("{}", self.get_info());

        let async_dev = self.create_as_async();
        let (mut tun_reader, mut tun_writer) = tokio::io::split(async_dev);

        // Задача для чтения из TUN и отправки в сеть
        tokio::spawn({
            let tx_to_tls = tx_to_tls.clone();
            async move {
                let mut buffer = BytesMut::with_capacity(MAX_PACKET_SIZE);
                loop {
                    match tun_reader.read_buf(&mut buffer).await {
                        Ok(n) => {
                            if n > 0 {
                                let packet = buffer.split_to(n).freeze();
                                if let Err(e) = tx_to_tls.send(packet).await {
                                    error!("Error TUN -> TLS: {:?}", e);
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to read from TUN: {}", e);
                            break;
                        }
                    }
                }
            }
        });

        // Задача для записи в TUN из сети
        tokio::spawn(async move {
            loop {
                match rx_to_tun.recv().await {
                    Some(packet) => {
                        if let Err(e) = tun_writer.write_all(&packet).await {
                            error!("Error TLS -> TUN: {:?}", e);
                            break;
                        }
                    }
                    None => {
                        break;
                    }
                }
            }
        });

        info!("Starting TUN packet processing on client...");
        Ok(())
    }

    pub fn get_info(&self) -> String {
        format!(
            "Address: {:?}, Netmask: {:?}, Destination: {:?}, Name: {}, MTU: {}",
            self.params.address,
            self.params.netmask,
            self.params.gateway,
            self.params.name,
            self.params.mtu
        )
    }
}
