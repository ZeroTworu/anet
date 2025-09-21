use anet_common::consts::{MAX_PACKET_SIZE, PACKETS_TO_YIELD};
use anet_common::protocol::AuthResponse;
use anet_common::tun_params::TunParams;
use anyhow::{Context, Result};
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

    #[inline]
    pub async fn start_processing(
        &mut self,
        tx_to_tls: mpsc::Sender<Vec<u8>>,
        mut rx_to_tun: mpsc::Receiver<Vec<u8>>,
    ) -> Result<()> {
        info!("{}", self.get_info());

        let async_dev = self.create_as_async();
        let (mut tun_reader, mut tun_writer) = tokio::io::split(async_dev);
        // Ссаный костыль из-за windows
        let mut tun_buffer = vec![0u8; MAX_PACKET_SIZE];

        tokio::spawn(async move {
            loop {
                match tun_reader.read(&mut tun_buffer).await {
                    Ok(n) => {
                        if n > 0 {
                            let pkt = tun_buffer[..n].to_vec();
                            if let Err(e) = tx_to_tls.send(pkt).await {
                                error!("Error TUN -> TLS: {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to read from TUN: {}", e);
                        return;
                    }
                }
            }
        });

        tokio::spawn(async move {
            let mut packet_count = 0;
            loop {
                let packet = rx_to_tun.recv().await;
                match packet {
                    Some(pkt) => {
                        if let Err(e) = tun_writer.write_all(&pkt).await {
                            tun_writer.flush().await.unwrap();
                            error!("Error TLS -> TUN: {:?}", e);
                            break;
                        }
                        packet_count += 1;
                        if packet_count >= PACKETS_TO_YIELD {
                            packet_count = 0;
                            tokio::task::yield_now().await;
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
            self.params.address,
            self.params.netmask,
            self.params.gateway,
            self.params.name,
            self.params.mtu
        )
    }
}
