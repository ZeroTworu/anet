use anyhow::{Context, Result};
use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use log::{debug, error, info};
use packet::{Error, ip::Packet as IpPacket};
use std::net::Ipv4Addr;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio_util::codec::{Decoder, Encoder, Framed};
use tun::{AsyncDevice, Configuration};
use anet_common::protocol::AssignedIp;

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
        let netmask: Ipv4Addr = params.netmask.parse().context("Invalid NETMASK address format")?;
        let gateway: Ipv4Addr = params.gateway.parse().context("Invalid GATEWAY address format")?;

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

        #[cfg(target_os = "linux")]
        {
            config = config.platform_config(|config| {
                config.ensure_root_privileges(true);
            });
        }

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
                info!("Device created");
                dev
            }
            Err(e) => {
                error!("Error creating device {:?}", e);
                panic!("Error creating device {:?}", e)
            }
        }
    }

    pub async fn start_processing(
        &mut self,
        tx_to_tls: mpsc::Sender<Vec<u8>>,
        mut rx_from_tun: mpsc::Receiver<Vec<u8>>,
    ) -> Result<()> {
        if self.params.address.is_none() {
            return Err(anyhow::anyhow!(
                "IP address must be set before starting processing"
            ));
        }

        let mut async_dev = self.create_as_async();
        let mut read_buf = vec![0u8; 65536]; // Буфер 64K

        info!("Starting TUN packet processing on client...");

        loop {
            tokio::select! {
            result = async_dev.read(&mut read_buf) => {
                match result {
                    Ok(n) => {
                        let packet = read_buf[..n].to_vec();
                        if let Err(e) = tx_to_tls.send(packet).await {
                            error!("Failed to send to TLS channel: {}", e);
                            break;
                        }
                        debug!("TUN -> TLS");
                    }
                    Err(err) => {
                        error!("Error reading from TUN: {:?}", err);
                        break;
                    }
                }
            }
            packet = rx_from_tun.recv() => {
                match packet {
                    Some(pkt) => {
                        debug!("TLS -> TUN");
                        if let Err(e) = async_dev.send(&pkt).await {
                            error!("TLS -> TUN: {}", e);
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
        }

        Ok(())
    }

    pub fn get_info(&self) -> String {
        format!(
            "Address: {:?}, Netmask: {:?}, Destination: {:?}, Name: {}, MTU: {}",
            self.params.address,
            self.params.netmask,
            self.params.destination,
            self.params.name,
            self.params.mtu
        )
    }
}

pub struct IPPacketCodec;

impl Decoder for IPPacketCodec {
    type Item = IpPacket<BytesMut>;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.is_empty() {
            return Ok(None);
        }

        let buf = buf.split_to(buf.len());
        Ok(match IpPacket::no_payload(buf) {
            Ok(pkt) => Some(pkt),
            Err(err) => {
                error!("error {err:?}");
                None
            }
        })
    }
}

impl Encoder<Vec<u8>> for IPPacketCodec {
    type Error = Error;

    fn encode(&mut self, item: Vec<u8>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.extend_from_slice(&item);
        Ok(())
    }
}
