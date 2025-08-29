use anyhow::{Context, Result};
use bytes::BytesMut;
use futures::StreamExt;
use log::{error, info};
use packet::{Error, ip::Packet};
use std::net::Ipv4Addr;
use tokio_util::{
    codec::{Decoder, FramedRead},
    sync::CancellationToken,
};
use tun::Configuration;

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

pub struct TunManager {
    params: TunParams,
}

impl TunManager {
    pub fn new() -> Self {
        Self {
            params: TunParams::default(),
        }
    }

    pub fn set_ip_address(&mut self, ip_address: &str) -> Result<()> {
        let address: Ipv4Addr = ip_address.parse().context("Invalid IP address format")?;

        self.params.address = Some(address);
        self.params.netmask = Some(Ipv4Addr::new(255, 255, 255, 0));
        self.params.destination = Some(Ipv4Addr::new(10, 0, 0, 1));

        Ok(())
    }

    fn create_config(&self) -> Result<Configuration> {
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

        #[cfg(target_os = "windows")]
        {
            config = config.platform_config(|config| {
                use uuid::Uuid;
                let guid = Uuid::new_v4().to_u128_le();
                config.device_guid(guid);
            });
        }

        Ok(config.clone())
    }

    pub async fn start_processing(&mut self, token: CancellationToken) -> Result<()> {
        if self.params.address.is_none() {
            return Err(anyhow::anyhow!(
                "IP address must be set before starting processing"
            ));
        }

        let config = self.create_config()?;
        let async_dev =
            tun::create_as_async(&config).context("Failed to create async TUN device")?;

        let mut stream = FramedRead::new(async_dev, IPPacketCodec);

        info!("Starting TUN packet processing on client...");
        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    info!("Shutting down TUN processing...");
                    break;
                }
                packet = stream.next() => {
                    match packet {
                        Some(Ok(pkt)) => {
                            info!("Client received packet: {:?}", pkt);
                        }
                        Some(Err(err)) => {
                            error!("Error reading packet: {:?}", err);
                        }
                        None => {
                            break;
                        }
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
    type Item = Packet<BytesMut>;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.is_empty() {
            return Ok(None);
        }

        let buf = buf.split_to(buf.len());
        Ok(match Packet::no_payload(buf) {
            Ok(pkt) => Some(pkt),
            Err(err) => {
                error!("error {err:?}");
                None
            }
        })
    }
}
