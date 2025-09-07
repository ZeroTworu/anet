use anyhow::{Context, Result};
use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use log::{debug, error, info};
use packet::{Error, ip::Packet as IpPacket};
use std::net::Ipv4Addr;
use tokio::sync::mpsc;
use tokio_util::codec::{Decoder, Encoder, Framed};
use tun::{AsyncDevice, Configuration};
use tokio::process::Command;

#[derive(Clone)]
pub struct TunParams {
    pub address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub name: String,
    pub mtu: u16,
}

impl Default for TunParams {
    fn default() -> Self {
        Self {
            address: Ipv4Addr::new(10, 0, 0, 2),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            name: "anet-server".to_string(),
            mtu: 1500,
        }
    }
}

pub struct TunManager {
    params: TunParams,
}

impl TunManager {
    pub fn new() -> Self {
        Self { params: TunParams::default() }
    }
    
    pub fn new_with_params(params: TunParams) -> Self {
        Self { params }
    }

    fn create_config(&self) -> Result<Configuration> {
        let mut binding = Configuration::default();
        let mut config = binding.tun_name(&self.params.name).mtu(self.params.mtu).up();

        config = config.address(self.params.address);
        config = config.netmask(self.params.netmask);
        config = config.destination(self.params.gateway);

        #[cfg(target_os = "linux")]
        {
            config = config.platform_config(|config| {
                config.ensure_root_privileges(true);
            });
        }

        Ok(config.clone())
    }
    
    pub async fn run(&self) -> Result<(mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>)> {
        let config = self.create_config()?;
        let async_dev: AsyncDevice =
            tun::create_as_async(&config).context("Failed to create async TUN device")?;

        let framed = Framed::new(async_dev, IPPacketCodec);
        let (mut sink, mut stream) = framed.split();


        let (tx_to_tun, mut rx_to_tun) = mpsc::channel::<Vec<u8>>(1024);

        let (tx_from_tun, rx_from_tun) = mpsc::channel::<Vec<u8>>(1024);

        tokio::spawn(async move {
            while let Some(pkt) = rx_to_tun.recv().await {
                debug!("TLS -> TUN");
                if let Err(e) = sink.send(pkt).await {
                    error!("Failed to write to TUN: {e}");
                }
            }
        });


        tokio::spawn(async move {
            info!("Starting TUN packet processing on server...");
            while let Some(item) = stream.next().await {
                match item {
                    Ok(pkt) => {
                        debug!("TUN -> TLS");
                        let raw = pkt.as_ref().to_vec();
                        if let Err(e) = tx_from_tun.send(raw).await {
                            error!("Failed to deliver packet from TUN: {e}");
                            break;
                        }
                    }
                    Err(err) => error!("Error reading packet from TUN: {err:?}"),
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

    pub async fn setup_tun_routing(tun: &str, external: &str) -> anyhow::Result<()> {
        // Включаем форвардинг пакетов
        Command::new("sysctl")
            .arg("-w")
            .arg("net.ipv4.ip_forward=1")
            .spawn()?
            .wait()
            .await?;

        // Чистим старые правила
        Command::new("iptables")
            .args(&["-t", "nat", "-D", "POSTROUTING", "-o", external, "-j", "MASQUERADE"])
            .spawn()
            .ok(); // игнорим ошибку если правила ещё нет

        // Добавляем MASQUERADE
        Command::new("iptables")
            .args(&["-t", "nat", "-A", "POSTROUTING", "-o", external, "-j", "MASQUERADE"])
            .spawn()?
            .wait()
            .await?;

        // Разрешаем форвардинг tun→eth
        Command::new("iptables")
            .args(&["-A", "FORWARD", "-i", tun, "-o", external, "-j", "ACCEPT"])
            .spawn()?
            .wait()
            .await?;

        // Разрешаем форвардинг eth→tun
        Command::new("iptables")
            .args(&["-A", "FORWARD", "-i", external, "-o", tun, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
            .spawn()?
            .wait()
            .await?;

        Ok(())
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
                // Log и пропускаем битый фрейм
                info!("decode error {err:?}");
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
