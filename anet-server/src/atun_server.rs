use anet_common::codecs::RawIpCodec;
use anet_common::tun_params::TunParams;
use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use log::{debug, error, info};
use std::net::Ipv4Addr;
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio_util::codec::Framed;
use tun::{AsyncDevice, Configuration};

pub struct TunManager {
    params: TunParams,
    network: Ipv4Addr,
}

impl TunManager {
    pub fn new(params: TunParams, network: Ipv4Addr) -> Self {
        Self { params, network }
    }

    fn create_config(&self) -> Result<Configuration> {
        let mut binding = Configuration::default();
        let mut config = binding
            .tun_name(&self.params.name)
            .mtu(self.params.mtu)
            .up();

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

        let framed = Framed::new(async_dev, RawIpCodec::new());
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
                        if let Err(e) = tx_from_tun.send(pkt).await {
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

    pub async fn setup_tun_routing(&self, external: &str) -> anyhow::Result<()> {
        // Включаем форвардинг пакетов
        Command::new("sysctl")
            .arg("-w")
            .arg("net.ipv4.ip_forward=1")
            .spawn()?
            .wait()
            .await?;

        // Чистим старые правила
        Command::new("iptables")
            .args(&[
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-o",
                external,
                "-j",
                "MASQUERADE",
            ])
            .spawn()
            .ok(); // игнорим ошибку если правила ещё нет

        // Добавляем MASQUERADE
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
            .spawn()?
            .wait()
            .await?;

        // Разрешаем форвардинг tun→eth
        Command::new("iptables")
            .args(&[
                "-A",
                "FORWARD",
                "-i",
                self.params.name.as_str(),
                "-o",
                external,
                "-j",
                "ACCEPT",
            ])
            .spawn()?
            .wait()
            .await?;

        // Разрешаем форвардинг eth→tun
        Command::new("iptables")
            .args(&[
                "-A",
                "FORWARD",
                "-i",
                external,
                "-o",
                self.params.name.as_str(),
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ])
            .spawn()?
            .wait()
            .await?;
        // явное указание маршрута для VPN подсети
        let prefix = self.netmask_to_prefix(self.params.netmask)?;
        let net = format!("{}/{}", self.network, prefix);
        Command::new("ip")
            .args(&[
                "route",
                "replace",
                net.as_str(),
                "dev",
                self.params.name.as_str(),
            ])
            .spawn()?
            .wait()
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
