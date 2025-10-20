use anet_common::consts::{CHANNEL_BUFFER_SIZE, MAX_PACKET_SIZE};
use anet_common::tun_params::TunParams;
use anyhow::{Context, Result};
use log::{error, info};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use tokio::process::Command;
use tokio::sync::mpsc;
use tun:: Configuration;
use bytes::Bytes;
use tokio_uring::net::UnixStream;
use std::os::unix::io::FromRawFd;

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


        config = config.platform_config(|config| {
            config.ensure_root_privileges(true);
        });


        Ok(config.clone())
    }

    pub async fn run(&self) -> Result<(mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>)> {
        info!("Starting TUN packet processing on server with io_uring...");

        let config = self.create_config()?;
        let tun_device = tun::create(&config).context("Failed to create TUN device")?;
        let tun_fd = tun_device.as_raw_fd();

        let (tx_to_tun, rx_to_tun) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
        let (tx_from_tun, rx_from_tun) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);

        let reader_stream = unsafe { UnixStream::from_raw_fd(libc::dup(tun_fd)) };
        let writer_stream = unsafe { UnixStream::from_raw_fd(libc::dup(tun_fd)) };

        tokio_uring::spawn(Self::tun_reader_task(reader_stream, tx_from_tun));
        tokio_uring::spawn(Self::tun_writer_task(writer_stream, rx_to_tun));

        Ok((tx_to_tun, rx_from_tun))
    }

    async fn tun_reader_task(stream: UnixStream, tx_from_tun: mpsc::Sender<Bytes>) {
        loop {
            let buffer = vec![0u8; MAX_PACKET_SIZE];
            let (res, buf) = stream.read(buffer).await;
            match  res {
                Ok(n) => {
                    if n > 0 {
                        let packet = Bytes::copy_from_slice(&buf[..n]);
                        if let Err(e) = tx_from_tun.send(packet).await {
                            error!("Failed to send packet from TUN: {}", e);
                            break;
                        }
                    }
                }
                Err(e) => {
                    error!("Error reading from TUN: {}", e);
                    break;
                }
            }
        }
    }

    async fn tun_writer_task(stream: UnixStream, mut rx_to_tun: mpsc::Receiver<Bytes>) {
        while let Some(packet) = rx_to_tun.recv().await {
            let (res, _) = stream.write_all(packet.to_vec()).await;
            match res  {
                Err(e) => {
                    error!("Error writing to TUN: {}", e);
                    break;
                },
                Ok(_) => {}

            }
        }
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

        // ОЧИСТКА всех старых правил
        let _ = Command::new("iptables")
            .args(&["-F"])
            .spawn()?.wait().await?;

        let _ = Command::new("iptables")
            .args(&["-t", "nat", "-F"])
            .spawn()?.wait().await?;

        // Устанавливаем политики по умолчанию
        Command::new("iptables")
            .args(&["-P", "INPUT", "ACCEPT"])
            .spawn()?.wait().await?;

        Command::new("iptables")
            .args(&["-P", "FORWARD", "ACCEPT"])
            .spawn()?.wait().await?;

        Command::new("iptables")
            .args(&["-P", "OUTPUT", "ACCEPT"])
            .spawn()?.wait().await?;

        // Добавляем MASQUERADE
        Command::new("iptables")
            .args(&[
                "-t", "nat", "-A", "POSTROUTING",
                "-o", external,
                "-j", "MASQUERADE"
            ])
            .spawn()?
            .wait()
            .await?;

        // Разрешаем форвардинг tun→eth
        Command::new("iptables")
            .args(&[
                "-A", "FORWARD",
                "-i", self.params.name.as_str(),
                "-o", external,
                "-j", "ACCEPT"
            ])
            .spawn()?
            .wait()
            .await?;

        // Разрешаем форвардинг eth→tun (только ответные пакеты)
        Command::new("iptables")
            .args(&[
                "-A", "FORWARD",
                "-i", external,
                "-o", self.params.name.as_str(),
                "-j", "ACCEPT"
            ])
            .spawn()?
            .wait()
            .await?;

        // Явное указание маршрута для VPN подсети
        let prefix = self.netmask_to_prefix(self.params.netmask)?;
        let net = format!("{}/{}", self.network, prefix);
        Command::new("ip")
            .args(&[
                "route", "replace", net.as_str(),
                "dev", self.params.name.as_str()
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
