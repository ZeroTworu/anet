use anet_common::consts::MAX_PACKET_SIZE;
use anet_common::protocol::AuthResponse;
use anet_common::tun_params::TunParams;
use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use log::{error, info, debug};
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::sync::broadcast;
use tun::Configuration;

#[derive(Clone)]
pub struct TunManager {
    pub params: TunParams,
    pub is_set: bool,
    stop_sender: Option<broadcast::Sender<()>>,
}

impl TunManager {
    pub fn new() -> Self {
        Self {
            params: TunParams::default_client(),
            is_set: false,
            stop_sender: None,
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

    pub async fn start_processing(
        &mut self,
        tx_to_tls: mpsc::Sender<Bytes>,
        mut rx_to_tun: mpsc::Receiver<Bytes>,
    ) -> Result<()> {
        info!("{}", self.get_info());
        let config = self.create_config();

        let async_dev = tun::create_as_async(&config)?;
        let (mut tun_reader, mut tun_writer) = tokio::io::split(async_dev);

        // Создаем канал для остановки
        let (stop_tx, _) = broadcast::channel(1);
        self.stop_sender = Some(stop_tx.clone());

        // Задача для чтения из TUN и отправки в сеть
        let mut stop_rx_reader = stop_tx.subscribe();
        let reader_handle = tokio::spawn({
            let tx_to_tls = tx_to_tls.clone();
            async move {
                let mut buffer = BytesMut::with_capacity(MAX_PACKET_SIZE);
                loop {
                    tokio::select! {
                        result = tun_reader.read_buf(&mut buffer) => {
                            match result {
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
                        _ = stop_rx_reader.recv() => {
                            debug!("Stop signal received in TUN reader");
                            break;
                        }
                    }
                }
                debug!("TUN reader task finished");
            }
        });

        // Задача для записи в TUN из сети
        let mut stop_rx_writer = stop_tx.subscribe();
        let writer_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    packet = rx_to_tun.recv() => {
                        match packet {
                            Some(packet) => {
                                if let Err(e) = tun_writer.write_all(&packet).await {
                                    error!("Error TLS -> TUN: {:?}", e);
                                    break;
                                }
                            }
                            None => {
                                debug!("TUN writer channel closed");
                                break;
                            }
                        }
                    }
                    _ = stop_rx_writer.recv() => {
                        debug!("Stop signal received in TUN writer");
                        break;
                    }
                }
            }
            debug!("TUN writer task finished");
        });

        // Задача для мониторинга завершения работы
        tokio::spawn(async move {
            let _ =tokio::join!(reader_handle, writer_handle);
            info!("Both TUN tasks finished");
        });

        info!("Starting TUN packet processing on client...");
        Ok(())
    }

    pub fn shutdown(&mut self) {
        if let Some(stop_tx) = &self.stop_sender {
            let _ = stop_tx.send(());
            debug!("Sent shutdown signal to TUN tasks");
        }
        self.stop_sender = None;
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