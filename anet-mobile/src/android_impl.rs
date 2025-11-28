use anet_client_core::traits::{RouteManager, TunFactory};
use anet_common::consts::{CHANNEL_BUFFER_SIZE, MAX_PACKET_SIZE};
use anet_common::protocol::AuthResponse;
use anyhow::Result;
use bytes::Bytes;
use jni::JavaVM;
use jni::objects::{GlobalRef, JValue};
use log::error;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tun::Configuration;

pub struct AndroidCallbackTunFactory {
    jvm: Arc<JavaVM>,
    vpn_service_ref: GlobalRef,
}

impl AndroidCallbackTunFactory {
    pub fn new(jvm: Arc<JavaVM>, vpn_service_ref: GlobalRef) -> Self {
        Self {
            jvm,
            vpn_service_ref,
        }
    }
}

#[async_trait::async_trait]
impl TunFactory for AndroidCallbackTunFactory {
    async fn create_tun(
        &self,
        auth: &AuthResponse,
    ) -> Result<(mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>, String)> {
        let mut env = self.jvm.attach_current_thread()?;

        let ip_jstr = env.new_string(&auth.ip)?;
        let mtu_jint = auth.mtu as i32;
        // Простой парсинг префикса (для 255.255.255.0 -> 24)
        let prefix = ip_mask_to_prefix(&auth.netmask)?;

        // Вызываем наш Java метод configureTun
        let fd_val = env.call_method(
            &self.vpn_service_ref,
            "configureTun",
            "(Ljava/lang/String;II)I",
            &[
                JValue::Object(&ip_jstr),
                JValue::Int(prefix as i32),
                JValue::Int(mtu_jint),
            ],
        )?;

        let fd = fd_val.i()?;
        if fd < 0 {
            return Err(anyhow::anyhow!("Java returned invalid FD"));
        }

        // Создаем Tokio File из FD
        let mut config = Configuration::default();
        // Важно: передаем raw_fd. В unix системах это i32 (RawFd)
        config.raw_fd(fd);

        // Настройки IP/MTU уже применены Java, но rust-tun может захотеть их знать
        // для своих внутренних структур. Передадим на всякий случай, хотя для raw_fd
        // он обычно не дергает ioctl.
        config.address(auth.ip.parse::<Ipv4Addr>()?);
        config.netmask(auth.netmask.parse::<Ipv4Addr>()?);
        config.mtu(auth.mtu as u16);
        config.up(); // На всякий случай

        // 3. Создаем Async Device
        let device = tun::create_as_async(&config)
            .map_err(|e| anyhow::anyhow!("Failed to create async TUN: {}", e))?;

        // 4. Разделяем (split)
        let (mut reader, mut writer) = tokio::io::split(device);

        // 5. Каналы и циклы (как было)
        let (tx_to_core, rx_from_tun) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
        let (tx_to_tun, mut rx_from_core) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);

        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET_SIZE];
            loop {
                match reader.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        let packet = Bytes::copy_from_slice(&buf[..n]);
                        if tx_to_core.send(packet).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        error!("TUN Read Error: {}", e);
                        break;
                    }
                }
            }
        });

        tokio::spawn(async move {
            while let Some(pkt) = rx_from_core.recv().await {
                match writer.write_all(&pkt).await {
                    Ok(_) => {}
                    Err(e) => {
                        error!("TUN Write Error: {}", e);
                        break;
                    }
                }
            }
        });

        Ok((tx_to_tun, rx_from_tun, "tun0".to_string()))
    }
}

fn ip_mask_to_prefix(mask_str: &str) -> Result<u8> {
    let mask: Ipv4Addr = mask_str.parse()?;
    Ok(u32::from(mask).count_ones() as u8)
}

// NoOp
pub struct AndroidRouteManager;
impl RouteManager for AndroidRouteManager {
    fn backup_routes(&self) -> Result<()> {
        Ok(())
    }
    fn add_exclusion_route(&self, _server_ip: &str) -> Result<()> {
        Ok(())
    }
    fn set_default_route(&self, _g: &str, _i: &str) -> Result<()> {
        Ok(())
    }
    fn restore_routes(&self) -> Result<()> {
        Ok(())
    }
}
