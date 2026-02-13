use anet_client_core::config::CoreConfig;
use anet_client_core::traits::TunFactory;
use anet_common::consts::{CHANNEL_BUFFER_SIZE, MAX_PACKET_SIZE};
use anet_common::protocol::AuthResponse;
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use ipnet::{IpNet, Ipv4Net};
use jni::JavaVM;
use jni::objects::{GlobalRef, JValue};
use log::info;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::lookup_host;
use tokio::sync::mpsc;
use tun::Configuration;

pub struct AndroidCallbackTunFactory {
    jvm: Arc<JavaVM>,
    vpn_service_ref: GlobalRef,
    config: CoreConfig,
}

impl AndroidCallbackTunFactory {
    pub fn new(jvm: Arc<JavaVM>, vpn_service_ref: GlobalRef, config: CoreConfig) -> Self {
        Self {
            jvm,
            vpn_service_ref,
            config,
        }
    }

    /// Резолвит строки конфига в вектор IpNet
    async fn resolve_to_ipnet(&self, list: &[String]) -> Vec<IpNet> {
        let mut result = Vec::new();
        for target in list {
            // 1. CIDR
            if let Ok(net) = target.parse::<IpNet>() {
                result.push(net);
                continue;
            }
            // 2. IP
            if let Ok(ip) = target.parse::<IpAddr>() {
                result.push(IpNet::from(ip));
                continue;
            }
            // 3. DNS
            let target_with_port = format!("{}:443", target);
            if let Ok(addrs) = lookup_host(&target_with_port).await {
                for addr in addrs {
                    result.push(IpNet::from(addr.ip()));
                }
            }
        }
        result
    }

    /// Превращает вектор IpNet в строку для Java
    fn ipnet_list_to_string(list: &[IpNet]) -> String {
        list.iter()
            .map(|n| format!("{}/{}", n.addr(), n.prefix_len()))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Вычитает исключения из 0.0.0.0/0
    fn calculate_fallback_routes(exclusions: &[IpNet]) -> Vec<IpNet> {
        if exclusions.is_empty() {
            // Если исключений нет, fallback не нужен (будет 0.0.0.0/0 в логике Java)
            // Но для корректности вернем полный мир, чтобы Java просто применила его.
            return vec![IpNet::V4(Ipv4Net::default())];
        }

        // Начинаем с полного мира IPv4
        let mut world = vec![IpNet::V4(Ipv4Net::default())]; // 0.0.0.0/0

        for exclude in exclusions {
            let mut new_world = Vec::new();

            for subnet in world {
                // Если исключение внутри этой подсети - разбиваем подсеть
                if subnet.contains(exclude) {
                    // Разбиваем subnet на части, исключая exclude
                    let sub_list = subnet_diff(subnet, *exclude);
                    new_world.extend(sub_list);
                } else if exclude.contains(&subnet) {
                    // Если подсеть полностью внутри исключения - удаляем её (не добавляем в new_world)
                    continue;
                } else {
                    // Не пересекаются - оставляем как есть
                    new_world.push(subnet);
                }
            }
            world = new_world;
        }
        world
    }
}

/// Вычитает `exclude` из `include`. Возвращает список подсетей.
/// Пример: 0.0.0.0/0 - 128.0.0.0/1 = [0.0.0.0/1]
fn subnet_diff(include: IpNet, exclude: IpNet) -> Vec<IpNet> {
    // В ipnet нет встроенного sub_diff, реализуем через разбиение
    if include == exclude {
        return vec![];
    }

    // Если exclude больше чем include или они не пересекаются - это ошибка логики вызова,
    // но вернем исходный.
    if !include.contains(&exclude) {
        return vec![include];
    }

    let mut result = Vec::new();
    let mut current = include;

    // Итеративное разбиение "сверху вниз"
    // Мы берем current (например /0) и бьем его пополам (/1, /1).
    // Одна половина чистая (добавляем в результат), вторая содержит exclude (продолжаем бить).

    while current.prefix_len() < exclude.prefix_len() {
        // subnets() возвращает итератор из 2-х половинок
        let subnets: Vec<IpNet> = current.subnets(current.prefix_len() + 1).unwrap().collect();

        let left = subnets[0];
        let right = subnets[1];

        if left.contains(&exclude) {
            // Исключение слева. Правая часть чистая -> в результат. Левую ломаем дальше.
            result.push(right);
            current = left;
        } else {
            // Исключение справа. Левая часть чистая -> в результат. Правую ломаем дальше.
            result.push(left);
            current = right;
        }
    }

    // В конце цикла current == exclude, мы его просто не добавляем в result.
    result
}

#[async_trait]
impl TunFactory for AndroidCallbackTunFactory {
    async fn create_tun(
        &self,
        auth: &AuthResponse,
    ) -> Result<(mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>, String)> {
        // --- 1. Асинхронная подготовка (БЕЗ JNI) ---

        // Резолвим конфиги в структуры IpNet
        let include_nets = self.resolve_to_ipnet(&self.config.main.route_for).await;
        let exclude_nets = self
            .resolve_to_ipnet(&self.config.main.exclude_route_for)
            .await;

        // Генерация строк
        let include_str = Self::ipnet_list_to_string(&include_nets);
        let exclude_str = Self::ipnet_list_to_string(&exclude_nets);

        // Генерация Fallback (эмуляция exclude для старых Android)
        // Считаем только если есть исключения и нет белого списка
        let fallback_str = if include_nets.is_empty() && !exclude_nets.is_empty() {
            let fallback_nets = Self::calculate_fallback_routes(&exclude_nets);
            Self::ipnet_list_to_string(&fallback_nets)
        } else {
            String::new()
        };

        let dns_str = self.config.main.dns_server_list.join(",");

        info!(
            "Routes Calc: IncludeItems={}, ExcludeItems={}",
            include_nets.len(),
            exclude_nets.len()
        );
        if !fallback_str.is_empty() {
            info!("Fallback generated: contains split routes covering 0.0.0.0/0 minus exclusions");
        }

        // --- 2. JNI ---
        let mut env = self.jvm.attach_current_thread()?;

        let ip_jstr = env.new_string(&auth.ip)?;
        let include_jstr = env.new_string(&include_str)?;
        let exclude_jstr = env.new_string(&exclude_str)?;
        let fallback_jstr = env.new_string(&fallback_str)?;
        let dns_jstr = env.new_string(&dns_str)?;

        let mtu_jint = auth.mtu as i32;
        let prefix = ip_mask_to_prefix(&auth.netmask)?;

        // Обновленная сигнатура: добавлен fallbackRoutes
        // (String, int, int, String, String, String, String) -> int
        let fd_val = env.call_method(
            &self.vpn_service_ref,
            "configureTun",
            "(Ljava/lang/String;IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I",
            &[
                JValue::Object(&ip_jstr),
                JValue::Int(prefix as i32),
                JValue::Int(mtu_jint),
                JValue::Object(&include_jstr),
                JValue::Object(&exclude_jstr),
                JValue::Object(&fallback_jstr),
                JValue::Object(&dns_jstr),
            ],
        )?;

        let fd = fd_val.i()?;
        if fd < 0 {
            return Err(anyhow::anyhow!("Java returned invalid FD"));
        }

        // --- 3. Tun Creation ---
        // (Код создания tun устройства тот же самый)
        let mut config = Configuration::default();
        config.raw_fd(fd);
        if let Ok(ipv4) = auth.ip.parse::<Ipv4Addr>() {
            config.address(ipv4);
        }
        if let Ok(mask) = auth.netmask.parse::<Ipv4Addr>() {
            config.netmask(mask);
        }
        config.mtu(auth.mtu as u16);
        config.up();

        let device = tun::create_as_async(&config)
            .map_err(|e| anyhow::anyhow!("Failed to create async TUN: {}", e))?;

        let (mut reader, mut writer) = tokio::io::split(device);
        let (tx_to_core, rx_from_tun) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
        let (tx_to_tun, mut rx_from_core) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);

        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET_SIZE];
            loop {
                match reader.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        if tx_to_core
                            .send(Bytes::copy_from_slice(&buf[..n]))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(_) => {
                        break;
                    }
                }
            }
        });

        tokio::spawn(async move {
            while let Some(pkt) = rx_from_core.recv().await {
                if writer.write_all(&pkt).await.is_err() {
                    break;
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
