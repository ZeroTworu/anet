use anet_client_core::config::CoreConfig;
use anet_client_core::traits::TunFactory;
use anet_common::consts::{CHANNEL_BUFFER_SIZE, MAX_PACKET_SIZE};
use anet_common::protocol::AuthResponse;
use anyhow::Result;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use ipnet::{IpNet, Ipv4Net};
use jni::JavaVM;
use jni::objects::{GlobalRef, JValue};
use log::{info, warn};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::lookup_host;
use tokio::sync::mpsc;
use tun::Configuration;

static TUN_ACTIVE_FLAG: AtomicBool = AtomicBool::new(false);
static DIRTY_GEN: AtomicU64 = AtomicU64::new(0);
static ACTIVE_TUN: OnceLock<tokio::sync::Mutex<Option<ActiveTunSession>>> = OnceLock::new();

fn active_tun_mutex() -> &'static tokio::sync::Mutex<Option<ActiveTunSession>> {
    ACTIVE_TUN.get_or_init(|| tokio::sync::Mutex::new(None))
}

struct TunSwapRequest {
    ack_prepared: tokio::sync::oneshot::Sender<()>,
    rx_new_device: tokio::sync::oneshot::Receiver<
        Option<(tun::AsyncDevice, tokio::sync::oneshot::Sender<()>)>,
    >,
}

struct ActiveTunSession {
    jvm: Arc<JavaVM>,
    vpn_service_ref: GlobalRef,
    auth: AuthResponse,
    include_nets: Vec<IpNet>,
    user_excludes: Vec<IpNet>,
    base_exclude_nets: Vec<IpNet>,
    dns_str: String,
    bypass_ips: Arc<std::sync::Mutex<Vec<(IpAddr, u8)>>>,
    tx_cmd: mpsc::UnboundedSender<TunSwapRequest>,
    applied_gen: u64,
}

impl ActiveTunSession {
    async fn rebind_tun(&mut self) -> Result<()> {
        let mut exclude_nets = self.base_exclude_nets.clone();
        let bypass_list = self.bypass_ips.lock().unwrap().clone();
        for (ip, prefix) in bypass_list {
            if ip.is_ipv4() {
                if let Ok(net) = IpNet::new(ip, prefix) {
                    if !exclude_nets.contains(&net) {
                        exclude_nets.push(net);
                    }
                }
            }
        }

        let include_str = AndroidCallbackTunFactory::ipnet_list_to_string(&self.include_nets);
        let exclude_str = AndroidCallbackTunFactory::ipnet_list_to_string(&exclude_nets);

        let fallback_str = if self.include_nets.is_empty() && !self.user_excludes.is_empty() {
            let fallback_nets =
                AndroidCallbackTunFactory::calculate_fallback_routes(&self.user_excludes);
            AndroidCallbackTunFactory::ipnet_list_to_string(&fallback_nets)
        } else if self.include_nets.is_empty()
            && !exclude_nets.is_empty()
            && exclude_nets.len() <= 256
        {
            let fallback_nets = AndroidCallbackTunFactory::calculate_fallback_routes(&exclude_nets);
            AndroidCallbackTunFactory::ipnet_list_to_string(&fallback_nets)
        } else {
            String::new()
        };

        // 1. Останавливаем и дропаем старые AsyncFd (reader/writer) до пересоздания TUN в Java
        let (ack_prep_tx, ack_prep_rx) = tokio::sync::oneshot::channel();
        let (tx_new_dev, rx_new_dev) = tokio::sync::oneshot::channel();
        if self
            .tx_cmd
            .send(TunSwapRequest {
                ack_prepared: ack_prep_tx,
                rx_new_device: rx_new_dev,
            })
            .is_err()
        {
            return Ok(());
        }
        let _ = ack_prep_rx.await;

        // 2. Пересоздаём TUN через JNI с обновлённым списком исключений
        let fd = match call_configure_tun_jni(
            &self.jvm,
            &self.vpn_service_ref,
            &self.auth,
            &include_str,
            &exclude_str,
            &fallback_str,
            &self.dns_str,
        ) {
            Ok(fd) => fd,
            Err(e) => {
                let _ = tx_new_dev.send(None);
                return Err(e);
            }
        };

        let new_device = match open_async_tun(fd, &self.auth) {
            Ok(dev) => dev,
            Err(e) => {
                let _ = tx_new_dev.send(None);
                return Err(e);
            }
        };

        // 3. Активируем новый AsyncDevice в I/O-координаторе и ждём готовности
        let (ack_act_tx, ack_act_rx) = tokio::sync::oneshot::channel();
        let _ = tx_new_dev.send(Some((new_device, ack_act_tx)));
        let _ = ack_act_rx.await;

        // Даём netd в Android время применить обновлённые правила маршрутизации до отдачи DNS-ответа
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;

        info!(
            "[Android RouteManager] Hot-updated VpnService TUN exclusions (ExcludeItems={})",
            exclude_nets.len()
        );
        Ok(())
    }
}

pub struct AndroidRouteManager {
    bypass_ips: Arc<std::sync::Mutex<Vec<(IpAddr, u8)>>>,
}

impl AndroidRouteManager {
    pub fn new(bypass_ips: Arc<std::sync::Mutex<Vec<(IpAddr, u8)>>>) -> Self {
        Self { bypass_ips }
    }
}

#[async_trait]
impl anet_client_core::traits::RouteManager for AndroidRouteManager {
    async fn backup_routes(&self) -> Result<()> {
        Ok(())
    }

    async fn add_bypass_route(&self, target: IpAddr, prefix: u8) -> Result<()> {
        self.add_bypass_routes(&[(target, prefix)]).await
    }

    async fn add_bypass_routes(&self, routes: &[(IpAddr, u8)]) -> Result<()> {
        let mut added_new = false;
        {
            let mut list = self.bypass_ips.lock().unwrap();
            for &(target, prefix) in routes {
                if !target.is_ipv4() {
                    continue;
                }
                if !list.contains(&(target, prefix)) {
                    info!(
                        "[Android RouteManager] Recorded bypass route: {}/{}",
                        target, prefix
                    );
                    list.push((target, prefix));
                    added_new = true;
                }
            }
        }

        if added_new {
            DIRTY_GEN.fetch_add(1, Ordering::AcqRel);
        }

        if !TUN_ACTIVE_FLAG.load(Ordering::Acquire) {
            return Ok(());
        }

        if added_new {
            // Коалесцируем параллельные DNS-ответы (например, example.com + static.example.com) в одно обновление TUN
            tokio::time::sleep(std::time::Duration::from_millis(15)).await;
        }

        let mutex = active_tun_mutex();
        let mut guard = mutex.lock().await;
        if let Some(session) = guard.as_mut() {
            let latest_gen = DIRTY_GEN.load(Ordering::Acquire);
            if session.applied_gen < latest_gen {
                session.applied_gen = latest_gen;
                if let Err(e) = session.rebind_tun().await {
                    warn!("[Android RouteManager] Failed to hot-update TUN routes: {e}");
                }
            }
        }

        Ok(())
    }

    async fn set_default_route(&self, _gateway: &str, _interface_name: &str) -> Result<()> {
        Ok(())
    }

    async fn add_specific_route(
        &self,
        _target: IpAddr,
        _prefix: u8,
        _gateway: &str,
        _interface_name: &str,
    ) -> Result<()> {
        Ok(())
    }

    async fn restore_routes(&self) -> Result<()> {
        TUN_ACTIVE_FLAG.store(false, Ordering::Release);
        *active_tun_mutex().lock().await = None;
        self.bypass_ips.lock().unwrap().clear();
        Ok(())
    }
}

pub struct AndroidCallbackTunFactory {
    jvm: Arc<JavaVM>,
    vpn_service_ref: GlobalRef,
    config: CoreConfig,
    bypass_ips: Arc<std::sync::Mutex<Vec<(IpAddr, u8)>>>,
}

impl AndroidCallbackTunFactory {
    pub fn new(
        jvm: Arc<JavaVM>,
        vpn_service_ref: GlobalRef,
        config: CoreConfig,
        bypass_ips: Arc<std::sync::Mutex<Vec<(IpAddr, u8)>>>,
    ) -> Self {
        Self {
            jvm,
            vpn_service_ref,
            config,
            bypass_ips,
        }
    }

    /// Резолвит строки конфига, CIDR или доменов (включая wildcard-шаблоны) в вектор IPv4 IpNet
    async fn resolve_to_ipnet(&self, list: &[String]) -> Vec<IpNet> {
        let mut result = Vec::new();
        for target in list {
            let trimmed = target.trim();
            if trimmed.is_empty() {
                continue;
            }
            // 1. CIDR
            if let Ok(net) = trimmed.parse::<IpNet>() {
                if net.addr().is_ipv4() && !result.contains(&net) {
                    result.push(net);
                }
                continue;
            }
            // 2. IP
            if let Ok(ip) = trimmed.parse::<IpAddr>() {
                if ip.is_ipv4() {
                    let net = IpNet::from(ip);
                    if !result.contains(&net) {
                        result.push(net);
                    }
                }
                continue;
            }
            // 3. Домен или Wildcard (например, "*.example.com", ".example.com", "example.com")
            let clean = trimmed
                .trim_start_matches('*')
                .trim_start_matches('.');
            if clean.is_empty() {
                continue;
            }

            let target_with_port = format!("{}:443", clean);
            if let Ok(addrs) = lookup_host(&target_with_port).await {
                for addr in addrs {
                    if addr.ip().is_ipv4() {
                        let net = IpNet::from(addr.ip());
                        if !result.contains(&net) {
                            result.push(net);
                        }
                    }
                }
            }
        }
        result
    }

    /// Превращает вектор IpNet в строку для Java
    fn ipnet_list_to_string(list: &[IpNet]) -> String {
        list.iter()
            .filter(|n| n.addr().is_ipv4())
            .map(|n| format!("{}/{}", n.addr(), n.prefix_len()))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Вычитает исключения из 0.0.0.0/0
    fn calculate_fallback_routes(exclusions: &[IpNet]) -> Vec<IpNet> {
        if exclusions.is_empty() {
            return vec![IpNet::V4(Ipv4Net::default())];
        }

        let mut world = vec![IpNet::V4(Ipv4Net::default())]; // 0.0.0.0/0

        for exclude in exclusions {
            if !exclude.addr().is_ipv4() {
                continue;
            }
            let mut new_world = Vec::new();

            for subnet in world {
                if subnet.contains(exclude) {
                    let sub_list = subnet_diff(subnet, *exclude);
                    new_world.extend(sub_list);
                } else if exclude.contains(&subnet) {
                    continue;
                } else {
                    new_world.push(subnet);
                }
            }
            world = new_world;
        }
        world
    }
}

/// Вычитает `exclude` из `include`. Возвращает список подсетей.
fn subnet_diff(include: IpNet, exclude: IpNet) -> Vec<IpNet> {
    if include == exclude {
        return vec![];
    }

    if !include.contains(&exclude) {
        return vec![include];
    }

    let mut result = Vec::new();
    let mut current = include;

    while current.prefix_len() < exclude.prefix_len() {
        let subnets: Vec<IpNet> = current.subnets(current.prefix_len() + 1).unwrap().collect();

        let left = subnets[0];
        let right = subnets[1];

        if left.contains(&exclude) {
            result.push(right);
            current = left;
        } else {
            result.push(left);
            current = right;
        }
    }

    result
}

fn call_configure_tun_jni(
    jvm: &Arc<JavaVM>,
    vpn_service_ref: &GlobalRef,
    auth: &AuthResponse,
    include_str: &str,
    exclude_str: &str,
    fallback_str: &str,
    dns_str: &str,
) -> Result<i32> {
    let mut env = jvm.attach_current_thread()?;

    let ip_jstr = env.new_string(&auth.ip)?;
    let include_jstr = env.new_string(include_str)?;
    let exclude_jstr = env.new_string(exclude_str)?;
    let fallback_jstr = env.new_string(fallback_str)?;
    let dns_jstr = env.new_string(dns_str)?;

    // На Android 11+ при наличии IPv6 минимально допустимый MTU для VpnService.Builder равен 1280 (RFC 8200)
    let mtu_jint = (auth.mtu as i32).max(1280);
    let prefix = ip_mask_to_prefix(&auth.netmask)?;

    let fd_val = env.call_method(
        vpn_service_ref,
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
    Ok(fd)
}

fn open_async_tun(fd: i32, auth: &AuthResponse) -> Result<tun::AsyncDevice> {
    let mut config = Configuration::default();
    config.raw_fd(fd);
    // КРИТИЧНО: fd принадлежит Java-стороне (ParcelFileDescriptor в VpnService).
    config.close_fd_on_drop(false);
    if let Ok(ipv4) = auth.ip.parse::<Ipv4Addr>() {
        config.address(ipv4);
    }
    if let Ok(mask) = auth.netmask.parse::<Ipv4Addr>() {
        config.netmask(mask);
    }
    config.mtu(auth.mtu as u16);
    config.up();

    tun::create_as_async(&config)
        .map_err(|e| anyhow::anyhow!("Failed to create async TUN: {}", e))
}

fn spawn_tun_io_worker(
    initial_device: tun::AsyncDevice,
    tx_to_core: mpsc::Sender<Bytes>,
    mut rx_from_core: mpsc::Receiver<Bytes>,
    mut rx_cmd: mpsc::UnboundedReceiver<TunSwapRequest>,
) {
    tokio::spawn(async move {
        let mut current_device_opt: Option<(
            tun::AsyncDevice,
            Option<tokio::sync::oneshot::Sender<()>>,
        )> = Some((initial_device, None));

        while let Some((device, ack_activated)) = current_device_opt.take() {
            let Ok((mut writer, mut reader)) = device.split() else {
                break;
            };

            let reader_stop = Arc::new(tokio::sync::Notify::new());
            let reader_stop_c = reader_stop.clone();
            let tx_to_core_c = tx_to_core.clone();

            let mut reader_handle = tokio::spawn(async move {
                const READ_CHUNK: usize = 64 * MAX_PACKET_SIZE;
                let mut buf = BytesMut::with_capacity(READ_CHUNK);
                loop {
                    if buf.capacity() < MAX_PACKET_SIZE {
                        buf = BytesMut::with_capacity(READ_CHUNK);
                    }
                    tokio::select! {
                        biased;
                        _ = reader_stop_c.notified() => break,
                        res = reader.read_buf(&mut buf) => {
                            match res {
                                Ok(n) if n > 0 => {
                                    if tx_to_core_c.send(buf.split().freeze()).await.is_err() {
                                        break;
                                    }
                                }
                                Ok(_) => break,
                                Err(_) => break,
                            }
                        }
                    }
                }
            });

            if let Some(ack) = ack_activated {
                let _ = ack.send(());
            }

            let mut swap_req = None;
            'io_loop: loop {
                tokio::select! {
                    biased;
                    cmd = rx_cmd.recv() => {
                        if let Some(req) = cmd {
                            swap_req = Some(req);
                        }
                        break 'io_loop;
                    }
                    _ = &mut reader_handle => {
                        break 'io_loop;
                    }
                    pkt_opt = rx_from_core.recv() => {
                        let Some(mut pkt) = pkt_opt else {
                            reader_stop.notify_one();
                            let _ = reader_handle.await;
                            return;
                        };
                        loop {
                            if writer.write_all(&pkt).await.is_err() {
                                reader_stop.notify_one();
                                let _ = reader_handle.await;
                                return;
                            }
                            match rx_from_core.try_recv() {
                                Ok(next) => pkt = next,
                                Err(_) => break,
                            }
                        }
                    }
                }
            }

            // Останавливаем и дропаем старые reader и writer до закрытия дескриптора в Java
            reader_stop.notify_one();
            let _ = reader_handle.await;
            drop(writer);

            if let Some(TunSwapRequest {
                ack_prepared,
                rx_new_device,
            }) = swap_req
            {
                let _ = ack_prepared.send(());
                if let Ok(Some((new_dev, ack_act))) = rx_new_device.await {
                    current_device_opt = Some((new_dev, Some(ack_act)));
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    });
}

#[async_trait]
impl TunFactory for AndroidCallbackTunFactory {
    async fn create_tun(
        &self,
        auth: &AuthResponse,
    ) -> Result<(mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>, String)> {
        TUN_ACTIVE_FLAG.store(false, Ordering::Release);
        *active_tun_mutex().lock().await = None;

        // --- 1. Асинхронная подготовка (БЕЗ JNI) ---
        let include_nets = self.resolve_to_ipnet(&self.config.main.route_for).await;
        let user_excludes = self
            .resolve_to_ipnet(&self.config.main.exclude_route_for)
            .await;
        let base_exclude_nets = user_excludes.clone();
        let mut exclude_nets = base_exclude_nets.clone();

        // Добавляем все маршруты обхода (сервер, DNS, статические Direct CIDR из rules.abc,
        // локальные overrides из client.toml), которые client.rs уже записал в bypass_ips
        let bypass_list = self.bypass_ips.lock().unwrap().clone();
        for (ip, prefix) in bypass_list {
            if ip.is_ipv4() {
                if let Ok(net) = IpNet::new(ip, prefix) {
                    if !exclude_nets.contains(&net) {
                        info!(
                            "[Android VpnService] Adding bypass route {}/{} to tunnel exclusions",
                            ip, prefix
                        );
                        exclude_nets.push(net);
                    }
                }
            }
        }

        let include_str = Self::ipnet_list_to_string(&include_nets);
        let exclude_str = Self::ipnet_list_to_string(&exclude_nets);

        let fallback_str = if include_nets.is_empty() && !user_excludes.is_empty() {
            let fallback_nets = Self::calculate_fallback_routes(&user_excludes);
            Self::ipnet_list_to_string(&fallback_nets)
        } else if include_nets.is_empty() && !exclude_nets.is_empty() && exclude_nets.len() <= 256 {
            let fallback_nets = Self::calculate_fallback_routes(&exclude_nets);
            Self::ipnet_list_to_string(&fallback_nets)
        } else {
            String::new()
        };

        // Настройка DNS: если список пуст, используем виртуальный шлюз туннеля (auth.gateway),
        // чтобы Android VpnService не пытался делать DoT на порт 853 (1.1.1.1:853), создавая 5-секундную задержку
        let dns_str = if self.config.main.dns_server_list.is_empty() {
            if !auth.gateway.trim().is_empty() {
                auth.gateway.trim().to_string()
            } else {
                "1.1.1.1".to_string()
            }
        } else {
            self.config.main.dns_server_list.join(",")
        };

        info!(
            "Routes Calc: IncludeItems={}, ExcludeItems={}",
            include_nets.len(),
            exclude_nets.len()
        );
        if !fallback_str.is_empty() {
            info!("Fallback generated: contains split routes covering 0.0.0.0/0 minus exclusions");
        }

        // --- 2. JNI ---
        let fd = call_configure_tun_jni(
            &self.jvm,
            &self.vpn_service_ref,
            auth,
            &include_str,
            &exclude_str,
            &fallback_str,
            &dns_str,
        )?;

        // --- 3. Tun Creation & Hot-Swap Worker ---
        let device = open_async_tun(fd, auth)?;

        let (tx_to_core, rx_from_tun) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
        let (tx_to_tun, rx_from_core) = mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
        let (tx_cmd, rx_cmd) = mpsc::unbounded_channel::<TunSwapRequest>();

        spawn_tun_io_worker(device, tx_to_core, rx_from_core, rx_cmd);

        let current_gen = DIRTY_GEN.load(Ordering::Acquire);
        *active_tun_mutex().lock().await = Some(ActiveTunSession {
            jvm: self.jvm.clone(),
            vpn_service_ref: self.vpn_service_ref.clone(),
            auth: auth.clone(),
            include_nets,
            user_excludes,
            base_exclude_nets,
            dns_str,
            bypass_ips: self.bypass_ips.clone(),
            tx_cmd,
            applied_gen: current_gen,
        });
        TUN_ACTIVE_FLAG.store(true, Ordering::Release);

        Ok((tx_to_tun, rx_from_tun, "tun0".to_string()))
    }
}

fn ip_mask_to_prefix(mask_str: &str) -> Result<u8> {
    let mask: Ipv4Addr = mask_str.parse()?;
    Ok(u32::from(mask).count_ones() as u8)
}
