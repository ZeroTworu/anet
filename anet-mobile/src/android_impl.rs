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
static REBIND_SCHEDULED: AtomicBool = AtomicBool::new(false);
static DIRTY_GEN: AtomicU64 = AtomicU64::new(0);
static NEXT_TUN_OWNER_ID: AtomicU64 = AtomicU64::new(1);
static ACTIVE_TUN: OnceLock<tokio::sync::Mutex<Option<ActiveTunSession>>> = OnceLock::new();

pub fn next_tun_owner_id() -> u64 {
    NEXT_TUN_OWNER_ID.fetch_add(1, Ordering::Relaxed)
}

fn active_tun_mutex() -> &'static tokio::sync::Mutex<Option<ActiveTunSession>> {
    ACTIVE_TUN.get_or_init(|| tokio::sync::Mutex::new(None))
}

struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct TunSwapRequest {
    ack_prepared: tokio::sync::oneshot::Sender<()>,
    rx_new_device: tokio::sync::oneshot::Receiver<
        Option<(tun::AsyncDevice, tokio::sync::oneshot::Sender<()>)>,
    >,
}

struct ActiveTunSession {
    owner_id: u64,
    jvm: Arc<JavaVM>,
    vpn_service_ref: GlobalRef,
    auth: AuthResponse,
    include_nets: Vec<IpNet>,
    user_excludes: Vec<IpNet>,
    base_exclude_nets: Vec<IpNet>,
    dns_str: String,
    bypass_ips: Arc<std::sync::Mutex<Vec<(IpAddr, u8)>>>,
    tx_cmd: mpsc::UnboundedSender<TunSwapRequest>,
    worker_stop: Arc<tokio::sync::Notify>,
    worker_handle: tokio::task::JoinHandle<()>,
    applied_gen: u64,
}

impl ActiveTunSession {
    #[allow(dead_code)]
    async fn rebind_tun(&mut self) -> Result<()> {
        if !TUN_ACTIVE_FLAG.load(Ordering::Acquire) {
            return Ok(());
        }
        let bypass_list = self.bypass_ips.lock().unwrap().clone();
        let exclude_nets = AndroidCallbackTunFactory::build_prioritized_exclude_nets(
            &self.base_exclude_nets,
            &bypass_list,
        );

        let include_str = AndroidCallbackTunFactory::ipnet_list_to_string(&self.include_nets);
        let exclude_str = AndroidCallbackTunFactory::ipnet_list_to_string(&exclude_nets);

        let fallback_str = if self.include_nets.is_empty() && !exclude_nets.is_empty() {
            let capped = if exclude_nets.len() <= 64 {
                &exclude_nets[..]
            } else {
                &exclude_nets[..64]
            };
            let fallback_nets = AndroidCallbackTunFactory::calculate_fallback_routes(capped);
            AndroidCallbackTunFactory::ipnet_list_to_string(&fallback_nets)
        } else {
            String::new()
        };

        // 1. Останавливаем и освобождаем старые AsyncFd (reader/writer) до пересоздания TUN в Java
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

        if !TUN_ACTIVE_FLAG.load(Ordering::Acquire) {
            let _ = tx_new_dev.send(None);
            return Ok(());
        }

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

        info!(
            "[Android RouteManager] Hot-updated VpnService TUN exclusions (ExcludeItems={})",
            exclude_nets.len()
        );
        Ok(())
    }
}

pub fn reset_tun_session_flags() {
    TUN_ACTIVE_FLAG.store(false, Ordering::Release);
    REBIND_SCHEDULED.store(false, Ordering::Release);
}

async fn stop_and_close_tun_session(session: ActiveTunSession) {
    // КРИТИЧНО: Сначала останавливаем Tokio I/O воркер и ждём его завершения, чтобы
    // дублированный файловый дескриптор (dup_fd) был дерегистрирован из epoll и закрыт
    // ДО того, как Java закроет свой ParcelFileDescriptor. Иначе ядро Linux может
    // переиспользовать номер fd для нового сокета/туннеля, пока старый AsyncFd ещё в epoll!
    session.worker_stop.notify_waiters();
    session.worker_handle.abort();
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        session.worker_handle,
    )
    .await;
    call_close_tun_jni(&session.jvm, &session.vpn_service_ref);
}

pub async fn shutdown_active_tun() {
    reset_tun_session_flags();
    let old_session = active_tun_mutex().lock().await.take();
    if let Some(session) = old_session {
        stop_and_close_tun_session(session).await;
    }
}

pub async fn shutdown_active_tun_for_owner(owner_id: u64) {
    let old_session = {
        let mut guard = active_tun_mutex().lock().await;
        if guard.as_ref().is_some_and(|s| s.owner_id == owner_id) {
            reset_tun_session_flags();
            guard.take()
        } else {
            None
        }
    };
    if let Some(session) = old_session {
        stop_and_close_tun_session(session).await;
    }
}

pub struct AndroidRouteManager {
    owner_id: u64,
    bypass_ips: Arc<std::sync::Mutex<Vec<(IpAddr, u8)>>>,
}

impl AndroidRouteManager {
    pub fn new(owner_id: u64, bypass_ips: Arc<std::sync::Mutex<Vec<(IpAddr, u8)>>>) -> Self {
        Self {
            owner_id,
            bypass_ips,
        }
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
        let tun_is_active = TUN_ACTIVE_FLAG.load(Ordering::Acquire);
        let mut added_new = false;
        {
            let mut list = self.bypass_ips.lock().unwrap();
            for &(target, prefix) in routes {
                let IpAddr::V4(v4) = target else {
                    continue;
                };
                let effective_prefix = prefix.min(32);

                let Ok(cand_net) = Ipv4Net::new(v4, effective_prefix).map(|n| n.trunc()) else {
                    continue;
                };

                // КРИТИЧНО для Android < 13 (API < 33, например Lenovo Tab P11 / Android 11):
                // Точные /32 маршруты (IP VPN-сервера, WebRTC TURN-сервера, DNS) НИКОГДА не должны
                // поглощаться или удаляться широкими подсетями /16 или /18 из rules.abc!
                // Иначе при расчёте fallback-маршрутов (первые N элементов) /32 адрес сервера/TURN
                // пропадает из начала списка и трафик к самому VPN/TURN-серверу заворачивается внутрь tun0 (routing loop).
                let already_covered = list.iter().any(|&(existing_ip, existing_p)| {
                    if let IpAddr::V4(ev4) = existing_ip {
                        if effective_prefix == 32 {
                            return existing_p == 32 && ev4 == cand_net.network();
                        }
                        if let Ok(existing_net) = Ipv4Net::new(ev4, existing_p) {
                            return existing_net.contains(&cand_net);
                        }
                    }
                    false
                });

                if !already_covered {
                    if effective_prefix < 32 {
                        list.retain(|&(existing_ip, existing_p)| {
                            // Никогда не удаляем точные /32 маршруты (сервер, TURN, DNS)
                            if existing_p == 32 {
                                return true;
                            }
                            if let IpAddr::V4(ev4) = existing_ip {
                                if existing_p > effective_prefix {
                                    if let Ok(existing_net) = Ipv4Net::new(ev4, existing_p) {
                                        return !cand_net.contains(&existing_net);
                                    }
                                }
                            }
                            true
                        });
                    }
                    let normalized_ip = IpAddr::V4(cand_net.network());
                    if routes.len() <= 16 {
                        info!(
                            "[Android RouteManager] Recorded bypass route: {}/{}",
                            normalized_ip, effective_prefix
                        );
                    }
                    if effective_prefix == 32 {
                        // Все /32 маршруты (VPN сервер, TURN relay, DNS) вставляем в начало списка,
                        // чтобы они гарантированно имели наивысший приоритет на всех версиях Android
                        let insert_pos = list
                            .iter()
                            .position(|&(_, p)| p < 32)
                            .unwrap_or(list.len());
                        list.insert(insert_pos, (normalized_ip, 32));
                    } else {
                        list.push((normalized_ip, effective_prefix));
                    }
                    added_new = true;
                }
            }
        }

        if added_new {
            DIRTY_GEN.fetch_add(1, Ordering::AcqRel);
        }

        // Все статические маршруты (VPN сервер, TURN, DNS, rules.abc, overrides) добавляются ДО вызова create_tun().
        // Когда TUN уже поднят (tun_is_active == true), мы НЕ вызываем VpnService.Builder.establish() повторно
        // на каждый фоновый DNS-ответ, так как на Android повторный establish() пересоздаёт интерфейс tun0
        // и сбрасывает активные сокеты (включая Speedtest и WebRTC/QUIC).
        let _ = tun_is_active;
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
        shutdown_active_tun_for_owner(self.owner_id).await;
        self.bypass_ips.lock().unwrap().clear();
        Ok(())
    }
}

pub struct AndroidCallbackTunFactory {
    owner_id: u64,
    jvm: Arc<JavaVM>,
    vpn_service_ref: GlobalRef,
    config: CoreConfig,
    bypass_ips: Arc<std::sync::Mutex<Vec<(IpAddr, u8)>>>,
}

impl AndroidCallbackTunFactory {
    pub fn new(
        owner_id: u64,
        jvm: Arc<JavaVM>,
        vpn_service_ref: GlobalRef,
        config: CoreConfig,
        bypass_ips: Arc<std::sync::Mutex<Vec<(IpAddr, u8)>>>,
    ) -> Self {
        Self {
            owner_id,
            jvm,
            vpn_service_ref,
            config,
            bypass_ips,
        }
    }

    /// Формирует список исключений с жёстким приоритетом:
    /// 1) Сначала все точные `/32` адреса (VPN-сервер, WebRTC TURN-серверы, DNS, хосты из exclude_route_for)
    /// 2) Затем пользовательские подсети из `exclude_route_for`
    /// 3) Затем остальные CIDR-маршруты из `rules.abc`
    /// Это гарантирует, что на Android < 13 (API < 33, где работает `fallback_str` с лимитом подсетей)
    /// IP-адреса самого VPN-сервера и TURN-релеев ВСЕГДА попадают в исключения и никогда не вызывают routing loop.
    fn build_prioritized_exclude_nets(
        base_exclude_nets: &[IpNet],
        bypass_list: &[(IpAddr, u8)],
    ) -> Vec<IpNet> {
        let mut exclude_nets = Vec::with_capacity(base_exclude_nets.len() + bypass_list.len());

        // 1. Сначала все /32 из bypass_list (сервер, TURN, DNS) и base_exclude_nets
        for &(ip, prefix) in bypass_list {
            if prefix == 32 && ip.is_ipv4() {
                if let Ok(net) = IpNet::new(ip, 32) {
                    let normalized = IpNet::new(net.network(), net.prefix_len()).unwrap_or(net);
                    if !exclude_nets.contains(&normalized) {
                        exclude_nets.push(normalized);
                    }
                }
            }
        }
        for net in base_exclude_nets {
            if net.addr().is_ipv4() && net.prefix_len() == 32 {
                let normalized = IpNet::new(net.network(), net.prefix_len()).unwrap_or(*net);
                if !exclude_nets.contains(&normalized) {
                    exclude_nets.push(normalized);
                }
            }
        }

        // 2. Пользовательские подсети из base_exclude_nets (< 32)
        for net in base_exclude_nets {
            if net.addr().is_ipv4() && net.prefix_len() < 32 {
                let normalized = IpNet::new(net.network(), net.prefix_len()).unwrap_or(*net);
                if !exclude_nets.contains(&normalized) {
                    exclude_nets.push(normalized);
                }
            }
        }

        // 3. Широкие подсети (< 32) из bypass_list (rules.abc и overrides)
        for &(ip, prefix) in bypass_list {
            if prefix < 32 && ip.is_ipv4() {
                if let Ok(net) = IpNet::new(ip, prefix) {
                    let normalized = IpNet::new(net.network(), net.prefix_len()).unwrap_or(net);
                    if !exclude_nets.contains(&normalized) {
                        exclude_nets.push(normalized);
                    }
                }
            }
        }

        exclude_nets
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
                if net.addr().is_ipv4() {
                    let normalized = IpNet::new(net.network(), net.prefix_len()).unwrap_or(net);
                    if !result.contains(&normalized) {
                        result.push(normalized);
                    }
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

fn call_close_tun_jni(jvm: &Arc<JavaVM>, vpn_service_ref: &GlobalRef) {
    if let Ok(mut env) = jvm.attach_current_thread() {
        if env.call_method(vpn_service_ref, "closeTun", "()V", &[]).is_err() {
            let _ = env.exception_clear();
        }
    }
}

fn open_async_tun(fd: i32, auth: &AuthResponse) -> Result<tun::AsyncDevice> {
    use std::os::fd::{BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};

    // КРИТИЧНО: Дублируем файловый дескриптор (F_DUPFD_CLOEXEC) специально для Rust/Tokio AsyncFd!
    // Если передавать сырой fd из Java напрямую с close_fd_on_drop(false), то при закрытии
    // ParcelFileDescriptor на стороне Java или переиспользовании номера fd ядром Linux
    // для нового сокета возникает конфликт в epoll реакторе Tokio (0 RX / зависание коннекта).
    // С собственным dup_fd и close_fd_on_drop(true) жизненный цикл epoll-регистрации в Rust
    // полностью изолирован от Java ParcelFileDescriptor.
    let dup_fd = unsafe { BorrowedFd::borrow_raw(fd) }
        .try_clone_to_owned()
        .map_err(|e| anyhow::anyhow!("Failed to duplicate TUN fd {}: {}", fd, e))?
        .into_raw_fd();

    let mut config = Configuration::default();
    config.raw_fd(dup_fd);
    config.close_fd_on_drop(true);
    if let Ok(ipv4) = auth.ip.parse::<Ipv4Addr>() {
        config.address(ipv4);
    }
    if let Ok(mask) = auth.netmask.parse::<Ipv4Addr>() {
        config.netmask(mask);
    }
    config.mtu(auth.mtu as u16);
    config.up();

    match tun::create_as_async(&config) {
        Ok(dev) => Ok(dev),
        Err(e) => {
            unsafe {
                let _ = OwnedFd::from_raw_fd(dup_fd);
            }
            Err(anyhow::anyhow!("Failed to create async TUN: {}", e))
        }
    }
}

fn spawn_tun_io_worker(
    initial_device: tun::AsyncDevice,
    tx_to_core: mpsc::Sender<Bytes>,
    mut rx_from_core: mpsc::Receiver<Bytes>,
    mut rx_cmd: mpsc::UnboundedReceiver<TunSwapRequest>,
    worker_stop: Arc<tokio::sync::Notify>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut current_device_opt: Option<(
            tun::AsyncDevice,
            Option<tokio::sync::oneshot::Sender<()>>,
        )> = Some((initial_device, None));

        while let Some((device, ack_activated)) = current_device_opt.take() {
            let mut swap_req = None;
            {
                let Ok((mut writer, mut reader)) = device.split() else {
                    break;
                };

                let reader_stop = Arc::new(tokio::sync::Notify::new());
                let reader_stop_c = reader_stop.clone();
                let worker_stop_c = worker_stop.clone();
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
                            _ = worker_stop_c.notified() => break,
                            res = reader.read_buf(&mut buf) => {
                                match res {
                                    Ok(n) if n > 0 => {
                                        let pkt = buf.split().freeze();
                                        tokio::select! {
                                            biased;
                                            _ = reader_stop_c.notified() => break,
                                            _ = worker_stop_c.notified() => break,
                                            send_res = tx_to_core_c.send(pkt) => {
                                                if send_res.is_err() {
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    Ok(_) => break,
                                    Err(_) => break,
                                }
                            }
                        }
                    }
                });
                // Гарантируем, что даже при внешнем abort() этой задачи дочерний reader_handle
                // мгновенно отменяется и освобождает AsyncFd!
                let _reader_abort_guard = AbortOnDrop(reader_handle.abort_handle());

                if let Some(ack) = ack_activated {
                    let _ = ack.send(());
                }

                let mut reader_finished = false;
                'io_loop: loop {
                    tokio::select! {
                        biased;
                        _ = worker_stop.notified() => {
                            break 'io_loop;
                        }
                        cmd = rx_cmd.recv() => {
                            if let Some(req) = cmd {
                                swap_req = Some(req);
                            }
                            break 'io_loop;
                        }
                        _ = &mut reader_handle => {
                            reader_finished = true;
                            break 'io_loop;
                        }
                        pkt_opt = rx_from_core.recv() => {
                            let Some(mut pkt) = pkt_opt else {
                                reader_stop.notify_one();
                                reader_handle.abort();
                                let _ = reader_handle.await;
                                return;
                            };
                            loop {
                                if writer.write_all(&pkt).await.is_err() {
                                    reader_stop.notify_one();
                                    reader_handle.abort();
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

                // Останавливаем и освобождаем старые reader и writer выходом из области видимости до закрытия дескриптора в Java
                if !reader_finished {
                    reader_stop.notify_one();
                    reader_handle.abort();
                    let _ = reader_handle.await;
                }
            }

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
    })
}

#[async_trait]
impl TunFactory for AndroidCallbackTunFactory {
    async fn create_tun(
        &self,
        auth: &AuthResponse,
    ) -> Result<(mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>, String)> {
        shutdown_active_tun().await;

        // --- 1. Асинхронная подготовка (БЕЗ JNI) ---
        let include_nets = self.resolve_to_ipnet(&self.config.main.route_for).await;
        let user_excludes = self
            .resolve_to_ipnet(&self.config.main.exclude_route_for)
            .await;
        let base_exclude_nets = user_excludes.clone();

        // Синхронизируем user_excludes в bypass_ips и собираем все маршруты обхода
        // (сервер, TURN, DNS, статические Direct CIDR из rules.abc, локальные overrides из client.toml)
        let bypass_list = {
            let mut guard = self.bypass_ips.lock().unwrap();
            for net in &base_exclude_nets {
                let entry = (net.network(), net.prefix_len());
                if !guard.contains(&entry) {
                    if net.prefix_len() == 32 {
                        let pos = guard
                            .iter()
                            .position(|&(_, p)| p < 32)
                            .unwrap_or(guard.len());
                        guard.insert(pos, entry);
                    } else {
                        guard.push(entry);
                    }
                }
            }
            guard.clone()
        };

        let exclude_nets =
            Self::build_prioritized_exclude_nets(&base_exclude_nets, &bypass_list);

        let include_str = Self::ipnet_list_to_string(&include_nets);
        let exclude_str = Self::ipnet_list_to_string(&exclude_nets);

        // На Android < 13 (API < 33, включая Android 11 на Lenovo Tab P11), где нет нативного
        // Builder.excludeRoute(IpPrefix), маршрутизация строится через вычитание исключений из 0.0.0.0/0.
        // Благодаря build_prioritized_exclude_nets в начале exclude_nets ВСЕГДА находятся все /32
        // маршруты (VPN-сервер, WebRTC TURN, DNS) и пользовательские исключения.
        let fallback_str = if include_nets.is_empty() && !exclude_nets.is_empty() {
            let capped = if exclude_nets.len() <= 64 {
                &exclude_nets[..]
            } else {
                &exclude_nets[..64]
            };
            let fallback_nets = Self::calculate_fallback_routes(capped);
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
        let worker_stop = Arc::new(tokio::sync::Notify::new());

        let worker_handle = spawn_tun_io_worker(
            device,
            tx_to_core,
            rx_from_core,
            rx_cmd,
            worker_stop.clone(),
        );

        let current_gen = DIRTY_GEN.load(Ordering::Acquire);
        *active_tun_mutex().lock().await = Some(ActiveTunSession {
            owner_id: self.owner_id,
            jvm: self.jvm.clone(),
            vpn_service_ref: self.vpn_service_ref.clone(),
            auth: auth.clone(),
            include_nets,
            user_excludes,
            base_exclude_nets,
            dns_str,
            bypass_ips: self.bypass_ips.clone(),
            tx_cmd,
            worker_stop,
            worker_handle,
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
