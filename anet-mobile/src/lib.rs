include!(concat!(env!("OUT_DIR"), "/built.rs"));

mod android_impl;

use crate::android_impl::{AndroidCallbackTunFactory, AndroidRouteManager};
use android_logger::Config;
use anet_client_core::client::AnetClient;
use anet_client_core::config::CoreConfig;
use anet_client_core::events::{self, AnetEvent, ClientState, EventHandler, TimestampedEvent, client_state, status};
use anet_client_core::updater::{GithubRelease, Updater};
use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::{JNIEnv, JavaVM};
use log::{LevelFilter, error, info};
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::sync::mpsc::{self, Sender};
use tokio::runtime::Runtime;

// Глобальные переменные состояния клиентов и асинхронного рантайма
static CLIENT: Mutex<Option<Arc<AnetClient>>> = Mutex::new(None);
static RUNTIME: Mutex<Option<Runtime>> = Mutex::new(None);
static PENDING_RELEASE: Mutex<Option<GithubRelease>> = Mutex::new(None);
static CLIENT_LIFECYCLE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static CLIENT_GENERATION: AtomicU64 = AtomicU64::new(0);
static CURRENT_CLIENT_STATE: AtomicI32 = AtomicI32::new(0);
static CURRENT_SERVER_NAME: Mutex<Option<String>> = Mutex::new(None);
static LAST_TELEMETRY: Mutex<Option<anet_common::connectivity::TelemetrySnapshot>> = Mutex::new(None);
static LAST_ACCOUNT_INFO: Mutex<Option<anet_client_core::events::AccountInfo>> = Mutex::new(None);

// --- ГЛОБАЛЬНЫЙ МНОГОПОТОЧНЫЙ JNI-МОСТ (Защита от утечек и дедлоков) ---
static JNI_SENDER: OnceLock<Sender<TimestampedEvent>> = OnceLock::new();
static VPN_CALLBACK_REF: Mutex<Option<GlobalRef>> = Mutex::new(None);
static UI_CALLBACK_REF: Mutex<Option<GlobalRef>> = Mutex::new(None);

// Наш асинхронный обработчик событий ядра.
// Теперь он просто мгновенно отправляет события в канал, не блокируя Tokio-потоки вызовами JNI.
struct AndroidEventHandler;

impl EventHandler for AndroidEventHandler {
    fn on_event(&self, event: TimestampedEvent) {
        match &event.event {
            AnetEvent::ClientStateChanged {
                state, server_name, ..
            } => {
                CURRENT_CLIENT_STATE.store(client_state_code(*state), Ordering::SeqCst);
                if let Some(server_name) = server_name {
                    *CURRENT_SERVER_NAME.lock().unwrap() = Some(server_name.clone());
                } else if matches!(state, ClientState::Disconnected | ClientState::Stopped) {
                    *CURRENT_SERVER_NAME.lock().unwrap() = None;
                    *LAST_TELEMETRY.lock().unwrap() = None;
                }
            }
            AnetEvent::TelemetryUpdated(tel) => {
                *LAST_TELEMETRY.lock().unwrap() = Some(tel.clone());
            }
            AnetEvent::AccountInfo(info) => {
                *LAST_ACCOUNT_INFO.lock().unwrap() = Some(info.clone());
            }
            _ => {}
        }
        if let Some(sender) = JNI_SENDER.get() {
            let _ = sender.send(event);
        }
    }
}

fn inspect_config(config_toml: &str) -> String {
    let mut config: CoreConfig = match toml::from_str(config_toml) {
        Ok(config) => config,
        Err(error) => return format!("ERROR\n{error}"),
    };
    if let Err(error) = config.sanitize() {
        return format!("ERROR\n{error}");
    }

    let mut result = String::from("OK");
    let has_groups = config.servers.iter().any(|s| {
        s.group_name.as_ref().map_or(false, |g| !g.trim().is_empty())
    });

    if has_groups {
        let mut seen = std::collections::HashSet::new();
        for server in &config.servers {
            if let Some(ref g_name) = server.group_name {
                let g_name = g_name.trim();
                let g_id = server.group_id.as_deref().unwrap_or(g_name).trim();
                if !g_name.is_empty() && seen.insert(g_id.to_string()) {
                    result.push('\n');
                    let id_safe = g_id.replace(['\r', '\n', '|'], " ");
                    let name_safe = g_name.replace(['\r', '\n', '|'], " ");
                    result.push_str(&format!("{}|{}", id_safe, name_safe));
                }
            }
        }
    } else {
        let mut dsn_counts = std::collections::HashMap::<String, usize>::new();
        for server in &config.servers {
            *dsn_counts.entry(server.dsn.trim().to_string()).or_insert(0) += 1;
        }
        for server in config.servers {
            result.push('\n');
            let name_safe = server.get_name().replace(['\r', '\n', '|'], " ");
            let raw_dsn = server.dsn.trim();
            let id_safe = if dsn_counts.get(raw_dsn).copied().unwrap_or(0) > 1 {
                name_safe.clone()
            } else {
                server.dsn.replace(['\r', '\n', '|'], " ")
            };
            result.push_str(&format!("{}|{}", id_safe, name_safe));
        }
    }
    result
}

fn client_state_code(state: ClientState) -> i32 {
    match state {
        ClientState::Disconnected => 0,
        ClientState::Connecting => 1,
        ClientState::Connected => 2,
        ClientState::Reconnecting => 3,
        ClientState::Stopping => 4,
        ClientState::Stopped => 5,
        ClientState::Failed => 6,
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    let bytes_f = bytes as f64;
    if bytes_f < KIB {
        format!("{} B", bytes)
    } else if bytes_f < MIB {
        format!("{:.2} KiB", bytes_f / KIB)
    } else if bytes_f < GIB {
        format!("{:.2} MiB", bytes_f / MIB)
    } else {
        format!("{:.2} GiB", bytes_f / GIB)
    }
}

fn format_bytes_per_sec(bytes_per_sec: f64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    if bytes_per_sec < KIB {
        format!("{:.0} B/s", bytes_per_sec)
    } else if bytes_per_sec < MIB {
        format!("{:.0} KiB/s", bytes_per_sec / KIB)
    } else if bytes_per_sec < GIB {
        format!("{:.0} MiB/s", bytes_per_sec / MIB)
    } else {
        format!("{:.0} GiB/s", bytes_per_sec / GIB)
    }
}

fn event_message(event: AnetEvent) -> Option<String> {
    match event {
        AnetEvent::Status(s) | AnetEvent::UpdateStatus(s) => Some(s),
        AnetEvent::Warn(s) => Some(format!("WARN: {s}")),
        AnetEvent::Error(s) => Some(format!("ERROR: {s}")),
        AnetEvent::UpdateProgress(p) => Some(format!("PROGRESS:{p:.2}")),
        AnetEvent::UpdateAvailable(rel) => Some(format!("Найдено обновление: {}", rel.tag_name)),
        AnetEvent::UpdateReady => Some("Update downloaded to cache".to_string()),
        AnetEvent::ServerConfigUpdated { nodes_count, .. } => {
            Some(format!("Серверный конфиг успешно обновлен (нод: {})", nodes_count))
        }
        AnetEvent::ServerConfigFetchFailed { error, .. } => {
            Some(format!("Ошибка обновления конфига: {}", error))
        }
        AnetEvent::ServerConfigOutdatedWarning { age_hours, .. } => {
            Some(format!("Внимание: конфиг устарел (возраст: {}ч)", age_hours))
        }
        AnetEvent::Stats { .. }
        | AnetEvent::TrafficUpdate { .. }
        | AnetEvent::ConnectivityUpdated(_)
        | AnetEvent::TelemetryUpdated(_)
        | AnetEvent::NodeProbeUpdated(_)
        | AnetEvent::ClientStateChanged { .. }
        | AnetEvent::AccountInfo(_) => None,
    }
}

fn get_or_init_runtime_handle() -> tokio::runtime::Handle {
    let mut rt_guard = RUNTIME.lock().unwrap();
    if rt_guard.is_none() {
        *rt_guard = Some(Runtime::new().unwrap());
    }
    rt_guard.as_ref().unwrap().handle().clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_state_codes_match_android_contract() {
        assert_eq!(client_state_code(ClientState::Disconnected), 0);
        assert_eq!(client_state_code(ClientState::Connecting), 1);
        assert_eq!(client_state_code(ClientState::Connected), 2);
        assert_eq!(client_state_code(ClientState::Reconnecting), 3);
        assert_eq!(client_state_code(ClientState::Stopping), 4);
        assert_eq!(client_state_code(ClientState::Stopped), 5);
        assert_eq!(client_state_code(ClientState::Failed), 6);
    }

    #[test]
    fn config_inspection_returns_sanitized_server_names() {
        let result = inspect_config(
            r#"
                [main]
                tun_name = "anet"
                [[servers]]
                name = "Primary"
                dsn = "quic://127.0.0.1:443"
            "#,
        );
        assert_eq!(result, "OK\nPrimary");
    }

    #[test]
    fn config_inspection_reports_invalid_toml() {
        assert!(inspect_config("not toml").starts_with("ERROR\n"));
    }

    #[test]
    fn event_message_skips_stats_and_traffic() {
        let stats_event = AnetEvent::Stats {
            rx: "10 MiB".to_string(),
            tx: "2 MiB".to_string(),
            rtt: "40ms".to_string(),
            rxm: "1.5 MiB/s".to_string(),
            txm: "200 KiB/s".to_string(),
        };
        assert!(event_message(stats_event).is_none());

        let traffic_event = AnetEvent::TrafficUpdate {
            rx: 1024,
            tx: 2048,
            rtt: 50,
            rxm: 1000,
            txm: 2000,
        };
        assert!(event_message(traffic_event).is_none());

        let state_event = AnetEvent::ClientStateChanged {
            state: ClientState::Connected,
            message: "Connected".to_string(),
            server_name: Some("Server1".to_string()),
        };
        assert!(event_message(state_event).is_none());

        let status_event = AnetEvent::Status("Hello".to_string());
        assert_eq!(event_message(status_event), Some("Hello".to_string()));
    }

    #[test]
    fn format_bytes_works_correctly() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.00 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MiB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GiB");
    }

    #[test]
    fn format_bytes_per_sec_works_correctly() {
        assert_eq!(format_bytes_per_sec(500.0), "500 B/s");
        assert_eq!(format_bytes_per_sec(1024.0), "1 KiB/s");
        assert_eq!(format_bytes_per_sec(1024.0 * 1024.0), "1 MiB/s");
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_MainActivity_inspectConfig(
    mut env: JNIEnv,
    _this: JObject,
    config_jstr: JString,
) -> jni::sys::jstring {
    let result = env
        .get_string(&config_jstr)
        .map(|value| {
            let s = String::from(value);
            let out = inspect_config(&s);
            if out.starts_with("OK") {
                let rt = get_or_init_runtime_handle();
                let _guard = rt.enter();
                anet_client_core::connectivity_monitor::NodeProbeMonitor::update_config_toml(&s);
            }
            out
        })
        .unwrap_or_else(|error| format!("ERROR\n{error}"));
    env.new_string(result).unwrap().into_raw()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_MainActivity_fetchConfigFromUrl(
    mut env: JNIEnv,
    _this: JObject,
    url_jstr: JString,
) -> jni::sys::jstring {
    let url: String = match env.get_string(&url_jstr) {
        Ok(s) => s.into(),
        Err(error) => return env.new_string(format!("ERROR\n{error}")).unwrap().into_raw(),
    };

    let rt = {
        let mut rt_guard = RUNTIME.lock().unwrap();
        if rt_guard.is_none() {
            *rt_guard = Some(Runtime::new().unwrap());
        }
        rt_guard.as_ref().unwrap().handle().clone()
    };

    let result = match rt.block_on(Updater::fetch_config_from_url(&url)) {
        Ok(content) => format!("OK\n{content}"),
        Err(error) => format!("ERROR\n{error}"),
    };

    env.new_string(result).unwrap().into_raw()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_MainActivity_getVpnStateCode(
    _env: JNIEnv,
    _this: JObject,
) -> i32 {
    CURRENT_CLIENT_STATE.load(Ordering::SeqCst)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_MainActivity_getVpnServerName(
    env: JNIEnv,
    _this: JObject,
) -> jni::sys::jstring {
    let server_name = CURRENT_SERVER_NAME
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_default();
    env.new_string(server_name).unwrap().into_raw()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_MainActivity_clearUiCallback(
    env: JNIEnv,
    this: JObject,
) {
    let mut callback = UI_CALLBACK_REF.lock().unwrap();
    if callback
        .as_ref()
        .is_some_and(|current| env.is_same_object(current.as_obj(), &this).unwrap_or(false))
    {
        *callback = None;
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_ANetVpnService_clearVpnCallback(
    env: JNIEnv,
    this: JObject,
) {
    let mut callback = VPN_CALLBACK_REF.lock().unwrap();
    if callback
        .as_ref()
        .is_some_and(|current| env.is_same_object(current.as_obj(), &this).unwrap_or(false))
    {
        *callback = None;
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_ANetVpnService_initLogger(_env: JNIEnv, _class: JClass) {
    android_logger::init_once(
        Config::default()
            .with_max_level(LevelFilter::Info)
            .with_tag("ANetRust"),
    );
    info!("Rust Logger Initialized");
}

// Запуск выделенного фонового потока JNI-моста (выполняется один раз на весь жизненный цикл приложения)
fn init_jni_bridge_thread(jvm: Arc<JavaVM>) {
    JNI_SENDER.get_or_init(move || {
        let (tx, rx) = mpsc::channel::<TimestampedEvent>(); // <-- изменили на TimestampedEvent

        std::thread::spawn(move || {
            info!("Rust JNI Bridge: Dedicated OS thread started.");

            if let Ok(mut env) = jvm.attach_current_thread() {
                while let Ok(TimestampedEvent { timestamp: _timestamp, event }) = rx.recv() {
                    if let AnetEvent::ConnectivityUpdated(snap) = event {
                        let ui_ref = UI_CALLBACK_REF.lock().unwrap().clone();
                        let vpn_ref = VPN_CALLBACK_REF.lock().unwrap().clone();
                        let targets: Vec<GlobalRef> =
                            [ui_ref, vpn_ref].into_iter().flatten().collect();

                        for cb in targets {
                            let j_title = env.new_string(&snap.title);
                            let j_subtitle = env.new_string(&snap.subtitle);
                            if let (Ok(j_title), Ok(j_subtitle)) = (j_title, j_subtitle) {
                                let rtt_val = snap.display_rtt_ms.map(|v| v as i64).unwrap_or(-1);
                                let _ = env.call_method(
                                    &cb,
                                    "onConnectivityUpdated",
                                    "(IIJZLjava/lang/String;Ljava/lang/String;IIII)V",
                                    &[
                                        JValue::Int(snap.condition.code()),
                                        JValue::Int(snap.pulse_color.code()),
                                        JValue::Long(rtt_val),
                                        JValue::Bool(u8::from(snap.vpn_connected)),
                                        JValue::Object(&j_title),
                                        JValue::Object(&j_subtitle),
                                        JValue::Int(snap.global_ok as i32),
                                        JValue::Int(snap.global_total as i32),
                                        JValue::Int(snap.domestic_ok as i32),
                                        JValue::Int(snap.domestic_total as i32),
                                    ],
                                );
                                let _ = env.exception_clear();
                            }
                        }
                        continue;
                    }

                    if let AnetEvent::TelemetryUpdated(tel) = event {
                        let ui_ref = UI_CALLBACK_REF.lock().unwrap().clone();
                        let vpn_ref = VPN_CALLBACK_REF.lock().unwrap().clone();
                        let targets: Vec<GlobalRef> =
                            [vpn_ref, ui_ref].into_iter().flatten().collect();

                        for cb in targets {
                            let j_rx_spd = env.new_string(&tel.rx_speed_str);
                            let j_tx_spd = env.new_string(&tel.tx_speed_str);
                            let j_rx_tot = env.new_string(&tel.total_rx_str);
                            let j_tx_tot = env.new_string(&tel.total_tx_str);
                            let j_rx_curve = env.new_float_array(tel.rx_curve.len() as i32);
                            let j_tx_curve = env.new_float_array(tel.tx_curve.len() as i32);

                            if let (
                                Ok(j_rx_spd),
                                Ok(j_tx_spd),
                                Ok(j_rx_tot),
                                Ok(j_tx_tot),
                                Ok(j_rx_curve),
                                Ok(j_tx_curve),
                            ) = (
                                j_rx_spd,
                                j_tx_spd,
                                j_rx_tot,
                                j_tx_tot,
                                j_rx_curve,
                                j_tx_curve,
                            ) {
                                let _ = env.set_float_array_region(&j_rx_curve, 0, &tel.rx_curve);
                                let _ = env.set_float_array_region(&j_tx_curve, 0, &tel.tx_curve);
                                let rtt_val = tel.rtt_ms.map(|v| v as i64).unwrap_or(-1);
                                let rx_curve_obj = JObject::from(j_rx_curve);
                                let tx_curve_obj = JObject::from(j_tx_curve);

                                let _ = env.call_method(
                                    &cb,
                                    "onTelemetryUpdated",
                                    "(JJJJJLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[F[F)V",
                                    &[
                                        JValue::Long(tel.rx_bps as i64),
                                        JValue::Long(tel.tx_bps as i64),
                                        JValue::Long(tel.total_rx_bytes as i64),
                                        JValue::Long(tel.total_tx_bytes as i64),
                                        JValue::Long(rtt_val),
                                        JValue::Object(&j_rx_spd),
                                        JValue::Object(&j_tx_spd),
                                        JValue::Object(&j_rx_tot),
                                        JValue::Object(&j_tx_tot),
                                        JValue::Object(&rx_curve_obj),
                                        JValue::Object(&tx_curve_obj),
                                    ],
                                );
                                let _ = env.exception_clear();
                            }
                        }
                        continue;
                    }

                    if let AnetEvent::NodeProbeUpdated(probe_snap) = event {
                        let ui_ref = UI_CALLBACK_REF.lock().unwrap().clone();
                        let vpn_ref = VPN_CALLBACK_REF.lock().unwrap().clone();
                        let targets: Vec<GlobalRef> =
                            [ui_ref, vpn_ref].into_iter().flatten().collect();

                        for cb in targets {
                            let count = probe_snap.groups.len() as i32;
                            let str_cls = env.find_class("java/lang/String");
                            let empty_1 = env.new_string("");
                            let empty_2 = env.new_string("");
                            let empty_3 = env.new_string("");

                            if let (Ok(str_cls), Ok(empty_1), Ok(empty_2), Ok(empty_3)) =
                                (str_cls, empty_1, empty_2, empty_3)
                            {
                                let j_ids = env.new_object_array(count, &str_cls, &empty_1);
                                let j_names = env.new_object_array(count, &str_cls, &empty_2);
                                let j_protos = env.new_object_array(count, &str_cls, &empty_3);
                                let j_statuses = env.new_int_array(count);
                                let j_rtts = env.new_int_array(count);
                                let j_full_rtts = env.new_int_array(count);
                                let j_reachables = env.new_int_array(count);
                                let j_totals = env.new_int_array(count);

                                if let (
                                    Ok(j_ids),
                                    Ok(j_names),
                                    Ok(j_protos),
                                    Ok(j_statuses),
                                    Ok(j_rtts),
                                    Ok(j_full_rtts),
                                    Ok(j_reachables),
                                    Ok(j_totals),
                                ) = (
                                    j_ids,
                                    j_names,
                                    j_protos,
                                    j_statuses,
                                    j_rtts,
                                    j_full_rtts,
                                    j_reachables,
                                    j_totals,
                                ) {
                                    let mut statuses_vec = Vec::with_capacity(count as usize);
                                    let mut rtts_vec = Vec::with_capacity(count as usize);
                                    let mut full_rtts_vec = Vec::with_capacity(count as usize);
                                    let mut reachables_vec = Vec::with_capacity(count as usize);
                                    let mut totals_vec = Vec::with_capacity(count as usize);

                                    for (i, g) in probe_snap.groups.iter().enumerate() {
                                        if let Ok(js) = env.new_string(&g.group_id) {
                                            let _ = env.set_object_array_element(&j_ids, i as i32, js);
                                        }
                                        if let Ok(js) = env.new_string(&g.group_name) {
                                            let _ = env.set_object_array_element(&j_names, i as i32, js);
                                        }
                                        if let Ok(js) = env.new_string(g.compact_protocols_text()) {
                                            let _ = env.set_object_array_element(&j_protos, i as i32, js);
                                        }
                                        statuses_vec.push(g.status.as_u8() as i32);
                                        rtts_vec.push(g.best_rtt_ms.map(|v| v as i32).unwrap_or(-1));
                                        full_rtts_vec.push(
                                            g.best_full_rtt_ms
                                                .or(g.best_rtt_ms)
                                                .map(|v| v as i32)
                                                .unwrap_or(-1),
                                        );
                                        reachables_vec.push(g.reachable_endpoints as i32);
                                        totals_vec.push(g.total_endpoints as i32);
                                    }

                                    let _ = env.set_int_array_region(&j_statuses, 0, &statuses_vec);
                                    let _ = env.set_int_array_region(&j_rtts, 0, &rtts_vec);
                                    let _ = env.set_int_array_region(&j_full_rtts, 0, &full_rtts_vec);
                                    let _ = env.set_int_array_region(&j_reachables, 0, &reachables_vec);
                                    let _ = env.set_int_array_region(&j_totals, 0, &totals_vec);

                                    let ids_obj = JObject::from(j_ids);
                                    let names_obj = JObject::from(j_names);
                                    let statuses_obj = JObject::from(j_statuses);
                                    let rtts_obj = JObject::from(j_rtts);
                                    let full_rtts_obj = JObject::from(j_full_rtts);
                                    let reachables_obj = JObject::from(j_reachables);
                                    let totals_obj = JObject::from(j_totals);
                                    let protos_obj = JObject::from(j_protos);

                                    let _ = env.call_method(
                                        &cb,
                                        "onNodeProbeUpdated",
                                        "([Ljava/lang/String;[Ljava/lang/String;[I[I[I[I[I[Ljava/lang/String;ZII)V",
                                        &[
                                            JValue::Object(&ids_obj),
                                            JValue::Object(&names_obj),
                                            JValue::Object(&statuses_obj),
                                            JValue::Object(&rtts_obj),
                                            JValue::Object(&full_rtts_obj),
                                            JValue::Object(&reachables_obj),
                                            JValue::Object(&totals_obj),
                                            JValue::Object(&protos_obj),
                                            JValue::Bool(u8::from(probe_snap.is_checking)),
                                            JValue::Int(probe_snap.completed_endpoints as i32),
                                            JValue::Int(probe_snap.total_endpoints as i32),
                                        ],
                                    );
                                    let _ = env.exception_clear();
                                }
                            }
                        }
                        continue;
                    }

                    if let AnetEvent::AccountInfo(info) = event {
                        let ui_ref = UI_CALLBACK_REF.lock().unwrap().clone();
                        let vpn_ref = VPN_CALLBACK_REF.lock().unwrap().clone();
                        let targets: Vec<GlobalRef> =
                            [vpn_ref, ui_ref].into_iter().flatten().collect();

                        for cb in targets {
                            let j_billing = env.new_string(&info.billing_str);
                            let j_group = env.new_string(&info.group_str);
                            let j_sessions = env.new_string(&info.sessions_str);
                            let j_speed = env.new_string(&info.speed_str);
                            let j_consumed = env.new_string(&info.consumed_str);
                            let j_limit = env.new_string(&info.limit_str);
                            let j_expires = env.new_string(&info.expires_str);

                            if let (Ok(jb), Ok(jg), Ok(jse), Ok(jsp), Ok(jc), Ok(jl), Ok(je)) = (
                                j_billing, j_group, j_sessions, j_speed, j_consumed, j_limit,
                                j_expires,
                            ) {
                                let _ = env.call_method(
                                    &cb,
                                    "onAccountInfo",
                                    "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                                    &[
                                        JValue::Object(&jb),
                                        JValue::Object(&jg),
                                        JValue::Object(&jse),
                                        JValue::Object(&jsp),
                                        JValue::Object(&jc),
                                        JValue::Object(&jl),
                                        JValue::Object(&je),
                                    ],
                                );
                                let _ = env.exception_clear();
                            }
                        }
                        continue;
                    }

                    let is_update_event = matches!(
                        event,
                        AnetEvent::UpdateAvailable(_)
                            | AnetEvent::UpdateProgress(_)
                            | AnetEvent::UpdateStatus(_)
                            | AnetEvent::UpdateReady
                    );
                    let callback_ref_opt = if is_update_event {
                        UI_CALLBACK_REF.lock().unwrap().clone()
                    } else {
                        VPN_CALLBACK_REF.lock().unwrap().clone()
                    };

                    if let Some(callback_ref) = callback_ref_opt {
                        match event {
                            AnetEvent::ClientStateChanged { state, message, server_name } => {
                                let jmsg = env.new_string(message);
                                let jserver = env.new_string(server_name.unwrap_or_default());
                                if let (Ok(jmsg), Ok(jserver)) = (jmsg, jserver) {
                                    let _ = env.call_method(
                                        &callback_ref,
                                        "onVpnStateChanged",
                                        "(ILjava/lang/String;Ljava/lang/String;)V",
                                        &[
                                            JValue::Int(client_state_code(state)),
                                            JValue::Object(&jmsg),
                                            JValue::Object(&jserver),
                                        ],
                                    );
                                    let _ = env.exception_clear();
                                }
                            }
                            AnetEvent::Stats { rx, tx, rtt, rxm, txm } => {
                                let j_rx = env.new_string(rx);
                                let j_tx = env.new_string(tx);
                                let j_rtt = env.new_string(rtt);
                                let j_rxm = env.new_string(rxm);
                                let j_txm = env.new_string(txm);
                                if let (Ok(j_rx), Ok(j_tx), Ok(j_rtt), Ok(j_rxm), Ok(j_txm)) =
                                    (j_rx, j_tx, j_rtt, j_rxm, j_txm)
                                {
                                    let _ = env.call_method(
                                        &callback_ref,
                                        "onTrafficStats",
                                        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                                        &[
                                            JValue::Object(&j_rx),
                                            JValue::Object(&j_tx),
                                            JValue::Object(&j_rtt),
                                            JValue::Object(&j_rxm),
                                            JValue::Object(&j_txm),
                                        ],
                                    );
                                    let _ = env.exception_clear();
                                }
                            }
                            AnetEvent::TrafficUpdate { rx, tx, rtt, rxm, txm } => {
                                let j_rx = env.new_string(format_bytes(rx));
                                let j_tx = env.new_string(format_bytes(tx));
                                let j_rtt = env.new_string(format!("{rtt}ms"));
                                let j_rxm = env.new_string(format_bytes_per_sec(rxm as f64));
                                let j_txm = env.new_string(format_bytes_per_sec(txm as f64));
                                if let (Ok(j_rx), Ok(j_tx), Ok(j_rtt), Ok(j_rxm), Ok(j_txm)) =
                                    (j_rx, j_tx, j_rtt, j_rxm, j_txm)
                                {
                                    let _ = env.call_method(
                                        &callback_ref,
                                        "onTrafficStats",
                                        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                                        &[
                                            JValue::Object(&j_rx),
                                            JValue::Object(&j_tx),
                                            JValue::Object(&j_rtt),
                                            JValue::Object(&j_rxm),
                                            JValue::Object(&j_txm),
                                        ],
                                    );
                                    let _ = env.exception_clear();
                                }
                            }
                            other => {
                                if let Some(msg) = event_message(other) {
                                    if let Ok(jmsg) = env.new_string(msg) {
                                        let _ = env.call_method(
                                            &callback_ref,
                                            "onStatusChanged",
                                            "(Ljava/lang/String;)V",
                                            &[JValue::Object(&jmsg)],
                                        );
                                        let _ = env.exception_clear();
                                    }
                                }
                            }
                        }
                    }
                }
            }
            info!("Rust JNI Bridge: Dedicated OS thread exiting.");
        });
        tx
    });
}

/// Запускает фоновый монитор состояния сети и линейного пульса сразу при открытии Android-приложения
/// (работает постоянно — как при выключенном, так и при включённом VPN).
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_MainActivity_startConnectivityMonitor(
    mut env: JNIEnv,
    this: JObject,
    config_jstr: JString,
) {
    let jvm = env.get_java_vm().unwrap();
    let jvm_arc = Arc::new(jvm);
    if let Ok(this_ref) = env.new_global_ref(this) {
        *UI_CALLBACK_REF.lock().unwrap() = Some(this_ref);
    }

    events::set_handler(Box::new(AndroidEventHandler));
    init_jni_bridge_thread(jvm_arc);

    let config_toml: String = env
        .get_string(&config_jstr)
        .map(Into::into)
        .unwrap_or_default();

    let connectivity_cfg = if !config_toml.trim().is_empty() {
        anet_client_core::config::ConnectivityConfig::from_toml_str(&config_toml)
    } else {
        anet_client_core::config::ConnectivityConfig::default()
    };

    let rt = get_or_init_runtime_handle();
    rt.spawn(async move {
        anet_client_core::connectivity_monitor::ConnectivityMonitor::ensure_started(
            connectivity_cfg,
        );
        let initial =
            anet_client_core::connectivity_monitor::ConnectivityMonitor::get_last_snapshot();
        events::emit(AnetEvent::ConnectivityUpdated(initial));
        if let Some(cached_tel) = LAST_TELEMETRY.lock().unwrap().clone() {
            events::emit(AnetEvent::TelemetryUpdated(cached_tel));
        }
        if let Some(cached_acc) = LAST_ACCOUNT_INFO.lock().unwrap().clone() {
            events::emit(AnetEvent::AccountInfo(cached_acc));
        }
        if !config_toml.trim().is_empty() {
            anet_client_core::connectivity_monitor::NodeProbeMonitor::update_config_toml(
                &config_toml,
            );
        }
    });
}

/// Принудительно запускает внеочередную проверку внешних контрольных точек связности (РФ / Мир).
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_MainActivity_triggerConnectivityCheck(
    _env: JNIEnv,
    _this: JObject,
) {
    let rt = get_or_init_runtime_handle();
    let _guard = rt.enter();
    anet_client_core::connectivity_monitor::ConnectivityMonitor::trigger_check_now();
}

/// Принудительно запускает внеочередную проверку пинга и доступности узлов VPN.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_MainActivity_triggerNodeProbe(
    env: JNIEnv,
    this: JObject,
) {
    if let Ok(jvm) = env.get_java_vm() {
        let jvm_arc = Arc::new(jvm);
        if let Ok(this_ref) = env.new_global_ref(this) {
            *UI_CALLBACK_REF.lock().unwrap() = Some(this_ref);
        }
        events::set_handler(Box::new(AndroidEventHandler));
        init_jni_bridge_thread(jvm_arc);
    }
    let rt = get_or_init_runtime_handle();
    let _guard = rt.enter();
    anet_client_core::connectivity_monitor::NodeProbeMonitor::trigger_probe_now();
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_MainActivity_checkUpdates(
    mut env: JNIEnv,
    this: JObject,
    config_jstr: JString,
) {
    info!("JNI: checkUpdates called");

    let jvm = env.get_java_vm().unwrap();
    let jvm_arc = Arc::new(jvm);
    let this_ref = env.new_global_ref(this).unwrap();

    events::set_handler(Box::new(AndroidEventHandler));

    // Настраиваем глобальную ссылку для вызовов JNI-моста
    {
        *UI_CALLBACK_REF.lock().unwrap() = Some(this_ref);
    }

    init_jni_bridge_thread(jvm_arc);

    let config_toml: String = match env.get_string(&config_jstr) {
        Ok(s) => s.into(),
        Err(_) => String::new(),
    };

    let update_url = if !config_toml.is_empty() {
        match toml::from_str::<CoreConfig>(&config_toml) {
            Ok(c) => {
                let url = c.main.update_url.clone();
                if url.is_empty() {
                    "https://api.github.com/repos/ZeroTworu/anet/releases/latest".to_string()
                } else {
                    url
                }
            },
            Err(_) => "https://api.github.com/repos/ZeroTworu/anet/releases/latest".to_string(),
        }
    } else {
        "https://api.github.com/repos/ZeroTworu/anet/releases/latest".to_string()
    };

    let rt = {
        let mut rt_guard = RUNTIME.lock().unwrap();
        if rt_guard.is_none() {
            *rt_guard = Some(Runtime::new().unwrap());
        }
        rt_guard.as_ref().unwrap().handle().clone()
    };

    rt.spawn(async move {
        info!("[UPDATER] Checking URL: {}", update_url);
        let current_ver = GIT_TAG;

        match Updater::check_latest(&update_url, current_ver).await {
            Ok(Some(release)) => {
                *PENDING_RELEASE.lock().unwrap() = Some(release.clone());
                events::emit(AnetEvent::UpdateAvailable(release));
            }
            Ok(None) => {
                events::emit(AnetEvent::UpdateStatus("У вас установлена актуальная версия.".into()));
            }
            Err(e) => {
                error!("[UPDATER] Error: {}", e);
                events::emit(AnetEvent::UpdateStatus(format!("Ошибка обновления: {}", e)));
            }
        }
    });
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_MainActivity_startDownload(mut env: JNIEnv, _this: JObject, j_path: JString) {
    let path: String = env.get_string(&j_path).unwrap().into();
    let release_opt = PENDING_RELEASE.lock().unwrap().take();

    if let Some(release) = release_opt {
        let rt_guard = RUNTIME.lock().unwrap();
        if let Some(rt) = rt_guard.as_ref() {
            rt.spawn(async move {
                if let Err(e) = Updater::download_apk(release, path).await {
                    error!("Download failed: {}", e);
                    events::err(format!("Ошибка загрузки: {}", e));
                }
            });
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_MainActivity_getAppVersion(env: JNIEnv, _this: JClass) -> jni::sys::jstring {
    let version = format!("{} ({})", GIT_TAG, COMMIT_HASH);
    env.new_string(version).unwrap().into_raw()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_MainActivity_getBuildInfo(env: JNIEnv, _this: JClass) -> jni::sys::jstring {
    let info = format!("Type: {} | Time: {}", BUILD_TYPE, BUILD_TIME);
    env.new_string(info).unwrap().into_raw()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_MainActivity_initLogger(_env: JNIEnv, _class: JClass) {
    android_logger::init_once(
        Config::default()
            .with_max_level(LevelFilter::Info)
            .with_tag("ANetRust"),
    );
    info!("Rust Logger Initialized");
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_ANetVpnService_connectVpn(
    mut env: JNIEnv,
    this: jni::objects::JObject,
    config_jstr: JString,
    selected_server_jstr: JString,
) {
    info!("JNI: connectVpn called");

    // Автоматически определяем путь к приватному кэшу приложения через Android Context: this.getCacheDir().getAbsolutePath()
    if let Ok(cache_dir_val) = env.call_method(&this, "getCacheDir", "()Ljava/io/File;", &[]) {
        if let Ok(cache_dir_obj) = cache_dir_val.l() {
            if !cache_dir_obj.as_raw().is_null() {
                if let Ok(path_val) =
                    env.call_method(&cache_dir_obj, "getAbsolutePath", "()Ljava/lang/String;", &[])
                {
                    if let Ok(path_obj) = path_val.l() {
                        let path_jstr = JString::from(path_obj);
                        if let Ok(path_rust) = env.get_string(&path_jstr) {
                            let cache_dir_str: String = path_rust.into();
                            let rules_path =
                                std::path::PathBuf::from(cache_dir_str).join("rules.abc");
                            unsafe {
                                std::env::set_var(
                                    "ANET_RULES_CACHE_PATH",
                                    rules_path.to_string_lossy().to_string(),
                                );
                            }
                            info!(
                                "[Android JNI] Configured ANET_RULES_CACHE_PATH={}",
                                rules_path.display()
                            );
                        }
                    }
                }
            }
        }
    }

    // Подготавливаем потокобезопасные структуры за пределами Tokio-рантайма
    let jvm = env.get_java_vm().unwrap();
    let jvm_arc = Arc::new(jvm);
    let jvm_for_factory = jvm_arc.clone();
    let jvm_for_bridge = jvm_arc.clone();
    let this_ref = env.new_global_ref(this).unwrap();

    // Обновляем глобальную ссылку для JNI-моста
    {
        *VPN_CALLBACK_REF.lock().unwrap() = Some(this_ref.clone());
    }

    init_jni_bridge_thread(jvm_for_bridge);

    events::set_handler(Box::new(AndroidEventHandler));

    let mut rt_guard = RUNTIME.lock().unwrap();
    if rt_guard.is_none() {
        *rt_guard = Some(Runtime::new().unwrap());
    }
    let rt = rt_guard.as_ref().unwrap();

    let config_toml: String = match env.get_string(&config_jstr) {
        Ok(java_str) => java_str.into(),
        Err(e) => {
            error!("Failed to read config string: {}", e);
            return;
        }
    };

    let selected_server: String = match env.get_string(&selected_server_jstr) {
        Ok(java_str) => java_str.into(),
        Err(_) => String::new(),
    };

    let mut config: CoreConfig = match toml::from_str::<CoreConfig>(&config_toml) {
        Ok(mut c) => {
            c.connectivity.apply_toml_fallbacks(&config_toml);
            c
        }
        Err(e) => {
            error!("Failed to parse TOML config: {}", e);
            status(format!("Failed to parse TOML config: {}", e));
            client_state(ClientState::Failed, format!("Invalid configuration: {e}"), None);
            return;
        }
    };

    let generation = CLIENT_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
    rt.spawn(async move {
        let client = {
            let _lifecycle = CLIENT_LIFECYCLE.lock().await;
            if CLIENT_GENERATION.load(Ordering::SeqCst) != generation { return; }
            let old_client = CLIENT.lock().unwrap().take();
            if let Some(client) = old_client {
                info!("Rust JNI: Stopping old active client task...");
                let _ = client.stop().await;
            }
            if CLIENT_GENERATION.load(Ordering::SeqCst) != generation { return; }
            if let Err(error) = config.sanitize() {
                client_state(ClientState::Failed, format!("Invalid configuration: {error}"), None);
                return;
            }

        let has_groups = config.servers.iter().any(|s| {
            s.group_name.as_ref().map_or(false, |g| !g.trim().is_empty())
        });

        if has_groups {
            let selected_group_id = if !selected_server.is_empty() {
                selected_server.clone()
            } else {
                config.servers.iter()
                    .find_map(|s| {
                        if s.group_name.as_deref().map_or(true, |g| g.trim().is_empty()) { return None; }
                        Some(s.group_id.as_deref().unwrap_or(s.group_name.as_ref().unwrap()).trim().to_string())
                    })
                    .unwrap_or_default()
            };

            let mut group_servers: Vec<_> = config.servers
                .iter()
                .filter(|s| {
                    if s.group_name.as_deref().map_or(true, |g| g.trim().is_empty()) { return false; }
                    let g_id = s.group_id.as_deref().unwrap_or(s.group_name.as_ref().unwrap()).trim();
                    g_id == selected_group_id.as_str()
                })
                .cloned()
                .collect();

            group_servers.sort_by(|a, b| b.weight().cmp(&a.weight()));

            if !group_servers.is_empty() {
                config.servers = group_servers;
                anet_client_core::events::status(format!("Группа выбрана (id): {}", selected_group_id));
            }
        } else if !selected_server.is_empty() {
            if let Some(idx) = config
                .servers
                .iter()
                .position(|s| s.dsn == selected_server || s.get_name() == selected_server)
            {
                config.servers.rotate_left(idx);
                anet_client_core::events::status(format!("Приоритет установлен: {}", selected_server));
            }
        }

            let bypass_ips = Arc::new(std::sync::Mutex::new(Vec::new()));
            let tun_factory = Box::new(AndroidCallbackTunFactory::new(
                jvm_for_factory,
                this_ref.clone(),
                config.clone(),
                bypass_ips.clone(),
            ));
            let route_manager = Box::new(AndroidRouteManager::new(bypass_ips));
            let client = Arc::new(AnetClient::new(config, tun_factory, route_manager));
            *CLIENT.lock().unwrap() = Some(client.clone());
            client
        };

        info!("Rust: Calling start()...");
        match client.start().await {
            Ok(_) => info!("Rust: VPN Loop exited cleanly"),
            Err(e) => {
                error!("Rust: VPN Start Failed: {}", e);
                client_state(ClientState::Failed, format!("VPN start failed: {e}"), None);
            }
        }
    });
}

// =========================================================================
// ПЕРЕНЕСЕНО ИЗ 073: Внешний триггер мгновенного переподключения
// =========================================================================
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_ANetVpnService_reconnectVpn(_env: JNIEnv, _class: JClass) {
    info!("Rust: reconnectVpn JNI trigger received");
    let client_opt = {
        let client_guard = CLIENT.lock().unwrap();
        client_guard.clone()
    };
    if let Some(client) = client_opt {
        client.trigger_reconnect();
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_ANetVpnService_stopVpn(_env: JNIEnv, _class: JClass) {
    info!("Rust: stopVpn JNI trigger received");
    client_state(ClientState::Stopping, "Stopping VPN", None);

    CLIENT_GENERATION.fetch_add(1, Ordering::SeqCst);
    let rt_guard = RUNTIME.lock().unwrap();
    if let Some(rt) = rt_guard.as_ref() {
        let client_opt = {
            let mut client_guard = CLIENT.lock().unwrap();
            client_guard.take()
        };
        if let Some(client) = client_opt {
            rt.block_on(async move {
                let _lifecycle = CLIENT_LIFECYCLE.lock().await;
                info!("Rust JNI: Sending stop signal to active client loop...");
                let _ = client.stop().await;
            });
        }
    }
    client_state(ClientState::Stopped, "VPN stopped", None);
    status("VPN Stopped");
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_MainActivity_getPendingTag(env: JNIEnv, _this: JObject) -> jni::sys::jstring {
    let guard = PENDING_RELEASE.lock().unwrap();
    let tag = guard.as_ref().map(|r| r.tag_name.clone()).unwrap_or_else(|| "v0.0.0".to_string());
    env.new_string(tag).unwrap().into_raw()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_MainActivity_getPendingBody(env: JNIEnv, _this: JObject) -> jni::sys::jstring {
    let guard = PENDING_RELEASE.lock().unwrap();
    let body = guard.as_ref()
        .and_then(|r| r.body.clone())
        .unwrap_or_else(|| "Описание изменений отсутствует.".to_string());
    env.new_string(body).unwrap().into_raw()
}
