include!(concat!(env!("OUT_DIR"), "/built.rs"));

mod android_impl;

use crate::android_impl::AndroidCallbackTunFactory;
use android_logger::Config;
use anet_client_core::client::AnetClient;
use anet_client_core::config::CoreConfig;
use anet_client_core::events::{self, AnetEvent, ClientState, EventHandler, client_state, status};
use anet_client_core::updater::{GithubRelease, Updater};
use anet_client_core::platform::NoOpRouteManager;
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

// --- ГЛОБАЛЬНЫЙ МНОГОПОТОЧНЫЙ JNI-МОСТ (Защита от утечек и дедлоков) ---
static JNI_SENDER: OnceLock<Sender<AnetEvent>> = OnceLock::new();
static VPN_CALLBACK_REF: Mutex<Option<GlobalRef>> = Mutex::new(None);
static UI_CALLBACK_REF: Mutex<Option<GlobalRef>> = Mutex::new(None);

// Наш асинхронный обработчик событий ядра.
// Теперь он просто мгновенно отправляет события в канал, не блокируя Tokio-потоки вызовами JNI.
struct AndroidEventHandler;

impl EventHandler for AndroidEventHandler {
    fn on_event(&self, event: AnetEvent) {
        if let AnetEvent::ClientStateChanged {
            state, server_name, ..
        } = &event
        {
            CURRENT_CLIENT_STATE.store(client_state_code(*state), Ordering::SeqCst);
            if let Some(server_name) = server_name {
                *CURRENT_SERVER_NAME.lock().unwrap() = Some(server_name.clone());
            } else if matches!(state, ClientState::Disconnected | ClientState::Stopped) {
                *CURRENT_SERVER_NAME.lock().unwrap() = None;
            }
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
    for server in config.servers {
        result.push('\n');
        result.push_str(&server.get_name().replace(['\r', '\n'], " "));
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

fn event_message(event: AnetEvent) -> Option<String> {
    match event {
        AnetEvent::Status(s) | AnetEvent::UpdateStatus(s) => Some(s),
        AnetEvent::Warn(s) => Some(format!("WARN: {s}")),
        AnetEvent::Error(s) => Some(format!("ERROR: {s}")),
        AnetEvent::UpdateProgress(p) => Some(format!("PROGRESS:{p:.2}")),
        AnetEvent::UpdateAvailable(rel) => Some(format!("Найдено обновление: {}", rel.tag_name)),
        AnetEvent::UpdateReady => Some("Update downloaded to cache".to_string()),
        AnetEvent::TrafficUpdate { .. } | AnetEvent::ClientStateChanged { .. } => None,
    }
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
                address = "127.0.0.1:443"
                mode = "quic"
            "#,
        );
        assert_eq!(result, "OK\nPrimary");
    }

    #[test]
    fn config_inspection_reports_invalid_toml() {
        assert!(inspect_config("not toml").starts_with("ERROR\n"));
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
        .map(|value| inspect_config(&String::from(value)))
        .unwrap_or_else(|error| format!("ERROR\n{error}"));
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
        let (tx, rx) = mpsc::channel::<AnetEvent>();

        std::thread::spawn(move || {
            info!("Rust JNI Bridge: Dedicated OS thread started.");

            // Прикрепляем выделенный системный поток к JVM один раз
            if let Ok(mut env) = jvm.attach_current_thread() {
                while let Ok(event) = rx.recv() {
                    let is_update_event = matches!(event, AnetEvent::UpdateAvailable(_) | AnetEvent::UpdateProgress(_) | AnetEvent::UpdateStatus(_) | AnetEvent::UpdateReady);
                    let callback_ref_opt = if is_update_event {
                        UI_CALLBACK_REF.lock().unwrap().clone()
                    } else {
                        VPN_CALLBACK_REF.lock().unwrap().clone()
                    };

                    if let Some(callback_ref) = callback_ref_opt {
                        if let AnetEvent::ClientStateChanged { state, message, server_name } = event {
                            let jmsg = env.new_string(message);
                            let jserver = env.new_string(server_name.unwrap_or_default());
                            if let (Ok(jmsg), Ok(jserver)) = (jmsg, jserver) {
                                let _ = env.call_method(&callback_ref, "onVpnStateChanged", "(ILjava/lang/String;Ljava/lang/String;)V", &[
                                    JValue::Int(client_state_code(state)),
                                    JValue::Object(&jmsg),
                                    JValue::Object(&jserver),
                                ]);
                            }
                        } else if let Some(msg) = event_message(event) {
                            if let Ok(jmsg) = env.new_string(msg) {
                                let _ = env.call_method(
                                    &callback_ref,
                                    "onStatusChanged",
                                    "(Ljava/lang/String;)V",
                                    &[JValue::Object(&jmsg)],
                                );
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

    let mut config: CoreConfig = match toml::from_str(&config_toml) {
        Ok(c) => c,
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

        if !selected_server.is_empty() {
            if let Some(idx) = config.servers.iter().position(|s| s.get_name() == selected_server) {
                config.servers.rotate_left(idx);
                anet_client_core::events::status(format!("Приоритет установлен: {}", selected_server));
            }
        }

            let tun_factory = Box::new(AndroidCallbackTunFactory::new(jvm_for_factory, this_ref.clone(), config.clone()));
            let route_manager = Box::new(NoOpRouteManager);
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
