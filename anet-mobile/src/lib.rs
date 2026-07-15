include!(concat!(env!("OUT_DIR"), "/built.rs"));

mod android_impl;

use crate::android_impl::AndroidCallbackTunFactory;
use android_logger::Config;
use anet_client_core::client::AnetClient;
use anet_client_core::config::CoreConfig;
use anet_client_core::events::{self, AnetEvent, EventHandler, status};
use anet_client_core::updater::{GithubRelease, Updater};
use anet_client_core::platform::NoOpRouteManager;
use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::{JNIEnv, JavaVM};
use log::{LevelFilter, error, info};
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;

/// Глобальный стейт, чтобы хранить клиента между вызовами
static CLIENT: Mutex<Option<Arc<AnetClient>>> = Mutex::new(None);
/// Рантайм тоже нужно хранить глобально
static RUNTIME: Mutex<Option<Runtime>> = Mutex::new(None);

static PENDING_RELEASE: Mutex<Option<GithubRelease>> = Mutex::new(None);

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_MainActivity_checkUpdates(
    mut env: JNIEnv,
    this: JObject,
    config_jstr: JString,
) {
    info!("JNI: checkUpdates called");

    let jvm = Arc::new(env.get_java_vm().unwrap());
    let this_ref = env.new_global_ref(this).unwrap();

    events::set_handler(Box::new(AndroidEventHandler {
        jvm: jvm.clone(),
        callback_ref: this_ref,
    }));

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
                status("У вас установлена актуальная версия.");
            }
            Err(e) => {
                error!("[UPDATER] Error: {}", e);
                status(format!("Ошибка обновления: {}", e));
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
pub extern "system" fn Java_org_alco_anet_ANetVpnService_initLogger(_env: JNIEnv, _class: JClass) {
    android_logger::init_once(
        Config::default()
            .with_max_level(LevelFilter::Info)
            .with_tag("ANetRust"),
    );
    info!("Rust Logger Initialized");
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

struct AndroidEventHandler {
    jvm: Arc<JavaVM>,
    callback_ref: GlobalRef,
}

impl EventHandler for AndroidEventHandler {
    fn on_event(&self, event: AnetEvent) {
        if let Ok(mut env) = self.jvm.attach_current_thread() {
            let msg_to_send: Option<String> = match event {
                AnetEvent::Status(s) => Some(s),
                AnetEvent::Warn(s) => Some(format!("WARN: {}", s)),
                AnetEvent::Error(s) => Some(format!("ERROR: {}", s)),
                AnetEvent::UpdateProgress(p) => Some(format!("PROGRESS:{:.2}", p)),
                AnetEvent::UpdateAvailable(rel) => Some(format!("Найдено обновление: {}", rel.tag_name)),
                AnetEvent::UpdateReady => Some("Update downloaded to cache".to_string()),
                _ => None,
            };

            if let Some(msg) = msg_to_send {
                if let Ok(jmsg) = env.new_string(msg) {
                    let _ = env.call_method(
                        &self.callback_ref,
                        "onStatusChanged",
                        "(Ljava/lang/String;)V",
                        &[JValue::Object(&jmsg)],
                    );
                }
            }
        }
    }
}

/// Кнопка Connect (Остановка старого клиента включена для предотвращения утечек памяти)
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_ANetVpnService_connectVpn(
    mut env: JNIEnv,
    this: JObject,
    config_jstr: JString,
    selected_server_jstr: JString,
) {
    info!("JNI: connectVpn called");

    let jvm = env.get_java_vm().unwrap();
    let jvm = Arc::new(jvm);

    let this_ref = env.new_global_ref(this).unwrap();
    let mut rt_guard = RUNTIME.lock().unwrap();
    if rt_guard.is_none() {
        *rt_guard = Some(Runtime::new().unwrap());
    }
    let rt = rt_guard.as_ref().unwrap();

    let event_ref = this_ref.clone();

    events::set_handler(Box::new(AndroidEventHandler {
        jvm: jvm.clone(),
        callback_ref: event_ref,
    }));

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
            return;
        }
    };

    rt.spawn(async move {
        let old_client = {
            let mut client_guard = CLIENT.lock().unwrap();
            client_guard.take()
        };
        if let Some(client) = old_client {
            info!("Rust JNI: Stopping old active client task...");
            let _ = client.stop().await;
        }

        // Применяем санитайзер
        let _ = config.sanitize();

        // Ротация серверов
        if !selected_server.is_empty() {
            if let Some(idx) = config.servers.iter().position(|s| s.get_name() == selected_server) {
                config.servers.rotate_left(idx);
                info!("Rust: Reordered server list. Starting node: {}", selected_server);
            }
        }

        let tun_factory = Box::new(AndroidCallbackTunFactory::new(
            jvm.clone(),
            this_ref.clone(),
            config.clone(),
        ));
        let route_manager = Box::new(NoOpRouteManager);

        let client = Arc::new(AnetClient::new(config, tun_factory, route_manager));

        {
            *CLIENT.lock().unwrap() = Some(client.clone());
        }

        info!("Rust: Calling start()...");
        match client.start().await {
            Ok(_) => info!("Rust: VPN Loop exited cleanly"),
            Err(e) => error!("Rust: VPN Start Failed: {}", e),
        }
    });
}

/// Кнопка Stop (Принудительно тушит клиентскую задачу в рантайме)
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_ANetVpnService_stopVpn(_env: JNIEnv, _class: JClass) {
    info!("Rust: stopVpn JNI trigger received");

    let rt_guard = RUNTIME.lock().unwrap();
    if let Some(rt) = rt_guard.as_ref() {
        let client_opt = {
            let mut client_guard = CLIENT.lock().unwrap();
            client_guard.take()
        };
        if let Some(client) = client_opt {
            // Асинхронно останавливаем клиент в контексте нашего рантайма
            rt.spawn(async move {
                info!("Rust JNI: Sending stop signal to active client loop...");
                let _ = client.stop().await;
            });
        }
    }
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
