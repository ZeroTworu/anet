mod android_impl;

use crate::android_impl::{AndroidRouteManager, AndroidCallbackTunFactory};
use android_logger::Config;
use anet_client_core::config::{CoreConfig, ClientKeys, MainConfig, StatsConfig};
use anet_common::config::StealthConfig;
use anet_client_core::AnetClient;
use anet_common::quic_settings::QuicConfig;
use jni::objects::{GlobalRef, JClass, JValue};
use jni::{JNIEnv, JavaVM};
use log::{error, info, LevelFilter};
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;
use anet_client_core::events::{self, AnetEvent, EventHandler};

// Глобальный стейт, чтобы хранить клиента между вызовами
static CLIENT: Mutex<Option<Arc<AnetClient>>> = Mutex::new(None);
// Рантайм тоже нужно хранить глобально
static RUNTIME: Mutex<Option<Runtime>> = Mutex::new(None);

/// Инициализация логгера (вызывается из Java onCreate)
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_ANetVpnService_initLogger(
    _env: JNIEnv,
    _class: JClass,
) {
    android_logger::init_once(
        Config::default().with_max_level(LevelFilter::Info).with_tag("ANetRust"),
    );
    info!("Rust Logger Initialized");
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_MainActivity_initLogger(
    _env: JNIEnv,
    _class: JClass,
) {
    android_logger::init_once(
        Config::default().with_max_level(LevelFilter::Info).with_tag("ANetRust"),
    );
    info!("Rust Logger Initialized");
}

struct AndroidEventHandler {
    jvm: Arc<JavaVM>,
    // Нам нужен глобальный реф на объект, который умеет принимать события.
    // В нашем случае это VpnService (this).
    callback_ref: GlobalRef,
}

impl EventHandler for AndroidEventHandler {
    fn on_event(&self, event: AnetEvent) {
        // Присоединяемся к JVM (этот поток может быть любым)
        if let Ok(mut env) = self.jvm.attach_current_thread() {
            match event {
                AnetEvent::Status(msg) => {
                    // Конвертируем Rust String -> Java String
                    if let Ok(jmsg) = env.new_string(msg) {
                        // Вызываем void onStatusChanged(String msg)
                        let _ = env.call_method(
                            &self.callback_ref,
                            "onStatusChanged",
                            "(Ljava/lang/String;)V",
                            &[JValue::Object(&jmsg)],
                        );
                    }
                }
                _ => { info!("Event called {:?}", event); }
            }
        }
    }
}


/// Кнопка Connect
#[unsafe(no_mangle)]
 pub extern "system" fn Java_org_alco_anet_ANetVpnService_connectVpn(
    env: JNIEnv,
    this: jni::objects::JObject,
) {
    info!("JNI: connectVpn called");

    let jvm = env.get_java_vm().unwrap();
    let jvm = Arc::new(jvm); // Arc<JavaVM> - Send

    let this_ref = env.new_global_ref(this).unwrap(); // GlobalRef - Send
    // 1. Поднимаем Runtime (если нет)
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

    // 2. Хардкодим конфиг (для теста!)
    // Вставь сюда РЕАЛЬНЫЕ ключи и IP своего сервера
    let config = CoreConfig {
        main: MainConfig {
            address: "".to_string(),
            tun_name: "tun0".to_string(),
        },
        keys: ClientKeys {
            private_key: "".to_string(),
            server_pub_key: "".to_string(),
        },
        quic_transport: QuicConfig::default(),
        stats: StatsConfig::default(),
        stealth: StealthConfig {
            padding_step: 0,
            min_jitter_ns: 0,
            max_jitter_ns: 0,
        },
    };

    // 3. Запускаем
    rt.spawn(async move {
        info!("Rust: Creating client...");

        // env здесь уже НЕДОСТУПЕН и не нужен

        let tun_factory = Box::new(AndroidCallbackTunFactory::new(jvm.clone(), this_ref.clone()));
        let route_manager = Box::new(AndroidRouteManager);

        let client = Arc::new(AnetClient::new(
            config,
            tun_factory,
            route_manager,
        ));

        info!("Rust: Calling start()...");
        match client.start().await {
            Ok(_) => info!("Rust: VPN Started!"),
            Err(e) => error!("Rust: VPN Start Failed: {}", e),
        }

        *CLIENT.lock().unwrap() = Some(client);
    });
}
