use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use tray_icon::{
    menu::{Menu, MenuItem, PredefinedMenuItem, CheckMenuItem, MenuEvent},
    TrayIconBuilder,
};

use crate::icons;
use crate::config::AppSettings;
use crate::app::{SharedState, ConnectionState};
use notify_rust::Notification;

#[cfg(target_os = "windows")]
use windows_sys::Win32::UI::WindowsAndMessaging::{
    PeekMessageW, TranslateMessage, DispatchMessageW, MSG, PM_REMOVE,
};

pub enum TrayCommand {
    WindowVisible(bool),
    NotifyHidden,
}

pub struct TrayBackground;

impl TrayBackground {
    pub fn spawn<F, G>(
        cmd_rx: Receiver<TrayCommand>,
        shared: Arc<Mutex<SharedState>>,
        settings: Arc<Mutex<AppSettings>>,
        on_show: F,
        on_toggle: G,
    ) where
        F: Fn() + Send + 'static,
        G: Fn() + Send + 'static,
    {
        std::thread::spawn(move || {
            let show_item = MenuItem::new("👁 Развернуть ANet", false, None);
            let toggle_vpn_item = MenuItem::new("⚪ Подключить VPN", true, None);
            let disable_notifs_item = CheckMenuItem::new("🔕 Без уведомлений", true, false, None);
            let quit_item = MenuItem::new("❌ Выход", true, None);

            let menu = Menu::new();
            let _ = menu.append_items(&[
                &show_item,
                &PredefinedMenuItem::separator(),
                &toggle_vpn_item,
                &PredefinedMenuItem::separator(),
                &disable_notifs_item,
                &PredefinedMenuItem::separator(),
                &quit_item,
            ]);

            let tray_icon = TrayIconBuilder::new()
                .with_menu(Box::new(menu))
                .with_tooltip("ANet VPN (Standby)")
                .with_icon(icons::load_tray_icon())
                .build()
                .unwrap();

            let id_show    = show_item.id().as_ref().to_string();
            let id_toggle  = toggle_vpn_item.id().as_ref().to_string();
            let id_quit    = quit_item.id().as_ref().to_string();
            let id_disable = disable_notifs_item.id().as_ref().to_string();

            let menu_rx = MenuEvent::receiver();
            let mut last_state = ConnectionState::Disconnected;

            loop {
                #[cfg(target_os = "windows")]
                unsafe {
                    let mut msg: MSG = std::mem::zeroed();
                    while PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
                        TranslateMessage(&msg as *const _);
                        DispatchMessageW(&msg as *const _);
                    }
                }

                // --- Команды от GUI
                while let Ok(cmd) = cmd_rx.try_recv() {
                    match cmd {
                        TrayCommand::WindowVisible(visible) => {
                            show_item.set_enabled(!visible);
                        }
                        TrayCommand::NotifyHidden => {
                            let muted = settings.lock().unwrap().disable_notifications;
                            if !muted { Self::notify_hidden(); }
                        }
                    }
                }

                // --- Клики по трею
                if let Ok(event) = menu_rx.try_recv() {
                    let eid = event.id.as_ref();
                    if eid == id_show { on_show(); }
                    else if eid == id_toggle { on_toggle(); }
                    else if eid == id_quit { std::process::exit(0); }
                    else if eid == id_disable {
                        let mut stg = settings.lock().unwrap();
                        stg.disable_notifications = !stg.disable_notifications;
                        stg.save();
                    }
                }

                // --- МОНИТОРИНГ СОСТОЯНИЯ VPN
                let current_state = shared.lock().unwrap().state;
                if current_state != last_state {
                    last_state = current_state;
                    let muted = settings.lock().unwrap().disable_notifications;

                    match current_state {
                        ConnectionState::Disconnected => {
                            toggle_vpn_item.set_text("🟢 Подключить VPN");
                            let _ = tray_icon.set_tooltip(Some("ANet VPN (Отключено)"));
                            if !muted { Self::notify_disconnected(); }
                        }
                        ConnectionState::Connecting => {
                            toggle_vpn_item.set_text("🔴 Отменить подключение");
                            let _ = tray_icon.set_tooltip(Some("ANet VPN (Подключение...)"));
                            if !muted { Self::notify_connecting(); }
                        }
                        ConnectionState::Connected => {
                            toggle_vpn_item.set_text("🔴 Отключить VPN");
                            let _ = tray_icon.set_tooltip(Some("ANet VPN (Подключено)"));
                            if !muted { Self::notify_connected(); }
                        }
                    }
                }

                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        });
    }

    pub fn notify_hidden() { send_system_notification("ANet VPN работает 🕵️‍♂️", "Приложение свернуто в трей."); }
    pub fn notify_connecting() { send_system_notification("Попытка доступа 📡", "Идёт установка защищённого туннеля..."); }
    pub fn notify_connected() { send_system_notification("Связь установлена 🟢", "ANet успешно подключился. Трафик защищён."); }
    pub fn notify_disconnected() { send_system_notification("Связь прервана 🔴", "Соединение разорвано."); }
}

fn send_system_notification(title: &str, body: &str) {
    let _ = Notification::new().summary(title).body(body).appname("ANet").show();
}