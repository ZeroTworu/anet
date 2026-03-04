use tray_icon::{
    menu::{Menu, MenuItem, PredefinedMenuItem, CheckMenuItem},
    TrayIcon, TrayIconBuilder,
};
use crate::icons;
use notify_rust::Notification;
use crate::app::ConnectionState;

pub struct TrayManager {
    pub tray_icon: TrayIcon,
    pub menu_show_id: tray_icon::menu::MenuId,
    pub menu_toggle_vpn_id: tray_icon::menu::MenuId,
    pub menu_quit_id: tray_icon::menu::MenuId,
    pub menu_disable_notifs_id: tray_icon::menu::MenuId,

    show_item: MenuItem,
    toggle_vpn_item: MenuItem,
    _disable_notifs_item: CheckMenuItem,
}

impl TrayManager {
    pub fn new(notifications_muted: bool) -> Self {
        let show_item = MenuItem::new("👁 Развернуть ANet", false, None);
        let toggle_vpn_item = MenuItem::new("⚪ Подключить VPN", true, None);
        let disable_notifs_item = CheckMenuItem::new("🔕 Без уведомлений", true, notifications_muted, None);
        let quit_item = MenuItem::new("❌ Выход", true, None);

        let menu_show_id = show_item.id().clone();
        let menu_toggle_vpn_id = toggle_vpn_item.id().clone();
        let menu_disable_notifs_id = disable_notifs_item.id().clone();
        let menu_quit_id = quit_item.id().clone();

        let tray_menu = Menu::new();
        let _ = tray_menu.append_items(&[
            &show_item, &PredefinedMenuItem::separator(),
            &toggle_vpn_item, &PredefinedMenuItem::separator(),
            &disable_notifs_item, &PredefinedMenuItem::separator(),
            &quit_item,
        ]);

        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(tray_menu))
            .with_tooltip("ANet VPN (Standby)")
            .with_icon(icons::load_tray_icon())
            .build()
            .unwrap();

        Self {
            tray_icon, menu_show_id, menu_toggle_vpn_id, menu_disable_notifs_id, menu_quit_id,
            show_item, toggle_vpn_item, _disable_notifs_item: disable_notifs_item,
        }
    }

    pub fn update_window_visibility(&self, is_visible: bool) {
        self.show_item.set_enabled(!is_visible);
    }

    pub fn update_vpn_state(&self, state: ConnectionState) {
        match state {
            ConnectionState::Disconnected => {
                self.toggle_vpn_item.set_text("🟢 Подключить VPN");
                let _ = self.tray_icon.set_tooltip(Some("ANet VPN - Отключен"));
            }
            ConnectionState::Connecting => {
                self.toggle_vpn_item.set_text("🔴 Отменить подключение");
                let _ = self.tray_icon.set_tooltip(Some("ANet VPN - Соединяемся... 🔄"));
            }
            ConnectionState::Connected => {
                self.toggle_vpn_item.set_text("🔴 Отключить VPN");
                let _ = self.tray_icon.set_tooltip(Some("ANet VPN - Сеть защищена 🛡️"));
            }
        }
    }

    pub fn notify_hidden(&self) { send_system_notification("ANet VPN работает 🕵️‍♂️", "Приложение свернуто в трей."); }
    pub fn notify_connecting(&self) { send_system_notification("Попытка доступа 📡", "Идёт установка защищённого туннеля..."); }
    pub fn notify_connected(&self) { send_system_notification("Связь установлена 🟢", "ANet успешно подключился. Трафик защищён."); }
    pub fn notify_disconnected(&self) { send_system_notification("Связь прервана 🔴", "Соединение разорвано."); }
}

fn send_system_notification(title: &str, body: &str) {
    let _ = Notification::new().summary(title).body(body).appname("ANet").show();
}