use crate::config::AppSettings;
use crate::tun_factory::DesktopTunFactory;
use crate::tray::TrayManager;
use anet_client_core::client::AnetClient;
use anet_client_core::config::CoreConfig;
use anet_client_core::events::{AnetEvent, EventHandler, set_handler};
use anet_client_core::platform::create_route_manager;
use eframe::egui;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;
use tray_icon::menu::MenuEvent;
use tokio::runtime::Handle;
use notify_rust::Notification;


// --- Event Handler ---
pub struct GuiEventHandler {
    tx: Sender<AnetEvent>,
}

impl GuiEventHandler {
    pub fn new(tx: Sender<AnetEvent>) -> Self {
        Self { tx }
    }
}

impl EventHandler for GuiEventHandler {
    fn on_event(&self, event: AnetEvent) {
        let _ = self.tx.send(event.clone());
    }
}

// --- App State Enum ---
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
}

pub struct SharedState { client: Option<Arc<AnetClient>>,
    state: ConnectionState,
}

// --- App Struct ---
pub struct ANetApp {
    rt: Runtime,
    logs: Arc<Mutex<Vec<String>>>,
    config_err: Option<String>,
    config_name: String,
    event_rx: Receiver<AnetEvent>,
    settings: Arc<Mutex<AppSettings>>,

    shared: Arc<Mutex<SharedState>>,

    tray_mgr: TrayManager,
    last_known_state: ConnectionState,
    window_hidden_notified: bool,

    // Our new fields for sidebar
    sidebar_open: bool,
    editing_config_id: Option<String>,
    edit_name_buffer: String,
}

fn send_notification(title: &str, body: &str) {
    let _ = Notification::new()
        .summary(title)
        .body(body)
        .appname("ANet VPN")
        .icon("dialog-information")
        .show();
}

fn toggle_vpn(shared: &Arc<Mutex<SharedState>>, rt_handle: &Handle, logs: &Arc<Mutex<Vec<String>>>) {
    let mut guard = shared.lock().unwrap();

    if guard.state == ConnectionState::Disconnected {
        // Убрали & перед guard, просто клонируем Option целиком
        if let Some(client_clone) = guard.client.clone() {
            guard.state = ConnectionState::Connecting;

            let logs_clone = logs.clone();
            rt_handle.spawn(async move {
                logs_clone.lock().unwrap().push("> Starting service...".into());
                match client_clone.start().await {
                    Ok(_) => logs_clone.lock().unwrap().push("> VPN Stopped (Ok)".into()),
                    Err(e) => logs_clone.lock().unwrap().push(format!("> Error: {}", e)),
                }
            });
        }
    } else {
        if let Some(client_clone) = guard.client.clone() {
            guard.state = ConnectionState::Disconnected;

            let logs_clone = logs.clone();
            rt_handle.spawn(async move {
                logs_clone.lock().unwrap().push("> Stopping service...".into());
                let _ = client_clone.stop().await;
            });
        }
    }
}

impl ANetApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let (tx, rx) = channel();
        set_handler(Box::new(GuiEventHandler::new(tx)));

        let settings = AppSettings::load();
        let settings_arc = Arc::new(Mutex::new(settings));

        let logs = Arc::new(Mutex::new(vec!["> System Ready...".to_string()]));

        let shared = Arc::new(Mutex::new(SharedState {
            client: None,
            state: ConnectionState::Disconnected,
        }));

        // --- НАСТРОЙКА ТРЕЯ ---
        let is_muted = settings_arc.lock().unwrap().disable_notifications;
        let tray_mgr = TrayManager::new(is_muted);

        let menu_show_id = tray_mgr.menu_show_id.clone();
        let menu_toggle_vpn_id = tray_mgr.menu_toggle_vpn_id.clone();
        let menu_quit_id = tray_mgr.menu_quit_id.clone();
        let menu_disable_notifs_id = tray_mgr.menu_disable_notifs_id.clone();

        // --- ФОНОВЫЙ ПОТОК КЛИКОВ ПО ТРЕЮ ---
        let tray_ctx = cc.egui_ctx.clone();
        let tray_shared = shared.clone();
        let tray_logs = logs.clone();
        let tray_settings_arc = settings_arc.clone();
        let rt = Runtime::new().unwrap();
        let tray_rt_handle = rt.handle().clone();

        std::thread::spawn(move || {

            let menu_rx = MenuEvent::receiver();
            loop {
                if let Ok(event) = menu_rx.try_recv() {
                    if event.id == menu_show_id {
                        force_wake_up_window(&tray_ctx);
                    } else if event.id == menu_disable_notifs_id {

                        let mut stg = tray_settings_arc.lock().unwrap();
                        stg.disable_notifications = !stg.disable_notifications;
                        stg.save();


                    } else if event.id == menu_toggle_vpn_id {
                        toggle_vpn(&tray_shared, &tray_rt_handle, &tray_logs);
                        tray_ctx.request_repaint(); // Форс обновление UI
                    } else if event.id == menu_quit_id {
                        {
                            let guard = tray_shared.lock().unwrap();
                            if guard.state != ConnectionState::Disconnected {
                                if let Some(c) = &guard.client {
                                    let c_clone = c.clone();
                                    tray_rt_handle.spawn(async move {
                                        let _ = c_clone.stop().await;
                                    });
                                }
                            }
                        }
                        std::process::exit(0);
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        });

        // Формирование финала:
        let mut app = Self {
            rt, logs, config_err: None, config_name: "Файл не выбран".to_string(),
            event_rx: rx,
            settings: settings_arc,
            shared,
            tray_mgr,
            last_known_state: ConnectionState::Disconnected,
            window_hidden_notified: false,
            sidebar_open: true,
            editing_config_id: None,
            edit_name_buffer: String::new(),
        };

        // Автозагрузка активного конфига
        let config_to_load = app.settings.lock().unwrap().get_active_config().map(|c| (c.content.clone(), c.name.clone()));
        if let Some((content, name)) = config_to_load {
            app.load_config_from_content(&content, &name);
        }

        app
    }

    fn log(&self, msg: &str) {
        if let Ok(mut logs) = self.logs.lock() {
            logs.push(format!("> {}", msg));
        }
    }

    fn start_vpn(&mut self) {
        let mut guard = self.shared.lock().unwrap();

        if let Some(client_clone) = guard.client.clone() {
            guard.state = ConnectionState::Connecting;
            let logs_clone = self.logs.clone();

            self.rt.spawn(async move {
                logs_clone.lock().unwrap().push("> Starting service...".into());
                match client_clone.start().await {
                    Ok(_) => logs_clone.lock().unwrap().push("> VPN Stopped (Ok)".into()),
                    Err(e) => logs_clone.lock().unwrap().push(format!("> Error: {}", e)),
                }
            });
        }
    }

    fn stop_vpn(&mut self) {
        let mut guard = self.shared.lock().unwrap();

        if let Some(client_clone) = guard.client.clone() {
            guard.state = ConnectionState::Disconnected;
            let logs_clone = self.logs.clone();

            self.rt.spawn(async move {
                logs_clone.lock().unwrap().push("> Stopping service...".into());
                let _ = client_clone.stop().await;
            });
        }
    }

    fn open_file_dialog(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("TOML Config", &["toml"])
            .pick_file()
        {
            self.add_config_from_path(path);
        }
    }

    fn add_config_from_path(&mut self, path: PathBuf) {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "toml" {
            self.log("Please select a .toml file");
            return;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                self.log(&format!("Failed to read file: {}", e));
                return;
            }
        };

        let clean_content = Self::strip_toml_comments(&content);

        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Unnamed")
            .trim_end_matches(".toml")
            .to_string();

        let id = {
            let mut settings = self.settings.lock().unwrap();
            settings.add_config(name, clean_content)
        };
        
        self.select_config(&id);
    }

    fn strip_toml_comments(content: &str) -> String {
        let mut result = String::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                continue;
            }
            if let Some(pos) = line.find('#') {
                let before_comment = line[..pos].trim_end();
                if !before_comment.is_empty() {
                    result.push_str(before_comment);
                    result.push('\n');
                }
            } else {
                result.push_str(line);
                result.push('\n');
            }
        }
        result
    }

    fn delete_config(&mut self, id: &str) {
        {
            let mut settings = self.settings.lock().unwrap();
            settings.remove_config(id);
        }
        
        if self.shared.lock().unwrap().client.is_none() {
            self.config_name = "Config deleted".to_string();
        }
    }

    fn start_edit_name(&mut self, id: &str, current_name: &str) {
        self.editing_config_id = Some(id.to_string());
        self.edit_name_buffer = current_name.to_string();
    }

    fn finish_edit_name(&mut self) {
        if let Some(id) = &self.editing_config_id {
            let new_name = self.edit_name_buffer.trim().to_string();
            if !new_name.is_empty() {
                let mut settings = self.settings.lock().unwrap();
                settings.rename_config(id, new_name);
            }
        }
        self.editing_config_id = None;
        self.edit_name_buffer.clear();
    }

    fn select_config(&mut self, id: &str) {
        let config = {
            let mut settings = self.settings.lock().unwrap();
            settings.set_active(id);
            settings.get_active_config()
        };
        
        if let Some(config) = config {
            self.load_config_from_content(&config.content, &config.name);
        }
    }

    fn load_config_from_content(&mut self, content: &str, name: &str) {
        match toml::from_str::<CoreConfig>(content) {
            Ok(cfg) => {
                let tun = Box::new(DesktopTunFactory::new(
                    cfg.main.tun_name.clone(),
                ));
                let route = match create_route_manager(false) {
                    Ok(r) => r,
                    Err(e) => {
                        self.config_err = Some(format!("Failed to create route manager: {}", e));
                        self.log("Failed to create route manager");
                        return;
                    }
                };

                self.config_err = None;
                self.config_name = name.to_string();

                self.shared.lock().unwrap().client = Some(Arc::new(AnetClient::new(cfg, tun, route)));
                self.log(&format!("Config loaded: {}", self.config_name));
            }
            Err(e) => {
                self.config_err = Some(e.to_string());
                self.log("Failed to parse config TOML");
            }
        }
    }
}

fn force_wake_up_window(ctx: &egui::Context) {
    #[cfg(target_os = "windows")]
    {
        // BUG: https://github.com/emilk/egui/issues/5229
        use windows_sys::Win32::Foundation::{BOOL, HWND, LPARAM};
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            EnumWindows, GetWindowTextW, GetWindowThreadProcessId, SetForegroundWindow, ShowWindow,
            SW_RESTORE, SW_SHOW,
        };
        unsafe extern "system" fn enum_window_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
            let mut process_id: u32 = 0;
            unsafe { GetWindowThreadProcessId(hwnd, &mut process_id) };

            if process_id == lparam as u32 {
                // берём заголовок окна
                let mut title_buf = [0u16; 256]; // по заветам дидов - переполняем буффер!

                let len = unsafe { GetWindowTextW(hwnd, title_buf.as_mut_ptr(), title_buf.len() as i32) };

                if len > 0 {
                    let title = String::from_utf16_lossy(&title_buf[..len as usize]);
                    if title == "ANet VPN" {
                        unsafe {
                            ShowWindow(hwnd, SW_RESTORE);
                            ShowWindow(hwnd, SW_SHOW);
                            SetForegroundWindow(hwnd);
                        }

                        return 0;
                    }
                }
            }
            1
        }

        unsafe {
            let pid = std::process::id();
            EnumWindows(Some(enum_window_callback), pid as LPARAM);
        }
    }


    // На Windows системный хак выше разбудит поток, и egui прочитает эту команду из очереди
    ctx.send_viewport_cmd_to(egui::ViewportId::ROOT, egui::ViewportCommand::Visible(true));
    ctx.send_viewport_cmd_to(egui::ViewportId::ROOT, egui::ViewportCommand::Focus);
    ctx.request_repaint_of(egui::ViewportId::ROOT);
}

impl eframe::App for ANetApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        //ПЕРЕХВАТ КРЕСТИКА (Сворачивание в трей)
        if ctx.input(|i| i.viewport().close_requested()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));

            // Как только окно сжалось до квантового атома — обновляем пункт Трея (Разблокировать развертку)
            self.tray_mgr.update_window_visibility(false);

            if !self.window_hidden_notified {
                // Если юзер не замьютил попапы:
                if !self.settings.lock().unwrap().disable_notifications {
                    self.tray_mgr.notify_hidden();
                }
                self.window_hidden_notified = true;
            }
        } else {
            // Если окошко В ВИДОИСКАТЕЛЕ: Дизаблим в трее пункт разворачивания! Ибо мы и так открыты
            self.tray_mgr.update_window_visibility(true);
            // Резетим предупреждалку о сворачивании (чтобы при некст свапе еще раз показалось "я вишу в фоне")
            self.window_hidden_notified = false;
        }


        // 1. Обработка событий из канала
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                AnetEvent::Status(msg) => {
                    self.log(&msg);
                    if msg.contains("Tunnel UP") {
                        self.shared.lock().unwrap().state = ConnectionState::Connected;
                    }
                    if msg.contains("Error") || msg.contains("Stopped") {
                        self.shared.lock().unwrap().state = ConnectionState::Disconnected;
                    }
                }
                _ => {}
            }
        }

        let current_state = self.shared.lock().unwrap().state;

        if self.last_known_state != current_state {
            self.last_known_state = current_state;
            self.tray_mgr.update_vpn_state(current_state);

            // ТРИГГЕРИМ ВИНДУ/МАК (Но сначала - проверяем нашу настройку без лишнего шума)
            if !self.settings.lock().unwrap().disable_notifications {
                match current_state {
                    ConnectionState::Disconnected => self.tray_mgr.notify_disconnected(),
                    ConnectionState::Connecting => self.tray_mgr.notify_connecting(),
                    ConnectionState::Connected => self.tray_mgr.notify_connected(),
                }
            }
        }

        // Сосноль
        let console_frame = egui::Frame::NONE
            .fill(egui::Color32::from_rgb(10, 10, 10)) // ЧЕРНЫЙ ФОН
            .inner_margin(8.0) // Отступ текста от краев
            // Тонкая линия сверху, чтобы отделить от основного окна
            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(40, 40, 40)));

        egui::TopBottomPanel::bottom("stalker_console")
            .resizable(true)
            .min_height(100.0)
            .default_height(160.0)
            .frame(console_frame)
            .show(ctx, |ui| {
                ui.vertical(|ui| {
                    // Заголовок
                    ui.label(
                        egui::RichText::new("SYSTEM LOG")
                            .family(egui::FontFamily::Monospace)
                            .size(10.0)
                            .color(egui::Color32::from_gray(100)),
                    );

                    ui.add_space(4.0);

                    // Область скролла
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            let logs = self.logs.lock().unwrap();
                            for line in logs.iter() {
                                let color = if line.contains("Error") || line.contains("Failed") {
                                    egui::Color32::from_rgb(255, 80, 80) // Красный для ошибок
                                } else if line.contains("Tunnel UP") {
                                    egui::Color32::from_rgb(50, 255, 50) // Ярко-зеленый для успеха
                                } else {
                                    egui::Color32::from_rgb(0, 180, 0) // Тускло-зеленый для спама
                                };

                                // Отрисовка текста
                                // TextWrapping false, чтобы логи не переносились уродливо
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(line)
                                            .family(egui::FontFamily::Monospace)
                                            .size(11.0)
                                            .color(color),
                                    )
                                    .wrap(),
                                );
                            }
                        });
                });
            });
        // SidePanel - Список конфигов
        let settings_guard = self.settings.lock().unwrap();
        let configs = settings_guard.configs.clone();
        let active_id = settings_guard.active_config_id.clone();
        let editing_id = self.editing_config_id.clone();
        drop(settings_guard);

        egui::SidePanel::left("config_sidebar")
            .resizable(true)
            .default_width(250.0)
            .frame(egui::Frame::NONE.fill(egui::Color32::from_rgb(25, 25, 25)))
            .show_animated(ctx, self.sidebar_open, |ui: &mut egui::Ui| {
                ui.add_space(8.0);

                ui.label(
                    egui::RichText::new("КОНФИГИ")
                        .size(12.0)
                        .color(egui::Color32::from_gray(100)),
                );

                ui.add_space(8.0);

                // Список конфигов
                for config in configs {
                    let is_active = active_id.as_deref() == Some(&config.id);
                    let is_editing = editing_id.as_deref() == Some(&config.id);

                    let bg_color = if is_active {
                        egui::Color32::from_rgb(40, 80, 60)
                    } else {
                        egui::Color32::from_rgb(35, 35, 35)
                    };

                    let text_color = egui::Color32::from_gray(220);

                    egui::Frame::NONE
                        .fill(bg_color)
                        .inner_margin(4.0)
                        .show(ui, |ui: &mut egui::Ui| {
                            ui.horizontal(|ui: &mut egui::Ui| {
                                if is_editing {
                                    let response = ui.add(
                                        egui::TextEdit::singleline(&mut self.edit_name_buffer)
                                            .desired_width(120.0),
                                    );
                                    if response.lost_focus() {
                                        self.finish_edit_name();
                                    }
                                    if ui.button("✓").clicked() {
                                        self.finish_edit_name();
                                    }
                                } else {
                                    if ui
                                        .add(egui::Label::new(
                                            egui::RichText::new(&config.name).color(text_color)
                                        ).sense(egui::Sense::click()))
                                        .clicked()
                                    {
                                        self.select_config(&config.id);
                                    }

                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui: &mut egui::Ui| {
                                        if ui
                                            .add(egui::Button::new("✏").frame(false).small())
                                            .clicked()
                                        {
                                            self.start_edit_name(&config.id, &config.name);
                                        }
                                        if ui
                                            .add(egui::Button::new("🗑").frame(false).small())
                                            .clicked()
                                        {
                                            self.delete_config(&config.id);
                                        }
                                    });
                                }
                            });
                        });
                }

                ui.add_space(16.0);

                // Кнопка добавления
                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new("➕ Добавить конфиг")
                                .color(egui::Color32::WHITE)
                        )
                        .fill(egui::Color32::from_rgb(60, 60, 60))
                    )
                    .clicked()
                {
                    self.open_file_dialog();
                }
            });

        let main_frame = egui::Frame::NONE
            .fill(egui::Color32::from_rgb(18, 18, 18))
            .inner_margin(12.0);

        egui::CentralPanel::default()
            .frame(main_frame)
            .show(ctx, |ui| {
                // Header
                ui.horizontal(|ui| {
                    if ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new("☰")
                                    .size(24.0)
                                    .strong()
                                    .color(egui::Color32::WHITE),
                            )
                            .frame(false),
                        )
                        .clicked()
                    {
                        self.sidebar_open = !self.sidebar_open;
                    }

                    ui.add_space(8.0);

                    ui.label(
                        egui::RichText::new("ANet VPN")
                            .size(24.0)
                            .strong()
                            .color(egui::Color32::WHITE),
                    );
                });

                ui.add_space(20.0);

                // Config Info
                ui.vertical_centered(|ui| {
                    if let Some(err) = &self.config_err {
                        ui.label(egui::RichText::new(err).color(egui::Color32::RED));
                    } else {
                        ui.label(egui::RichText::new(&self.config_name).color(egui::Color32::GRAY));
                    }
                    if self.shared.lock().unwrap().client.is_none() && self.config_err.is_none() {
                        ui.label(
                            egui::RichText::new("(Выберите конфиг слева или добавьте новый)")
                                .size(15.0)
                                .strong()
                                .color(egui::Color32::from_gray(80)),
                        );
                    }
                });

                ui.add_space(ui.available_height() * 0.15);

                // --- MAIN BUTTON LOGIC ---
                ui.vertical_centered(|ui| {
                    let btn_size = egui::vec2(180.0, 180.0);

                    // Логика цвета и текста
                    let (btn_text, btn_color) = match self.shared.lock().unwrap().state {
                        ConnectionState::Disconnected => (
                            "Подключить VPN",
                            egui::Color32::from_rgb(76, 175, 80), // Зеленый
                        ),
                        ConnectionState::Connecting => {
                            // АНИМАЦИЯ ПУЛЬСАЦИИ
                            // Используем time (секунды) для синусоиды
                            let time = ctx.input(|i| i.time);
                            // Синус от -1 до 1, переводим в 0..1
                            let factor = (time.sin() + 1.0) / 2.0;

                            // Интерполируем между Желтым и Оранжевым
                            // Yellow: (255, 235, 59)
                            // Orange: (255, 152, 0)

                            let r = 255; // Red всегда 255
                            let g = (235.0 + (152.0 - 235.0) * factor) as u8; // Green меняется
                            let b = (59.0 + (0.0 - 59.0) * factor) as u8; // Blue меняется

                            // Запрашиваем перерисовку постоянно, чтобы анимация была плавной
                            ctx.request_repaint();

                            ("Подключение...", egui::Color32::from_rgb(r, g, b))
                        }
                        ConnectionState::Connected => (
                            "Отключить VPN",
                            egui::Color32::from_rgb(244, 67, 54), // Красный
                        ),
                    };

                    let btn = egui::Button::new(
                        egui::RichText::new(btn_text)
                            .size(24.0)
                            .strong()
                            .color(egui::Color32::WHITE),
                    )
                    .min_size(btn_size)
                    .corner_radius(90.0)
                    .fill(btn_color);
                    let state = self.shared.lock().unwrap().state.clone();
                    if ui.add(btn).clicked() {
                        match state {
                            ConnectionState::Disconnected => {
                                if self.shared.lock().unwrap().client.is_none() {
                                    self.log("Error: No config loaded! Press ⚙ or drag file.");
                                    self.open_file_dialog();
                                } else {
                                    self.start_vpn();
                                }
                            }
                            ConnectionState::Connecting => {
                                // Если нажали во время подключения - отменяем
                                self.stop_vpn();
                            }
                            ConnectionState::Connected => {
                                self.stop_vpn();
                            }
                        }
                    }

                    ui.add_space(20.0);

                    // СТАТУС ТЕКСТ
                    match self.shared.lock().unwrap().state {
                        ConnectionState::Connected => {
                            ui.label(
                                egui::RichText::new("VPN соединение установлено!")
                                    .size(16.0)
                                    .strong()
                                    .color(egui::Color32::GREEN),
                            );
                        }
                        ConnectionState::Disconnected => {
                            ui.label(
                                egui::RichText::new("VPN соединение не установлено.")
                                    .size(16.0)
                                    .strong()
                                    .color(egui::Color32::RED),
                            );
                        }
                        ConnectionState::Connecting => {
                            ui.label(
                                egui::RichText::new("Установка соединения...")
                                    .size(16.0)
                                    .strong()
                                    .color(egui::Color32::YELLOW),
                            );
                        }
                    }
                });
            });
    }
}
