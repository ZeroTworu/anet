include!(concat!(env!("OUT_DIR"), "/built.rs"));

use crate::config::AppSettings;
use crate::tun_factory::DesktopTunFactory;
use crate::tray::TrayBackground;
use crate::tray::TrayCommand;
use anet_client_core::updater::{Updater, GithubRelease};
use anet_client_core::client::AnetClient;
use anet_client_core::config::CoreConfig;
use anet_client_core::events::{AnetEvent, EventHandler, set_handler};
use anet_client_core::platform::create_route_manager;
use eframe::egui;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;
use tokio::runtime::Handle;
use notify_rust::Notification;

// Состояния для апдейтера
#[derive(Clone)]
pub enum UpdateStatus {
    Idle,
    Checking,
    Available(GithubRelease),
    Downloading(f32),
    ReadyToRestart,
    Error(String),
}

// --- Event Handler
pub struct GuiEventHandler {
    tx: Sender<AnetEvent>,
    ctx: egui::Context,
    shared: Arc<Mutex<SharedState>>,
}

impl EventHandler for GuiEventHandler {
    fn on_event(&self, event: AnetEvent) {
        let _ = self.tx.send(event.clone());

        match &event {
            AnetEvent::Status(msg) => {
                let mut guard = self.shared.lock().unwrap();
                // Только чёткие финальные статусы от ядра!
                if msg.contains("Tunnel UP") {
                    guard.state = ConnectionState::Connected;
                } else if msg.contains("Stopped") || msg.contains("Error") {
                    guard.state = ConnectionState::Disconnected;
                }
            }
            AnetEvent::Error(_) => {
                self.shared.lock().unwrap().state = ConnectionState::Disconnected;
            }
            _ => {}
        }

        self.ctx.request_repaint();
    }
}

// --- App State Enum ---
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
}

pub struct SharedState {
    client: Option<Arc<AnetClient>>,
    pub state: ConnectionState,
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

    tray_cmd_tx: Sender<TrayCommand>,

    last_known_state: ConnectionState,
    is_in_tray: bool,
    sidebar_open: bool,
    editing_config_id: Option<String>,
    edit_name_buffer: String,
    error_modal: Option<String>,
    update_status: UpdateStatus,
}

fn send_notification(title: &str, body: &str) {
    let _ = Notification::new()
        .summary(title)
        .body(body)
        .appname("ANet VPN")
        .icon("dialog-information")
        .show();
}

pub fn toggle_vpn(shared: &Arc<Mutex<SharedState>>, rt_handle: &Handle, logs: &Arc<Mutex<Vec<String>>>) {
    let mut guard = shared.lock().unwrap();

    if guard.state == ConnectionState::Disconnected {
        if let Some(client_clone) = guard.client.clone() {
            guard.state = ConnectionState::Connecting;
            drop(guard); // освобождаем мьютекс перед await

            let logs_clone = logs.clone();
            let shared_clone = shared.clone();
            rt_handle.spawn(async move {
                logs_clone.lock().unwrap().push("> Starting service...".into());
                match client_clone.start().await {
                    Ok(_) => {
                        logs_clone.lock().unwrap().push("> VPN Stopped (Ok)".into());
                        // Connected установит GuiEventHandler при "Tunnel UP"
                    }
                    Err(e) => {
                        logs_clone.lock().unwrap().push(format!("> Error: {}", e));
                        shared_clone.lock().unwrap().state = ConnectionState::Disconnected;
                        anet_client_core::events::err(e.to_string());
                    }
                }
            });
        }
    } else {
        if let Some(client_clone) = guard.client.clone() {
            guard.state = ConnectionState::Disconnected;
            drop(guard);

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
        // Чистим старые .old файлы при запуске
        // crate::updater::cleanup_old_version();
        let rt = Runtime::new().unwrap();

        let settings = AppSettings::load();
        let settings_arc = Arc::new(Mutex::new(settings));

        let logs = Arc::new(Mutex::new(vec!["> System Ready...".to_string()]));

        let shared = Arc::new(Mutex::new(SharedState {
            client: None,
            state: ConnectionState::Disconnected,
        }));

        let (event_tx, event_rx) = channel::<AnetEvent>();
        let (tray_cmd_tx, tray_cmd_rx) = channel::<TrayCommand>();

        // Обработчик событий ядра — обновляет shared.state
        let shared_for_handler = shared.clone();
        set_handler(Box::new(GuiEventHandler {
            tx: event_tx,
            ctx: cc.egui_ctx.clone(),
            shared: shared_for_handler,
        }));

        // Замыкания для трея
        let show_ctx = cc.egui_ctx.clone();
        let on_show = move || { force_wake_up_window(&show_ctx); };

        // Замыкание "Toggle VPN" — захватывает shared, runtime и logs
        let toggle_shared = shared.clone();
        let toggle_rt = rt.handle().clone();
        let toggle_logs = logs.clone();
        let on_toggle = move || { toggle_vpn(&toggle_shared, &toggle_rt, &toggle_logs); };

        // Запускаем фоновый поток трея
        TrayBackground::spawn(
            tray_cmd_rx,
            shared.clone(),
            settings_arc.clone(),
            on_show,
            on_toggle,
        );


        let mut app = Self {
            rt, logs, config_err: None,
            config_name: "Файл не выбран".to_string(),
            event_rx,
            settings: settings_arc,
            shared,
            tray_cmd_tx, // <-- сохраняем
            last_known_state: ConnectionState::Disconnected,
            is_in_tray: false,
            sidebar_open: false,
            editing_config_id: None,
            edit_name_buffer: String::new(),
            error_modal: None,
            update_status: UpdateStatus::Idle,
        };

        let config_to_load = app.settings.lock().unwrap().get_active_config().map(|c| (c.content.clone(), c.name.clone()));
        if let Some((content, name)) = config_to_load {
            app.load_config_from_content(&content, &name);
        }

        app
    }

    fn check_for_updates(&mut self) {
        // Достаем URL из текущего загруженного конфига клиента
        let update_url = if let Some(client) = self.shared.lock().unwrap().client.as_ref() {
            client.get_config().main.update_url.clone()
        } else {
            // Если конфиг не загружен, берем дефолтный
            "https://api.github.com/repos/ZeroTworu/anet/releases/latest".to_string()
        };

        self.update_status = UpdateStatus::Checking;
        let current_ver = GIT_TAG.to_string();
        let rt_handle = self.rt.handle().clone();

        self.log(&format!("Проверка обновлений (текущая: {})...", current_ver));

        rt_handle.spawn(async move {
            // Передаем URL в апдейтер
            match Updater::check_latest(&update_url, &current_ver).await {
                Ok(Some(release)) => {
                    anet_client_core::events::emit(AnetEvent::UpdateAvailable(release));
                }
                Ok(None) => {
                    anet_client_core::events::status("У вас установлена актуальная версия.");
                }
                Err(e) => {
                    anet_client_core::events::err(format!("Ошибка обновления: {}", e));
                }
            }
        });
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
            drop(guard);

            let logs_clone = self.logs.clone();
            let shared_clone = self.shared.clone();
            self.rt.spawn(async move {
                logs_clone.lock().unwrap().push("> Starting service...".into());
                match client_clone.start().await {
                    Ok(_) => logs_clone.lock().unwrap().push("> VPN Stopped (Ok)".into()),
                    Err(e) => {
                        logs_clone.lock().unwrap().push(format!("> Error: {}", e));
                        shared_clone.lock().unwrap().state = ConnectionState::Disconnected;
                        anet_client_core::events::err(e.to_string());
                    }
                }
            });
        }
    }

    fn stop_vpn(&mut self) {
        let mut guard = self.shared.lock().unwrap();
        if let Some(client_clone) = guard.client.clone() {
            guard.state = ConnectionState::Disconnected;
            drop(guard);

            let logs_clone = self.logs.clone();
            self.rt.spawn(async move {
                logs_clone.lock().unwrap().push("> Stopping service...".into());
                let _ = client_clone.stop().await;
            });
        }
    }

    fn open_file_dialog(&mut self) {
        if let Some(path) = rfd::FileDialog::new().add_filter("TOML Config", &["toml"]).pick_file() {
            self.add_config_from_path(path);
        }
    }

    fn add_config_from_path(&mut self, path: PathBuf) {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "toml" { self.log("Please select a .toml file"); return; }
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => { self.log(&format!("Failed to read file: {}", e)); return; }
        };
        let clean_content = Self::strip_toml_comments(&content);
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("Unnamed").trim_end_matches(".toml").to_string();
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
            if trimmed.starts_with('#') { continue; }
            if let Some(pos) = line.find('#') {
                let before_comment = line[..pos].trim_end();
                if !before_comment.is_empty() { result.push_str(before_comment); result.push('\n'); }
            } else { result.push_str(line); result.push('\n'); }
        }
        result
    }

    fn delete_config(&mut self, id: &str) {
        self.settings.lock().unwrap().remove_config(id);
        if self.shared.lock().unwrap().client.is_none() { self.config_name = "Config deleted".to_string(); }
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
        if let Some(config) = config { self.load_config_from_content(&config.content, &config.name); }
    }

    fn load_config_from_content(&mut self, content: &str, name: &str) {
        match toml::from_str::<CoreConfig>(content) {
            Ok(cfg) => {
                let tun = Box::new(DesktopTunFactory::new(cfg.main.tun_name.clone()));
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

pub fn force_wake_up_window(ctx: &egui::Context) {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Foundation::{BOOL, HWND, LPARAM};
        use windows_sys::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowTextW, GetWindowThreadProcessId, SetForegroundWindow, ShowWindow, SW_RESTORE, SW_SHOW};
        unsafe extern "system" fn enum_window_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
            let mut process_id: u32 = 0;
            unsafe { GetWindowThreadProcessId(hwnd, &mut process_id) };
            if process_id == lparam as u32 {
                let mut title_buf = [0u16; 256];
                let len = unsafe { GetWindowTextW(hwnd, title_buf.as_mut_ptr(), title_buf.len() as i32) };
                if len > 0 {
                    let title = String::from_utf16_lossy(&title_buf[..len as usize]);
                    if title.starts_with("ANet") {
                        unsafe { ShowWindow(hwnd, SW_RESTORE); ShowWindow(hwnd, SW_SHOW); SetForegroundWindow(hwnd); }
                        return 0;
                    }
                }
            }
            1
        }
        unsafe { let pid = std::process::id(); EnumWindows(Some(enum_window_callback), pid as LPARAM); }
    }
    ctx.send_viewport_cmd_to(egui::ViewportId::ROOT, egui::ViewportCommand::Visible(true));
    ctx.send_viewport_cmd_to(egui::ViewportId::ROOT, egui::ViewportCommand::Focus);
    ctx.request_repaint_of(egui::ViewportId::ROOT);
}

impl eframe::App for ANetApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(std::time::Duration::from_millis(500));

        // 1. Прятки в трей
        let is_minimized = ctx.input(|i| i.viewport().minimized.unwrap_or(false));
        if is_minimized {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            if !self.is_in_tray {
                self.is_in_tray = true;
                let _ = self.tray_cmd_tx.send(TrayCommand::WindowVisible(false));
                let _ = self.tray_cmd_tx.send(TrayCommand::NotifyHidden);
            }
        }

        // 2. Читаем события ядра (логи, модалки, обновления)
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                AnetEvent::Status(msg) => {
                    self.log(&msg);
                }
                AnetEvent::Error(msg) => {
                    let err = format!("CRITICAL ERROR: {}", msg);
                    self.log(&err);
                    self.error_modal = Some(msg);
                    if !self.settings.lock().unwrap().disable_notifications {
                        send_notification("Ошибка ANeT", &err);
                    }
                    // НЕ обновляем shared.state здесь!
                }
                AnetEvent::UpdateProgress(p) => {
                    self.update_status = UpdateStatus::Downloading(p);
                }
                AnetEvent::UpdateAvailable(release) => {
                    self.log(&format!("Найдено обновление: {}", release.tag_name));
                    self.update_status = UpdateStatus::Available(release);
                }
                AnetEvent::UpdateReady => {
                    self.update_status = UpdateStatus::ReadyToRestart;
                }
                _ => {}
            }
        }

        // 3. Синхронизируем UI с единым состоянием
        self.last_known_state = self.shared.lock().unwrap().state;

        let console_frame = egui::Frame::NONE.fill(egui::Color32::from_rgb(10, 10, 10)).inner_margin(8.0).stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(40, 40, 40)));
        egui::TopBottomPanel::bottom("stalker_console").resizable(true).min_height(100.0).default_height(160.0).frame(console_frame).show(ctx, |ui| {
            ui.vertical(|ui| {
                ui.label(egui::RichText::new("SYSTEM LOG").family(egui::FontFamily::Monospace).size(10.0).color(egui::Color32::from_gray(100)));
                ui.add_space(4.0);
                egui::ScrollArea::vertical().auto_shrink([false, false]).stick_to_bottom(true).show(ui, |ui| {
                    let logs = self.logs.lock().unwrap();
                    for line in logs.iter() {
                        let color = if line.contains("Error") || line.contains("Failed") { egui::Color32::from_rgb(255, 80, 80) } else if line.contains("Tunnel UP") { egui::Color32::from_rgb(50, 255, 50) } else { egui::Color32::from_rgb(0, 180, 0) };
                        ui.add(egui::Label::new(egui::RichText::new(line).family(egui::FontFamily::Monospace).size(11.0).color(color)).wrap());
                    }
                });
            });
        });

        let settings_guard = self.settings.lock().unwrap();
        let configs = settings_guard.configs.clone();
        let active_id = settings_guard.active_config_id.clone();
        let editing_id = self.editing_config_id.clone();
        drop(settings_guard);


        egui::SidePanel::left("config_sidebar").resizable(true).default_width(250.0).frame(egui::Frame::NONE.fill(egui::Color32::from_rgb(25, 25, 25))).show_animated(ctx, self.sidebar_open, |ui| {
            ui.add_space(8.0);
            ui.label(egui::RichText::new("КОНФИГИ").size(12.0).color(egui::Color32::from_gray(100)));
            ui.add_space(8.0);
            for config in configs {
                let is_active = active_id.as_deref() == Some(&config.id);
                let is_editing = editing_id.as_deref() == Some(&config.id);
                let bg_color = if is_active { egui::Color32::from_rgb(40, 80, 60) } else { egui::Color32::from_rgb(35, 35, 35) };
                egui::Frame::NONE.fill(bg_color).inner_margin(4.0).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        if is_editing {
                            let response = ui.add(egui::TextEdit::singleline(&mut self.edit_name_buffer).desired_width(120.0));
                            if response.lost_focus() { self.finish_edit_name(); }
                            if ui.button("✓").clicked() { self.finish_edit_name(); }
                        } else {
                            if ui.add(egui::Label::new(egui::RichText::new(&config.name).color(egui::Color32::from_gray(220))).sense(egui::Sense::click())).clicked() {
                                self.select_config(&config.id);
                            }
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.add(egui::Button::new("✏").frame(false).small()).clicked() { self.start_edit_name(&config.id, &config.name); }
                                if ui.add(egui::Button::new("🗑").frame(false).small()).clicked() { self.delete_config(&config.id); }
                            });
                        }
                    });
                });
            }
            ui.add_space(16.0);
            if ui.add(egui::Button::new(egui::RichText::new("➕ Добавить конфиг")
                .color(egui::Color32::WHITE))
                .fill(egui::Color32::from_rgb(60, 60, 60))).clicked() {
                self.open_file_dialog();
            }

            // КНОПКА ОБНОВЛЕНИЯ ВНИЗУ САЙДБАРА
            ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                ui.add_space(10.0);

                // Проверяем, не занят ли апдейтер
                let is_busy = matches!(self.update_status, UpdateStatus::Checking | UpdateStatus::Downloading(_));

                ui.add_enabled_ui(!is_busy, |ui| {
                    let label = if is_busy { "⏳ ЖДИТЕ..." } else { "🔄 ПРОВЕРИТЬ ОБНОВЛЕНИЯ" };
                    if ui.add(egui::Button::new(egui::RichText::new(label).size(11.0))).clicked() {
                        self.check_for_updates();
                    }
                });
            });
        });

        let main_frame = egui::Frame::NONE.fill(egui::Color32::from_rgb(18, 18, 18)).inner_margin(12.0);
        egui::CentralPanel::default().frame(main_frame).show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.add(egui::Button::new(egui::RichText::new("☰").size(24.0).strong().color(egui::Color32::WHITE)).frame(false)).clicked() { self.sidebar_open = !self.sidebar_open; }
                ui.add_space(8.0);
                ui.label(egui::RichText::new("ANet VPN").size(24.0).strong().color(egui::Color32::WHITE));
            });
            ui.add_space(20.0);
            ui.vertical_centered(|ui| {
                if let Some(err) = &self.config_err {
                    ui.label(egui::RichText::new(err).color(egui::Color32::RED));
                } else {
                    ui.label(egui::RichText::new(&self.config_name).color(egui::Color32::GRAY));
                }
                if self.shared.lock().unwrap().client.is_none() && self.config_err.is_none() {
                    ui.label(egui::RichText::new("(Выберите конфиг слева или добавьте новый)").size(15.0).strong().color(egui::Color32::from_gray(80)));
                }
            });
            ui.add_space(ui.available_height() * 0.15);
            ui.vertical_centered(|ui| {
                let btn_size = egui::vec2(180.0, 180.0);
                let (btn_text, btn_color) = match self.shared.lock().unwrap().state {
                    ConnectionState::Disconnected => ("Подключить VPN", egui::Color32::from_rgb(76, 175, 80)),
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
                    ConnectionState::Connected => ("Отключить VPN", egui::Color32::from_rgb(244, 67, 54)),
                };
                let btn = egui::Button::new(egui::RichText::new(btn_text).size(24.0).strong().color(egui::Color32::WHITE)).min_size(btn_size).corner_radius(90.0).fill(btn_color);
                let state = self.shared.lock().unwrap().state.clone();
                if ui.add(btn).clicked() {
                    match state {
                        ConnectionState::Disconnected => { if self.shared.lock().unwrap().client.is_none() { self.open_file_dialog(); } else { self.start_vpn(); } }
                        _ => { self.stop_vpn(); }
                    }
                }
                ui.add_space(20.0);
                match self.shared.lock().unwrap().state {
                    ConnectionState::Connected => { ui.label(egui::RichText::new("VPN соединение установлено!").size(16.0).strong().color(egui::Color32::GREEN)); }
                    ConnectionState::Disconnected => { ui.label(egui::RichText::new("VPN соединение не установлено.").size(16.0).strong().color(egui::Color32::RED)); }
                    ConnectionState::Connecting => { ui.label(egui::RichText::new("Установка соединения...").size(16.0).strong().color(egui::Color32::YELLOW)); }
                }
            });
        });

        // МОДАЛКА ОШИБКИ
        if let Some(err_msg) = self.error_modal.clone() {
            let neon_orange = egui::Color32::from_rgb(255, 100, 0);
            let modal_bg = egui::Color32::from_rgb(32, 32, 32);
            egui::Window::new("ERROR_SYSTEM").anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0)).collapsible(false).resizable(false).title_bar(false).frame(egui::Frame::NONE.fill(modal_bg).stroke(egui::Stroke::new(3.0, neon_orange)).inner_margin(24.0).corner_radius(4.0)).show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("ОШИБКА ДОСТУПА").size(22.0).strong().color(neon_orange));
                    ui.add_space(16.0);
                    ui.label(egui::RichText::new(&err_msg).size(16.0).line_height(Some(20.0)).color(neon_orange).family(egui::FontFamily::Monospace));
                    ui.add_space(24.0);
                    if ui.add(egui::Button::new(egui::RichText::new(" ПОНЯТНО (OK) ").size(16.0).strong().color(egui::Color32::BLACK)).fill(neon_orange).min_size(egui::vec2(140.0, 36.0))).clicked() {
                        self.error_modal = None;
                        while self.event_rx.try_recv().is_ok() {}
                    }
                });
            });
        }
        // --- МОДАЛКА ГОТОВНОСТИ ОБНОВЛЕНИЯ ---
        if matches!(self.update_status, UpdateStatus::ReadyToRestart) {
            let neon_orange = egui::Color32::from_rgb(255, 100, 0);
            let modal_bg = egui::Color32::from_rgb(32, 32, 32);

            egui::Window::new("RESTART_REQUIRED")
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .collapsible(false).resizable(false).title_bar(false)
                .frame(egui::Frame::NONE.fill(modal_bg).stroke(egui::Stroke::new(3.0, neon_orange)).inner_margin(24.0).corner_radius(4.0))
                .show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.label(egui::RichText::new("ОБНОВЛЕНИЕ ЗАГРУЖЕНО").size(22.0).strong().color(neon_orange));
                        ui.add_space(16.0);
                        ui.label(egui::RichText::new("Все компоненты системы заменены на новые.\nПерезапустить приложение сейчас?").size(16.0).color(neon_orange).family(egui::FontFamily::Monospace));
                        ui.add_space(24.0);

                        ui.horizontal(|ui| {
                            ui.add_space(ui.available_width() / 6.0);

                            if ui.add(egui::Button::new(egui::RichText::new(" ПЕРЕЗАПУСК ").size(16.0).strong().color(egui::Color32::BLACK)).fill(neon_orange).min_size(egui::vec2(120.0, 36.0))).clicked() {
                                Updater::final_restart();
                            }

                            ui.add_space(20.0);

                            if ui.add(egui::Button::new(egui::RichText::new(" ПОЗЖЕ ").size(16.0).strong().color(neon_orange)).frame(false)).clicked() {
                                self.update_status = UpdateStatus::Idle;
                                self.log("Обновление будет применено при следующем запуске.");
                            }
                        });
                    });
                });
        }
        // МОДАЛКА ОБНОВЛЕНИЯ
        let (show_upd, release_data, progress) = match &self.update_status {
            UpdateStatus::Available(r) => (true, Some(r.clone()), None),
            UpdateStatus::Downloading(p) => (true, None, Some(*p)),
            _ => (false, None, None),
        };

        if show_upd {
            let neon_orange = egui::Color32::from_rgb(255, 100, 0);
            let modal_bg = egui::Color32::from_rgb(32, 32, 32);

            egui::Window::new("UPDATE_SYSTEM")
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .collapsible(false).resizable(false).title_bar(false)
                .frame(egui::Frame::NONE.fill(modal_bg).stroke(egui::Stroke::new(3.0, neon_orange)).inner_margin(24.0).corner_radius(4.0))
                .show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.label(egui::RichText::new("SYSTEM UPDATE").size(22.0).strong().color(neon_orange));

                        if let Some(rel) = release_data {
                            // --- ФАЗА 1: ВЫБОР (Текст + Кнопки) ---
                            ui.label(egui::RichText::new(format!("Доступна версия: {}", rel.tag_name)).size(16.0).color(neon_orange));
                            ui.add_space(16.0);
                            ui.add_space(16.0);
                            ui.label(egui::RichText::new("Список изменений:").size(14.0).color(neon_orange).strong());
                            ui.add_space(4.0);

                            egui::ScrollArea::vertical()
                                .max_height(180.0) // Можно чуть увеличить высоту
                                .auto_shrink([false, true]) // Чтобы область подстраивалась под текст
                                .show(ui, |ui| {
                                    let changelog = rel.body.as_deref().unwrap_or("Описание изменений отсутствует.");

                                    // Используем ui.add с явным включением переноса строк (.wrap())
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(changelog)
                                                .size(13.0)
                                                .color(neon_orange)
                                                .family(egui::FontFamily::Monospace)
                                        ).wrap()
                                    );
                                });
                            ui.add_space(24.0);
                            ui.horizontal(|ui| {
                                // Расположим кнопки симметрично
                                ui.add_space(ui.available_width() / 6.0);

                                // --- Кнопка ОБНОВИТЬ ---
                                let btn_update = egui::Button::new(
                                    egui::RichText::new("ОБНОВИТЬ")
                                        .size(16.0)
                                        .strong()
                                        .color(egui::Color32::BLACK),
                                )
                                    .fill(neon_orange)
                                    .min_size(egui::vec2(120.0, 36.0));

                                if ui.add(btn_update).clicked() {
                                    let r_clone = rel.clone();
                                    self.logs.lock().unwrap().push(format!("> Обновляемся на {}", rel.tag_name));
                                    self.update_status = UpdateStatus::Downloading(0.0);
                                    self.rt.spawn(async move {
                                        if let Err(e) = Updater::download_and_apply(r_clone).await {
                                            anet_client_core::events::err(format!("Ошибка загрузки: {}", e));
                                        }
                                    });
                                }

                                ui.add_space(20.0); // Промежуток между кнопками

                                let btn_cancel = egui::Button::new(
                                    egui::RichText::new("ПОЗДНЕЕ")
                                        .size(16.0)
                                        .strong()
                                        .color(egui::Color32::BLACK),
                                )
                                    .fill(neon_orange)
                                    .min_size(egui::vec2(120.0, 36.0));

                                if ui.add(btn_cancel).clicked() {
                                    self.update_status = UpdateStatus::Idle;
                                }
                            });
                        } else if let Some(p) = progress {
                            // --- ФАЗА 2: ЗАГРУЗКА (Прогресс-бар) ---
                            ui.add_space(20.0);
                            ui.label(egui::RichText::new("СКАЧИВАНИЕ НОВЫХ БИНАРНИКОВ...").color(neon_orange).strong());
                            ui.add_space(12.0);

                            ui.add(egui::ProgressBar::new(p)
                                .text(format!("{:.1}%", p * 100.0))
                                .desired_width(260.0)
                                .fill(neon_orange));

                            ui.add_space(20.0);
                            ui.label(egui::RichText::new("Пожалуйста, не закрывайте приложение").size(11.0).italics().color(neon_orange));
                        }
                    });
                });
        }
    }
}
