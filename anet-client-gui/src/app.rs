#![allow(warnings)]
include!(concat!(env!("OUT_DIR"), "/built.rs"));

use crate::config::AppSettings;
use crate::tun_factory::DesktopTunFactory;
use crate::tray::TrayBackground;
use crate::tray::TrayCommand;
use anet_client_core::updater::{ Updater, GithubRelease };
use anet_client_core::client::AnetClient;
use anet_client_core::config::CoreConfig;
use anet_client_core::events::{ AnetEvent, ClientState, EventHandler, set_handler };
use anet_client_core::platform::create_route_manager;
use eframe::egui;
use std::path::PathBuf;
use std::sync::mpsc::{ Receiver, Sender, channel };
use std::sync::{ Arc, Mutex };
use tokio::runtime::Runtime;
use tokio::runtime::Handle;
use notify_rust::Notification;
use egui::{ RichText, FontId, FontDefinitions, FontData, FontFamily, Stroke, Visuals };
use egui::widgets::Spinner;
use egui::text::{ LayoutJob, TextFormat };
use std::fs;
use std::io;
use std::fs::OpenOptions;
use std::io::Write;
use std::collections::BTreeMap;
use sysinfo::System;
use chrono::Local;

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

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum FilterMode {
    All,
    Include,
    Exclude,
}

// --- Event Handler
pub struct GuiEventHandler {
    tx: Sender<AnetEvent>,
    ctx: egui::Context,
    shared: Arc<Mutex<SharedState>>,
}

// Информация об одном запущенном процессе
pub struct ProcessItem {
    pub pid: u32,
    pub name: String,
    pub is_selected: bool,
    // В будущем сюда можно добавить egui::TextureHandle для иконки
}

pub struct AppState {
    pub processes: Vec<ProcessItem>,
    pub sys: System,
}

impl AppState {
    #[cfg(target_os = "windows")]
    pub fn new() -> Self {
        let mut slf = Self {
            processes: Vec::new(),
            sys: System::new_all(),
        };
        slf.refresh_processes();
        slf
    }

    // Обновление списка .exe процессов
    #[cfg(target_os = "windows")]
    pub fn refresh_processes(&mut self) {
        // 1. Сохраняем имена уже выбранных приложений перед обновлением
        let selected_apps: std::collections::HashSet<String> = self.processes
            .iter()
            .filter(|p| p.is_selected)
            .map(|p| p.name.clone())
            .collect();

        self.sys.refresh_all();

        let mut map: BTreeMap<String, ProcessItem> = BTreeMap::new();

        for (pid, process) in self.sys.processes() {
            let name = process.name().to_string();

            if name.ends_with(".exe") || cfg!(windows) {
                // 2. Восстанавливаем состояние is_selected, если процесс был выбран ранее
                let is_selected = selected_apps.contains(&name);

                map.entry(name.clone()).or_insert(ProcessItem {
                    pid: pid.as_u32(),
                    name,
                    is_selected,
                });
            }
        }

        self.processes = map.into_values().collect();
    }
}

impl EventHandler for GuiEventHandler {
    fn on_event(&self, event: AnetEvent) {
        let _ = self.tx.send(event.clone());

        match &event {
            AnetEvent::ClientStateChanged { state, .. } => {
                let mut guard = self.shared.lock().unwrap();
                guard.state = match state {
                    ClientState::Connected => ConnectionState::Connected,
                    ClientState::Connecting | ClientState::Reconnecting | ClientState::Stopping =>
                        ConnectionState::Connecting,
                    ClientState::Disconnected | ClientState::Stopped | ClientState::Failed =>
                        ConnectionState::Disconnected,
                };
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
    appbar_open: bool,
    editing_config_id: Option<String>,
    edit_name_buffer: String,
    error_modal: Option<String>,
    update_status: UpdateStatus,

    pub processes: Vec<ProcessItem>,
    pub sys: System,

    pub filter_mode: FilterMode,
}

fn send_notification(title: &str, body: &str) {
    let _ = Notification::new()
        .summary(title)
        .body(body)
        .appname("ANet VPN")
        .icon("dialog-information")
        .show();
}

pub fn toggle_vpn(
    shared: &Arc<Mutex<SharedState>>,
    rt_handle: &Handle,
    logs: &Arc<Mutex<Vec<String>>>
) {
    let mut guard = shared.lock().unwrap();

    if guard.state == ConnectionState::Disconnected {
        if let Some(client_clone) = guard.client.clone() {
            guard.state = ConnectionState::Connecting;
            drop(guard);

            let logs_clone = logs.clone();
            let shared_clone = shared.clone();
            rt_handle.spawn(async move {
                logs_clone.lock().unwrap().push("> Starting service...".into());
                match client_clone.start().await {
                    Ok(_) => {
                        logs_clone.lock().unwrap().push("> VPN Stopped (Ok)".into());
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
    // Функция сканирования запущенных .exe процессов
    #[cfg(target_os = "windows")]
    pub fn refresh_processes(&mut self) {
        // 1. Сохраняем имена уже выбранных приложений перед обновлением
        let selected_apps: std::collections::HashSet<String> = self.processes
            .iter()
            .filter(|p| p.is_selected)
            .map(|p| p.name.clone())
            .collect();

        self.sys.refresh_all();

        let mut map = std::collections::BTreeMap::new();

        for (pid, process) in self.sys.processes() {
            let name = process.name().to_string();

            if name.ends_with(".exe") || cfg!(windows) {
                // 2. Восстанавливаем состояние is_selected
                let is_selected = selected_apps.contains(&name);

                map.entry(name.clone()).or_insert(ProcessItem {
                    pid: pid.as_u32(),
                    name,
                    is_selected,
                });
            }
        }

        self.processes = map.into_values().collect();
    }

    // Метод отрисовки таблицы процессов
    #[cfg(target_os = "windows")]
    fn render_process_list(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            ui.label("Режим фильтрации:");

            if
                ui
                    .radio_value(&mut self.filter_mode, FilterMode::All, "Vpn для всех приложений")
                    .changed()
            {
                println!("Переключено на All");
            }

            if
                ui
                    .radio_value(
                        &mut self.filter_mode,
                        FilterMode::Include,
                        "Vpn только для выбранных"
                    )
                    .changed()
            {
                println!("Переключено на Include");
            }

            if
                ui
                    .radio_value(
                        &mut self.filter_mode,
                        FilterMode::Exclude,
                        "Vpn для всего, кроме выбранных"
                    )
                    .changed()
            {
                println!("Переключено на Exclude");
            }
        });
        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("🔄 Обновить").clicked() {
                self.refresh_processes();
            }
            if ui.button(" Применить").clicked() {
                // 1. Собираем выбранные .exe
                let selected_apps: Vec<String> = self.processes
                    .iter()
                    .filter(|p| p.is_selected)
                    .map(|p| p.name.clone())
                    .collect();

                // 2. Определяем режим фильтрации
                let filter_mode = self.filter_mode;

                let mut updated_config_data: Option<(String, String, String)> = None;

                // 3. Обновляем конфигурацию в памяти
                {
                    let mut settings = self.settings.lock().unwrap();
                    let active_id = settings.active_config_id.clone();

                    if let Some(id) = active_id {
                        let updated_info = {
                            if let Some(cfg) = settings.configs.iter_mut().find(|c| c.id == id) {
                                // Модифицируем TOML текст с учетом per_app_mode
                                cfg.content = Self::inject_per_app_to_toml(
                                    &cfg.content,
                                    &selected_apps,
                                    filter_mode
                                );
                                Some((cfg.id.clone(), cfg.content.clone(), cfg.name.clone()))
                            } else {
                                None
                            }
                        };

                        if let Some((cfg_id, cfg_content, cfg_name)) = updated_info {
                            settings.save();
                            updated_config_data = Some((cfg_id, cfg_content, cfg_name));
                        }
                    }
                }

                // 4. Записываем файл на диск и перезагружаем ядро
                if let Some((id, content, name)) = updated_config_data {
                    let path_by_id = std::path::PathBuf
                        ::from("configs")
                        .join(format!("{}.toml", id));
                    let path_by_name = std::path::PathBuf
                        ::from("configs")
                        .join(format!("{}.toml", name));

                    let target_path = if path_by_id.exists() {
                        Some(path_by_id)
                    } else if path_by_name.exists() {
                        Some(path_by_name)
                    } else {
                        let root_id = std::path::PathBuf::from(format!("{}.toml", id));
                        let root_name = std::path::PathBuf::from(format!("{}.toml", name));
                        if root_id.exists() {
                            Some(root_id)
                        } else if root_name.exists() {
                            Some(root_name)
                        } else {
                            None
                        }
                    };

                    if let Some(path) = target_path {
                        match std::fs::write(&path, &content) {
                            Ok(_) =>
                                self.log(
                                    &format!("Конфиг успешно перезаписан на диске: {:?}", path)
                                ),
                            Err(e) => self.log(&format!(" Ошибка записи в {:?}: {}", path, e)),
                        }
                    } else {
                        self.log(
                            &format!(
                                " Предупреждение: Не удалось найти путь к файлу для ID: {} / Имя: {}",
                                id,
                                name
                            )
                        );
                    }

                    // Перезагружаем ядро
                    self.load_config_from_content(&id, &content, &name);
                    self.log("Настройки приложений применены.");

                    // === БЕЗОПАСНЫЙ РЕКОМНЕКТ ДЛЯ TOKIO ===
                    let current_state = self.shared.lock().unwrap().state;
                    if current_state == ConnectionState::Connected {
                        self.log("Переподключение VPN из-за изменения настроек...");

                        // 1. Останавливаем VPN
                        self.stop_vpn();

                        // 2. Подготавливаем данные для фоновой задачи вне async блока
                        let shared_clone = self.shared.clone();
                        let logs_clone = self.logs.clone();
                        let rt_handle = self.rt.handle().clone();

                        rt_handle.spawn(async move {
                            // Небольшая пауза
                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;

                            // Получаем клиента и сразу отпускаем мьютекс через drop,
                            // чтобы не держать его во время .await вызовов!
                            let client_opt = {
                                let mut guard = shared_clone.lock().unwrap();
                                guard.state = ConnectionState::Connecting;
                                guard.client.clone()
                            }; // <--- Здесь guard гарантированно уничтожается (dropped)

                            if let Some(client_clone) = client_opt {
                                logs_clone.lock().unwrap().push("> Re-starting service...".into());

                                // Вызов .await происходит БЕЗ удерживающегося мьютекса в контексте задачи
                                match client_clone.start().await {
                                    Ok(_) => {
                                        logs_clone
                                            .lock()
                                            .unwrap()
                                            .push("> VPN Stopped (Ok)".into());
                                    }
                                    Err(e) => {
                                        logs_clone.lock().unwrap().push(format!("> Error: {}", e));
                                        shared_clone.lock().unwrap().state =
                                            ConnectionState::Disconnected;
                                        anet_client_core::events::err(e.to_string());
                                    }
                                }
                            }
                        });
                    }
                } else {
                    self.log(" Ошибка: нет активного конфига для применения настроек.");
                }
            }
        });

        ui.separator();

        egui::ScrollArea
            ::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Grid
                    ::new("process_grid")
                    .striped(true)
                    .spacing([12.0, 8.0])
                    .min_col_width(24.0)
                    .show(ui, |ui| {
                        ui.strong("");
                        ui.strong("icon");
                        ui.strong("name");
                        ui.end_row();

                        for proc in &mut self.processes {
                            ui.scope(|ui| {
                                let checkbox_white = egui::Color32::from_rgb(255, 255, 255);
                                let checkbox_grey = egui::Color32::from_rgb(76, 76, 76);
                                let checkbox_gold = egui::Color32::from_rgb(238, 188, 122);

                                let checkbox_stroke = egui::Stroke::new(2.0, checkbox_gold);
                                let checkbox_active_stroke = egui::Stroke::new(2.0, checkbox_gold);
                                let checkbox_inactive_stroke = egui::Stroke::new(
                                    2.0,
                                    checkbox_grey
                                );
                                let checkbox_inactive_chevron = egui::Stroke::new(
                                    2.0,
                                    checkbox_white
                                );

                                ui.style_mut().visuals.widgets.inactive.fg_stroke =
                                    checkbox_inactive_chevron;

                                if proc.is_selected {
                                    ui.style_mut().visuals.widgets.inactive.bg_stroke =
                                        checkbox_active_stroke;
                                } else {
                                    ui.style_mut().visuals.widgets.inactive.bg_stroke =
                                        checkbox_inactive_stroke;
                                }

                                ui.style_mut().visuals.widgets.hovered.bg_stroke = checkbox_stroke;

                                if ui.checkbox(&mut proc.is_selected, "").changed() {
                                    // Реакция на переключение чекбокса
                                }
                            });
                            ui.label("⚙");

                            let text_color = if proc.is_selected {
                                egui::Color32::from_rgb(238, 188, 122)
                            } else {
                                egui::Color32::from_rgb(136, 136, 136)
                            };

                            ui.colored_label(text_color, &proc.name);

                            ui.end_row();
                        }
                    });
            });
    }

    /// Функция для обновления per_app и per_app_mode в TOML
    #[cfg(target_os = "windows")]
    fn inject_per_app_to_toml(content: &str, apps: &[String], mode: FilterMode) -> String {
        let normalized = content.replace("\r\n", "\n");
        let mut lines: Vec<String> = normalized
            .lines()
            .map(|s| s.to_string())
            .collect();

        let apps_str = apps
            .iter()
            .map(|app| format!("\"{}\"", app))
            .collect::<Vec<_>>()
            .join(", ");

        let per_app_line = format!("per_app = [{}]", apps_str);

        let mode_str = match mode {
            FilterMode::All => "all",
            FilterMode::Include => "include",
            FilterMode::Exclude => "exclude",
        };
        let mode_line = format!("per_app_mode = \"{}\"", mode_str);

        let mut in_main = false;
        let mut main_end_idx = None;
        let mut per_app_idx = None;
        let mut mode_idx = None;
        let mut old_exclude_idx = None; // на случай старого параметра в файле

        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                if trimmed == "[main]" {
                    in_main = true;
                } else if in_main {
                    main_end_idx = Some(i);
                    in_main = false;
                }
            } else if in_main {
                if trimmed.starts_with('#') {
                    continue;
                }

                let clean_line: String = trimmed
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect();

                if clean_line.starts_with("per_app=[") {
                    per_app_idx = Some(i);
                } else if clean_line.starts_with("per_app_mode=") {
                    mode_idx = Some(i);
                } else if clean_line.starts_with("per_app_exclude=") {
                    old_exclude_idx = Some(i);
                }
            }
        }

        let default_insert_pos = main_end_idx.unwrap_or(lines.len());

        // 1. Обновляем или добавляем per_app
        match per_app_idx {
            Some(idx) => {
                lines[idx] = per_app_line.clone();
            }
            None => {
                lines.insert(default_insert_pos, per_app_line.clone());
                main_end_idx = Some(default_insert_pos + 1);
            }
        }

        let current_insert_pos = main_end_idx.unwrap_or(lines.len());

        // 2. Если в старом конфиге остался per_app_exclude, удалим его, чтобы не плодить мусор
        if let Some(idx) = old_exclude_idx {
            lines.remove(idx);
            // сдвигаем индексы если нужно, либо просто заменим на новый ниже
        }

        // 3. Обновляем или добавляем per_app_mode
        match mode_idx {
            Some(idx) => {
                lines[idx] = mode_line.clone();
            }
            None => {
                // Если старый exclude был удален до idx, можно безопасно вставлять
                let insert_pos = if let Some(old_idx) = old_exclude_idx {
                    if old_idx < current_insert_pos {
                        current_insert_pos.saturating_sub(1)
                    } else {
                        current_insert_pos
                    }
                } else {
                    current_insert_pos
                };
                lines.insert(insert_pos.min(lines.len()), mode_line.clone());
            }
        }

        lines.join("\n")
    }

    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        load_fonts(&cc.egui_ctx);

        let rt = Runtime::new().unwrap();

        let settings = AppSettings::load();
        let settings_arc = Arc::new(Mutex::new(settings));

        let logs = Arc::new(Mutex::new(vec!["> System Ready...".to_string()]));

        let shared = Arc::new(
            Mutex::new(SharedState {
                client: None,
                state: ConnectionState::Disconnected,
            })
        );

        let (event_tx, event_rx) = channel::<AnetEvent>();
        let (tray_cmd_tx, tray_cmd_rx) = channel::<TrayCommand>();

        let shared_for_handler = shared.clone();
        set_handler(
            Box::new(GuiEventHandler {
                tx: event_tx,
                ctx: cc.egui_ctx.clone(),
                shared: shared_for_handler,
            })
        );

        let show_ctx = cc.egui_ctx.clone();
        let on_show = move || {
            force_wake_up_window(&show_ctx);
        };

        let toggle_shared = shared.clone();
        let toggle_rt = rt.handle().clone();
        let toggle_logs = logs.clone();
        let on_toggle = move || {
            toggle_vpn(&toggle_shared, &toggle_rt, &toggle_logs);
        };

        TrayBackground::spawn(
            tray_cmd_rx,
            shared.clone(),
            settings_arc.clone(),
            on_show,
            on_toggle
        );

        let mut app = Self {
            rt,
            logs,
            config_err: None,
            config_name: "Файл не выбран".to_string(),
            event_rx,
            settings: settings_arc,
            shared,
            tray_cmd_tx,
            last_known_state: ConnectionState::Disconnected,
            is_in_tray: false,
            sidebar_open: false,
            appbar_open: false,
            editing_config_id: None,
            edit_name_buffer: String::new(),
            error_modal: None,
            update_status: UpdateStatus::Idle,
            processes: Vec::new(),
            sys: System::new_all(),

            filter_mode: FilterMode::Include,
        };

        #[cfg(target_os = "windows")]
        app.refresh_processes(); // <--- Сначала сканируем процессы

        let config_to_load = app.settings.lock().unwrap().get_active_config();
        if let Some(config) = config_to_load {
            app.load_config_from_content(&config.id, &config.content, &config.name); // <--- Потом грузим конфиг (тут применятся галочки)
        }

        app
    }

    fn check_for_updates(&mut self) {
        let update_url = if let Some(client) = self.shared.lock().unwrap().client.as_ref() {
            client.get_config().main.update_url.clone()
        } else {
            "https://api.github.com/repos/ZeroTworu/anet/releases/latest".to_string()
        };

        self.update_status = UpdateStatus::Checking;
        let current_ver = GIT_TAG.to_string();
        let rt_handle = self.rt.handle().clone();

        self.log(&format!("Проверка обновлений (текущая: {})...", current_ver));

        rt_handle.spawn(async move {
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
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
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

        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Unnamed")
            .trim_end_matches(".toml")
            .to_string();
        let id = {
            let mut settings = self.settings.lock().unwrap();
            settings.add_config(name, content)
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
        self.settings.lock().unwrap().remove_config(id);
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
            self.load_config_from_content(&config.id, &config.content, &config.name);
        }
    }

    fn load_config_from_content(&mut self, id: &str, content: &str, name: &str) {
        let _ = self.rt.enter();

        let route_result = self.rt.block_on(async { create_route_manager(false) });

        match toml::from_str::<CoreConfig>(content) {
            Ok(mut cfg) => {
                let _ = cfg.sanitize();
                // Синхронизируем режимы фильтрации из конфига в UI состояние
                self.filter_mode = match cfg.main.per_app_mode {
                    anet_client_core::config::PerAppMode::All => FilterMode::All,
                    anet_client_core::config::PerAppMode::Include => FilterMode::Include,
                    anet_client_core::config::PerAppMode::Exclude => FilterMode::Exclude,
                };

                // Отмечаем галочками те процессы, которые прописаны в cfg.main.per_app
                for proc in &mut self.processes {
                    proc.is_selected = cfg.main.per_app.contains(&proc.name);
                }

                let selected_name_opt = {
                    let settings = self.settings.lock().unwrap();
                    settings.selected_servers.get(id).cloned()
                };

                if let Some(selected_name) = selected_name_opt {
                    if
                        let Some(idx) = cfg.servers
                            .iter()
                            .position(|s| s.get_name() == selected_name)
                    {
                        cfg.servers.rotate_left(idx);
                    }
                }

                let tun = Box::new(
                    DesktopTunFactory::new(cfg.main.tun_name.clone(), !cfg.main.per_app.is_empty())
                );

                let route = match route_result {
                    Ok(r) => r,
                    Err(e) => {
                        self.config_err = Some(format!("Failed to create route manager: {}", e));
                        self.log("Failed to create route manager");
                        return;
                    }
                };
                self.config_err = None;
                self.config_name = name.to_string();
                self.shared.lock().unwrap().client = Some(
                    Arc::new(AnetClient::new(cfg, tun, route))
                );
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
        use windows_sys::Win32::Foundation::{ BOOL, HWND, LPARAM };
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            EnumWindows,
            GetWindowTextW,
            GetWindowThreadProcessId,
            SetForegroundWindow,
            ShowWindow,
            SW_RESTORE,
            SW_SHOW,
        };
        unsafe extern "system" fn enum_window_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
            let mut process_id: u32 = 0;
            unsafe {
                GetWindowThreadProcessId(hwnd, &mut process_id);
            }
            if process_id == (lparam as u32) {
                let mut title_buf = [0u16; 256];
                let len = unsafe {
                    GetWindowTextW(hwnd, title_buf.as_mut_ptr(), title_buf.len() as i32)
                };
                if len > 0 {
                    let title = String::from_utf16_lossy(&title_buf[..len as usize]);
                    if title.starts_with("ANet") {
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
    ctx.send_viewport_cmd_to(egui::ViewportId::ROOT, egui::ViewportCommand::Visible(true));
    ctx.send_viewport_cmd_to(egui::ViewportId::ROOT, egui::ViewportCommand::Focus);
    ctx.request_repaint_of(egui::ViewportId::ROOT);
}

fn load_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    // 1. Внедряем файлы шрифтов
    let jetbrains_font_data = include_bytes!("./assets/fonts/JetBrainsMono.ttf");
    let inter_font_data = include_bytes!("./assets/fonts/Inter/Inter-Light.otf");

    // 2. Добавляем в коллекцию под вашими именами
    fonts.font_data.insert(
        "JetBrainsMono".to_owned(),
        std::sync::Arc::new(egui::FontData::from_static(jetbrains_font_data))
    );
    fonts.font_data.insert(
        "Inter-V".to_owned(),
        std::sync::Arc::new(egui::FontData::from_static(inter_font_data))
    );

    // 3. 📌 ВАЖНО: Регистрируем кастомное имя в семействе FontFamilies,
    // чтобы egui разрешил использовать FontFamily::Name("Inter-V".into())
    fonts.families
        .entry(egui::FontFamily::Name("Inter-V".into()))
        .or_default()
        .push("Inter-V".to_owned());

    // Также можно сделать Inter-V основным пропорциональным шрифтом (по желанию):
    fonts.families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .insert(0, "Inter-V".to_owned());

    fonts.families
        .entry(egui::FontFamily::Name("JetBrainsMono".into()))
        .or_default()
        .push("JetBrainsMono".to_owned());

    ctx.set_fonts(fonts);
}

impl eframe::App for ANetApp {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        egui::Rgba::TRANSPARENT.to_array()
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui_extras::install_image_loaders(ctx);

        let ivory_color = egui::Color32::from_rgb(234, 233, 235);
        let gold_color = egui::Color32::from_rgb(238, 188, 122);
        let light_blue_color = egui::Color32::from_rgb(128, 172, 202);

        let white_color = egui::Color32::from_rgb(255, 255, 255);

        let title_bg = egui::Color32::from_rgb(23, 25, 31);
        let dark_color = egui::Color32::from_rgb(22, 24, 31);
        let console_bg = egui::Color32::from_rgb(32, 34, 41);

        let grey_color = egui::Color32::from_rgb(128, 128, 128);

        
        let connected_text_color = egui::Color32::from_rgb(84, 210, 87);


        let text_button_color = egui::Color32::from_rgb(0, 0, 0);
        let green_button_color = egui::Color32::from_rgb(65, 180, 65); // Зеленый
        let orange_button_color = egui::Color32::from_rgb(218, 130, 0); // Оранжевый
        let red_button_color = egui::Color32::from_rgb(220, 60, 60); // Красный

        let button_size = egui::vec2(32.0, 32.0);
        let button_icon_size = egui::vec2(26.0, 26.0);

        let margin = 20.0;
        let label_size = 10.0;

        let mut visuals = egui::Visuals::dark();

        visuals.window_fill = dark_color;
        visuals.window_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(50, 50, 50));
        visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(20, 20, 20);
        visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(30, 30, 30);
        visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(45, 45, 45);
        visuals.widgets.active.bg_fill = egui::Color32::from_rgb(40, 80, 60);

        ctx.set_visuals(visuals);

        ctx.request_repaint_after(std::time::Duration::from_millis(500));

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

        let titlebar_height = 38.0;
        let titlebar_button = egui::vec2(42.0, 38.0);
        let titlebar_button_d2 = 19.0;

        egui::TopBottomPanel
            ::top("custom_titlebar")
            .frame(egui::Frame::none().outer_margin(0.0).inner_margin(0.0))
            .exact_height(38.0)
            .show(ctx, |ui| {
                let mut rect = ui.max_rect();
                rect.min.x = ctx.screen_rect().min.x;
                rect.max.x = ctx.screen_rect().max.x;
                rect.max.y = rect.min.y + 38.0;

                // 1. Рисуем сплошной фон на всю высоту и ширину
                // let bg_color = egui::Color32::from_rgb(40, 40, 40);
                ui.painter().rect_filled(
                    rect,
                    egui::CornerRadius { nw: 14, ne: 14, sw: 0, se: 0 },
                    title_bg
                );

                // 2. Интерактивная зона для перетаскивания окна
                let response = ui.interact(
                    rect,
                    ui.id().with("title_bar"),
                    egui::Sense::click_and_drag()
                );
                if response.dragged_by(egui::PointerButton::Primary) {
                    ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
                }

                // 3. Рисуем содержимое внутри точного прямоугольника высотой 38px
                ui.allocate_ui_at_rect(rect, |ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
                        let available_height = 38.0;

                        // ЛЕВАЯ ЧАСТЬ (Индикатор + Текст)
                        let left_width = ui.available_width() - 80.0;
                        let left_rect = egui::Rect::from_min_size(
                            rect.min + egui::vec2(6.0, 0.0),
                            egui::vec2(left_width, available_height)
                        );

                        ui.allocate_ui_at_rect(left_rect, |ui| {
                            ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                ui.set_min_height(available_height);
                                ui.add_space(8.0);
                                ui.ctx().style_mut(|style| {
                                    style.interaction.selectable_labels = false;
                                });

                                // Зеленый индикатор
                                let indicator_color = egui::Color32::from_rgb(76, 175, 80);
                                let (dot_rect, _) = ui.allocate_exact_size(
                                    egui::vec2(8.0, 8.0),
                                    egui::Sense::hover()
                                );
                                ui.painter().circle_filled(dot_rect.center(), 4.0, indicator_color);

                                ui.add_space(8.0);

                                // Название приложения и версии через LayoutJob
                                use egui::text::{ LayoutJob, TextFormat };

                                let mut job = LayoutJob::default();
                                let font_id = egui::FontId::new(
                                    12.0,
                                    egui::FontFamily::Name("Inter-V".into())
                                );

                                // 1. Часть "ANet VPN" (белый цвет)
                                job.append("ANet VPN ", 0.0, TextFormat {
                                    font_id: font_id.clone(),
                                    color: white_color, // Белый
                                    ..Default::default()
                                });

                                // 2. Часть с версией и хэшем (серый цвет)
                                let version_str = format!("{} ({})", GIT_TAG, COMMIT_HASH);
                                job.append(&version_str, 0.0, TextFormat {
                                    font_id,
                                    color: grey_color, // Серый
                                    ..Default::default()
                                });

                                // Выводим скомпонованный текст как единый элемент интерфейса
                                ui.add(egui::Label::new(job));
                            });
                        });

                        // ПРАВАЯ ЧАСТЬ (Кнопки управления)
                        let right_rect = egui::Rect::from_min_size(
                            rect.right_top() - egui::vec2(80.0, 0.0), // Исправлено на right_top()
                            egui::vec2(80.0, available_height)
                        );

                        ui.allocate_ui_at_rect(right_rect, |ui| {
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.set_min_height(available_height);
                                ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);

                                let size = titlebar_button;

                                // 1. Кнопка "Закрыть"
                                let (close_rect, close_response) = ui.allocate_exact_size(
                                    size,
                                    egui::Sense::click()
                                );

                                if close_response.hovered() {
                                    ui.painter().rect_filled(
                                        close_rect,
                                        egui::CornerRadius { nw: 0, ne: 14, sw: 0, se: 0 },
                                        egui::Color32::from_rgb(205, 39, 39)
                                    );
                                }

                                let close_img = egui::Image
                                    ::new(egui::include_image!("./assets/close.svg"))
                                    .fit_to_exact_size(egui::vec2(14.0, 14.0));
                                let close_img_rect = egui::Rect::from_center_size(
                                    close_rect.center(),
                                    egui::vec2(14.0, 14.0)
                                );
                                close_img.paint_at(ui, close_img_rect);

                                if close_response.clicked() {
                                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                                }

                                // 2. Кнопка "Свернуть"
                                let (min_rect, min_response) = ui.allocate_exact_size(
                                    size,
                                    egui::Sense::click()
                                );

                                if min_response.hovered() {
                                    ui.painter().rect_filled(
                                        min_rect,
                                        0.0,
                                        egui::Color32::from_rgb(98, 98, 98)
                                    );
                                }

                                let minimize_img = egui::Image
                                    ::new(egui::include_image!("./assets/minimize.svg"))
                                    .fit_to_exact_size(egui::vec2(14.0, 14.0));
                                let min_img_rect = egui::Rect::from_center_size(
                                    min_rect.center(),
                                    egui::vec2(14.0, 14.0)
                                );
                                minimize_img.paint_at(ui, min_img_rect);

                                if min_response.clicked() {
                                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                                }
                            });
                        });
                    });
                });

                // 4. Аккуратная разделительная линия строго по нижней границе шапки
                let painter = ui.painter();
                painter.line_segment(
                    [rect.left_bottom(), rect.right_bottom()],
                    egui::Stroke::new(1.0, ui.style().visuals.window_stroke.color)
                );
            });

        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                AnetEvent::Status(msg) => {
                    self.log(&msg);
                }
                AnetEvent::ClientStateChanged { message, server_name, .. } => {
                    self.log(&message);
                    if let Some(active_name) = server_name {
                        let mut settings = self.settings.lock().unwrap();
                        if let Some(active_cfg) = settings.get_active_config() {
                            settings.selected_servers.insert(active_cfg.id.clone(), active_name);
                            settings.save();
                        }
                    }
                }
                AnetEvent::Error(msg) => {
                    let err = format!("CRITICAL ERROR: {}", msg);
                    self.log(&err);
                    self.error_modal = Some(msg);
                    if !self.settings.lock().unwrap().disable_notifications {
                        send_notification("Ошибка ANeT", &err);
                    }
                }
                AnetEvent::UpdateProgress(p) => {
                    self.update_status = UpdateStatus::Downloading(p);
                }
                AnetEvent::UpdateStatus(msg) => self.log(&msg),
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

        self.last_known_state = self.shared.lock().unwrap().state;

        // 1. Конфигурируем внутренний блок (карточку) для логов
        let console_inner_frame = egui::Frame::NONE
            .fill(console_bg) // Фон внутреннего контейнера
            .inner_margin(egui::Margin::same(10)) // Внутренние отступы для текста
            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(50, 50, 50))) // (Опционально) Тонкая рамка
            .corner_radius(egui::CornerRadius { nw: 0, ne: 0, sw: 14, se: 14 }); // Скругление углов

        // 2. Внешняя панель консоли
        egui::TopBottomPanel
            ::bottom("stalker_console")
            .resizable(false)
            .min_height(150.0)
            .default_height(150.0)
            .show_separator_line(false)
            .frame(egui::Frame::NONE)
            .show(ctx, |ui| {
                // Внешняя обертка для создания отступов от краев главного окна
                egui::Frame::NONE
                    .outer_margin(egui::Margin {
                        left: 0,
                        right: 0,
                        top: 0,
                        bottom: 0,
                    })
                    .inner_margin(egui::Margin {
                        left: 20,
                        right: 20,
                        top: 10,
                        bottom: 20,
                    })
                    .fill(dark_color) // Фон внутреннего контейнера
                    .corner_radius(egui::CornerRadius { nw: 0, ne: 0, sw: 14, se: 14 })
                    .show(ui, |ui| {
                        ui.vertical(|ui| {
                            // Конфигурируем стили для контейнера заголовка
                            let header_frame = egui::Frame::NONE
                                .fill(console_bg) // Цвет фона плашки
                                .inner_margin(egui::Margin::symmetric(8, 4)) // Внутренние отступы (слева/справа: 8px, сверху/снизу: 4px)
                                .corner_radius(egui::CornerRadius { nw: 14, ne: 14, sw: 0, se: 0 }) // Скругление углов
                                .stroke(
                                    egui::Stroke::new(1.0, egui::Color32::from_rgb(50, 50, 50))
                                ); // (Опционально) Тонкая рамка

                            // Оборачиваем заголовок
                            header_frame.show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.label(
                                    egui::RichText
                                        ::new("SYSTEM LOG")
                                        .family(egui::FontFamily::Name("Inter-V".into()))
                                        .size(10.0)
                                        .color(white_color)
                                );
                            });

                            // Вложенный блок со своим фоном, рамкой и скруглением
                            console_inner_frame.show(ui, |ui| {
                                egui::ScrollArea
                                    ::vertical()
                                    .auto_shrink([false, false])
                                    .stick_to_bottom(true)
                                    .show(ui, |ui| {
                                        let logs = self.logs.lock().unwrap();

                                        for line in logs.iter() {
                                            let color = if
                                                line.contains("Error") ||
                                                line.contains("Failed")
                                            {
                                                red_button_color
                                            } else if line.contains("Tunnel UP") {
                                                green_button_color
                                            } else if line.contains("Config loaded") {
                                                gold_color
                                            } else {
                                                grey_color
                                            };

                                            ui.horizontal(|ui| {
                                                ui.add(
                                                    egui::Label
                                                        ::new(
                                                            egui::RichText
                                                                ::new(line)
                                                                .family(egui::FontFamily::Monospace)
                                                                .size(11.0)
                                                                .color(color)
                                                        )
                                                        .selectable(true)
                                                        .wrap()
                                                );
                                            });
                                        }
                                    });
                            });
                        });
                    });
            });

        let settings_guard = self.settings.lock().unwrap();
        let configs = settings_guard.configs.clone();
        let active_id = settings_guard.active_config_id.clone();
        let editing_id = self.editing_config_id.clone();
        drop(settings_guard);

        let mut server_names = Vec::new();
        let mut selected_server_name = String::new();
        {
            let settings = self.settings.lock().unwrap();
            if let Some(active_cfg) = settings.get_active_config() {
                if let Ok(mut raw_cfg) = toml::from_str::<CoreConfig>(&active_cfg.content) {
                    let _ = raw_cfg.sanitize();
                    server_names = raw_cfg.servers
                        .iter()
                        .map(|s| s.get_name())
                        .collect();
                }
                selected_server_name = settings.selected_servers
                    .get(&active_cfg.id)
                    .cloned()
                    .unwrap_or_else(|| { server_names.first().cloned().unwrap_or_default() });
            }
        }

        let main_frame = egui::Frame::NONE.fill(dark_color).inner_margin(margin);
        //.corner_radius(egui::CornerRadius { nw: 0, ne: 0, sw: 14, se: 14 });

        egui::CentralPanel
            ::default()
            .frame(main_frame)
            .show(ctx, |ui| {
                let state = self.shared.lock().unwrap().state.clone();

                ui.horizontal(|ui| {
                    // 1. Левая кнопка (MENU) занимает минимальное пространство
                    ui.allocate_ui_with_layout(
                        egui::vec2(60.0, ui.available_height()), // фиксированная минимальная ширина под кнопку
                        egui::Layout::top_down(egui::Align::Center),
                        |ui| {
                            // 1. Уникальный ID для сохранения состояния анимации между кадрами
                            let anim_id = ui.id().with("gear_btn_color");

                            // Получаем значение анимации с ПРЕДЫДУЩЕГО кадра (от 0.0 до 1.0)
                            let hover_t: f32 = ui.data(|d| d.get_temp(anim_id)).unwrap_or(0.0);

                            // 🌟 2. ПЛАВНЫЙ ПЕРЕХОД ЦВЕТА (Обычный цвет -> Цвет при наведении)
                            let normal_color = white_color;
                            let hover_color = gold_color;

                            // Интерполируем каналы R, G, B в зависимости от hover_t
                            let r = ((normal_color.r() as f32) * (1.0 - hover_t) +
                                (hover_color.r() as f32) * hover_t) as u8;
                            let g = ((normal_color.g() as f32) * (1.0 - hover_t) +
                                (hover_color.g() as f32) * hover_t) as u8;
                            let b = ((normal_color.b() as f32) * (1.0 - hover_t) +
                                (hover_color.b() as f32) * hover_t) as u8;
                            let current_color = egui::Color32::from_rgb(r, g, b);

                            // 3. Создаем иконку фиксированного размера с плавно меняющимся цветом
                            let icon = egui::Image
                                ::new(egui::include_image!("./assets/gear_3.svg"))
                                .fit_to_exact_size(button_icon_size) // Используем исходный размер
                                .tint(current_color);

                            let menu_button = egui::Button
                                ::image(icon)
                                .min_size(button_size)
                                .stroke(egui::Stroke::NONE)
                                .frame(false)
                                .rounding(button_size.y / 2.0);

                            let response = ui
                                .add(menu_button)
                                .on_hover_cursor(egui::CursorIcon::PointingHand);

                            // 4. Вычисляем целевое значение анимации для следующего кадра
                            let target_t = if response.hovered() { 1.0 } else { 0.0 };

                            // Плавная интерполяция за ~0.2 секунды
                            let dt = ui.input(|i| i.stable_dt);
                            let speed = 1.0 / 0.2;
                            let new_t = if hover_t < target_t {
                                (hover_t + speed * dt).min(target_t)
                            } else {
                                (hover_t - speed * dt).max(target_t)
                            };

                            // Сохраняем состояние в память egui
                            ui.data_mut(|d| d.insert_temp(anim_id, new_t));

                            // Запрос перерисовки пока идет анимация
                            if new_t != target_t {
                                ui.ctx().request_repaint();
                            }

                            // Обработка клика
                            if response.clicked() {
                                self.sidebar_open = !self.sidebar_open;
                            }

                            ui.add_space(2.0);
                            ui.label(RichText::new("MENU").size(label_size).color(grey_color));
                        }
                    );

                    // 2. Центральная область (ANET VPN) забирает всю оставшуюся ширину
                    let available_width = ui.available_width() - 60.0; // вычитаем ширину правой панели (если Windows)

                    #[cfg(target_os = "windows")]
                    let available_width = ui.available_width() - 60.0; // отнимаем правую кнопку тоже

                    ui.allocate_ui_with_layout(
                        egui::vec2(available_width, ui.available_height()),
                        egui::Layout::centered_and_justified(egui::Direction::LeftToRight),
                        |ui| {
                            let mut job = LayoutJob::default();
                            let font_id = egui::FontId::new(
                                24.0,
                                egui::FontFamily::Name("Inter-V".into())
                            );

                            job.append("ANET ", 0.0, TextFormat {
                                font_id: font_id.clone(),
                                color: ivory_color,
                                ..Default::default()
                            });

                            job.append("VPN", 0.0, TextFormat {
                                font_id,
                                color: gold_color,
                                ..Default::default()
                            });

                            ui.add(egui::Label::new(job));
                        }
                    );

                    // 3. Правая кнопка (APPS) занимает минимальное пространство (только для Windows)
                    #[cfg(target_os = "windows")]
                    {
                        ui.allocate_ui_with_layout(
                            egui::vec2(60.0, ui.available_height()),
                            egui::Layout::top_down(egui::Align::Center),
                            |ui| {
                                // 1. Уникальный ID для сохранения состояния анимации между кадрами
                                let anim_id = ui.id().with("apps_btn_color");

                                // Получаем значение анимации с ПРЕДЫДУЩЕГО кадра (от 0.0 до 1.0)
                                let hover_t: f32 = ui.data(|d| d.get_temp(anim_id)).unwrap_or(0.0);

                                // 🌟 2. ПЛАВНЫЙ ПЕРЕХОД ЦВЕТА (Обычный цвет -> Цвет при наведении)
                                let normal_color = white_color;
                                let hover_color = gold_color;

                                // Интерполируем каналы R, G, B в зависимости от hover_t
                                let r = ((normal_color.r() as f32) * (1.0 - hover_t) +
                                    (hover_color.r() as f32) * hover_t) as u8;
                                let g = ((normal_color.g() as f32) * (1.0 - hover_t) +
                                    (hover_color.g() as f32) * hover_t) as u8;
                                let b = ((normal_color.b() as f32) * (1.0 - hover_t) +
                                    (hover_color.b() as f32) * hover_t) as u8;
                                let current_color = egui::Color32::from_rgb(r, g, b);

                                // 3. Создаем иконку фиксированного размера с плавно меняющимся цветом
                                let icon = egui::Image
                                    ::new(egui::include_image!("./assets/apps_white.svg"))
                                    .fit_to_exact_size(button_icon_size) // Используем исходный размер
                                    .tint(current_color);

                                let menu_button = egui::Button
                                    ::image(icon)
                                    .min_size(button_size)
                                    .stroke(egui::Stroke::NONE)
                                    .frame(false)
                                    .rounding(button_size.y / 2.0);

                                let response = ui
                                    .add(menu_button)
                                    .on_hover_cursor(egui::CursorIcon::PointingHand);

                                // 4. Вычисляем целевое значение анимации для следующего кадра
                                let target_t = if response.hovered() { 1.0 } else { 0.0 };

                                // Плавная интерполяция за ~0.2 секунды
                                let dt = ui.input(|i| i.stable_dt);
                                let speed = 1.0 / 0.2;
                                let new_t = if hover_t < target_t {
                                    (hover_t + speed * dt).min(target_t)
                                } else {
                                    (hover_t - speed * dt).max(target_t)
                                };

                                // Сохраняем состояние в память egui
                                ui.data_mut(|d| d.insert_temp(anim_id, new_t));

                                // Запрос перерисовки пока идет анимация
                                if new_t != target_t {
                                    ui.ctx().request_repaint();
                                }

                                // Обработка клика
                                if response.clicked() {
                                    self.appbar_open = !self.appbar_open;
                                }

                                ui.add_space(2.0);
                                ui.label(RichText::new("APPS").size(label_size).color(grey_color));
                            }
                            // |ui| {
                            //     let icon = egui::Image
                            //         ::new(egui::include_image!("./assets/apps_white.svg"))
                            //         .fit_to_exact_size(button_icon_size);

                            //     let menu_button = egui::Button
                            //         ::image(icon)
                            //         .min_size(button_size)
                            //         .stroke(egui::Stroke::NONE)
                            //         .frame(false)
                            //         .rounding(button_size.y / 2.0);

                            //     // Добавляем кнопку один раз, сразу настраиваем курсор и получаем response
                            //     let response = ui
                            //         .add(menu_button)
                            //         .on_hover_cursor(egui::CursorIcon::PointingHand);

                            //     // Проверяем клик через полученный response
                            //     if response.clicked() {
                            //         self.appbar_open = !self.appbar_open; // Или sidebar_open, в зависимости от нужной кнопки
                            //     }
                            //     ui.add_space(2.0);
                            //     ui.label(RichText::new("APPS").size(label_size).color(grey_color));
                            // }
                        );
                    }
                });

                ui.add_space(20.0);
                ui.vertical_centered(|ui| {
                    if let Some(err) = &self.config_err {
                        ui.label(egui::RichText::new(err).color(egui::Color32::RED));
                    } else {
                        ui.label(egui::RichText::new(&self.config_name).color(gold_color));
                    }
                    if self.shared.lock().unwrap().client.is_none() && self.config_err.is_none() {
                        ui.label(
                            egui::RichText
                                ::new("(Выберите конфиг слева или добавьте новый)")
                                .size(15.0)
                                .strong()
                                .color(egui::Color32::from_gray(80))
                        );
                    }
                });

                if !server_names.is_empty() {
                    ui.add_space(10.0);
                    ui.vertical_centered(|ui| {
                        if state == ConnectionState::Disconnected {
                            ui.horizontal(|ui| {
                                ui.add_space(ui.available_width() * 0.1);
                                ui.label(egui::RichText::new("Подключение к:").color(ivory_color));

                                let mut changed = false;
                                let mut selected_name = String::new();

                                egui::ComboBox
                                    ::from_id_salt("first_server_select")
                                    .selected_text(
                                        egui::RichText::new(&selected_server_name).color(gold_color)
                                    )
                                    .show_ui(ui, |ui| {
                                        for name in &server_names {
                                            let option_text = egui::RichText
                                                ::new(name)
                                                .color(gold_color);

                                            if
                                                ui
                                                    .selectable_label(
                                                        name == &selected_server_name,
                                                        option_text
                                                    )
                                                    .clicked()
                                            {
                                                selected_name = name.clone();
                                                changed = true;
                                            }
                                        }
                                    });

                                if changed {
                                    let active_cfg_data = {
                                        let mut settings = self.settings.lock().unwrap();
                                        if let Some(active_cfg) = settings.get_active_config() {
                                            settings.selected_servers.insert(
                                                active_cfg.id.clone(),
                                                selected_name
                                            );
                                            settings.save();

                                            Some((
                                                active_cfg.id.clone(),
                                                active_cfg.content.clone(),
                                                active_cfg.name.clone(),
                                            ))
                                        } else {
                                            None
                                        }
                                    };

                                    if let Some((id, content, name)) = active_cfg_data {
                                        self.load_config_from_content(&id, &content, &name);
                                    }
                                }
                            });
                        } else {
                            ui.horizontal(|ui| {
                                ui.add_space(ui.available_width() * 0.1);
                                ui.label(egui::RichText::new("Активная нода:").color(gold_color));
                                ui.label(
                                    egui::RichText
                                        ::new(&selected_server_name)
                                        .strong()
                                        .color(gold_color)
                                );
                            });
                        }
                    });
                }

                ui.add_space(ui.available_height() * 0.15);

                //кнопка CONNECT

                ui.vertical_centered(|ui| {
                    let btn_size = egui::vec2(180.0, 180.0);

                    // Определяем текст и цвета градиента (верх и низ)
                    let (btn_text, color_top, color_bottom) = match state {
                        ConnectionState::Disconnected =>
                            (
                                "CONNECT",
                                gold_color, // Светло-зеленый
                                light_blue_color, // Темно-зеленый
                            ),
                        ConnectionState::Connecting => {
                            let time = ctx.input(|i| i.time);
                            let factor = (time.sin() + 1.0) / 2.0;
                            ctx.request_repaint();

                            let r = 255;
                            let g = (140.0 + (80.0 - 140.0) * factor) as u8;
                            let top = egui::Color32::from_rgb(r, g, 0);
                            let bottom = egui::Color32::from_rgb(200, 60, 0);

                            ("CONNECTING", 
                            egui::Color32::from_rgb(247, 137, 46), 
                            egui::Color32::from_rgb(244, 46, 82)
                        )
                        }
                        ConnectionState::Connected =>
                            (
                                "DISCONNECT",
                                 egui::Color32::from_rgb(248, 61, 170), // Темно-красный
                                egui::Color32::from_rgb(243, 208, 120), // Светло-красный
                               
                            ),
                    };

                    let (rect, response) = ui.allocate_exact_size(btn_size, egui::Sense::click());
                    response.clone().on_hover_cursor(egui::CursorIcon::PointingHand);
                    let center = rect.center();
                    let radius = btn_size.x / 2.0;

                    // АНИМАЦИЯ СВЕЧЕНИЯ
                    let hover_animation_id = response.id.with("hover_glow");
                    let hover_t = ui.ctx().animate_bool_with_time(
                        hover_animation_id,
                        response.hovered(),
                        0.5 // Длительность анимации в секундах
                    );

                    //  РИСУЕМ СВЕЧЕНИЕ (интенсивность зависит от hover_t)
                    if hover_t > 0.0 {
                        for glow_i in (1..=6).rev() {
                            let glow_radius = radius + (glow_i as f32) * 2.5;
                            let alpha = ((55.0 - (glow_i as f32) * 3.0) * hover_t) as u8;

                            if alpha > 0 {
                                ui.painter().circle_stroke(
                                    center,
                                    glow_radius,
                                    egui::Stroke::new(
                                        2.5,
                                        egui::Color32::from_rgba_unmultiplied(
                                            color_top.r(),
                                            color_top.g(),
                                            color_top.b(),
                                            alpha
                                        )
                                    )
                                );
                            }
                        }
                        // Запрашиваем перерисовку, пока идет анимация
                        ui.ctx().request_repaint();
                    }

                    // 📌 РИСУЕМ ОСНОВНОЙ КОНТУР КРУГА С ГРАДИЕНТОМ
                    let stroke_width = 2.5;
                    let segments = 128;

                    for i in 0..segments {
                        let a0 = ((i as f32) / (segments as f32)) * std::f32::consts::TAU;
                        let a1 = (((i + 1) as f32) / (segments as f32)) * std::f32::consts::TAU;

                        let p0 = center + radius * egui::vec2(a0.cos(), a0.sin());
                        let p1 = center + radius * egui::vec2(a1.cos(), a1.sin());

                        let y_mid = (p0.y + p1.y) / 2.0;
                        let t = (y_mid - center.y + radius) / (radius * 2.0);
                        let t = t.clamp(0.0, 1.0);

                        let r_col = ((color_top.r() as f32) * (1.0 - t) +
                            (color_bottom.r() as f32) * t) as u8;
                        let g_col = ((color_top.g() as f32) * (1.0 - t) +
                            (color_bottom.g() as f32) * t) as u8;
                        let b_col = ((color_top.b() as f32) * (1.0 - t) +
                            (color_bottom.b() as f32) * t) as u8;

                        ui.painter().line_segment(
                            [p0, p1],
                            egui::Stroke::new(
                                stroke_width,
                                egui::Color32::from_rgb(r_col, g_col, b_col)
                            )
                        );
                    }

                    // Поверх рисуем текст кнопки по центру
                    let galley = ui
                        .painter()
                        .layout_no_wrap(
                            btn_text.to_string(),
                            egui::FontId::proportional(24.0),
                            egui::Color32::WHITE
                        );
                    let text_pos = center - galley.size() / 2.0;
                    ui.painter().galley(text_pos, galley, egui::Color32::WHITE);

                    // Обработка клика
                    if response.clicked() {
                        match state {
                            ConnectionState::Disconnected => {
                                if self.shared.lock().unwrap().client.is_none() {
                                    self.open_file_dialog();
                                } else {
                                    self.start_vpn();
                                }
                            }
                            _ => {
                                self.stop_vpn();
                            }
                        }
                    }

                    ui.add_space(20.0);

                    // Статусный текст снизу
                    match state {
                        ConnectionState::Connected => {
                            ui.label(
                                egui::RichText
                                    ::new("CONNECTED")
                                    .size(16.0)
                                    .strong()
                                    .color(connected_text_color)
                            );
                        }
                        ConnectionState::Disconnected => {
                            ui.label(
                                egui::RichText
                                    ::new("DISCONNECTED")
                                    .size(16.0)
                                    .strong()
                                    .color(grey_color)
                            );
                        }
                        ConnectionState::Connecting => {
                            ui.label(
                                egui::RichText
                                    ::new("CONNECTING")
                                    .size(16.0)
                                    .strong()
                                    .color(egui::Color32::YELLOW)
                            );
                        }
                    }
                });

                ui.add_space(20.0);
            });

        if self.sidebar_open {
            egui::Area
                ::new(egui::Id::new("config_appbar"))
                .order(egui::Order::Foreground)
                .fixed_pos(egui::pos2(0.0, 0.0))
                .show(ctx, |ui| {
                    let screen_rect = ui.ctx().screen_rect();

                    let border_color = egui::Color32::from_rgb(100, 100, 100);
                    let corner_radius = 14.0; // Укажите ваш радиус скругления

                    egui::Frame
                        ::none()
                        .fill(ui.visuals().window_fill())
                        .inner_margin(margin)
                        .corner_radius(corner_radius) // Скругление углов для appbar
                        .stroke(egui::Stroke::new(1.0, border_color)) // Обводка в 1 пиксель
                        .show(ui, |ui| {
                            ui.set_width(screen_rect.width() - margin * 2.0);
                            ui.set_height(screen_rect.height() - margin * 2.0);

                            if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                                self.sidebar_open = false;
                            }

                            ui.horizontal(|ui| {
                                let circle_button = egui::Button
                                    ::new("⏴")
                                    .min_size(button_size)
                                    .stroke(Stroke::NONE)
                                    .rounding(button_size.y / 2.0);

                                // Добавляем кнопку, сразу настраиваем курсор и сохраняем результат
                                let response = ui
                                    .add(circle_button)
                                    .on_hover_cursor(egui::CursorIcon::PointingHand);

                                if response.clicked() {
                                    self.sidebar_open = false;
                                }

                                ui.heading("Настройки профиля");
                            });
                            ui.separator();

                            //let gold_color = egui::Color32::from_rgb(255, 100, 0);

                            ui.label(
                                egui::RichText::new("КОНФИГИ").size(12.0).strong().color(gold_color)
                            );
                            ui.add_space(8.0);

                            for config in configs {
                                let is_active = active_id.as_deref() == Some(&config.id);
                                let is_editing = editing_id.as_deref() == Some(&config.id);

                                let bg_color = if is_active {
                                    egui::Color32::from_rgb(40, 50, 45)
                                } else {
                                    egui::Color32::from_rgb(30, 30, 30)
                                };

                                egui::Frame::NONE
                                    .fill(bg_color)
                                    .inner_margin(4.0)
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            if is_editing {
                                                let response = ui.add(
                                                    egui::TextEdit
                                                        ::singleline(&mut self.edit_name_buffer)
                                                        .desired_width(120.0)
                                                );
                                                if response.lost_focus() {
                                                    self.finish_edit_name();
                                                }
                                                if ui.button("✔").clicked() {
                                                    self.finish_edit_name();
                                                }
                                            } else {
                                                let text_color = if is_active {
                                                    egui::Color32::WHITE
                                                } else {
                                                    gold_color
                                                };
                                                if
                                                    ui
                                                        .add(
                                                            egui::Label
                                                                ::new(
                                                                    egui::RichText
                                                                        ::new(&config.name)
                                                                        .color(text_color)
                                                                )
                                                                .sense(egui::Sense::click())
                                                        )
                                                        .clicked()
                                                {
                                                    self.select_config(&config.id);
                                                }
                                                ui.with_layout(
                                                    egui::Layout::right_to_left(
                                                        egui::Align::Center
                                                    ),
                                                    |ui| {
                                                        if
                                                            ui
                                                                .add(
                                                                    egui::Button
                                                                        ::new("✏")
                                                                        .frame(false)
                                                                        .small()
                                                                )
                                                                .clicked()
                                                        {
                                                            self.start_edit_name(
                                                                &config.id,
                                                                &config.name
                                                            );
                                                        }
                                                        if
                                                            ui
                                                                .add(
                                                                    egui::Button
                                                                        ::new("🗑")
                                                                        .frame(false)
                                                                        .small()
                                                                )
                                                                .clicked()
                                                        {
                                                            self.delete_config(&config.id);
                                                        }
                                                    }
                                                );
                                            }
                                        });
                                    });
                            }
                            ui.add_space(16.0);

                            if
                                ui
                                    .add(
                                        egui::Button
                                            ::new(
                                                egui::RichText
                                                    ::new("➕ Добавить конфиг")
                                                    .color(gold_color)
                                            )
                                            .fill(egui::Color32::from_rgb(45, 45, 45))
                                    )
                                    .clicked()
                            {
                                self.open_file_dialog();
                            }

                            ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                                ui.add_space(10.0);

                                let is_busy = matches!(
                                    self.update_status,
                                    UpdateStatus::Checking | UpdateStatus::Downloading(_)
                                );

                                ui.add_enabled_ui(!is_busy, |ui| {
                                    let label = if is_busy {
                                        "⏳ ЖДИТЕ..."
                                    } else {
                                        "🔄 ПРОВЕРИТЬ ОБНОВЛЕНИЯ"
                                    };

                                    let btn_text = egui::RichText
                                        ::new(label)
                                        .size(11.0)
                                        .strong()
                                        .color(gold_color);
                                    if
                                        ui
                                            .add(
                                                egui::Button
                                                    ::new(btn_text)
                                                    .fill(egui::Color32::from_rgb(45, 45, 45))
                                            )
                                            .clicked()
                                    {
                                        self.check_for_updates();
                                    }
                                });
                            });

                            let (show_upd, release_data, progress) = match &self.update_status {
                                UpdateStatus::Available(r) => (true, Some(r.clone()), None),
                                UpdateStatus::Downloading(p) => (true, None, Some(*p)),
                                _ => (false, None, None),
                            };

                            if show_upd {
                                let modal_bg = egui::Color32::from_rgb(32, 32, 32);

                                egui::Window
                                    ::new("UPDATE_SYSTEM")
                                    .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                                    .collapsible(false)
                                    .resizable(false)
                                    .title_bar(false)
                                    .order(egui::Order::Foreground)
                                    .frame(
                                        egui::Frame::NONE
                                            .fill(modal_bg)
                                            .stroke(egui::Stroke::new(3.0, gold_color))
                                            .inner_margin(24.0)
                                            .corner_radius(4.0)
                                    )
                                    .show(ctx, |ui| {
                                        ui.vertical_centered(|ui| {
                                            ui.label(
                                                egui::RichText
                                                    ::new("SYSTEM UPDATE")
                                                    .size(22.0)
                                                    .strong()
                                                    .color(gold_color)
                                            );

                                            if let Some(rel) = release_data {
                                                ui.label(
                                                    egui::RichText
                                                        ::new(
                                                            format!(
                                                                "Доступна версия: {}",
                                                                rel.tag_name
                                                            )
                                                        )
                                                        .size(16.0)
                                                        .color(gold_color)
                                                );
                                                ui.add_space(16.0);
                                                ui.add_space(16.0);
                                                ui.label(
                                                    egui::RichText
                                                        ::new("Список изменений:")
                                                        .size(14.0)
                                                        .color(gold_color)
                                                        .strong()
                                                );
                                                ui.add_space(4.0);

                                                egui::ScrollArea
                                                    ::vertical()
                                                    .max_height(180.0)
                                                    .auto_shrink([false, true])
                                                    .show(ui, |ui| {
                                                        let changelog = rel.body
                                                            .as_deref()
                                                            .unwrap_or(
                                                                "Описание изменений отсутствует."
                                                            );
                                                        ui.add(
                                                            egui::Label
                                                                ::new(
                                                                    egui::RichText
                                                                        ::new(changelog)
                                                                        .size(13.0)
                                                                        .color(gold_color)
                                                                        .family(
                                                                            egui::FontFamily::Monospace
                                                                        )
                                                                )
                                                                .wrap()
                                                        );
                                                    });
                                                ui.add_space(24.0);
                                                ui.horizontal(|ui| {
                                                    ui.add_space(ui.available_width() / 6.0);

                                                    let btn_update = egui::Button
                                                        ::new(
                                                            egui::RichText
                                                                ::new("ОБНОВИТЬ")
                                                                .size(16.0)
                                                                .strong()
                                                                .color(egui::Color32::BLACK)
                                                        )
                                                        .fill(gold_color)
                                                        .min_size(egui::vec2(120.0, 36.0));

                                                    if ui.add(btn_update).clicked() {
                                                        let r_clone = rel.clone();
                                                        self.logs
                                                            .lock()
                                                            .unwrap()
                                                            .push(
                                                                format!(
                                                                    "> Обновляемся на {}",
                                                                    rel.tag_name
                                                                )
                                                            );
                                                        self.update_status =
                                                            UpdateStatus::Downloading(0.0);
                                                        self.rt.spawn(async move {
                                                            if
                                                                let Err(e) =
                                                                    Updater::download_and_apply(
                                                                        r_clone
                                                                    ).await
                                                            {
                                                                anet_client_core::events::err(
                                                                    format!("Ошибка загрузки: {}", e)
                                                                );
                                                            }
                                                        });
                                                    }

                                                    ui.add_space(20.0);

                                                    let btn_cancel = egui::Button
                                                        ::new(
                                                            egui::RichText
                                                                ::new("ПОЗДНЕЕ")
                                                                .size(16.0)
                                                                .strong()
                                                                .color(egui::Color32::BLACK)
                                                        )
                                                        .fill(gold_color)
                                                        .min_size(egui::vec2(120.0, 36.0));

                                                    if ui.add(btn_cancel).clicked() {
                                                        self.update_status = UpdateStatus::Idle;
                                                    }
                                                });
                                            } else if let Some(p) = progress {
                                                ui.add_space(20.0);
                                                ui.label(
                                                    egui::RichText
                                                        ::new("СКАЧИВАНИЕ НОВЫХ БИНАРНИКОВ...")
                                                        .color(gold_color)
                                                        .strong()
                                                );
                                                ui.add_space(12.0);

                                                ui.add(
                                                    egui::ProgressBar
                                                        ::new(p)
                                                        .text(format!("{:.1}%", p * 100.0))
                                                        .desired_width(260.0)
                                                        .fill(gold_color)
                                                );

                                                ui.add_space(20.0);
                                                ui.label(
                                                    egui::RichText
                                                        ::new(
                                                            "Пожалуйста, не закрывайте приложение"
                                                        )
                                                        .size(11.0)
                                                        .italics()
                                                        .color(gold_color)
                                                );
                                            }
                                        });
                                    });
                            }
                        });
                });
        }

        #[cfg(target_os = "windows")]
        if self.appbar_open {
            egui::Area
                ::new(egui::Id::new("config_appbar"))
                .order(egui::Order::Foreground)
                .fixed_pos(egui::pos2(0.0, 0.0))
                .show(ctx, |ui| {
                    let screen_rect = ui.ctx().screen_rect();

                    let border_color = egui::Color32::from_rgb(100, 100, 100);
                    let corner_radius = 14.0; // Укажите ваш радиус скругления

                    egui::Frame
                        ::none()
                        .fill(ui.visuals().window_fill())
                        .inner_margin(margin)
                        .corner_radius(corner_radius) // Скругление углов для appbar
                        .stroke(egui::Stroke::new(1.0, border_color)) // Обводка в 1 пиксель
                        .show(ui, |ui| {
                            ui.set_width(screen_rect.width() - margin * 2.0);
                            ui.set_height(screen_rect.height() - margin * 2.0);

                            if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                                self.appbar_open = false;
                            }

                            ui.horizontal(|ui| {
                                let circle_button = egui::Button
                                    ::new("⏴")
                                    .min_size(button_size)
                                    .stroke(Stroke::NONE)
                                    .rounding(button_size.y / 2.0);

                                // Добавляем кнопку, сразу настраиваем курсор и сохраняем результат
                                let response = ui
                                    .add(circle_button)
                                    .on_hover_cursor(egui::CursorIcon::PointingHand);

                                if response.clicked() {
                                    self.appbar_open = false;
                                }

                                ui.heading("App tunnel");
                            });
                            ui.separator();

                            self.render_process_list(ui);
                        });
                });
        }

        if let Some(err_msg) = self.error_modal.clone() {
            let modal_bg = egui::Color32::from_rgb(32, 32, 32);
            egui::Window
                ::new("ERROR_SYSTEM")
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .collapsible(false)
                .resizable(false)
                .title_bar(false)
                .frame(
                    egui::Frame::NONE
                        .fill(modal_bg)
                        .stroke(egui::Stroke::new(3.0, gold_color))
                        .inner_margin(24.0)
                        .corner_radius(4.0)
                )
                .show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.label(
                            egui::RichText
                                ::new("ОШИБКА ДОСТУПА")
                                .size(22.0)
                                .strong()
                                .color(gold_color)
                        );
                        ui.add_space(16.0);
                        ui.label(
                            egui::RichText
                                ::new(&err_msg)
                                .size(16.0)
                                .line_height(Some(20.0))
                                .color(gold_color)
                                .family(egui::FontFamily::Monospace)
                        );
                        ui.add_space(24.0);
                        if
                            ui
                                .add(
                                    egui::Button
                                        ::new(
                                            egui::RichText
                                                ::new(" ПОНЯТНО (OK) ")
                                                .size(16.0)
                                                .strong()
                                                .color(egui::Color32::BLACK)
                                        )
                                        .fill(gold_color)
                                        .min_size(egui::vec2(140.0, 36.0))
                                )
                                .clicked()
                        {
                            self.error_modal = None;
                            while self.event_rx.try_recv().is_ok() {}
                        }
                    });
                });
        }

        if matches!(self.update_status, UpdateStatus::ReadyToRestart) {
            // let gold_color = egui::Color32::from_rgb(255, 100, 0);
            let modal_bg = egui::Color32::from_rgb(32, 32, 32);

            egui::Window
                ::new("RESTART_REQUIRED")
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .collapsible(false)
                .resizable(false)
                .title_bar(false)
                .frame(
                    egui::Frame::NONE
                        .fill(modal_bg)
                        .stroke(egui::Stroke::new(3.0, gold_color))
                        .inner_margin(24.0)
                        .corner_radius(4.0)
                )
                .show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.label(
                            egui::RichText
                                ::new("ОБНОВЛЕНИЕ ЗАГРУЖЕНО")
                                .size(22.0)
                                .strong()
                                .color(gold_color)
                        );
                        ui.add_space(16.0);
                        ui.label(
                            egui::RichText
                                ::new(
                                    "Все компоненты системы заменены на новые.\nПерезапустить приложение сейчас?"
                                )
                                .size(16.0)
                                .color(gold_color)
                                .family(egui::FontFamily::Monospace)
                        );
                        ui.add_space(24.0);

                        ui.horizontal(|ui| {
                            ui.add_space(ui.available_width() / 6.0);

                            if
                                ui
                                    .add(
                                        egui::Button
                                            ::new(
                                                egui::RichText
                                                    ::new(" ПЕРЕЗАПУСК ")
                                                    .size(16.0)
                                                    .strong()
                                                    .color(egui::Color32::BLACK)
                                            )
                                            .fill(gold_color)
                                            .min_size(egui::vec2(120.0, 36.0))
                                    )
                                    .clicked()
                            {
                                Updater::final_restart();
                            }

                            ui.add_space(20.0);

                            if
                                ui
                                    .add(
                                        egui::Button
                                            ::new(
                                                egui::RichText
                                                    ::new(" ПОЗЖЕ ")
                                                    .size(16.0)
                                                    .strong()
                                                    .color(gold_color)
                                            )
                                            .frame(false)
                                    )
                                    .clicked()
                            {
                                self.update_status = UpdateStatus::Idle;
                                self.log("Обновление будет применено при следующем запуске.");
                            }
                        });
                    });
                });
        }

        let painter = ctx.layer_painter(
            egui::LayerId::new(egui::Order::Foreground, egui::Id::new("window_border"))
        );
        let screen_rect = ctx.screen_rect();

        // Укажите реальный радиус скругления ваших углов вместо 8.0
        let corner_radius = 14.0;

        painter.rect_stroke(
            screen_rect,
            corner_radius,
            egui::Stroke::new(1.0, egui::Color32::from_rgb(100, 100, 100)),
            egui::StrokeKind::Inside // Прижимаем обводку внутрь, чтобы она не обрезалась границами экрана
        );
    }
}
