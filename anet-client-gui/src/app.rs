#![allow(warnings)]
include!(concat!(env!("OUT_DIR"), "/built.rs"));

use sysinfo::System;
use tokio::runtime::{ Handle, Runtime };

use eframe::egui;
use egui::{
    containers::Sides,
    scroll_area::ScrollBarVisibility,
    text::{ LayoutJob, TextFormat },
    FontData,
    FontDefinitions,
    FontFamily,
    FontId,
    RichText,
    Stroke,
    Visuals,
};

use notify_rust::Notification;

use anet_client_core::{
    client::AnetClient,
    config::CoreConfig,
    events::{ set_handler, AnetEvent, ClientState, EventHandler },
    platform::create_route_manager,
    updater::{ GithubRelease, Updater },
};

use crate::{
    config::AppSettings,
    tray::{ TrayBackground, TrayCommand },
    tun_factory::DesktopTunFactory,
};

use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{ mpsc::{ channel, Receiver, Sender }, Arc, Mutex },
};

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

        if let AnetEvent::ClientStateChanged { state, .. } = &event {
            let mut guard = self.shared.lock().unwrap();
            guard.state = match state {
                ClientState::Connected => ConnectionState::Connected,
                ClientState::Connecting | ClientState::Reconnecting | ClientState::Stopping => {
                    ConnectionState::Connecting
                }
                ClientState::Disconnected | ClientState::Stopped | ClientState::Failed => {
                    ConnectionState::Disconnected
                }
            };
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
    logbar_open: bool,
    node_popup_open: bool,
    editing_config_id: Option<String>,
    edit_name_buffer: String,
    error_modal: Option<String>,
    update_status: UpdateStatus,

    pub processes: Vec<ProcessItem>,
    pub sys: System,

    pub filter_mode: FilterMode,

    pub total_rx: String,
    pub total_tx: String,
    pub total_rtt: String,
    pub total_rxm: String,
    pub total_txm: String,

    tray_value: bool,
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
    } else if let Some(client_clone) = guard.client.clone() {
        guard.state = ConnectionState::Disconnected;
        drop(guard);

        let logs_clone = logs.clone();
        rt_handle.spawn(async move {
            logs_clone.lock().unwrap().push("> Stopping service...".into());
            let _ = client_clone.stop().await;
        });
    }
}

impl ANetApp {
    #[cfg(target_os = "windows")]
    pub fn refresh_processes(&mut self) {
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
                let selected_apps: Vec<String> = self.processes
                    .iter()
                    .filter(|p| p.is_selected)
                    .map(|p| p.name.clone())
                    .collect();

                let filter_mode = self.filter_mode;
                let mut updated_config_data: Option<(String, String, String)> = None;

                {
                    let mut settings = self.settings.lock().unwrap();
                    let active_id = settings.active_config_id.clone();

                    if let Some(id) = active_id {
                        let updated_info = {
                            if let Some(cfg) = settings.configs.iter_mut().find(|c| c.id == id) {
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
                            Ok(_) => {
                                self.log(
                                    &format!("Конфиг успешно перезаписан на диске: {:?}", path)
                                );
                            }
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

                    self.load_config_from_content(&id, &content, &name);
                    self.log("Настройки приложений применены.");

                    let current_state = self.shared.lock().unwrap().state;
                    if current_state == ConnectionState::Connected {
                        self.log("Переподключение VPN из-за изменения настроек...");
                        self.stop_vpn();

                        let shared_clone = self.shared.clone();
                        let logs_clone = self.logs.clone();
                        let rt_handle = self.rt.handle().clone();

                        rt_handle.spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;

                            let client_opt = {
                                let mut guard = shared_clone.lock().unwrap();
                                guard.state = ConnectionState::Connecting;
                                guard.client.clone()
                            };

                            if let Some(client_clone) = client_opt {
                                logs_clone.lock().unwrap().push("> Re-starting service...".into());

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

        ui.style_mut().spacing.scroll.foreground_color = false;
        ui.style_mut().visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(80, 80, 80);
        ui.style_mut().visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(120, 120, 120);
        ui.style_mut().visuals.widgets.active.bg_fill = egui::Color32::from_rgb(160, 160, 160);

        egui::ScrollArea
            ::vertical()
            .auto_shrink([false, false])
            .scroll_bar_visibility(ScrollBarVisibility::AlwaysVisible)
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
        let mut old_exclude_idx = None;

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

        if let Some(idx) = old_exclude_idx {
            lines.remove(idx);
            if let Some(ref mut p) = per_app_idx {
                if *p > idx {
                    *p -= 1;
                }
            }
            if let Some(ref mut m) = mode_idx {
                if *m > idx {
                    *m -= 1;
                }
            }
            if let Some(ref mut e) = main_end_idx {
                if *e > idx {
                    *e -= 1;
                }
            }
        }

        match per_app_idx {
            Some(idx) => {
                lines[idx] = per_app_line.clone();
            }
            None => {
                let default_insert_pos = main_end_idx.unwrap_or(lines.len());
                lines.insert(default_insert_pos, per_app_line.clone());
                main_end_idx = Some(default_insert_pos + 1);
            }
        }

        match mode_idx {
            Some(idx) => {
                lines[idx] = mode_line.clone();
            }
            None => {
                let insert_pos = main_end_idx.unwrap_or(lines.len());
                lines.insert(insert_pos.min(lines.len()), mode_line.clone());
            }
        }

        lines.join("\n")
    }

    #[cfg(target_os = "windows")]
    fn inject_tray_mode_to_toml(content: &str, tray_mode: bool) -> String {
    let normalized = content.replace("\r\n", "\n");
    let mut lines: Vec<String> = normalized
        .lines()
        .map(|s| s.to_string())
        .collect();

    let tray_line = format!("tray_mode = {}", tray_mode);

    let mut in_main = false;
    let mut main_end_idx = None;
    let mut tray_mode_idx = None;

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
            let clean_line: String = trimmed
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();

            if clean_line.starts_with("tray_mode=") {
                tray_mode_idx = Some(i);
            }
        }
    }

    match tray_mode_idx {
        Some(idx) => {
            lines[idx] = tray_line;
        }
        None => {
            let insert_pos = main_end_idx.unwrap_or(lines.len());
            lines.insert(insert_pos, tray_line);
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
            logbar_open: false,
            node_popup_open: false,
            editing_config_id: None,
            edit_name_buffer: String::new(),
            error_modal: None,
            update_status: UpdateStatus::Idle,
            processes: Vec::new(),
            sys: System::new_all(),
            filter_mode: FilterMode::Include,

            total_rx: "0 B".to_string(),
            total_tx: "0 B".to_string(),
            total_rtt: "0".to_string(),
            total_rxm: "0 B".to_string(),
            total_txm: "0 B".to_string(),

            tray_value: true,
        };

        #[cfg(target_os = "windows")]
        app.refresh_processes();

        let config_to_load = app.settings.lock().unwrap().get_active_config();
        if let Some(config) = config_to_load {
            app.load_config_from_content(&config.id, &config.content, &config.name);
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
                self.filter_mode = match cfg.main.per_app_mode {
                    anet_client_core::config::PerAppMode::All => FilterMode::All,
                    anet_client_core::config::PerAppMode::Include => FilterMode::Include,
                    anet_client_core::config::PerAppMode::Exclude => FilterMode::Exclude,
                };

                // Загружаем настройку сворачивания в трей из [main]
if let Ok(raw_toml) = toml::from_str::<toml::Value>(content) {
    self.tray_value = raw_toml
        .get("main")
        .and_then(|main| main.get("tray_mode"))
        .and_then(|value| value.as_bool())
        .unwrap_or(true);
}

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
    // Сбрасываем состояние минимизации и делаем окно видимым
    ctx.send_viewport_cmd_to(egui::ViewportId::ROOT, egui::ViewportCommand::Minimized(false));
    ctx.send_viewport_cmd_to(egui::ViewportId::ROOT, egui::ViewportCommand::Visible(true));
    ctx.send_viewport_cmd_to(egui::ViewportId::ROOT, egui::ViewportCommand::Focus);
    ctx.request_repaint_of(egui::ViewportId::ROOT);
}

fn load_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    let jetbrains_font_data = include_bytes!("./assets/fonts/JetBrainsMono.ttf");
    let inter_font_data = include_bytes!("./assets/fonts/Inter/Inter-Light.otf");

    fonts.font_data.insert(
        "JetBrainsMono".to_owned(),
        std::sync::Arc::new(egui::FontData::from_static(jetbrains_font_data))
    );
    fonts.font_data.insert(
        "Inter-V".to_owned(),
        std::sync::Arc::new(egui::FontData::from_static(inter_font_data))
    );

    fonts.families
        .entry(egui::FontFamily::Name("Inter-V".into()))
        .or_default()
        .push("Inter-V".to_owned());

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
        let console_bg = egui::Color32::from_rgb(21, 26, 35);
        let grey_color = egui::Color32::from_rgb(128, 128, 128);
        let green_color = egui::Color32::from_rgb(65, 180, 65);
        let orange_color = egui::Color32::from_rgb(218, 130, 0);
        let red_color = egui::Color32::from_rgb(220, 60, 60);

        let button_size = egui::vec2(32.0, 32.0);
        let button_icon_size = egui::vec2(26.0, 26.0);

        let margin = 20.0;
        let label_size = 10.0;

        let track_width = 2.0;
        let track_margin = -2.0;

        let track_corner = egui::CornerRadius::same(3);
        let track_color = egui::Color32::from_black_alpha(40);

        let tracker_corner = egui::CornerRadius::same(3);
        let tracker_color = egui::Color32::from_rgb(60, 112, 222);

        let mut visuals = egui::Visuals::dark();

        visuals.window_fill = dark_color;
        visuals.window_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(50, 50, 50));
        visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(20, 20, 20);
        visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(30, 30, 30);
        visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(45, 45, 45);
        visuals.widgets.active.bg_fill = egui::Color32::from_rgb(40, 80, 60);

        ctx.set_visuals(visuals);
        ctx.request_repaint_after(std::time::Duration::from_millis(500));


        // --- ОБРАБОТКА СВОРАЧИВАНИЯ ---
let is_minimized = ctx.input(|i| {
    i.viewport().minimized.unwrap_or(false)
});

if self.tray_value {
    // Режим "Сворачивать приложение в трей"
    if is_minimized {
        if !self.is_in_tray {
            self.is_in_tray = true;

            ctx.send_viewport_cmd(
                egui::ViewportCommand::Visible(false)
            );

            let _ = self.tray_cmd_tx.send(
                TrayCommand::WindowVisible(false)
            );

            let _ = self.tray_cmd_tx.send(
                TrayCommand::NotifyHidden
            );
        }

        return;
    } else if self.is_in_tray {
        self.is_in_tray = false;

        let _ = self.tray_cmd_tx.send(
            TrayCommand::WindowVisible(true)
        );
    }
}

// Если tray_value == false —
// обычная минимизация окна никак не перехватывается.

        let titlebar_button = egui::vec2(42.0, 38.0);

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
                ui.painter().rect_filled(
                    rect,
                    egui::CornerRadius {
                        nw: 14,
                        ne: 14,
                        sw: 0,
                        se: 0,
                    },
                    title_bg
                );

                // 2. Интерактивная зона для перетаскивания окна
                let response = ui.interact(
                    rect,
                    ui.id().with("title_bar"),
                    egui::Sense::click_and_drag()
                );
                if
                    response.dragged_by(egui::PointerButton::Primary) ||
                    response.drag_started_by(egui::PointerButton::Primary)
                {
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

                                let indicator_color = egui::Color32::from_rgb(76, 175, 80);
                                let (dot_rect, _) = ui.allocate_exact_size(
                                    egui::vec2(8.0, 8.0),
                                    egui::Sense::hover()
                                );
                                ui.painter().circle_filled(dot_rect.center(), 4.0, indicator_color);

                                ui.add_space(8.0);

                                let mut job = LayoutJob::default();
                                let font_id = egui::FontId::new(
                                    12.0,
                                    egui::FontFamily::Name("Inter-V".into())
                                );

                                job.append("ANet VPN ", 0.0, TextFormat {
                                    font_id: font_id.clone(),
                                    color: white_color,
                                    ..Default::default()
                                });

                                let version_str = format!("{} ({})", GIT_TAG, COMMIT_HASH);
                                job.append(&version_str, 0.0, TextFormat {
                                    font_id,
                                    color: grey_color,
                                    ..Default::default()
                                });

                                ui.add(egui::Label::new(job));
                            });
                        });

                        // ПРАВАЯ ЧАСТЬ (Кнопки управления)
                        let right_rect = egui::Rect::from_min_size(
                            rect.right_top() - egui::vec2(80.0, 0.0),
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
                                        egui::CornerRadius {
                                            nw: 0,
                                            ne: 14,
                                            sw: 0,
                                            se: 0,
                                        },
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

                                // Прямое скрытие окна в трей
                                // Кнопка "Свернуть"
if min_response.clicked() {
    if self.tray_value {
        // ==========================================
        // РЕЖИМ: СВОРАЧИВАНИЕ В ТРЕЙ
        // ==========================================
        self.is_in_tray = true;

        ctx.send_viewport_cmd(
            egui::ViewportCommand::Visible(false)
        );

        let _ = self.tray_cmd_tx.send(
            TrayCommand::WindowVisible(false)
        );

        let _ = self.tray_cmd_tx.send(
            TrayCommand::NotifyHidden
        );
    } else {
        // ==========================================
        // ОБЫЧНЫЙ РЕЖИМ: МИНИМИЗАЦИЯ ОКНА
        // ==========================================
        ctx.send_viewport_cmd(
            egui::ViewportCommand::Minimized(true)
        );
    }
}
                            });
                        });
                    });
                });

                // 4. Разделительная линия
                let painter = ui.painter();
                painter.line_segment(
                    [rect.left_bottom(), rect.right_bottom()],
                    egui::Stroke::new(1.0, ui.style().visuals.window_stroke.color)
                );
            });

        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                // 1. Каждую секунду обновляем переменные интерфейса (без записи в лог)
                AnetEvent::Stats { rx, tx, rtt, rxm, txm } => {
                    self.total_rx = rx;
                    self.total_tx = tx;
                    self.total_rtt = rtt;
                    self.total_rxm = rxm;
                    self.total_txm = txm;
                }

                AnetEvent::Status(msg) => {
                    self.log(&msg);
                }
                AnetEvent::ClientStateChanged { state, message, server_name } => {
                    self.log(&message);

                    if
                        matches!(
                            state,
                            ClientState::Disconnected | ClientState::Stopped | ClientState::Failed
                        )
                    {
                        self.total_rx = "0 B".to_string();
                        self.total_tx = "0 B".to_string();
                        self.total_rtt = "0".to_string();
                        self.total_rxm = "0 B".to_string();
                        self.total_txm = "0 B".to_string();
                    }

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

        let panel_frame = egui::Frame::NONE.fill(console_bg).corner_radius(egui::CornerRadius {
            nw: 0,
            ne: 0,
            sw: 14,
            se: 14,
        });

        let console_inner_frame = egui::Frame::NONE
            .fill(console_bg)
            .inner_margin(egui::Margin::same(10))
            .outer_margin(egui::Margin::same(0))
            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(38, 41, 50)))
            .corner_radius(egui::CornerRadius {
                nw: 0,
                ne: 0,
                sw: 14,
                se: 14,
            });

        let border_color = egui::Color32::from_rgb(38, 41, 50);
        let text_muted = egui::Color32::from_rgb(140, 145, 155);
        let text_white = egui::Color32::WHITE;

        egui::TopBottomPanel
            ::bottom("stalker_console")
            .resizable(false)
            .min_height(170.0)
            .default_height(170.0)
            .show_separator_line(false)
            .frame(panel_frame)
            .show(ctx, |ui| {
                // Внутренняя карточка со внешними отступами от границ окна
                egui::Frame::NONE
                    .fill(dark_color)
                    .stroke(egui::Stroke::new(1.0, border_color))
                    .corner_radius(egui::CornerRadius {
                        nw: 14,
                        ne: 14,
                        sw: 14,
                        se: 14,
                    })
                    .outer_margin(egui::Margin::same(10)) // Внешний отступ, отделяющий карточку от краев
                    .inner_margin(egui::Margin::same(12)) // Внутренние отступы контента
                    .show(ui, |ui| {
                        ui.vertical(|ui| {
                            // --- HEADER ---
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText
                                        ::new("CONNECTION")
                                        .family(egui::FontFamily::Name("Inter-V".into()))
                                        .size(11.0)
                                        .color(text_muted)
                                        .strong()
                                );

                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        let btn = ui.add(
                                            egui::Label
                                                ::new(
                                                    egui::RichText
                                                        ::new("VIEW LOG →")
                                                        .family(
                                                            egui::FontFamily::Name("Inter-V".into())
                                                        )
                                                        .size(11.0)
                                                        .color(text_muted)
                                                )
                                                .sense(egui::Sense::click())
                                        );

                                        if btn.hovered() {
                                            ui.ctx().set_cursor_icon(
                                                egui::CursorIcon::PointingHand
                                            );
                                        }
                                        if btn.clicked() {
                                            self.logbar_open = !self.logbar_open;
                                        }
                                    }
                                );
                            });

                            ui.add_space(6.0);
                            let (rect, _) = ui.allocate_exact_size(
                                egui::vec2(ui.available_width(), 1.0),
                                egui::Sense::hover()
                            );
                            ui.painter().line_segment(
                                [rect.left_center(), rect.right_center()],
                                egui::Stroke::new(1.0, border_color)
                            );
                            ui.add_space(6.0);

                            // --- TOP ROW: RTT | DOWNLOAD | UPLOAD ---
                            ui.columns(3, |cols| {
                                // 1. RTT
                                cols[0].vertical(|ui| {
                                    ui.label(
                                        egui::RichText
                                            ::new("RTT")
                                            .size(10.0)
                                            .color(text_muted)
                                            .family(egui::FontFamily::Name("Inter-V".into()))
                                    );
                                    ui.add_space(2.0);
                                    ui.label(
                                        egui::RichText
                                            ::new(format!("{}", self.total_rtt))
                                            .size(15.0)
                                            .color(text_white)
                                            .strong()
                                            .family(egui::FontFamily::Name("Inter-V".into()))
                                    );
                                });

                                // 2. DOWNLOAD
                                cols[1].vertical(|ui| {
                                    ui.label(
                                        egui::RichText
                                            ::new("↓ DOWNLOAD")
                                            .size(10.0)
                                            .color(text_muted)
                                            .family(egui::FontFamily::Name("Inter-V".into()))
                                    );
                                    ui.add_space(2.0);
                                    ui.label(
                                        egui::RichText
                                            ::new(format!("{:.2} Mbps", self.total_rxm))
                                            .size(15.0)
                                            .color(text_white)
                                            .strong()
                                            .family(egui::FontFamily::Name("Inter-V".into()))
                                    );
                                });

                                // 3. UPLOAD
                                cols[2].vertical(|ui| {
                                    ui.label(
                                        egui::RichText
                                            ::new("↑ UPLOAD")
                                            .size(10.0)
                                            .color(text_muted)
                                            .family(egui::FontFamily::Name("Inter-V".into()))
                                    );
                                    ui.add_space(2.0);
                                    ui.label(
                                        egui::RichText
                                            ::new(format!("{:.2} Mbps", self.total_txm))
                                            .size(15.0)
                                            .color(text_white)
                                            .strong()
                                            .family(egui::FontFamily::Name("Inter-V".into()))
                                    );
                                });
                            });

                            ui.add_space(6.0);
                            let (rect, _) = ui.allocate_exact_size(
                                egui::vec2(ui.available_width(), 1.0),
                                egui::Sense::hover()
                            );
                            ui.painter().line_segment(
                                [rect.left_center(), rect.right_center()],
                                egui::Stroke::new(1.0, border_color)
                            );
                            ui.add_space(6.0);

                            // --- BOTTOM ROW: TOTAL RX | TOTAL TX ---
                            ui.columns(2, |cols| {
                                // 1. TOTAL RX
                                cols[0].vertical(|ui| {
                                    ui.label(
                                        egui::RichText
                                            ::new("↓ TOTAL RX")
                                            .size(10.0)
                                            .color(text_muted)
                                            .family(egui::FontFamily::Name("Inter-V".into()))
                                    );
                                    ui.add_space(2.0);
                                    ui.label(
                                        egui::RichText
                                            ::new(format!("{}", self.total_rx))
                                            .size(15.0)
                                            .color(text_white)
                                            .strong()
                                            .family(egui::FontFamily::Name("Inter-V".into()))
                                    );
                                });

                                // 2. TOTAL TX
                                cols[1].vertical(|ui| {
                                    ui.label(
                                        egui::RichText
                                            ::new("↑ TOTAL TX")
                                            .size(10.0)
                                            .color(text_muted)
                                            .family(egui::FontFamily::Name("Inter-V".into()))
                                    );
                                    ui.add_space(2.0);
                                    ui.label(
                                        egui::RichText
                                            ::new(format!("{}", self.total_tx))
                                            .size(15.0)
                                            .color(text_white)
                                            .strong()
                                            .family(egui::FontFamily::Name("Inter-V".into()))
                                    );
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
                    .unwrap_or_else(|| server_names.first().cloned().unwrap_or_default());
            }
        }

        let main_frame = egui::Frame::NONE.fill(dark_color).inner_margin(margin);

        egui::CentralPanel
            ::default()
            .frame(main_frame)
            .show(ctx, |ui| {
                let state = self.shared.lock().unwrap().state.clone();

                ui.horizontal(|ui| {
                    ui.allocate_ui_with_layout(
                        egui::vec2(60.0, ui.available_height()),
                        egui::Layout::top_down(egui::Align::Center),
                        |ui| {
                            let anim_id = ui.id().with("gear_btn_color");
                            let hover_t: f32 = ui.data(|d| d.get_temp(anim_id)).unwrap_or(0.0);

                            let normal_color = white_color;
                            let hover_color = gold_color;

                            let r = ((normal_color.r() as f32) * (1.0 - hover_t) +
                                (hover_color.r() as f32) * hover_t) as u8;
                            let g = ((normal_color.g() as f32) * (1.0 - hover_t) +
                                (hover_color.g() as f32) * hover_t) as u8;
                            let b = ((normal_color.b() as f32) * (1.0 - hover_t) +
                                (hover_color.b() as f32) * hover_t) as u8;
                            let current_color = egui::Color32::from_rgb(r, g, b);

                            let icon = egui::Image
                                ::new(egui::include_image!("./assets/gear_3.svg"))
                                .fit_to_exact_size(button_icon_size)
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

                            let target_t = if response.hovered() { 1.0 } else { 0.0 };
                            let dt = ui.input(|i| i.stable_dt);
                            let speed = 1.0 / 0.2;
                            let new_t = if hover_t < target_t {
                                (hover_t + speed * dt).min(target_t)
                            } else {
                                (hover_t - speed * dt).max(target_t)
                            };

                            ui.data_mut(|d| d.insert_temp(anim_id, new_t));

                            if new_t != target_t {
                                ui.ctx().request_repaint();
                            }

                            if response.clicked() {
                                self.sidebar_open = !self.sidebar_open;
                            }

                            ui.add_space(2.0);
                            ui.label(RichText::new("MENU").size(label_size).color(grey_color));
                        }
                    );

                    #[cfg(target_os = "windows")]
                    let center_width = (ui.available_width() - 60.0).max(0.0);
                    #[cfg(not(target_os = "windows"))]
                    let center_width = ui.available_width();

                    ui.allocate_ui_with_layout(
                        egui::vec2(center_width, ui.available_height()),
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

                    #[cfg(target_os = "windows")]
                    {
                        ui.allocate_ui_with_layout(
                            egui::vec2(60.0, ui.available_height()),
                            egui::Layout::top_down(egui::Align::Center),
                            |ui| {
                                let anim_id = ui.id().with("apps_btn_color");
                                let hover_t: f32 = ui.data(|d| d.get_temp(anim_id)).unwrap_or(0.0);

                                let normal_color = white_color;
                                let hover_color = gold_color;

                                let r = ((normal_color.r() as f32) * (1.0 - hover_t) +
                                    (hover_color.r() as f32) * hover_t) as u8;
                                let g = ((normal_color.g() as f32) * (1.0 - hover_t) +
                                    (hover_color.g() as f32) * hover_t) as u8;
                                let b = ((normal_color.b() as f32) * (1.0 - hover_t) +
                                    (hover_color.b() as f32) * hover_t) as u8;
                                let current_color = egui::Color32::from_rgb(r, g, b);

                                let icon = egui::Image
                                    ::new(egui::include_image!("./assets/apps_white.svg"))
                                    .fit_to_exact_size(button_icon_size)
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

                                let target_t = if response.hovered() { 1.0 } else { 0.0 };
                                let dt = ui.input(|i| i.stable_dt);
                                let speed = 1.0 / 0.2;
                                let new_t = if hover_t < target_t {
                                    (hover_t + speed * dt).min(target_t)
                                } else {
                                    (hover_t - speed * dt).max(target_t)
                                };

                                ui.data_mut(|d| d.insert_temp(anim_id, new_t));

                                if new_t != target_t {
                                    ui.ctx().request_repaint();
                                }

                                if response.clicked() {
                                    self.appbar_open = !self.appbar_open;
                                }

                                ui.add_space(2.0);
                                ui.label(RichText::new("APPS").size(label_size).color(grey_color));
                            }
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
                        let header_text = if state == ConnectionState::Disconnected {
                            "Подключение к:"
                        } else {
                            "Активная нода:"
                        };

                        ui.label(
                            egui::RichText
                                ::new(header_text)
                                .size(13.0)
                                .color(ivory_color)
                                .family(egui::FontFamily::Name("Inter-V".into()))
                        );
                        ui.add_space(7.0);

                        // Один и тот же геометрический компонент в обоих состояниях.
                        // Важно: здесь НЕТ Frame с inner_margin — он больше не может
                        // увеличивать фактическую высоту активной ноды.
                        const NODE_WIDTH: f32 = 266.0;
                        const NODE_HEIGHT: f32 = 36.0;
                        const NODE_RADIUS: u8 = 18;
                        const ITEM_HEIGHT: f32 = 34.0;

                        // Node status indicator: gray until the client is REALLY connected.
                        // Selecting a node/config must not make the indicator orange.
                        let orange = egui::Color32::from_rgb(235, 140, 52);
                        let indicator = match state {
                            ConnectionState::Connected => orange,
                            ConnectionState::Disconnected | ConnectionState::Connecting => {
                                egui::Color32::from_rgb(120, 124, 132)
                            }
                        };
                        let bg = egui::Color32::from_rgb(25, 28, 36);
                        let hover_bg = egui::Color32::from_rgb(31, 35, 44);
                        let border = egui::Color32::from_rgb(50, 54, 66);
                        let text = egui::Color32::from_rgb(242, 243, 246);
                        let muted = egui::Color32::from_rgb(160, 164, 172);

                        let (rect, response) = ui.allocate_exact_size(
                            egui::vec2(NODE_WIDTH, NODE_HEIGHT),
                            if state == ConnectionState::Disconnected {
                                egui::Sense::click()
                            } else {
                                egui::Sense::hover()
                            }
                        );

                        // Popup state belongs to the app, not egui temporary data.
                        // This makes closing on item click deterministic.
                        if state != ConnectionState::Disconnected {
                            self.node_popup_open = false;
                        }

                        if state == ConnectionState::Disconnected && response.clicked() {
                            self.node_popup_open = !self.node_popup_open;
                        }

                        let popup_open = self.node_popup_open;

                        // The field itself is painted manually, so active and inactive
                        // states are pixel-identical in size and shape.
                        let field_fill = if
                            response.hovered() &&
                            state == ConnectionState::Disconnected
                        {
                            hover_bg
                        } else {
                            bg
                        };
                        ui.painter().rect_filled(
                            rect,
                            egui::CornerRadius::same(NODE_RADIUS),
                            field_fill
                        );
                        ui.painter().rect_stroke(
                            rect,
                            egui::CornerRadius::same(NODE_RADIUS),
                            egui::Stroke::new(1.0, border),
                            egui::StrokeKind::Inside
                        );

                        let center_y = rect.center().y;
                        let dot_center = egui::pos2(rect.left() + 18.0, center_y);
                        ui.painter().circle_filled(dot_center, 5.0, indicator);

                        ui.painter().text(
                            egui::pos2(rect.left() + 32.0, center_y),
                            egui::Align2::LEFT_CENTER,
                            &selected_server_name,
                            egui::FontId::new(13.0, egui::FontFamily::Name("Inter-V".into())),
                            text
                        );

                        // Only the disconnected state gets the small dropdown chevron.
                        if state == ConnectionState::Disconnected {
                            let cx = rect.right() - 17.0;
                            let cy = center_y;
                            ui.painter().add(
                                egui::Shape::convex_polygon(
                                    vec![
                                        egui::pos2(cx - 5.0, cy - 2.0),
                                        egui::pos2(cx + 5.0, cy - 2.0),
                                        egui::pos2(cx, cy + 4.0)
                                    ],
                                    muted,
                                    egui::Stroke::NONE
                                )
                            );
                        }

                        // Custom popup: no ScrollArea and no ComboBox-internal scrolling.
                        // Its height is exactly the number of nodes that must be shown.
                        if state == ConnectionState::Disconnected && popup_open {
                            let popup_height = 12.0 + (server_names.len() as f32) * ITEM_HEIGHT;
                            let popup_pos = egui::pos2(rect.left(), rect.bottom() + 6.0);
                            let popup_area_id = egui::Id::new("node_selection_popup");

                            egui::Area
                                ::new(popup_area_id)
                                .order(egui::Order::Foreground)
                                .fixed_pos(popup_pos)
                                .interactable(true)
                                .show(ui.ctx(), |popup_ui| {
                                    popup_ui.set_min_size(egui::vec2(NODE_WIDTH, popup_height));
                                    popup_ui.set_max_size(egui::vec2(NODE_WIDTH, popup_height));

                                    egui::Frame::NONE
                                        .fill(bg)
                                        .stroke(egui::Stroke::new(1.0, border))
                                        .corner_radius(egui::CornerRadius::same(14))
                                        .inner_margin(egui::Margin::symmetric(6, 6))
                                        .show(popup_ui, |popup_ui| {
                                            for name in &server_names {
                                                let selected = name == &selected_server_name;
                                                let (item_rect, item_response) =
                                                    popup_ui.allocate_exact_size(
                                                        egui::vec2(NODE_WIDTH - 12.0, ITEM_HEIGHT),
                                                        egui::Sense::click()
                                                    );

                                                if item_response.hovered() {
                                                    popup_ui
                                                        .painter()
                                                        .rect_filled(
                                                            item_rect,
                                                            egui::CornerRadius::same(9),
                                                            hover_bg
                                                        );
                                                }

                                                if selected {
                                                    popup_ui
                                                        .painter()
                                                        .circle_filled(
                                                            egui::pos2(
                                                                item_rect.left() + 13.0,
                                                                item_rect.center().y
                                                            ),
                                                            4.0,
                                                            orange
                                                        );
                                                }

                                                popup_ui
                                                    .painter()
                                                    .text(
                                                        egui::pos2(
                                                            item_rect.left() + 25.0,
                                                            item_rect.center().y
                                                        ),
                                                        egui::Align2::LEFT_CENTER,
                                                        name,
                                                        egui::FontId::new(
                                                            13.0,
                                                            egui::FontFamily::Name("Inter-V".into())
                                                        ),
                                                        if selected {
                                                            text
                                                        } else {
                                                            muted
                                                        }
                                                    );

                                                if item_response.clicked() {
                                                    // Select the node and immediately collapse the popup.
                                                    // This is the authoritative popup state.
                                                    self.node_popup_open = false;

                                                    let selected_name = name.clone();
                                                    {
                                                        let mut settings = self.settings
                                                            .lock()
                                                            .unwrap();
                                                        if
                                                            let Some(active_cfg) =
                                                                settings.get_active_config()
                                                        {
                                                            settings.selected_servers.insert(
                                                                active_cfg.id.clone(),
                                                                selected_name.clone()
                                                            );
                                                            settings.save();
                                                        }
                                                    }

                                                    let active_cfg_data = {
                                                        let settings = self.settings
                                                            .lock()
                                                            .unwrap();
                                                        settings
                                                            .get_active_config()
                                                            .map(|cfg| {
                                                                (
                                                                    cfg.id.clone(),
                                                                    cfg.content.clone(),
                                                                    cfg.name.clone(),
                                                                )
                                                            })
                                                    };

                                                    if
                                                        let Some((id, content, name)) =
                                                            active_cfg_data
                                                    {
                                                        self.load_config_from_content(
                                                            &id,
                                                            &content,
                                                            &name
                                                        );
                                                    }
                                                }
                                            }
                                        });

                                    // Close the popup when clicking outside it.
                                    let pointer_pos = popup_ui.input(|i| i.pointer.interact_pos());
                                    let outside_click =
                                        popup_ui.input(|i| i.pointer.any_pressed()) &&
                                        pointer_pos.map_or(
                                            false,
                                            |p| !popup_ui.max_rect().contains(p)
                                        );
                                    if outside_click {
                                        self.node_popup_open = false;
                                    }
                                });
                        }
                    });
                }

                ui.add_space(ui.available_height() * 0.15);

                ui.vertical_centered(|ui| {
                    let btn_size = egui::vec2(180.0, 180.0);

                    let (btn_text, color_top, color_bottom) = match state {
                        ConnectionState::Disconnected => ("CONNECT", gold_color, light_blue_color),
                        ConnectionState::Connecting => {
                            let time = ctx.input(|i| i.time);
                            let factor = (time.sin() + 1.0) / 2.0;
                            ctx.request_repaint();

                            let g = (140.0 + (80.0 - 140.0) * factor) as u8;

                            (
                                "CONNECTING",
                                egui::Color32::from_rgb(247, g, 46),
                                egui::Color32::from_rgb(244, 46, 82),
                            )
                        }
                        ConnectionState::Connected =>
                            (
                                "DISCONNECT",
                                egui::Color32::from_rgb(255, 43, 68),
                                egui::Color32::from_rgb(131, 140, 251),
                            ),
                    };

                    let (rect, response) = ui.allocate_exact_size(btn_size, egui::Sense::click());
                    response.clone().on_hover_cursor(egui::CursorIcon::PointingHand);
                    let center = rect.center();
                    let radius = btn_size.x / 2.0;

                    let hover_animation_id = response.id.with("hover_glow");
                    let hover_t = ui
                        .ctx()
                        .animate_bool_with_time(hover_animation_id, response.hovered(), 0.5);

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
                        ui.ctx().request_repaint();
                    }

                    let stroke_width = 5.0;
                    let segments = 128;

                    for i in 0..segments {
                        let a0 = ((i as f32) / (segments as f32)) * std::f32::consts::TAU;
                        let a1 = (((i + 1) as f32) / (segments as f32)) * std::f32::consts::TAU;

                        let p0 = center + radius * egui::vec2(a0.cos(), a0.sin());
                        let p1 = center + radius * egui::vec2(a1.cos(), a1.sin());

                        let y_mid = (p0.y + p1.y) / 2.0;
                        let t = ((y_mid - center.y + radius) / (radius * 2.0)).clamp(0.0, 1.0);

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

                    let galley = ui
                        .painter()
                        .layout_no_wrap(
                            btn_text.to_string(),
                            egui::FontId::proportional(24.0),
                            egui::Color32::WHITE
                        );
                    let text_pos = center - galley.size() / 2.0;
                    ui.painter().galley(text_pos, galley, egui::Color32::WHITE);

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

                    match state {
                        ConnectionState::Connected => {
                            let text_str = "CONNECTED";
                            let font_size = 16.0;

                            let font_id = egui::FontId::new(
                                font_size,
                                egui::FontFamily::Proportional
                            );
                            let galley = ui
                                .painter()
                                .layout_no_wrap(text_str.to_string(), font_id, grey_color);
                            let text_width = galley.rect.width();

                            let icon_size = egui::vec2(16.0, 16.0);
                            let spacing = 2.0;

                            let available_width = ui.available_width();
                            let text_start_x = (available_width - text_width) / 2.0;
                            let left_padding = (text_start_x - icon_size.x + spacing).max(0.0);

                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = spacing;
                                ui.add_space(left_padding);

                                let indicator_color = egui::Color32::from_rgb(76, 175, 80);
                                let (rect, _) = ui.allocate_exact_size(
                                    icon_size,
                                    egui::Sense::hover()
                                );

                                let shifted_rect = rect.translate(egui::vec2(0.0, 0.0));

                                egui::Image
                                    ::new(egui::include_image!("./assets/dot.svg"))
                                    .tint(indicator_color.linear_multiply(0.15))
                                    .paint_at(ui, shifted_rect.expand(4.0));

                                egui::Image
                                    ::new(egui::include_image!("./assets/dot.svg"))
                                    .tint(indicator_color.linear_multiply(0.35))
                                    .paint_at(ui, shifted_rect.expand(2.0));

                                egui::Image
                                    ::new(egui::include_image!("./assets/dot.svg"))
                                    .max_size(icon_size)
                                    .paint_at(ui, shifted_rect);

                                ui.label(
                                    egui::RichText
                                        ::new(text_str)
                                        .size(font_size)
                                        .strong()
                                        .color(green_color)
                                );
                            });
                        }
                        ConnectionState::Disconnected => {
                            let text_str = "DISCONNECTED";
                            let font_size = 16.0;

                            let font_id = egui::FontId::new(
                                font_size,
                                egui::FontFamily::Proportional
                            );
                            let galley = ui
                                .painter()
                                .layout_no_wrap(text_str.to_string(), font_id, grey_color);
                            let text_width = galley.rect.width();

                            let icon_size = egui::vec2(16.0, 16.0);
                            let spacing = 2.0;

                            let available_width = ui.available_width();
                            let text_start_x = (available_width - text_width) / 2.0;
                            let left_padding = (text_start_x - icon_size.x + spacing).max(0.0);

                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = spacing;
                                ui.add_space(left_padding);

                                let indicator_color = grey_color;
                                let (rect, _) = ui.allocate_exact_size(
                                    icon_size,
                                    egui::Sense::hover()
                                );

                                let shifted_rect = rect.translate(egui::vec2(0.0, 0.0));

                                egui::Image
                                    ::new(egui::include_image!("./assets/block.svg"))
                                    .tint(indicator_color.linear_multiply(0.15))
                                    .paint_at(ui, shifted_rect.expand(4.0));

                                egui::Image
                                    ::new(egui::include_image!("./assets/block.svg"))
                                    .tint(indicator_color.linear_multiply(0.35))
                                    .paint_at(ui, shifted_rect.expand(2.0));

                                egui::Image
                                    ::new(egui::include_image!("./assets/block.svg"))
                                    .max_size(icon_size)
                                    .paint_at(ui, shifted_rect);

                                ui.label(
                                    egui::RichText
                                        ::new(text_str)
                                        .size(font_size)
                                        .strong()
                                        .color(grey_color)
                                );
                            });
                        }
                        ConnectionState::Connecting => {
                            let text_str = "CONNECTING";
                            let font_size = 16.0;

                            let font_id = egui::FontId::new(
                                font_size,
                                egui::FontFamily::Proportional
                            );
                            let galley = ui
                                .painter()
                                .layout_no_wrap(text_str.to_string(), font_id, grey_color);
                            let text_width = galley.rect.width();

                            let icon_size = egui::vec2(16.0, 16.0);
                            let spacing = 2.0;

                            let available_width = ui.available_width();
                            let text_start_x = (available_width - text_width) / 2.0;
                            let left_padding = (text_start_x - icon_size.x + spacing).max(0.0);

                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = spacing;
                                ui.add_space(left_padding);

                                let indicator_color = orange_color;
                                let (rect, _) = ui.allocate_exact_size(
                                    icon_size,
                                    egui::Sense::hover()
                                );

                                let shifted_rect = rect.translate(egui::vec2(0.0, 0.0));

                                egui::Image
                                    ::new(egui::include_image!("./assets/connecting.svg"))
                                    .tint(indicator_color.linear_multiply(0.35))
                                    .paint_at(ui, shifted_rect.expand(2.0));

                                egui::Image
                                    ::new(egui::include_image!("./assets/connecting.svg"))
                                    .max_size(icon_size)
                                    .paint_at(ui, shifted_rect);

                                ui.label(
                                    egui::RichText
                                        ::new(text_str)
                                        .size(font_size)
                                        .strong()
                                        .color(orange_color)
                                );
                            });
                        }
                    }
                });

                ui.add_space(20.0);
            });

        if self.sidebar_open {
            egui::Area
                ::new(egui::Id::new("config_sidebar"))
                .order(egui::Order::Foreground)
                .fixed_pos(egui::pos2(0.0, 0.0))
                .show(ctx, |ui| {
                    let screen_rect = ui.ctx().screen_rect();
                    let corner_radius = 14.0;

                    egui::Frame
                        ::none()
                        .fill(ui.visuals().window_fill())
                        .inner_margin(margin)
                        .corner_radius(corner_radius)
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

                                let response = ui
                                    .add(circle_button)
                                    .on_hover_cursor(egui::CursorIcon::PointingHand);

                                if response.clicked() {
                                    self.sidebar_open = false;
                                }

                                ui.heading("Настройки профиля");
                            });
                            ui.separator();

                            if ui
    .checkbox(&mut self.tray_value, "Сворачивать приложение в трэй")
    .changed()
{
    let tray_mode = self.tray_value;

    let mut updated_config_data: Option<(String, String, String)> = None;

    {
        let mut settings = self.settings.lock().unwrap();

        if let Some(active_id) = settings.active_config_id.clone() {
            if let Some(cfg) = settings
                .configs
                .iter_mut()
                .find(|c| c.id == active_id)
            {
                cfg.content = Self::inject_tray_mode_to_toml(
                    &cfg.content,
                    tray_mode,
                );

                updated_config_data = Some((
                    cfg.id.clone(),
                    cfg.content.clone(),
                    cfg.name.clone(),
                ));
            }

            settings.save();
        }
    }

    // Записываем изменения непосредственно в .toml
    if let Some((id, content, name)) = updated_config_data {
        let path_by_id = std::path::PathBuf::from("configs")
            .join(format!("{}.toml", id));

        let path_by_name = std::path::PathBuf::from("configs")
            .join(format!("{}.toml", name));

        let target_path = if path_by_id.exists() {
            Some(path_by_id)
        } else if path_by_name.exists() {
            Some(path_by_name)
        } else {
            let root_id =
                std::path::PathBuf::from(format!("{}.toml", id));

            let root_name =
                std::path::PathBuf::from(format!("{}.toml", name));

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
                Ok(_) => {
                    self.log(&format!(
                        "Настройка tray_mode сохранена: {}",
                        tray_mode
                    ));
                }

                Err(e) => {
                    self.log(&format!(
                        "Ошибка записи tray_mode в {:?}: {}",
                        path, e
                    ));
                }
            }
        }
    }
}
                            ui.separator();
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

                                                ui.style_mut().spacing.scroll.foreground_color = false;
                                                ui.style_mut().visuals.widgets.inactive.bg_fill =
                                                    egui::Color32::from_rgb(80, 80, 80);
                                                ui.style_mut().visuals.widgets.hovered.bg_fill =
                                                    egui::Color32::from_rgb(120, 120, 120);
                                                ui.style_mut().visuals.widgets.active.bg_fill =
                                                    egui::Color32::from_rgb(160, 160, 160);

                                                egui::ScrollArea
                                                    ::vertical()
                                                    .max_height(180.0)
                                                    .auto_shrink([false, true])
                                                    .scroll_bar_visibility(
                                                        ScrollBarVisibility::AlwaysVisible
                                                    )
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
                    let corner_radius = 14.0;
                    egui::Frame
                        ::none()
                        .fill(ui.visuals().window_fill())
                        .inner_margin(margin)
                        .corner_radius(corner_radius)
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

        if self.logbar_open {
            egui::Area
                ::new(egui::Id::new("config_logbar"))
                .order(egui::Order::Foreground)
                .fixed_pos(egui::pos2(0.0, 0.0))
                .show(ctx, |ui| {
                    let screen_rect = ui.ctx().screen_rect();
                    let corner_radius = 14.0;

                    egui::Frame
                        ::none()
                        .fill(ui.visuals().window_fill())
                        .inner_margin(margin)
                        .corner_radius(corner_radius)
                        .show(ui, |ui| {
                            ui.set_width(screen_rect.width() - margin * 2.0);
                            ui.set_height(screen_rect.height() - margin * 2.0);

                            if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                                self.logbar_open = false;
                            }

                            ui.horizontal(|ui| {
                                let circle_button = egui::Button
                                    ::new("⏴")
                                    .min_size(button_size)
                                    .stroke(Stroke::NONE)
                                    .rounding(button_size.y / 2.0);

                                let response = ui
                                    .add(circle_button)
                                    .on_hover_cursor(egui::CursorIcon::PointingHand);

                                if response.clicked() {
                                    self.logbar_open = false;
                                }

                                ui.heading("Log");
                            });
                            ui.separator();

                            let console_inner_frame = egui::Frame::NONE;
                            console_inner_frame.show(ui, |ui| {
                                let output2 = egui::ScrollArea
                                    ::vertical()
                                    .auto_shrink([false, false])
                                    .scroll_bar_visibility(
                                        egui::scroll_area::ScrollBarVisibility::AlwaysHidden
                                    )
                                    .stick_to_bottom(true)
                                    .show(ui, |ui| {
                                        let logs = self.logs.lock().unwrap();

                                        for line in logs.iter() {
                                            let color = if
                                                line.contains("Error") ||
                                                line.contains("Failed") ||
                                                line.contains("error")
                                            {
                                                red_color
                                            } else if line.contains("Tunnel UP") {
                                                green_color
                                            } else if line.contains("Config loaded") {
                                                gold_color
                                            } else if line.contains("Connection lost") {
                                                red_color
                                            } else if line.contains("Cleaning up dead session") {
                                                orange_color
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

                                let viewport_height2 = output2.inner_rect.height();
                                let content_height2 = output2.content_size.y;

                                if content_height2 > viewport_height2 {
                                    let offset_y2 = output2.state.offset.y;

                                    let track_rect2 = egui::Rect::from_min_size(
                                        egui::pos2(
                                            output2.inner_rect.right() - track_width - track_margin,
                                            output2.inner_rect.top()
                                        ),
                                        egui::vec2(track_width, viewport_height2)
                                    );

                                    let thumb_proportion2 = viewport_height2 / content_height2;
                                    let thumb_height2 = (viewport_height2 * thumb_proportion2).max(
                                        20.0
                                    );

                                    let max_scroll2 = content_height2 - viewport_height2;
                                    let scroll_ratio2 = if max_scroll2 > 0.0 {
                                        offset_y2 / max_scroll2
                                    } else {
                                        0.0
                                    };
                                    let thumb_start_y2 =
                                        track_rect2.top() +
                                        scroll_ratio2 * (viewport_height2 - thumb_height2);

                                    let thumb_rect2 = egui::Rect::from_min_size(
                                        egui::pos2(track_rect2.left(), thumb_start_y2),
                                        egui::vec2(track_width, thumb_height2)
                                    );

                                    let painter2 = ui.painter();
                                    painter2.rect_filled(track_rect2, track_corner, track_color);
                                    painter2.rect_filled(
                                        thumb_rect2,
                                        tracker_corner,
                                        tracker_color
                                    );
                                }
                            });
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
                        .corner_radius(14.0)
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
                                                ::new("ЗАКРЫТЬ")
                                                .size(16.0)
                                                .strong()
                                                .color(egui::Color32::BLACK)
                                        )
                                        .fill(gold_color)
                                        .min_size(egui::vec2(120.0, 36.0))
                                )
                                .clicked()
                        {
                            self.error_modal = None;
                        }
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
