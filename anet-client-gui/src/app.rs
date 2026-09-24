//! Главный контроллер и состояние приложения ANetApp

use std::{
    collections::hash_map::DefaultHasher,
    hash::{ Hash, Hasher },
    path::PathBuf,
    sync::{ mpsc::{ channel, Receiver, Sender }, Arc, Mutex },
};

use eframe::egui;
use sysinfo::System;
use tokio::runtime::Runtime;

use anet_client_core::{
    client::AnetClient,
    config::CoreConfig,
    events::{ set_handler, AccountInfo, AnetEvent, ClientState },
    platform::create_route_manager,
    updater::Updater,
};

use crate::{
    config::AppSettings,
    events::GuiEventHandler,
    theme::{ apply_dark_theme, Colors },
    tray::{ TrayBackground, TrayCommand },
    tun_factory::DesktopTunFactory,
    types::{
        ConfigLoadOutcome, ConnectionState, FilterMode, ProcessItem,
        SettingsCategory, SharedState, UpdateStatus,
    },
    ui,
    utils::{
        helpers::{ force_wake_up_window, lock_ignore_poison, push_log, send_notification, toggle_vpn },
        toml::{ inject_exclude_route_to_toml, inject_per_app_to_toml, inject_tray_mode_to_toml },
        validator::validate_exclude_route,
    },
    GIT_TAG, // <-- импортируем из crate (объявлен в lib.rs)
};

pub struct ANetApp {
    pub rt: Runtime,
    pub logs: Arc<Mutex<Vec<String>>>,
    pub config_err: Option<String>,
    pub config_name: String,
    pub event_rx: Receiver<AnetEvent>,
    pub settings: Arc<Mutex<AppSettings>>,
    pub shared: Arc<Mutex<SharedState>>,

    pub config_load_tx: Sender<ConfigLoadOutcome>,
    pub config_load_rx: Receiver<ConfigLoadOutcome>,

    pub file_dialog_tx: Sender<PathBuf>,
    pub file_dialog_rx: Receiver<PathBuf>,

    pub log_save_tx: Sender<Result<PathBuf, String>>,
    pub log_save_rx: Receiver<Result<PathBuf, String>>,

    pub server_names_cache: Vec<(String, String)>,
    pub server_names_cache_key: Option<(String, u64)>,

    pub tray_cmd_tx: Sender<TrayCommand>,

    pub last_known_state: ConnectionState,
    pub is_in_tray: bool,
    pub sidebar_open: bool,    
    pub exclbar_open: bool,
    pub logbar_open: bool,
    pub settingsbar_open: bool,
    pub active_settings_page: Option<SettingsCategory>,
    pub node_popup_open: bool,
    pub editing_config_id: Option<String>,
    pub edit_name_buffer: String,
    pub error_modal: Option<String>,
    pub update_status: UpdateStatus,

    pub processes: Vec<ProcessItem>,
    pub sys: System,

    pub filter_mode: FilterMode,

    pub total_rx: String,
    pub total_tx: String,
    pub total_rtt: String,
    pub total_rxm: String,
    pub total_txm: String,
    pub account_info: Option<AccountInfo>,

    pub tariff_billing: String,
    pub tariff_group: String,
    pub tariff_sessions: String,
    pub tariff_speed: String,
    pub tariff_consumed: String,
    pub tariff_limit: String,
    pub tariff_expires: String,

    pub tray_value: bool,

    pub exclude_routes: Vec<String>,
    pub exclude_route_input: String,
    pub exclude_routes_changed: bool,

    pub toast_message: Option<String>,
    pub toast_until: Option<std::time::Instant>,

    pub status_text: String,
    pub status_color: egui::Color32,
}

impl ANetApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
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
        let (config_load_tx, config_load_rx) = channel::<ConfigLoadOutcome>();
        let (file_dialog_tx, file_dialog_rx) = channel::<PathBuf>();
        let (log_save_tx, log_save_rx) = channel::<Result<PathBuf, String>>();

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
            config_load_tx,
            config_load_rx,
            file_dialog_tx,
            file_dialog_rx,
            log_save_tx,      
            log_save_rx,      
            server_names_cache: Vec::new(),
            server_names_cache_key: None,
            tray_cmd_tx,
            last_known_state: ConnectionState::Disconnected,
            is_in_tray: false,
            sidebar_open: false,            
            exclbar_open: false,
            logbar_open: false,
            settingsbar_open: false,
            active_settings_page: None,
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
            account_info: None,

            tariff_billing: "—".to_string(),
            tariff_group: "—".to_string(),
            tariff_sessions: "—".to_string(),
            tariff_speed: "—".to_string(),
            tariff_consumed: "0 B".to_string(),
            tariff_limit: "—".to_string(),
            tariff_expires: "—".to_string(),

            tray_value: true,

            exclude_routes: Vec::new(),
            exclude_route_input: String::new(),
            exclude_routes_changed: false,

            toast_message: None,
            toast_until: None,

            status_text: "CONNECTION".to_string(),
            status_color: egui::Color32::from_rgb(128, 128, 128),
        };

        #[cfg(target_os = "windows")]
        app.refresh_processes();

        let config_to_load = lock_ignore_poison(&app.settings).get_active_config();
        if let Some(config) = config_to_load {
            app.load_config_from_content(&config.id, &config.content, &config.name, false);
        }

        app
    }

    pub fn show_toast(&mut self, message: impl Into<String>) {
        self.toast_message = Some(message.into());
        self.toast_until = Some(std::time::Instant::now() + std::time::Duration::from_millis(2500));
    }

    pub fn log(&self, msg: &str) {
        push_log(&self.logs, msg);
    }

    /// Список приложений из `per_app` активного конфига (.toml)
    #[cfg(target_os = "windows")]
    pub fn configured_per_app(&self) -> Vec<String> {
        let config = lock_ignore_poison(&self.settings).get_active_config();
        let Some(config) = config else {
            return Vec::new();
        };

        toml::from_str::<toml::Value>(&config.content)
            .ok()
            .and_then(|val| {
                val.get("main")
                    .and_then(|main| main.get("per_app"))
                    .and_then(|apps| apps.as_array())
                    .map(|apps| {
                        apps.iter()
                            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                            .filter(|name| !name.is_empty())
                            .collect()
                    })
            })
            .unwrap_or_default()
    }

    /// Обновление списка запущенных процессов (Windows)
    #[cfg(target_os = "windows")]
    pub fn refresh_processes(&mut self) {
        let selected_apps: std::collections::HashSet<String> = self.processes
            .iter()
            .filter(|p| p.is_selected)
            .map(|p| p.name.to_lowercase())
            .collect();
        let listed_names: std::collections::HashSet<String> = self.processes
            .iter()
            .map(|p| p.name.to_lowercase())
            .collect();

        self.sys.refresh_all();

        let mut map = std::collections::BTreeMap::new();

        for (pid, process) in self.sys.processes() {
            let name = process.name().to_string();

            if name.ends_with(".exe") || cfg!(windows) {
                let is_selected = selected_apps.contains(&name.to_lowercase());

                map.entry(name.to_lowercase()).or_insert(ProcessItem {
                    pid: pid.as_u32(),
                    name,
                    is_selected,
                });
            }
        }

        for name in self.configured_per_app() {
            let key = name.to_lowercase();
            if map.contains_key(&key) {
                continue;
            }
            let is_selected = if listed_names.contains(&key) {
                selected_apps.contains(&key)
            } else {
                true
            };
            map.entry(key).or_insert(ProcessItem {
                pid: 0,
                name,
                is_selected,
            });
        }

        self.processes = map.into_values().collect();
    }

    /// Заглушка для Linux / macOS
    #[cfg(not(target_os = "windows"))]
    pub fn refresh_processes(&mut self) {}

    /// Загрузка конфигурации TOML, выбор ноды и запуск клиента
    pub fn load_config_from_content(&mut self, id: &str, content: &str, name: &str, reconnect: bool) {
        match toml::from_str::<CoreConfig>(content) {
            Ok(mut cfg) => {
                let _ = cfg.sanitize();
                self.filter_mode = match cfg.main.per_app_mode {
                    anet_client_core::config::PerAppMode::All => FilterMode::All,
                    anet_client_core::config::PerAppMode::Include => FilterMode::Include,
                    anet_client_core::config::PerAppMode::Exclude => FilterMode::Exclude,
                };

                if let Ok(raw_toml) = toml::from_str::<toml::Value>(content) {
                    self.tray_value = raw_toml
                        .get("main")
                        .and_then(|main| main.get("tray_mode"))
                        .and_then(|value| value.as_bool())
                        .unwrap_or(true);

                    self.exclude_routes = raw_toml
                        .get("main")
                        .and_then(|main| main.get("exclude_route_for"))
                        .and_then(|value| value.as_array())
                        .map(|values| {
                            values
                                .iter()
                                .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                                .collect()
                        })
                        .unwrap_or_default();
                }

                for proc in &mut self.processes {
                    proc.is_selected = cfg.main.per_app.iter().any(|app| app.eq_ignore_ascii_case(&proc.name));
                }

                let selected_name_opt = {
                    let settings = lock_ignore_poison(&self.settings);
                    settings.selected_servers.get(id).cloned()
                };

                let has_groups = cfg.servers.iter().any(|s| {
                    s.group_name.as_ref().map_or(false, |g| !g.trim().is_empty())
                });

                if has_groups {
                    let selected_group_id = selected_name_opt
                        .filter(|id| {
                            cfg.servers
                                .iter()
                                .any(|s| {
                                    let g_name = s.group_name.as_deref().unwrap_or("");
                                    let g_id = s.group_id.as_deref().unwrap_or(g_name).trim();
                                    g_id == id.as_str()
                                })
                        })
                        .unwrap_or_else(|| {
                            cfg.servers
                                .iter()
                                .find_map(|s| {
                                    if s.group_name.as_deref().map_or(true, |g| g.trim().is_empty()) { return None; }
                                    Some(s.group_id.as_deref().unwrap_or(s.group_name.as_ref().unwrap()).trim().to_string())
                                })
                                .unwrap_or_default()
                        });

                    if !selected_group_id.is_empty() {
                        let mut settings = lock_ignore_poison(&self.settings);
                        settings.selected_servers.insert(id.to_string(), selected_group_id.clone());
                        settings.save();
                    }

                    let mut group_servers: Vec<_> = cfg.servers
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
                        cfg.servers = group_servers;
                    }
                } else if let Some(selected_id) = selected_name_opt {
                    if let Some(idx) = cfg.servers
                        .iter()
                        .position(|s| s.dsn == selected_id)
                    {
                        cfg.servers.rotate_left(idx);
                    }
                }

                let tun = Box::new(
                    DesktopTunFactory::new(cfg.main.tun_name.clone(), !cfg.main.per_app.is_empty())
                );

                let cached_info = {
                    let settings = lock_ignore_poison(&self.settings);
                    settings.cached_accounts.get(id).cloned()
                };
                if let Some(info) = cached_info {
                    self.tariff_billing = info.billing_str.clone();
                    self.tariff_group = info.group_str.clone();
                    self.tariff_sessions = info.sessions_str.clone();
                    self.tariff_speed = info.speed_str.clone();
                    self.tariff_consumed = info.consumed_str.clone();
                    self.tariff_limit = info.limit_str.clone();
                    self.tariff_expires = info.expires_str.clone();
                    self.account_info = Some(info);
                } else {
                    self.account_info = None;
                    self.tariff_billing = "—".to_string();
                    self.tariff_group = "—".to_string();
                    self.tariff_sessions = "—".to_string();
                    self.tariff_speed = "—".to_string();
                    self.tariff_consumed = "0 B".to_string();
                    self.tariff_limit = "—".to_string();
                    self.tariff_expires = "—".to_string();
                }

                self.config_err = None;
                self.log(&format!("Загрузка конфигурации: {}...", name));

                let shared_clone = self.shared.clone();
                let config_load_tx = self.config_load_tx.clone();
                let id_owned = id.to_string();
                let name_owned = name.to_string();
                let old_client = if reconnect {
                    lock_ignore_poison(&self.shared).client.clone()
                } else {
                    None
                };

                self.rt.spawn(async move {
                    if let Some(old) = old_client {
                        let _ = old.stop().await;
                    }
                    let _ = tokio::task::spawn_blocking(move || {
                        match create_route_manager(false) {
                            Ok(route) => {
                                let client = Arc::new(AnetClient::new(cfg, tun, route));
                                lock_ignore_poison(&shared_clone).client = Some(client);
                                let _ = config_load_tx.send(ConfigLoadOutcome::Loaded {
                                    id: id_owned,
                                    name: name_owned,
                                    reconnect,
                                });
                            }
                            Err(e) => {
                                let _ = config_load_tx.send(ConfigLoadOutcome::Failed {
                                    id: id_owned,
                                    error: format!("Failed to create route manager: {}", e),
                                });
                            }
                        }
                    }).await;
                });
            }
            Err(e) => {
                self.config_err = Some(e.to_string());
                self.log("Failed to parse config TOML");
            }
        }
    }

    pub fn refresh_server_names_cache(&mut self, active_config_id: &str, content: &str) {
        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        let key = (active_config_id.to_string(), hasher.finish());

        if self.server_names_cache_key.as_ref() == Some(&key) {
            return;
        }

        self.server_names_cache = match toml::from_str::<CoreConfig>(content) {
            Ok(mut raw_cfg) => {
                let _ = raw_cfg.sanitize();
                let has_groups = raw_cfg.servers.iter().any(|s| {
                    s.group_name.as_ref().map_or(false, |g| !g.trim().is_empty())
                });

                if has_groups {
                    let mut groups = Vec::new();
                    let mut seen = std::collections::HashSet::new();
                    for s in &raw_cfg.servers {
                        if let Some(ref g_name) = s.group_name {
                            let g_name = g_name.trim();
                            if g_name.is_empty() { continue; }
                            let g_id = s.group_id.as_deref().unwrap_or(g_name).trim();
                            if seen.insert(g_id.to_string()) {
                                groups.push((g_id.to_string(), g_name.to_string()));
                            }
                        }
                    }
                    groups
                } else {
                    raw_cfg.servers.iter().map(|s| (s.dsn.clone(), s.get_name())).collect()
                }
            }
            Err(_) => Vec::new(),
        };
        self.server_names_cache_key = Some(key);
    }

    pub fn save_exclude_routes(&mut self) {
        let mut updated_config_data: Option<(String, String, String)> = None;

        {
            let mut settings = lock_ignore_poison(&self.settings);
            if let Some(active_id) = settings.active_config_id.clone() {
                if let Some(cfg) = settings.configs.iter_mut().find(|c| c.id == active_id) {
                    cfg.content = inject_exclude_route_to_toml(&cfg.content, &self.exclude_routes);
                    updated_config_data = Some((cfg.id.clone(), cfg.content.clone(), cfg.name.clone()));
                }
                settings.save();
            }
        }

        let Some((id, content, name)) = updated_config_data else {
            self.log("Ошибка: нет активного конфига для сохранения исключений.");
            return;
        };

        let path_by_id = std::path::PathBuf::from("configs").join(format!("{}.toml", id));
        let path_by_name = std::path::PathBuf::from("configs").join(format!("{}.toml", name));

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
                Ok(_) => self.log("Список исключённых адресов сохранён."),
                Err(e) => {
                    self.log(&format!("Ошибка записи исключений в {:?}: {}", path, e));
                    return;
                }
            }
        }

        let should_reconnect = lock_ignore_poison(&self.shared).state == ConnectionState::Connected;
        if should_reconnect {
            self.log("Переподключение VPN с обновленными исключениями...");
        }

        self.load_config_from_content(&id, &content, &name, should_reconnect);
    }

    pub fn check_for_updates(&mut self) {
        let update_url = if let Some(client) = lock_ignore_poison(&self.shared).client.as_ref() {
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

    pub fn start_vpn(&mut self) {
        let mut guard = lock_ignore_poison(&self.shared);
        if guard.state != ConnectionState::Disconnected {
            return;
        }
        if let Some(client_clone) = guard.client.clone() {
            guard.state = ConnectionState::Connecting;
            drop(guard);

            let shared_clone = self.shared.clone();
            self.rt.spawn(async move {
                if let Err(e) = client_clone.start().await {
                    lock_ignore_poison(&shared_clone).state = ConnectionState::Disconnected;
                    anet_client_core::events::err(e.to_string());
                }
            });
        }
    }

    pub fn stop_vpn(&mut self) {
        let mut guard = lock_ignore_poison(&self.shared);
        if let Some(client_clone) = guard.client.clone() {
            guard.state = ConnectionState::Disconnected;
            drop(guard);

            self.rt.spawn(async move {
                let _ = client_clone.stop().await;
            });
        }
    }

    pub fn open_file_dialog(&mut self) {
        let tx = self.file_dialog_tx.clone();
        std::thread::spawn(move || {
            if let Some(path) = rfd::FileDialog::new().add_filter("TOML Config", &["toml"]).pick_file() {
                let _ = tx.send(path);
            }
        });
    }

    pub fn save_logs_to_file(&mut self) {
        let logs = self.logs.clone();
        let tx = self.log_save_tx.clone();

        std::thread::spawn(move || {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let default_name = format!("anet_logs_{}.log", timestamp);

            let Some(path) = rfd::FileDialog::new()
                .set_file_name(&default_name)
                .add_filter("Log files", &["log", "txt"])
                .save_file()
            else {
                return;
            };

            let content = {
                let guard = lock_ignore_poison(&logs);
                guard.join("\n")
            };

            let result = match std::fs::write(&path, content) {
                Ok(_) => Ok(path),
                Err(e) => Err(e.to_string()),
            };
            let _ = tx.send(result);
        });
    }

    pub fn add_config_from_path(&mut self, path: PathBuf) {
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
            let mut settings = lock_ignore_poison(&self.settings);
            settings.add_config(name, content)
        };
        self.select_config(&id);
    }

    pub fn delete_config(&mut self, id: &str) {
        if lock_ignore_poison(&self.shared).state != ConnectionState::Disconnected {
            let is_active = lock_ignore_poison(&self.settings).active_config_id.as_deref() == Some(id);
            if is_active {
                self.show_toast("Нельзя удалить активный конфиг при подключенном VPN");
                self.log("Нельзя удалить активную конфигурацию при подключенном VPN");
                return;
            }
        }
        lock_ignore_poison(&self.settings).remove_config(id);
        if lock_ignore_poison(&self.shared).client.is_none() {
            self.config_name = "Config deleted".to_string();
        }
    }

    pub fn start_edit_name(&mut self, id: &str, current_name: &str) {
        self.editing_config_id = Some(id.to_string());
        self.edit_name_buffer = current_name.to_string();
    }

    pub fn finish_edit_name(&mut self) {
        if let Some(id) = &self.editing_config_id {
            let new_name = self.edit_name_buffer.trim().to_string();
            if !new_name.is_empty() {
                let mut settings = lock_ignore_poison(&self.settings);
                settings.rename_config(id, new_name);
            }
        }
        self.editing_config_id = None;
        self.edit_name_buffer.clear();
    }

    pub fn select_config(&mut self, id: &str) {
        if lock_ignore_poison(&self.shared).state != ConnectionState::Disconnected {
            self.show_toast("Сначала отключите VPN для смены конфигурации");
            self.log("Нельзя сменить конфигурацию при активном подключении");
            return;
        }
        let config = {
            let mut settings = lock_ignore_poison(&self.settings);
            settings.set_active(id);
            settings.get_active_config()
        };
        if let Some(config) = config {
            self.load_config_from_content(&config.id, &config.content, &config.name, false);
        }
    }

    pub fn drain_events(&mut self) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                AnetEvent::Stats { rx, tx, rtt, rxm, txm } => {
                    self.total_rx = rx;
                    self.total_tx = tx;
                    self.total_rtt = rtt;
                    self.total_rxm = rxm;
                    self.total_txm = txm;
                }
                AnetEvent::Status(msg) => self.log(&msg),
                AnetEvent::Warn(msg) => self.log(&msg),
                AnetEvent::ClientStateChanged { state, server_name, .. } => {
                    if matches!(
                        state,
                        ClientState::Disconnected | ClientState::Stopped | ClientState::Failed
                    ) {
                        self.total_rx = "0 B".to_string();
                        self.total_tx = "0 B".to_string();
                        self.total_rtt = "0".to_string();
                        self.total_rxm = "0 B".to_string();
                        self.total_txm = "0 B".to_string();
                    }

                    if let Some(active_name) = server_name {
                        if let Some((active_id, _)) = self.server_names_cache.iter().find(|(_, name)| name == &active_name) {
                            let mut settings = lock_ignore_poison(&self.settings);
                            if let Some(active_cfg) = settings.get_active_config() {
                                settings.selected_servers.insert(active_cfg.id.clone(), active_id.clone());
                                settings.save();
                            }
                        }
                    }
                }
                AnetEvent::AccountInfo(info) => {
                    self.tariff_billing = info.billing_str.clone();
                    self.tariff_group = info.group_str.clone();
                    self.tariff_sessions = info.sessions_str.clone();
                    self.tariff_speed = info.speed_str.clone();
                    self.tariff_consumed = info.consumed_str.clone();
                    self.tariff_limit = info.limit_str.clone();
                    self.tariff_expires = info.expires_str.clone();
                    self.account_info = Some(info.clone());

                    let mut settings = lock_ignore_poison(&self.settings);
                    if let Some(active_cfg) = settings.get_active_config() {
                        settings.cached_accounts.insert(active_cfg.id.clone(), info);
                        settings.save();
                    }
                }
                AnetEvent::Error(msg) => {
                    let err = format!("CRITICAL ERROR: {}", msg);
                    self.log(&err);
                    self.error_modal = Some(msg.clone());
                    if matches!(self.update_status, UpdateStatus::Downloading(_) | UpdateStatus::Checking) {
                        self.update_status = UpdateStatus::Error(msg);
                    }
                    if !lock_ignore_poison(&self.settings).disable_notifications {
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

        while let Ok(outcome) = self.config_load_rx.try_recv() {
            match outcome {
                ConfigLoadOutcome::Loaded { id, name, reconnect } => {
                    let is_still_active = lock_ignore_poison(&self.settings)
                        .active_config_id.as_deref() == Some(id.as_str());
                    if is_still_active {
                        self.config_err = None;
                        self.config_name = name.clone();
                        self.log(&format!("Config loaded: {}", name));

                        if reconnect {
                            self.start_vpn();
                        }
                    }
                }
                ConfigLoadOutcome::Failed { id, error } => {
                    let is_still_active = lock_ignore_poison(&self.settings)
                        .active_config_id.as_deref() == Some(id.as_str());
                    if is_still_active {
                        self.config_err = Some(error);
                        self.log("Failed to create route manager");
                    }
                }
            }
        }

        while let Ok(path) = self.file_dialog_rx.try_recv() {
            self.add_config_from_path(path);
        }

        while let Ok(result) = self.log_save_rx.try_recv() {
            match result {
                Ok(path) => {
                    let msg = format!("Лог сохранён: {}", path.display());
                    self.log(&msg);
                    self.show_toast(msg);
                }
                Err(e) => {
                    let msg = format!("Ошибка сохранения лога: {}", e);
                    self.log(&msg);
                    self.show_toast(msg);
                }
            }
        }
    }
}

impl eframe::App for ANetApp {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        egui::Rgba::TRANSPARENT.to_array()
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui_extras::install_image_loaders(ctx);
        apply_dark_theme(ctx);
        ctx.request_repaint_after(std::time::Duration::from_millis(500));

        self.drain_events();

        // 1. Заголовок окна (Titlebar)
        ui::titlebar::render_titlebar(self, ctx);

        // 2. Нижняя консоль со статистикой трафика
        ui::bottom_console::render_bottom_console(self, ctx);

        // 3. Центральная панель управления
        ui::central_panel::render_central_panel(self, ctx);

        // 4. Оверлеи и модальные окна
        ui::settings_modal::render_settings_modal(self, ctx);
        ui::logs_modal::render_logs_modal(self, ctx);
        ui::update_modal::render_update_modal(self, ctx);
        ui::error_modal::render_error_modal(self, ctx);
        ui::toast::render_toast(self, ctx);
    }
}