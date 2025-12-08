use crate::router::DesktopRouteManager;
use crate::tun_factory::DesktopTunFactory;
use anet_client_core::AnetClient;
use anet_client_core::config::CoreConfig;
use anet_client_core::events::{AnetEvent, EventHandler, set_handler};
use eframe::egui;
use std::path::PathBuf; // Добавлено для работы с путями
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;

// Logs
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

// --- App Struct ---

pub struct ANetApp {
    rt: Runtime,
    client: Option<Arc<AnetClient>>,
    logs: Arc<Mutex<Vec<String>>>,
    config_err: Option<String>,
    config_name: String,
    event_rx: Receiver<AnetEvent>,
}

impl ANetApp {
    pub fn new() -> Self {
        let (tx, rx) = channel();
        set_handler(Box::new(GuiEventHandler::new(tx)));
        Self {
            rt: Runtime::new().unwrap(),
            client: None,
            logs: Arc::new(Mutex::new(vec!["> System Ready...".to_string()])),
            config_err: None,
            config_name: "No config loaded".to_string(),
            event_rx: rx,
        }
    }

    fn log(&self, msg: &str) {
        if let Ok(mut logs) = self.logs.lock() {
            logs.push(format!("> {}", msg));
        }
    }

    fn start_vpn(&mut self) {
        if let Some(client) = &self.client {
            let client_clone = client.clone();
            let logs_clone = self.logs.clone();
            self.rt.spawn(async move {
                logs_clone
                    .lock()
                    .unwrap()
                    .push("> Starting service...".into());
                match client_clone.start().await {
                    Ok(_) => logs_clone.lock().unwrap().push("> VPN Tunnel UP".into()),
                    Err(e) => logs_clone.lock().unwrap().push(format!("> Error: {}", e)),
                }
            });
        }
    }

    fn stop_vpn(&mut self) {
        if let Some(client) = &self.client {
            let client_clone = client.clone();
            let logs_clone = self.logs.clone();
            self.rt.spawn(async move {
                logs_clone
                    .lock()
                    .unwrap()
                    .push("> Stopping service...".into());
                let _ = client_clone.stop().await;
                logs_clone.lock().unwrap().push("> VPN Stopped".into());
            });
        }
    }

    /// Общая логика загрузки конфига по пути к файлу
    fn load_config_from_path(&mut self, path: PathBuf) {
        // Проверка расширения (опционально, но полезно для UX)
        if let Some(ext) = path.extension() {
            if ext != "toml" {
                self.config_err = Some("Invalid file type. Please drop a .toml file".to_string());
                self.log("Ignored non-toml file");
                return;
            }
        }

        let config_content = match std::fs::read_to_string(&path) {
            Ok(content) => content,
            Err(e) => {
                self.config_err = Some(format!("Read error: {}", e));
                return;
            }
        };

        match toml::from_str::<CoreConfig>(&config_content) {
            Ok(cfg) => {
                let tun = Box::new(DesktopTunFactory::new(cfg.main.tun_name.clone()));
                let route = Box::new(DesktopRouteManager::new());

                self.config_err = None;
                self.config_name = path.file_name().unwrap_or_default().to_string_lossy().to_string();

                // Если клиент уже был запущен, стоило бы его остановить,
                // но пока просто заменяем структуру (в GUI это кнопка Connect разрулит)
                self.client = Some(Arc::new(AnetClient::new(cfg, tun, route)));
                self.log(&format!("Config loaded: {}", self.config_name));
            }
            Err(e) => {
                self.config_err = Some(e.to_string());
                self.log("Failed to parse config TOML");
            }
        }
    }

    /// Открытие диалога выбора файла
    fn open_file_dialog(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("TOML Config", &["toml"])
            .pick_file()
        {
            self.load_config_from_path(path);
        }
    }
}

// --- UI Rendering ---

impl eframe::App for ANetApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 1. Обработка Drag-and-Drop (ЭТОГО БЛОКА НЕ БЫЛО В ВАШЕМ КОДЕ)
        if !ctx.input(|i| i.raw.dropped_files.is_empty()) {
            let dropped_files = ctx.input(|i| i.raw.dropped_files.clone());

            // Берем первый файл
            if let Some(file) = dropped_files.first() {
                if let Some(path) = &file.path {
                    self.load_config_from_path(path.clone());
                }
            }
        }


        // 2. Обработка событий из канала (логи, статусы)
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                AnetEvent::Status(msg) => {
                    self.log(&msg);
                }
                _ => {}
            }
        }

        let is_running = self
            .client
            .as_ref()
            .map(|c| c.is_running())
            .unwrap_or(false);

        let main_frame = egui::Frame::none()
            .fill(egui::Color32::from_rgb(18, 18, 18)) // Тот самый черный цвет
            .inner_margin(12.0); // Отступы от краев окна

        // Используем CentralPanel для всего контента
        egui::CentralPanel::default().frame(main_frame).show(ctx, |ui| {
            // Подсветка зоны перетаскивания (визуальная индикация)
            if ctx.input(|i| !i.raw.hovered_files.is_empty()) {
                let painter = ctx.layer_painter(egui::LayerId::new(egui::Order::Foreground, egui::Id::new("dnd_overlay")));
                let screen_rect = ctx.input(|i| i.screen_rect());
                painter.rect_filled(
                    screen_rect,
                    0.0,
                    egui::Color32::from_black_alpha(100),
                );
                painter.text(
                    screen_rect.center(),
                    egui::Align2::CENTER_CENTER,
                    "Drop config here",
                    egui::FontId::proportional(32.0),
                    egui::Color32::WHITE,
                );
            }

            // 1. Header (Top Bar)
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("ANet VPN")
                        .size(24.0)
                        .strong()
                        .color(egui::Color32::WHITE),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add(egui::Button::new(egui::RichText::new("⚙").size(24.0)).frame(false))
                        .clicked()
                    {
                        self.open_file_dialog();
                    }
                });
            });

            ui.add_space(20.0);

            // 2. Config Info
            ui.vertical_centered(|ui| {
                if let Some(err) = &self.config_err {
                    ui.label(egui::RichText::new(err).color(egui::Color32::RED));
                } else {
                    ui.label(egui::RichText::new(&self.config_name).color(egui::Color32::GRAY));
                }
                // Подсказка для пользователя
                if self.client.is_none() && self.config_err.is_none() {
                    ui.label(
                        egui::RichText::new("(Drag .toml config here or click ⚙)")
                            .size(10.0)
                            .color(egui::Color32::from_gray(80)),
                    );
                }
            });

            // --- ГЛАВНАЯ КНОПКА ---
            ui.add_space(ui.available_height() * 0.15);

            ui.vertical_centered(|ui| {
                let btn_size = egui::vec2(180.0, 180.0);
                let btn_text = if is_running { "STOP" } else { "CONNECT" };
                let btn_color = if is_running {
                    egui::Color32::from_rgb(244, 67, 54)
                } else {
                    egui::Color32::from_rgb(76, 175, 80)
                };

                let btn = egui::Button::new(
                    egui::RichText::new(btn_text)
                        .size(24.0)
                        .strong()
                        .color(egui::Color32::WHITE),
                )
                    .min_size(btn_size)
                    .rounding(90.0)
                    .fill(btn_color);

                if ui.add(btn).clicked() {
                    if self.client.is_none() {
                        self.log("Error: No config loaded! Press ⚙ or drag file.");
                        self.open_file_dialog();
                    } else {
                        if is_running {
                            self.stop_vpn();
                        } else {
                            self.start_vpn();
                        }
                    }
                }

                ui.add_space(20.0);
                let status_text = if is_running {
                    "SECURED"
                } else {
                    "DISCONNECTED"
                };
                let status_color = if is_running {
                    btn_color
                } else {
                    egui::Color32::from_rgb(255, 82, 82)
                };
                ui.label(
                    egui::RichText::new(status_text)
                        .size(16.0)
                        .strong()
                        .color(status_color),
                );
            });

            // --- ЛОГИ (Прижаты к низу) ---
            let bottom_height = 120.0;
            ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                ui.add_space(0.0);

                egui::ScrollArea::vertical()
                    .max_height(bottom_height)
                    .auto_shrink([false, true])
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        let logs = self.logs.lock().unwrap();
                        for line in logs.iter().rev() {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new(">").color(egui::Color32::DARK_GRAY));
                                ui.label(
                                    egui::RichText::new(line)
                                        .family(egui::FontFamily::Monospace)
                                        .size(12.0)
                                        .color(egui::Color32::GREEN),
                                );
                            });
                        }
                    });

                ui.separator();
                ui.label("System Logs:");
            });

            ctx.request_repaint_after(std::time::Duration::from_millis(200));
        });
    }
}
