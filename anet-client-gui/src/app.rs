#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use crate::router::DesktopRouteManager;
use crate::tun_factory::DesktopTunFactory;
use anet_client_core::AnetClient;
use anet_client_core::config::CoreConfig;
use anet_client_core::events::{AnetEvent, EventHandler, set_handler};
use eframe::egui;
use log::info;
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
        // Просто пересылаем событие в канал.
        // Если получатель (UI) умер, игнорируем ошибку.
        let _ = self.tx.send(event.clone());
    }
}

// --- App Struct ---

pub struct ANetApp {
    rt: Runtime,
    client: Option<Arc<AnetClient>>,
    logs: Arc<Mutex<Vec<String>>>,
    config_err: Option<String>,

    // Состояние конфига для отображения
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
            // Ограничим лог, чтобы память не текла
            if logs.len() > 100 {
                logs.remove(0);
            }
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

    fn load_config(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("TOML Config", &["toml"])
            .pick_file()
        {
            let config_content = std::fs::read_to_string(&path).unwrap_or_default();
            match toml::from_str::<CoreConfig>(&config_content) {
                Ok(cfg) => {
                    let tun = Box::new(DesktopTunFactory::new(cfg.main.tun_name.clone()));
                    let route = Box::new(DesktopRouteManager::new());

                    self.config_err = None;
                    self.config_name = path.file_name().unwrap().to_string_lossy().to_string();
                    self.client = Some(Arc::new(AnetClient::new(cfg, tun, route)));
                    self.log(&format!("Config loaded: {}", self.config_name));
                }
                Err(e) => {
                    self.config_err = Some(e.to_string());
                    self.log("Failed to parse config");
                }
            }
        }
    }
}

// --- UI Rendering ---

impl eframe::App for ANetApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                AnetEvent::Status(msg) => {
                    self.log(&msg);

                    // Можно добавить реакцию на статусы для переключения UI
                    if msg.contains("Tunnel UP") {
                        // self.is_connected = true (если ты хранишь стейт отдельно)
                    }
                }
                // Другие типы событий
                _ => {}
            }
        }

        let is_running = self
            .client
            .as_ref()
            .map(|c| c.is_running())
            .unwrap_or(false);

        // Используем CentralPanel для всего контента
        egui::CentralPanel::default().show(ctx, |ui| {
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
                        self.load_config();
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
            });

            // --- ГЛАВНАЯ КНОПКА ---
            // Используем flexible space, чтобы отодвинуть кнопку от верха, но не слишком далеко
            ui.add_space(ui.available_height() * 0.15); // 15% от высоты окна отступ сверху

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
                .rounding(90.0) // Используй rounding, если corner_radius нет
                .fill(btn_color);

                if ui.add(btn).clicked() {
                    if self.client.is_none() {
                        // Если конфига нет - пробуем загрузить или ругаемся
                        self.log("Error: No config loaded! Press ⚙ to load.");
                        // Можно сразу открыть диалог:
                        // self.load_config();
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
            // Забираем всё оставшееся место, но рисуем внизу
            let bottom_height = 120.0;
            ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                ui.add_space(0.0); // Отступ от края окна

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

            // Автообновление
            ctx.request_repaint_after(std::time::Duration::from_millis(200));
        });
    }
}
