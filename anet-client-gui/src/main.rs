#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anet_client_core::AnetClient;
use anet_client_core::config::CoreConfig;
use anet_client_gui::router::DesktopRouteManager;
use anet_client_gui::tun_factory::DesktopTunFactory;
use eframe::egui;
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;

fn main() -> Result<(), eframe::Error> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([400.0, 600.0]), // Размер окна как у телефона
        ..Default::default()
    };

    eframe::run_native(
        "ANet VPN",
        options,
        Box::new(|cc| Ok(Box::new(ANetApp::new(cc)))),
    )
}

struct ANetApp {
    rt: Runtime,
    client: Option<Arc<AnetClient>>,
    logs: Arc<Mutex<Vec<String>>>,
    config_err: Option<String>,
}

impl ANetApp {
    fn new(_cc: &eframe::CreationContext) -> Self {
        Self {
            rt: Runtime::new().unwrap(),
            client: None,
            logs: Arc::new(Mutex::new(vec!["Welcome to ANet.".to_string()])),
            config_err: None,
        }
    }

    fn log(&self, msg: &str) {
        if let Ok(mut logs) = self.logs.lock() {
            logs.push(msg.to_string());
        }
    }

    // Функция запуска
    fn start_vpn(&mut self) {
        if let Some(client) = &self.client {
            let client_clone = client.clone();
            let logs_clone = self.logs.clone();

            self.rt.spawn(async move {
                logs_clone.lock().unwrap().push("Starting...".into());
                match client_clone.start().await {
                    Ok(_) => logs_clone.lock().unwrap().push("VPN Started!".into()),
                    Err(e) => logs_clone.lock().unwrap().push(format!("Error: {}", e)),
                }
            });
        }
    }

    fn stop_vpn(&mut self) {
        if let Some(client) = &self.client {
            let client_clone = client.clone();
            let logs_clone = self.logs.clone();
            self.rt.spawn(async move {
                logs_clone.lock().unwrap().push("Stopping...".into());
                let _ = client_clone.stop().await;
                logs_clone.lock().unwrap().push("Stopped.".into());
            });
        }
    }
}

impl eframe::App for ANetApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("ANet VPN");

            // 1. Выбор конфига
            if ui.button("Select Config File").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("TOML Config", &["toml"])
                    .pick_file()
                {
                    // Парсим и создаем клиента
                    let config_content = std::fs::read_to_string(&path).unwrap_or_default();
                    match toml::from_str::<CoreConfig>(&config_content) {
                        Ok(cfg) => {
                            // Инициализация зависимостей
                            let tun = Box::new(DesktopTunFactory::new(cfg.main.tun_name.clone()));
                            let route = Box::new(DesktopRouteManager::new());

                            self.client = Some(Arc::new(AnetClient::new(cfg, tun, route)));
                            self.config_err = None;
                            self.log(&format!("Loaded: {:?}", path));
                        }
                        Err(e) => self.config_err = Some(e.to_string()),
                    }
                }
            }

            if let Some(err) = &self.config_err {
                ui.colored_label(egui::Color32::RED, err);
            }

            ui.separator();

            // 2. Кнопка Connect/Disconnect
            let is_running = self
                .client
                .as_ref()
                .map(|c| c.is_running())
                .unwrap_or(false);

            let btn_text = if is_running { "DISCONNECT" } else { "CONNECT" };
            let btn_color = if is_running {
                egui::Color32::RED
            } else {
                egui::Color32::GREEN
            };

            if ui
                .add_enabled(
                    self.client.is_some(),
                    egui::Button::new(btn_text)
                        .fill(btn_color)
                        .min_size([200.0, 50.0].into()),
                )
                .clicked()
            {
                if is_running {
                    self.stop_vpn();
                } else {
                    self.start_vpn();
                }
            }

            ui.separator();

            // 3. Логи
            ui.label("Logs:");
            egui::ScrollArea::vertical()
                .auto_shrink([false; 2])
                .show(ui, |ui| {
                    let logs = self.logs.lock().unwrap();
                    for line in logs.iter() {
                        ui.label(line);
                    }
                });

            // Автообновление UI для логов (костыль, но работает)
            ctx.request_repaint_after(std::time::Duration::from_millis(500));
        });
    }
}
