use crate::config::AppSettings;
use crate::tun_factory::DesktopTunFactory;
use anet_client_core::{AnetClient, create_route_manager};
use anet_client_core::config::CoreConfig;
use anet_client_core::events::{AnetEvent, EventHandler, set_handler};
use eframe::egui;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;

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
#[derive(PartialEq, Clone, Copy)]
enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
}

// --- App Struct ---
pub struct ANetApp {
    rt: Runtime,
    client: Option<Arc<AnetClient>>,
    logs: Arc<Mutex<Vec<String>>>,
    config_err: Option<String>,
    config_name: String,
    event_rx: Receiver<AnetEvent>,

    // Новые поля
    state: ConnectionState,
    settings: AppSettings,
}

impl ANetApp {
    pub fn new() -> Self {
        let (tx, rx) = channel();
        set_handler(Box::new(GuiEventHandler::new(tx)));

        let settings = AppSettings::load();

        let mut app = Self {
            rt: Runtime::new().unwrap(),
            client: None,
            logs: Arc::new(Mutex::new(vec!["> System Ready...".to_string()])),
            config_err: None,
            config_name: "Файл настроек не выбран!".to_string(),
            event_rx: rx,
            state: ConnectionState::Disconnected,
            settings: settings.clone(),
        };

        // Автозагрузка конфига
        if let Some(path_str) = &settings.last_config_path {
            let path = PathBuf::from(path_str);
            if path.exists() {
                app.load_config_from_path(path);
            }
        }

        app
    }

    fn log(&self, msg: &str) {
        if let Ok(mut logs) = self.logs.lock() {
            logs.push(format!("> {}", msg));
        }
    }

    fn start_vpn(&mut self) {
        if let Some(client) = &self.client {
            // Переходим в состояние подключения
            self.state = ConnectionState::Connecting;

            let client_clone = client.clone();
            let logs_clone = self.logs.clone();

            // Внимание: Здесь мы должны как-то узнать, что подключение успешно.
            // Сейчас AnetClient.start() блокирует поток выполнения.
            // Поэтому состояние Connected мы выставим только если start() вернет Ok,
            // но start() работает пока VPN работает.
            // Значит, нам нужно ловить событие "Tunnel UP" через канал событий (AnetEvent).
            // А пока просто запустим таску.

            self.rt.spawn(async move {
                logs_clone
                    .lock()
                    .unwrap()
                    .push("> Starting service...".into());
                // В реальном клиенте тут должен быть неблокирующий запуск или мы ждем ошибку
                match client_clone.start().await {
                    Ok(_) => {
                        // VPN остановился штатно (например, стоп вызвали)
                        logs_clone.lock().unwrap().push("> VPN Stopped (Ok)".into())
                    }
                    Err(e) => logs_clone.lock().unwrap().push(format!("> Error: {}", e)),
                }
            });
        }
    }

    fn stop_vpn(&mut self) {
        if let Some(client) = &self.client {
            let client_clone = client.clone();
            let logs_clone = self.logs.clone();

            // Тут можно сразу ставить Disconnected, либо ждать события
            self.state = ConnectionState::Disconnected;

            self.rt.spawn(async move {
                logs_clone
                    .lock()
                    .unwrap()
                    .push("> Stopping service...".into());
                let _ = client_clone.stop().await;
            });
        }
    }

    fn load_config_from_path(&mut self, path: PathBuf) {
        if let Some(ext) = path.extension() {
            if ext != "toml" {
                self.config_err = Some("Пожалуйста выберите файл с расширением .toml ".to_string());
                return;
            }
        }

        let config_content = match std::fs::read_to_string(&path) {
            Ok(content) => content,
            Err(e) => {
                self.config_err = Some(format!("Ошибка чтения: {}", e));
                return;
            }
        };

        match toml::from_str::<CoreConfig>(&config_content) {
            Ok(cfg) => {
                let tun = Box::new(DesktopTunFactory::new(cfg.main.tun_name.clone()));
                // Для гуя нет смысла в ручном роутенге.
                let route = match create_route_manager(false) {
                    Ok(r) => r,
                    Err(e) => {
                        self.config_err = Some(format!("Failed to create route manager: {}", e));
                        self.log("Failed to create route manager");
                        return;
                    }
                };

                self.config_err = None;
                self.config_name = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();

                // Сохраняем путь
                self.settings.last_config_path = Some(path.to_string_lossy().to_string());
                self.settings.save();

                self.client = Some(Arc::new(AnetClient::new(cfg, tun, route)));
                self.log(&format!("Config loaded: {}", self.config_name));
            }
            Err(e) => {
                self.config_err = Some(e.to_string());
                self.log("Failed to parse config TOML");
            }
        }
    }

    fn open_file_dialog(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("TOML Config", &["toml"])
            .pick_file()
        {
            self.load_config_from_path(path);
        }
    }
}

impl eframe::App for ANetApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 1. Обработка событий из канала
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                AnetEvent::Status(msg) => {
                    self.log(&msg);
                    // Эвристика для смены статуса (в идеале добавить enum в AnetEvent)
                    if msg.contains("Tunnel UP") {
                        self.state = ConnectionState::Connected;
                    }
                    if msg.contains("Error") || msg.contains("Stopped") {
                        // Если мы были в Connecting и получили ошибку -> Disconnected
                        // Если были Connected и получили Error -> Disconnected
                        self.state = ConnectionState::Disconnected;
                    }
                }
                _ => {}
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
            .frame(console_frame) // <--- ПРИМЕНЯЕМ СТИЛЬ СЮДА
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
        let main_frame = egui::Frame::NONE
            .fill(egui::Color32::from_rgb(18, 18, 18))
            .inner_margin(12.0);

        egui::CentralPanel::default()
            .frame(main_frame)
            .show(ctx, |ui| {
                // Header
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("ANet VPN")
                            .size(24.0)
                            .strong()
                            .color(egui::Color32::WHITE),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add(
                                egui::Button::new(
                                    egui::RichText::new("⚙")
                                        .size(24.0)
                                        .strong()
                                        .color(egui::Color32::WHITE),
                                )
                                .frame(false),
                            )
                            .clicked()
                        {
                            self.open_file_dialog();
                        }
                    });
                });

                ui.add_space(20.0);

                // Config Info
                ui.vertical_centered(|ui| {
                    if let Some(err) = &self.config_err {
                        ui.label(egui::RichText::new(err).color(egui::Color32::RED));
                    } else {
                        ui.label(egui::RichText::new(&self.config_name).color(egui::Color32::GRAY));
                    }
                    if self.client.is_none() && self.config_err.is_none() {
                        ui.label(
                            egui::RichText::new("(Нажмите ⚙ и выберите файл настроек)")
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
                    let (btn_text, btn_color) = match self.state {
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

                    if ui.add(btn).clicked() {
                        match self.state {
                            ConnectionState::Disconnected => {
                                if self.client.is_none() {
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
                    match self.state {
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
