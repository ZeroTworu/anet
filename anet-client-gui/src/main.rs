#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anet_client_gui::app::ANetApp;
use eframe::egui;

fn main() -> Result<(), eframe::Error> {
    #[cfg(windows)]
    {
        use winapi::um::wincon::GetConsoleWindow;
        use winapi::um::winuser::{ShowWindow, SW_HIDE};

        let window = unsafe { GetConsoleWindow() };
        if window != std::ptr::null_mut() {
            unsafe { ShowWindow(window, SW_HIDE) };
        }
    }

    // env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 600.0]) // Мобильный форм-фактор
            .with_resizable(false) // Фиксированный размер
            .with_drag_and_drop(true), // DnD
        ..Default::default()
    };

    eframe::run_native(
        "ANet VPN",
        options,
        Box::new(|cc| {
            // Настройка стилей при старте
            configure_styles(&cc.egui_ctx);
            Ok(Box::new(ANetApp::new()))
        }),
    )
}

fn configure_styles(ctx: &egui::Context) {
    // 1. Сначала берем стандартную темную тему как базу
    let style = (*ctx.style()).clone();
    let mut visuals = egui::Visuals::dark(); // Жестко включаем Dark Mode

    // 2. Настраиваем цвета фона
    let dark_bg = egui::Color32::from_rgb(18, 18, 18); // Onyx Black
    visuals.window_fill = dark_bg;
    visuals.panel_fill = dark_bg;

    // 3. Настраиваем цвета элементов
    visuals.widgets.noninteractive.bg_fill = egui::Color32::TRANSPARENT;
    visuals.widgets.inactive.bg_fill = egui::Color32::from_gray(40);

    // Цвет обводки и текста
    visuals.selection.bg_fill = egui::Color32::from_rgb(76, 175, 80); // Акцентный зеленый
    visuals.selection.stroke = egui::Stroke::new(1.0, egui::Color32::WHITE);

    ctx.set_visuals(visuals);
    ctx.set_style(style);
}

