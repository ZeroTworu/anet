// #![cfg_attr(not(feature = "console"), windows_subsystem = "windows")]

include!(concat!(env!("OUT_DIR"), "/built.rs"));

use anet_client_gui::app::ANetApp;
use anet_client_gui::icons;
use eframe::egui;
#[cfg(target_os = "macos")]
use std::process::Command;

fn main() -> Result<(), eframe::Error> {
    #[cfg(target_os = "macos")]
    {
        if !is_root() {
            let exe = std::env::current_exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| "anet-gui".to_string());

            // Красивый скрипт для Mac: открываем терминал и просим пароль админа
            let script = format!(
                r#"
                set theResult to display dialog "ANet VPN requires administrator privileges to create network tunnels.\n\nWould you like to open Terminal with the sudo command?" with title "ANet VPN {}" buttons {{"Cancel", "Open Terminal"}} default button "Open Terminal" with icon caution
                if button returned of theResult is "Open Terminal" then
                    tell application "Terminal"
                        activate
                        do script "sudo '{}' ; exit"
                    end tell
                end if
                "#,
                GIT_TAG, // Показываем версию даже в системном диалоге
                exe.replace("'", "'\\''")
            );

            let _ = Command::new("osascript")
                .arg("-e")
                .arg(&script)
                .output();

            std::process::exit(0);
        }
    }

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Загрузка иконки (твоя функция из icons.rs)
    let icon = icons::load_icon();

    // Формируем заголовок окна: "ANet VPN v0.5.2 (5313b9e)"
    let window_title = format!("ANet VPN {} ({})", GIT_TAG, COMMIT_HASH);

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(window_title) // Устанавливаем заголовок с версией
            .with_inner_size([400.0, 600.0])
            .with_icon(icon)
            .with_resizable(false)
            .with_drag_and_drop(true),
        ..Default::default()
    };

    eframe::run_native(
        "ANet VPN", // Это внутренний ID приложения
        options,
        Box::new(|cc| {
            // Применяем твою кастомную стилизацию (Onyx Black & Green)
            configure_styles(&cc.egui_ctx);
            Ok(Box::new(ANetApp::new(cc)))
        }),
    )
}

/// Настройка стилей в стиле Half-Life / Киберпанк
fn configure_styles(ctx: &egui::Context) {
    let style = (*ctx.style()).clone();
    let mut visuals = egui::Visuals::dark();

    // Цвета фона (Onyx Black)
    let dark_bg = egui::Color32::from_rgb(18, 18, 18);
    visuals.window_fill = dark_bg;
    visuals.panel_fill = dark_bg;

    // Настройка виджетов
    visuals.widgets.noninteractive.bg_fill = egui::Color32::TRANSPARENT;
    visuals.widgets.inactive.bg_fill = egui::Color32::from_gray(40);

    // Акцентный зеленый (как в твоем GUI)
    visuals.selection.bg_fill = egui::Color32::from_rgb(76, 175, 80);
    visuals.selection.stroke = egui::Stroke::new(1.0, egui::Color32::WHITE);

    ctx.set_visuals(visuals);
    ctx.set_style(style);
}

/// Проверка прав root на macOS
#[cfg(target_os = "macos")]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
