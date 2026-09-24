// src/main.rs
#![cfg_attr(not(feature = "console"), windows_subsystem = "windows")]

use anet_client_gui::{
    app::ANetApp,
    icons,
    theme::{configure_styles, load_fonts},
    GIT_TAG, COMMIT_HASH,
};
use eframe::egui;

#[cfg(target_os = "macos")]
use std::process::Command;

fn main() -> Result<(), eframe::Error> {
    // 1. Проверка прав администратора на macOS для TUN
    #[cfg(target_os = "macos")]
    {
        if !is_root() {
            let exe = std::env::current_exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| "anet-gui".to_string());

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
                GIT_TAG,
                exe.replace("'", "'\\''")
            );

            let _ = Command::new("osascript")
                .arg("-e")
                .arg(&script)
                .output();

            std::process::exit(0);
        }
    }

    // 2. Инициализация логгера
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // 3. Иконка и заголовок
    let icon = icons::load_icon();
    let window_title = format!("ANet VPN {} ({})", GIT_TAG, COMMIT_HASH);

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(window_title)
            .with_inner_size([400.0, 720.0])
            .with_min_inner_size([360.0, 640.0])
            .with_icon(icon)
            .with_resizable(false)
            .with_decorations(false)
            .with_transparent(true),
        ..Default::default()
    };

    eframe::run_native(
        "ANet VPN",
        options,
        Box::new(|cc| {
            load_fonts(&cc.egui_ctx);
            configure_styles(&cc.egui_ctx);
            Ok(Box::new(ANetApp::new(cc)))
        }),
    )
}

#[cfg(target_os = "macos")]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}