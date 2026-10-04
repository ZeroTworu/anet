//! Таблица запущенных процессов для Per-App туннелирования (Windows)

#[cfg(target_os = "windows")]
use eframe::egui;
#[cfg(target_os = "windows")]
use egui::scroll_area::ScrollBarVisibility;
#[cfg(target_os = "windows")]
use anet_client_core::server_config::{SERVER_CONFIG_ID, SERVER_CONFIG_DISPLAY_NAME};
#[cfg(target_os = "windows")]
use crate::{
    app::ANetApp,
    theme::Colors,
    types::FilterMode,
    utils::helpers::lock_ignore_poison,
};

#[cfg(target_os = "windows")]
pub fn render_process_list(app: &mut ANetApp, ui: &mut egui::Ui) {
    let is_server_cfg = {
        let settings = lock_ignore_poison(&app.settings);
        settings.active_config_id.as_deref() == Some(SERVER_CONFIG_ID)
            || app.config_name == SERVER_CONFIG_DISPLAY_NAME
            || (settings.active_config_id.is_none() && settings.cached_server_config.is_some())
    };
    
    ui.add_space(6.0);

    ui.vertical(|ui| {
        ui.label("Режим фильтрации:");
        ui.radio_value(&mut app.filter_mode, FilterMode::All, "VPN для всех приложений");
        ui.radio_value(&mut app.filter_mode, FilterMode::Include, "VPN только для выбранных");
        ui.radio_value(&mut app.filter_mode, FilterMode::Exclude, "VPN для всего, кроме выбранных");
    });
    ui.separator();

    ui.horizontal(|ui| {
        if ui.add(
            egui::Button::new(egui::RichText::new("🔄 Обновить").size(11.0))
                .min_size(egui::vec2(90.0, 32.0))
                .corner_radius(6.0)
        ).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
            app.refresh_processes();
        }

        if ui.add(
            egui::Button::new(egui::RichText::new("💾 Применить").size(11.0).strong().color(egui::Color32::BLACK))
                .fill(Colors::GOLD)
                .min_size(egui::vec2(90.0, 32.0))
                .corner_radius(6.0)
        ).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
            // Вызываем единый метод сохранения ANetApp с поддержкой Server config
            app.save_per_app_settings();
        }
    });

    ui.separator();

    ui.style_mut().spacing.scroll.foreground_color = false;
    ui.style_mut().visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(80, 80, 80);
    ui.style_mut().visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(120, 120, 120);
    ui.style_mut().visuals.widgets.active.bg_fill = egui::Color32::from_rgb(160, 160, 160);

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .scroll_bar_visibility(ScrollBarVisibility::AlwaysVisible)
        .show(ui, |ui| {
            egui::Grid::new("process_grid")
                .striped(true)
                .spacing([12.0, 8.0])
                .min_col_width(24.0)
                .show(ui, |ui| {
                    ui.strong("");
                    ui.strong("icon");
                    ui.strong("name");
                    ui.end_row();

                    for proc in &mut app.processes {
                        ui.scope(|ui| {
                            let checkbox_white = egui::Color32::from_rgb(255, 255, 255);
                            let checkbox_grey = egui::Color32::from_rgb(76, 76, 76);
                            let checkbox_gold = Colors::GOLD;

                            let checkbox_stroke = egui::Stroke::new(2.0, checkbox_gold);
                            let checkbox_active_stroke = egui::Stroke::new(2.0, checkbox_gold);
                            let checkbox_inactive_stroke = egui::Stroke::new(2.0, checkbox_grey);
                            let checkbox_inactive_chevron = egui::Stroke::new(2.0, checkbox_white);

                            ui.style_mut().visuals.widgets.inactive.fg_stroke = checkbox_inactive_chevron;

                            if proc.is_selected {
                                ui.style_mut().visuals.widgets.inactive.bg_stroke = checkbox_active_stroke;
                                ui.style_mut().visuals.widgets.inactive.bg_fill = checkbox_gold;
                                ui.style_mut().visuals.widgets.inactive.fg_stroke = egui::Stroke::new(2.0, checkbox_grey);
                            } else {
                                ui.style_mut().visuals.widgets.inactive.bg_stroke = checkbox_inactive_stroke;
                            }

                            ui.style_mut().visuals.widgets.hovered.bg_stroke = checkbox_stroke;
                            ui.checkbox(&mut proc.is_selected, "");
                        });
                        ui.label("⚙");

                        let text_color = if proc.is_selected {
                            Colors::GOLD
                        } else {
                            egui::Color32::from_rgb(136, 136, 136)
                        };

                        ui.colored_label(text_color, &proc.name);
                        ui.end_row();
                    }
                });
        });
}