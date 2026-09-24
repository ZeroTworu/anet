//! Таблица запущенных процессов для Per-App туннелирования (Windows)

#[cfg(target_os = "windows")]
use eframe::egui;
#[cfg(target_os = "windows")]
use egui::scroll_area::ScrollBarVisibility;
#[cfg(target_os = "windows")]
use crate::{
    app::ANetApp,
    theme::Colors,
    types::{ConnectionState, FilterMode},
    utils::{
        helpers::lock_ignore_poison,
        toml::inject_per_app_to_toml,
    },
};

#[cfg(target_os = "windows")]
pub fn render_process_list(app: &mut ANetApp, ui: &mut egui::Ui) {
    ui.vertical(|ui| {
        ui.label("Режим фильтрации:");
        ui.radio_value(&mut app.filter_mode, FilterMode::All, "VPN для всех приложений");
        ui.radio_value(&mut app.filter_mode, FilterMode::Include, "VPN только для выбранных");
        ui.radio_value(&mut app.filter_mode, FilterMode::Exclude, "VPN для всего, кроме выбранных");
    });
    ui.separator();

    ui.horizontal(|ui| {
        if ui.button("🔄 Обновить").clicked() {
            app.refresh_processes();
        }

        if ui.button("💾 Применить").clicked() {
            let selected_apps: Vec<String> = app.processes
                .iter()
                .filter(|p| p.is_selected)
                .map(|p| p.name.clone())
                .collect();

            let filter_mode = app.filter_mode;
            let mut updated_config_data: Option<(String, String, String)> = None;

            {
                let mut settings = lock_ignore_poison(&app.settings);
                let active_id = settings.active_config_id.clone();

                if let Some(id) = active_id {
                    let updated_info = {
                        if let Some(cfg) = settings.configs.iter_mut().find(|c| c.id == id) {
                            cfg.content = inject_per_app_to_toml(
                                &cfg.content,
                                &selected_apps,
                                filter_mode,
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
                        Ok(_) => app.log(&format!("Конфиг сохранен: {:?}", path)),
                        Err(e) => app.log(&format!("Ошибка записи в {:?}: {}", path, e)),
                    }
                }

                let should_reconnect = lock_ignore_poison(&app.shared).state == ConnectionState::Connected;
                if should_reconnect {
                    app.log("Переподключение VPN с новыми настройками приложений...");
                }

                app.load_config_from_content(&id, &content, &name, should_reconnect);
                app.log("Настройки приложений применены.");
                app.show_toast("Настройки приложений сохранены и применены");
            } else {
                app.log("Ошибка: нет активного конфига для применения настроек.");
                app.show_toast("Ошибка: нет активного конфига");
            }
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