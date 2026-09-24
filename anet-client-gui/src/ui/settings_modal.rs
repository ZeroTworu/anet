//! Оверлей настроек приложения и его категории

use eframe::egui;
use egui::Stroke;
use crate::{
    app::ANetApp,
    theme::Colors,
    types::SettingsCategory,
    utils::{
        helpers::lock_ignore_poison,
        toml::inject_tray_mode_to_toml,
        validator::validate_exclude_route,
    },
};

pub fn render_settings_modal(app: &mut ANetApp, ctx: &egui::Context) {
    if !app.settingsbar_open {
        return;
    }

    let margin = 20.0;
    let button_size = egui::vec2(32.0, 32.0);

    egui::Area::new(egui::Id::new("config_settingsbar"))
        .order(egui::Order::Foreground)
        .fixed_pos(egui::pos2(0.0, 0.0))
        .show(ctx, |ui| {
            let screen_rect = ui.ctx().screen_rect();
            let corner_radius = 14.0;

            egui::Frame::none()
                .fill(ui.visuals().window_fill())
                .inner_margin(margin)
                .corner_radius(corner_radius)
                .show(ui, |ui| {
                    ui.set_width(screen_rect.width() - margin * 2.0);
                    ui.set_height(screen_rect.height() - margin * 2.0);

                    if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                        if app.active_settings_page.is_some() {
                            app.active_settings_page = None;
                        } else {
                            app.settingsbar_open = false;
                            app.active_settings_page = None;
                        }
                    }

                    render_settings_overlay(app, ui, button_size);
                });
        });
}

pub fn render_settings_overlay(app: &mut ANetApp, ui: &mut egui::Ui, button_size: egui::Vec2) {
    if let Some(category) = app.active_settings_page {
        ui.horizontal(|ui| {
            let circle_button = egui::Button::new("⏴")
                .min_size(button_size)
                .stroke(Stroke::NONE)
                .rounding(button_size.y / 2.0);

            let response = ui.add(circle_button).on_hover_cursor(egui::CursorIcon::PointingHand);
            if response.clicked() {
                app.active_settings_page = None;  
                if app.exclbar_open {
                    app.exclbar_open = false;
                    if app.exclude_routes_changed {
                        app.exclude_routes_changed = false;
                        app.save_exclude_routes();
                    }
                }                  
            }

            ui.heading(category.title());
        });            
        ui.add_space(10.0);

        egui::Frame::NONE
            .fill(egui::Color32::from_rgb(26, 29, 36))
            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(38, 41, 50)))
            .corner_radius(8.0)
            .inner_margin(egui::Margin::same(14))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.vertical(|ui| {                    
                    match category {
                        SettingsCategory::General => render_general_settings(app, ui),
                        SettingsCategory::Configs => render_configs_settings(app, ui),
                        SettingsCategory::PerApp => {
                            #[cfg(target_os = "windows")]
                            crate::ui::process_grid::render_process_list(app, ui);

                            #[cfg(not(target_os = "windows"))]
                            {
                                ui.label(
                                    egui::RichText::new("Туннелирование по приложениям поддерживается только на Windows.")
                                        .size(13.0)
                                        .color(Colors::GREY)
                                        .family(egui::FontFamily::Name("Inter-V".into()))
                                );
                            }
                        }
                        SettingsCategory::ExcludedAdds => render_excluded_adds_settings(app, ui),
                        SettingsCategory::Connection => render_connection_settings(ui),
                        SettingsCategory::Routing => render_routing_settings(ui),
                        SettingsCategory::Security => render_security_settings(ui),
                        SettingsCategory::SplitTunnel => render_split_tunnel_settings(ui),
                        SettingsCategory::Updates => render_updates_settings(ui),
                    }
                });
            });
    } else {
        render_categories_list(app, ui, button_size);
    }
}

fn render_categories_list(app: &mut ANetApp, ui: &mut egui::Ui, button_size: egui::Vec2) {
    ui.horizontal(|ui| {
        let circle_button = egui::Button::new("⏴")
            .min_size(button_size)
            .stroke(Stroke::NONE)
            .rounding(button_size.y / 2.0);

        let response = ui.add(circle_button).on_hover_cursor(egui::CursorIcon::PointingHand);
        if response.clicked() {
            app.settingsbar_open = false;
            app.active_settings_page = None;
        }

        ui.heading("Настройки");
    });            
    ui.add_space(8.0);
    ui.label(
        egui::RichText::new("Выберите категорию параметров для настройки:")
            .size(11.0)
            .color(Colors::GREY)
            .family(egui::FontFamily::Name("Inter-V".into()))
    );
    ui.add_space(12.0);

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let categories = [
                SettingsCategory::General,
                SettingsCategory::Configs,
                SettingsCategory::PerApp,
                SettingsCategory::ExcludedAdds,
                SettingsCategory::Connection,
                SettingsCategory::Routing,
                SettingsCategory::Security,
                SettingsCategory::SplitTunnel,
                SettingsCategory::Updates,
            ];

            for cat in categories {
                let cat_id = ui.id().with("settings_cat_card").with(cat.title());
                let is_hovered: bool = ui.data(|d| d.get_temp(cat_id)).unwrap_or(false);

                let bg_color = if is_hovered {
                    egui::Color32::from_rgb(34, 38, 48)
                } else {
                    egui::Color32::from_rgb(26, 29, 36)
                };
                let border_color = if is_hovered {
                    Colors::GOLD
                } else {
                    egui::Color32::from_rgb(45, 48, 58)
                };

                let frame_resp = egui::Frame::NONE
                    .fill(bg_color)
                    .stroke(egui::Stroke::new(1.0, border_color))
                    .corner_radius(8.0)
                    .inner_margin(egui::Margin::same(12))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.vertical(|ui| {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new(cat.icon()).size(18.0).color(Colors::GOLD));
                                ui.label(
                                    egui::RichText::new(cat.title())
                                        .size(14.0)
                                        .strong()
                                        .color(if is_hovered { Colors::GOLD } else { egui::Color32::WHITE })
                                );
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    ui.label(
                                        egui::RichText::new("›")
                                            .size(18.0)
                                            .color(if is_hovered { Colors::GOLD } else { Colors::GREY })
                                    );
                                });
                            });
                            ui.add_space(4.0);
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(cat.description())
                                        .size(11.0)
                                        .color(Colors::GREY)
                                        .family(egui::FontFamily::Name("Inter-V".into()))
                                )
                                .wrap()
                            );
                        });
                    });

                let response = ui.interact(frame_resp.response.rect, cat_id, egui::Sense::click());
                let now_hovered = response.hovered();
                if now_hovered != is_hovered {
                    ui.data_mut(|d| d.insert_temp(cat_id, now_hovered));
                    ui.ctx().request_repaint();
                }

                if response.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                    app.active_settings_page = Some(cat);
                }

                ui.add_space(10.0);
            }
        });
}

fn render_general_settings(app: &mut ANetApp, ui: &mut egui::Ui) {
    ui.style_mut().spacing.scroll.foreground_color = false;
    ui.style_mut().visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(80, 80, 80);
    ui.style_mut().visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(120, 120, 120);
    ui.style_mut().visuals.widgets.active.bg_fill = egui::Color32::from_rgb(160, 160, 160);

    if ui.checkbox(&mut app.tray_value, "Сворачивать приложение в трэй").changed() {
        let tray_mode = app.tray_value;
        let mut updated_config_data: Option<(String, String, String)> = None;

        {
            let mut settings = lock_ignore_poison(&app.settings);
            if let Some(active_id) = settings.active_config_id.clone() {
                if let Some(cfg) = settings.configs.iter_mut().find(|c| c.id == active_id) {
                    cfg.content = inject_tray_mode_to_toml(&cfg.content, tray_mode);
                    updated_config_data = Some((cfg.id.clone(), cfg.content.clone(), cfg.name.clone()));
                }
                settings.save();
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
                    Ok(_) => {
                        app.log(&format!("Настройка tray_mode сохранена: {}", tray_mode));
                        app.show_toast(&format!("Настройка tray_mode сохранена: {}", tray_mode));
                    }
                    Err(e) => {
                        app.log(&format!("Ошибка записи tray_mode в {:?}: {}", path, e));
                    }
                }
            }
        }
    }
    ui.separator();
}

fn render_configs_settings(app: &mut ANetApp, ui: &mut egui::Ui) {
    let settings_guard = lock_ignore_poison(&app.settings);
    let configs = settings_guard.configs.clone();
    let active_id = settings_guard.active_config_id.clone();
    let editing_id = app.editing_config_id.clone();
    drop(settings_guard);

    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("СПИСОК КОНФИГУРАЦИЙ")
                .size(11.0)
                .strong()
                .color(Colors::GOLD)
                .family(egui::FontFamily::Name("Inter-V".into()))
        );
        ui.label(
            egui::RichText::new(format!("({})", configs.len()))
                .size(10.0)
                .color(Colors::GREY)
        );
    });

    ui.add_space(8.0);

    // 1. Кнопка импорта с центрированным текстом во всю ширину
    let add_btn = egui::Button::new(
        egui::RichText::new("ИМПОРТИРОВАТЬ .TOML КОНФИГ")
            .size(11.5)
            .strong()
            .color(Colors::GOLD)
            .family(egui::FontFamily::Name("Inter-V".into()))
    )
    .fill(egui::Color32::from_rgb(32, 35, 45))
    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(60, 65, 80)))
    .corner_radius(8.0);

    let add_btn_resp = ui.add_sized([ui.available_width(), 36.0], add_btn);
    if add_btn_resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
        app.open_file_dialog();
    }

    ui.add_space(12.0);

    if configs.is_empty() {
        egui::Frame::NONE
            .fill(egui::Color32::from_rgb(20, 22, 28))
            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(40, 44, 55)))
            .corner_radius(8.0)
            .inner_margin(egui::Margin::same(24))
            .show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("📂").size(24.0));
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new("Нет загруженных конфигураций")
                            .size(12.0)
                            .color(Colors::GREY)
                            .family(egui::FontFamily::Name("Inter-V".into()))
                    );
                    ui.add_space(2.0);
                    ui.label(
                        egui::RichText::new("Нажмите кнопку выше, чтобы выбрать файл .toml")
                            .size(10.0)
                            .color(egui::Color32::from_rgb(100, 105, 115))
                    );
                });
            });
        return;
    }

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for config in &configs {
                let is_active = active_id.as_deref() == Some(&config.id);
                let is_editing = editing_id.as_deref() == Some(&config.id);

                let card_id = ui.id().with("config_card").with(&config.id);
                let is_hovered: bool = ui.data(|d| d.get_temp(card_id)).unwrap_or(false);

                let bg_color = if is_active {
                    egui::Color32::from_rgb(28, 38, 33)
                } else if is_hovered {
                    egui::Color32::from_rgb(32, 35, 45)
                } else {
                    egui::Color32::from_rgb(22, 24, 30)
                };

                let border_color = if is_active {
                    egui::Color32::from_rgb(76, 175, 80)
                } else if is_hovered {
                    Colors::GOLD
                } else {
                    egui::Color32::from_rgb(40, 44, 55)
                };

                egui::Frame::NONE
                    .fill(bg_color)
                    .stroke(egui::Stroke::new(1.0, border_color))
                    .corner_radius(8.0)
                    .inner_margin(egui::Margin::symmetric(12, 10))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());

                        if is_editing {
                            // Режим редактирования названия во всю ширину
                            ui.horizontal(|ui| {
                                let (dot_rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                                ui.painter().circle_filled(dot_rect.center(), 4.0, Colors::GOLD);

                                ui.add_space(4.0);

                                let input_width = (ui.available_width() - 36.0).max(100.0);
                                let response = ui.add(
                                    egui::TextEdit::singleline(&mut app.edit_name_buffer)
                                        .desired_width(input_width)
                                        .font(egui::FontId::new(12.5, egui::FontFamily::Name("Inter-V".into())))
                                );

                                if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                                    app.finish_edit_name();
                                }

                                if ui.add(
                                    egui::Button::new(
                                        egui::RichText::new("✔").size(12.0).color(Colors::GOLD)
                                    )
                                    .fill(egui::Color32::from_rgb(40, 44, 55))
                                    .min_size(egui::vec2(28.0, 24.0))
                                    .corner_radius(4.0)
                                ).clicked() {
                                    app.finish_edit_name();
                                }
                            });
                        } else {
                            // Обычный режим: левая зона активирует профиль, правые кнопки свободны
                            ui.horizontal(|ui| {
                                let right_buttons_width = 68.0;
                                let left_width = (ui.available_width() - right_buttons_width).max(80.0);

                                let (left_rect, left_response) = ui.allocate_exact_size(
                                    egui::vec2(left_width, 34.0),
                                    egui::Sense::click()
                                );

                                if left_response.hovered() != is_hovered {
                                    ui.data_mut(|d| d.insert_temp(card_id, left_response.hovered()));
                                    ui.ctx().request_repaint();
                                }

                                if left_response.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                                    if is_active {
                                        // Уже активен
                                    } else if lock_ignore_poison(&app.shared).state != crate::types::ConnectionState::Disconnected {
                                        app.show_toast("Нельзя сменить конфигурацию при активном подключении");
                                        app.log("Нельзя сменить конфигурацию при активном подключении");
                                    } else {
                                        app.select_config(&config.id);
                                    }
                                }

                                // Отрисовка левой части (индикатор + название + статус)
                                let center_y = left_rect.center().y;
                                let dot_pos = egui::pos2(left_rect.left() + 6.0, center_y);
                                let dot_color = if is_active {
                                    egui::Color32::from_rgb(76, 175, 80)
                                } else {
                                    egui::Color32::from_rgb(70, 75, 85)
                                };
                                ui.painter().circle_filled(dot_pos, 4.0, dot_color);

                                let text_color = if is_active {
                                    egui::Color32::WHITE
                                } else if is_hovered {
                                    Colors::GOLD
                                } else {
                                    egui::Color32::from_rgb(220, 222, 228)
                                };

                                let title_pos = egui::pos2(left_rect.left() + 20.0, if is_active { center_y - 7.0 } else { center_y });
                                ui.painter().text(
                                    title_pos,
                                    egui::Align2::LEFT_CENTER,
                                    &config.name,
                                    egui::FontId::new(12.5, egui::FontFamily::Name("Inter-V".into())),
                                    text_color,
                                );

                                if is_active {
                                    let sub_pos = egui::pos2(left_rect.left() + 20.0, center_y + 8.0);
                                    ui.painter().text(
                                        sub_pos,
                                        egui::Align2::LEFT_CENTER,
                                        "● АКТИВНЫЙ ПРОФИЛЬ",
                                        egui::FontId::new(9.0, egui::FontFamily::Name("Inter-V".into())),
                                        egui::Color32::from_rgb(76, 175, 80),
                                    );
                                }

                                // Кнопки действий ✏ и 🗑
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    let del_btn = ui.add(
                                        egui::Button::new(
                                            egui::RichText::new("🗑")
                                                .size(13.0)
                                                .color(if is_hovered { egui::Color32::from_rgb(240, 80, 80) } else { Colors::GREY })
                                        )
                                        .frame(false)
                                    );
                                    if del_btn.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Удалить конфиг").clicked() {
                                        app.delete_config(&config.id);
                                    }

                                    let edit_btn = ui.add(
                                        egui::Button::new(
                                            egui::RichText::new("✏")
                                                .size(13.0)
                                                .color(if is_hovered { Colors::GOLD } else { Colors::GREY })
                                        )
                                        .frame(false)
                                    );
                                    if edit_btn.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Переименовать").clicked() {
                                        app.start_edit_name(&config.id, &config.name);
                                    }
                                });
                            });
                        }
                    });

                ui.add_space(8.0);
            }
        });
}


fn render_excluded_adds_settings(app: &mut ANetApp, ui: &mut egui::Ui) {
    app.exclbar_open = true;
    if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
        app.exclbar_open = false;
        if app.exclude_routes_changed {
            app.exclude_routes_changed = false;
            app.save_exclude_routes();
        }
    }

    ui.label(
        egui::RichText::new("Эти адреса будут исключены из VPN-туннеля.")
            .size(11.0)
            .color(Colors::GREY)
            .family(egui::FontFamily::Name("Inter-V".into()))
    );

    ui.add_space(14.0);

    ui.horizontal(|ui| {
        let input_width = (ui.available_width() - 92.0).max(160.0);

        let response = ui.add(
            egui::TextEdit::singleline(&mut app.exclude_route_input)
                .desired_width(input_width)
                .hint_text("IP, CIDR или домен")
        );

        let add_clicked = ui.add(
            egui::Button::new(
                egui::RichText::new("ДОБАВИТЬ").size(11.0).strong()
            )
            .min_size(egui::vec2(82.0, 28.0))
        )
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked();

        let enter_pressed = response.lost_focus()
            && ui.input(|i| i.key_pressed(egui::Key::Enter));

        if add_clicked || enter_pressed {
            let route = app.exclude_route_input.trim().to_string();

            if !validate_exclude_route(&route) {
                app.log(&format!("Некорректный адрес: {}", route));
                app.show_toast(&format!("Некорректный адрес: {}", route));
            } else if app.exclude_routes.iter().any(|r| r == &route) {
                app.log(&format!("Адрес уже добавлен: {}", route));
                app.show_toast(&format!("Адрес уже добавлен: {}", route));
            } else {
                app.log(&format!("Адрес добавлен: {}", route));
                app.show_toast(&format!("Адрес добавлен: {}", route));

                app.exclude_routes.push(route);
                app.exclude_route_input.clear();
                app.exclude_routes_changed = true;
            }
        }
    });

    ui.add_space(18.0);

    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("ИСКЛЮЧЁННЫЕ АДРЕСА")
                .size(11.0)
                .strong()
                .color(Colors::GOLD)
        );
        ui.label(
            egui::RichText::new(app.exclude_routes.len().to_string())
                .size(10.0)
                .color(Colors::GREY)
        );
    });

    ui.add_space(8.0);

    egui::Frame::NONE
        .fill(egui::Color32::from_rgb(25, 27, 33))
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(45, 47, 54)))
        .corner_radius(8.0)
        .inner_margin(egui::Margin::same(8))
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    if app.exclude_routes.is_empty() {
                        ui.vertical_centered(|ui| {
                            ui.add_space(20.0);
                            ui.label(
                                egui::RichText::new("Нет исключённых адресов")
                                    .size(11.0)
                                    .color(Colors::GREY)
                            );
                        });
                    } else {
                        let mut remove_index = None;
                        for (index, route) in app.exclude_routes.iter().enumerate() {
                            egui::Frame::NONE
                                .fill(if index % 2 == 0 {
                                    egui::Color32::from_rgb(30, 32, 39)
                                } else {
                                    egui::Color32::TRANSPARENT
                                })
                                .corner_radius(6.0)
                                .inner_margin(egui::Margin::symmetric(8, 5))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(egui::RichText::new("•").color(Colors::GOLD));
                                        ui.label(
                                            egui::RichText::new(route)
                                                .size(11.0)
                                                .family(egui::FontFamily::Name("JetBrainsMono".into()))
                                        );

                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            if ui.add(egui::Button::new(egui::RichText::new("Удалить").size(10.0)).frame(false))
                                                .on_hover_cursor(egui::CursorIcon::PointingHand)
                                                .clicked()
                                            {
                                                remove_index = Some(index);
                                            }
                                        });
                                    });
                                });
                        }

                        if let Some(index) = remove_index {
                            app.exclude_routes.remove(index);
                            app.exclude_routes_changed = true;
                            app.show_toast("Адрес удален");
                            app.log("Адрес удален");
                        }
                    }
                });
        });
}

fn render_connection_settings(ui: &mut egui::Ui) {
    ui.label(egui::RichText::new("• Предпочтительный транспорт: Авто (QUIC / AHTTP)").size(11.5).color(egui::Color32::WHITE));
    ui.add_space(6.0);
    ui.label(egui::RichText::new("• Размер MTU сетевого интерфейса: 1420 байт").size(11.5).color(egui::Color32::WHITE));
}

fn render_routing_settings(ui: &mut egui::Ui) {
    ui.label(egui::RichText::new("• Маршрутизация всего системного трафика: Включено").size(11.5).color(egui::Color32::WHITE));
}

fn render_security_settings(ui: &mut egui::Ui) {
    ui.label(egui::RichText::new("• Kill Switch (блокировка при обрыве): Включено").size(11.5).color(egui::Color32::WHITE));
}

fn render_split_tunnel_settings(ui: &mut egui::Ui) {
    ui.label(egui::RichText::new("• Режим фильтрации: Включить только выбранные приложения").size(11.5).color(egui::Color32::WHITE));
}

fn render_updates_settings(ui: &mut egui::Ui) {
    ui.label(egui::RichText::new("• Автоматическая проверка релизов GitHub: Включено").size(11.5).color(egui::Color32::WHITE));
}