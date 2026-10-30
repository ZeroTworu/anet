// anet-client-gui/src/ui/settings_modal.rs
use eframe::egui;
use egui::Stroke;
use crate::{
    app::ANetApp,
    secure_store::DesktopSecureStore,
    theme::Colors,
    types::{OverrideTab, SettingsCategory},
    utils::{
        helpers::lock_ignore_poison,
        validator::validate_routing_override_target,
    },
};
use anet_client_core::server_config::{
    validate_server_config_url,
    SERVER_CONFIG_ID,
    SERVER_CONFIG_DISPLAY_NAME,
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
            let screen_rect = ui.ctx().content_rect();
            let corner_radius = 14.0;

            egui::Frame::NONE
                .fill(ui.visuals().window_fill())
                .inner_margin(margin)
                .corner_radius(corner_radius)
                .show(ui, |ui| {
                    ui.set_width(screen_rect.width() - margin * 2.0);
                    ui.set_height(screen_rect.height() - margin * 2.0);

                    // Обработка выхода по клавише Escape
                    if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                        if app.active_settings_page.is_some() {                          
                            if app.routing_overrides_changed {
                                app.routing_overrides_changed = false;
                                app.save_routing_overrides();
                            }
                            app.active_settings_page = None;
                        } else {
                            app.settingsbar_open = false;
                            app.active_settings_page = None;
                            app.check_and_show_url_modal_if_empty();
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
                .corner_radius(button_size.y / 2.0);

            let response = ui.add(circle_button).on_hover_cursor(egui::CursorIcon::PointingHand);
            
            // Нажатие на круглую кнопку ⏴ возврата в меню настроек:
            if response.clicked() {
                app.active_settings_page = None;

                // 2. Сохранение [routing.overrides] при выходе
                if app.routing_overrides_changed {
                    app.routing_overrides_changed = false;
                    app.save_routing_overrides();
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
                let is_server_cfg =
                    lock_ignore_poison(&app.settings).active_config_id.as_deref() ==
                    Some(SERVER_CONFIG_ID);

                ui.horizontal(|ui| {
                    let (dot_color, label_text) = if is_server_cfg {
                        (Colors::GOLD, "Настройки применяются поверх Server config".to_string())
                    } else {
                        (
                            egui::Color32::from_rgb(76, 175, 80),
                            format!("Профиль: {}", app.config_name),
                        )
                    };
                    let (dot_rect, _) = ui.allocate_exact_size(
                        egui::vec2(6.0, 6.0),
                        egui::Sense::hover(),
                    );
                    ui.painter().circle_filled(dot_rect.center(), 3.0, dot_color);
                    ui.label(egui::RichText::new(label_text).size(10.5).color(dot_color));
                });
                ui.add_space(8.0);
                ui.set_width(ui.available_width());
                ui.vertical(|ui| {
                    match category {
                        SettingsCategory::General => render_general_settings(app, ui),
                        SettingsCategory::Configs => render_configs_settings(app, ui),
                        SettingsCategory::ServerUrl => render_server_url_settings(app, ui),
                        SettingsCategory::PerApp => {
                            #[cfg(target_os = "windows")]
                            crate::ui::process_grid::render_process_list(app, ui);

                            #[cfg(not(target_os = "windows"))]
                            {
                                ui.label(
                                    egui::RichText::new(
                                        "Туннелирование по приложениям поддерживается только на Windows.",
                                    )
                                    .size(13.0)
                                    .color(Colors::GREY)
                                    .family(egui::FontFamily::Name("Inter-V".into())),
                                );
                            }
                        }                      
                        SettingsCategory::RoutingOverrides => render_routing_overrides_settings(app, ui),
                        SettingsCategory::Routing => render_routing_settings(app, ui),
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
            .corner_radius(button_size.y / 2.0);

        let response = ui.add(circle_button).on_hover_cursor(egui::CursorIcon::PointingHand);
        if response.clicked() {
            app.settingsbar_open = false;
            app.active_settings_page = None;
            app.check_and_show_url_modal_if_empty();
        }

        ui.heading("Настройки");
    });
    ui.add_space(8.0);
    ui.label(
        egui::RichText::new("Выберите категорию параметров для настройки:")
            .size(11.0)
            .color(Colors::GREY)
            .family(egui::FontFamily::Name("Inter-V".into())),
    );
    ui.add_space(12.0);

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let categories = [
                SettingsCategory::General,
                SettingsCategory::Configs,
                SettingsCategory::ServerUrl,
                SettingsCategory::PerApp,                
                SettingsCategory::RoutingOverrides,
                SettingsCategory::Routing,
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

                let frame_resp = egui::Frame::NONE
                    .fill(bg_color)
                    .corner_radius(8.0)
                    .inner_margin(egui::Margin::same(12))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.vertical(|ui| {
                            ui.horizontal(|ui| {
                                let icon_img = egui::Image::new(cat.icon())
                                    .fit_to_exact_size(egui::vec2(18.0, 18.0))
                                    .tint(if is_hovered { Colors::GOLD } else { egui::Color32::WHITE });

                                ui.add(icon_img);
                                ui.label(
                                    egui::RichText::new(cat.title())
                                        .size(14.0)
                                        .strong()
                                        .color(if is_hovered { Colors::GOLD } else { egui::Color32::WHITE }),
                                );
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.label(
                                            egui::RichText::new("›")
                                                .size(18.0)
                                                .color(if is_hovered { Colors::GOLD } else { Colors::GREY }),
                                        );
                                    },
                                );
                            });
                            ui.add_space(4.0);
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(cat.description())
                                        .size(11.0)
                                        .color(Colors::GREY)
                                        .family(egui::FontFamily::Name("Inter-V".into())),
                                )
                                .wrap(),
                            );
                        });
                    });

                let response = ui.interact(frame_resp.response.rect, cat_id, egui::Sense::click());
                let now_hovered = frame_resp.response.contains_pointer();
                if now_hovered != is_hovered {
                    ui.data_mut(|d| d.insert_temp(cat_id, now_hovered));
                    ui.ctx().request_repaint();
                }

                ui.add_space(8.0);

                if response.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                    app.active_settings_page = Some(cat);
                }

                ui.add_space(10.0);
            }
        });
}

fn render_server_url_settings(app: &mut ANetApp, ui: &mut egui::Ui) {
    let saved_url = DesktopSecureStore::get_server_config_url().unwrap_or_default();

    ui.label(
        egui::RichText::new("Персональная ссылка доступа на серверный конфиг ANet.")
            .size(11.0)
            .color(Colors::GREY)
            .family(egui::FontFamily::Name("Inter-V".into())),
    );
    ui.add_space(4.0);
    ui.label(
        egui::RichText::new("Ссылка безопасно хранится в защищенном системном хранилище.")
            .size(10.0)
            .color(Colors::GOLD),
    );

    ui.add_space(12.0);

    ui.label(
        egui::RichText::new("Ссылка на конфигурацию:").size(11.0).strong().color(Colors::GOLD),
    );
    ui.add_space(6.0);

    let row_height = 32.0;
    let input_width = ui.available_width();

    let input_response = ui.scope(|ui| {
        let radius = egui::CornerRadius::same(6);
        let w = &mut ui.visuals_mut().widgets;
        w.inactive.corner_radius = radius;
        w.hovered.corner_radius = radius;
        w.active.corner_radius = radius;
        ui.visuals_mut().widgets.open.corner_radius = radius;

        ui.add_sized(
            [input_width, row_height],
            egui::TextEdit::singleline(&mut app.url_input_buffer)
                .hint_text("example.com/config или https://...")
                .vertical_align(egui::Align::Center),
        )
    }).inner;

    if let Some(err) = &app.url_modal_error {
        ui.add_space(4.0);
        ui.label(egui::RichText::new(err).size(11.0).color(Colors::RED));
    }

    ui.add_space(16.0);

    ui.horizontal(|ui| {
        let save_btn = ui.add(
            egui::Button::new(
                egui::RichText::new("СОХРАНИТЬ").size(11.5).strong().color(egui::Color32::BLACK),
            )
            .fill(Colors::GOLD)
            .min_size(egui::vec2(90.0, 32.0))
            .corner_radius(6.0),
        );

        let enter_pressed =
            input_response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if save_btn.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() || enter_pressed {
            let raw_url = app.url_input_buffer.trim();
            match validate_server_config_url(raw_url) {
                Ok(normalized) => {
                    app.url_modal_error = None;
                    if let Err(e) = DesktopSecureStore::set_server_config_url(&normalized) {
                        app.url_modal_error = Some(format!("Ошибка Keystore: {}", e));
                    } else {
                        {
                            let mut settings = lock_ignore_poison(&app.settings);
                            settings.set_active(SERVER_CONFIG_ID);
                            settings.save();
                        }
                        app.show_toast("Ссылка сохранена");
                        app.fetch_and_apply_server_config(false);
                    }
                }
                Err(err_msg) => {
                    app.url_modal_error = Some(err_msg.to_string());
                }
            }
        }

        if !saved_url.is_empty() {
            let update_btn = ui.add(
                egui::Button::new(egui::RichText::new("ОБНОВИТЬ").size(11.5).strong().color(Colors::GOLD))
                    .fill(egui::Color32::from_rgb(34, 38, 48))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(60, 65, 80)))
                    .min_size(egui::vec2(90.0, 32.0))
                    .corner_radius(6.0),
            );

            if update_btn.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                app.fetch_and_apply_server_config(true);
                app.show_toast("Запрос обновления серверного конфига...");
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let del_btn = ui.add(
                    egui::Button::new(
                        egui::RichText::new("🗑 УДАЛИТЬ")
                            .size(11.0)
                            .color(egui::Color32::from_rgb(240, 80, 80)),
                    )
                    .fill(egui::Color32::from_rgb(45, 26, 26))
                    .min_size(egui::vec2(90.0, 32.0))
                    .corner_radius(6.0),
                );

                if del_btn.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                    let _ = DesktopSecureStore::delete_server_config_url();
                    app.url_input_buffer.clear();
                    app.delete_config(SERVER_CONFIG_ID);
                    app.show_toast("Ссылка удалена");
                }
            });
        }
    });
}

fn render_general_settings(app: &mut ANetApp, ui: &mut egui::Ui) {
    let checkbox_white = egui::Color32::from_rgb(255, 255, 255);
    let checkbox_grey = egui::Color32::from_rgb(76, 76, 76);

    let checkbox_inactive_chevron = egui::Stroke::new(2.0, checkbox_white);
    let checkbox_inactive_stroke = egui::Stroke::new(2.0, checkbox_grey);

    ui.style_mut().visuals.widgets.inactive.fg_stroke = checkbox_inactive_chevron;
    ui.style_mut().visuals.widgets.inactive.bg_stroke = checkbox_inactive_stroke;
    ui.style_mut().visuals.widgets.inactive.bg_fill = checkbox_grey;

    if ui.checkbox(&mut app.tray_value, "Сворачивать приложение в трэй").changed() {
        app.save_tray_mode_setting();
    }
}

fn render_configs_settings(app: &mut ANetApp, ui: &mut egui::Ui) {
    let settings_guard = lock_ignore_poison(&app.settings);
    let configs = settings_guard.configs.clone();
    let active_id = settings_guard.active_config_id.clone();
    let editing_id = app.editing_config_id.clone();
    let has_server_cache = settings_guard.cached_server_config.is_some();
    drop(settings_guard);

    let has_server_url = DesktopSecureStore::get_server_config_url().is_some();
    let show_server_config_card = has_server_url || has_server_cache;

    let total_count = configs.len() + (if show_server_config_card { 1 } else { 0 });

    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("РЕЕСТР КОНФИГУРАЦИЙ")
                .size(11.0)
                .strong()
                .color(Colors::GOLD)
                .family(egui::FontFamily::Name("Inter-V".into())),
        );
        ui.label(egui::RichText::new(format!("({})", total_count)).size(10.0).color(Colors::GREY));
    });

    ui.add_space(8.0);

    let icon_url_btn = egui::Image::new(egui::include_image!("../assets/server_url.svg"))
        .fit_to_exact_size(egui::vec2(18.0, 18.0))
        .tint(Colors::GOLD);

    let url_btn = egui::Button::image_and_text(
        icon_url_btn,
        egui::RichText::new("Ссылка на конфигурацию (url)")
            .size(11.5)
            .strong()
            .family(egui::FontFamily::Name("Inter-V".into())),
    )
    .fill(egui::Color32::from_rgb(32, 35, 45))
    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(60, 65, 80)))
    .corner_radius(8.0);

    let url_btn_resp = ui.add_sized([ui.available_width(), 34.0], url_btn);
    if url_btn_resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
        app.active_settings_page = Some(SettingsCategory::ServerUrl);
    }

    ui.add_space(8.0);

    let icon_add_btn = egui::Image::new(egui::include_image!("../assets/folder.svg"))
        .fit_to_exact_size(egui::vec2(18.0, 18.0))
        .tint(Colors::GOLD);

    let add_btn = egui::Button::image_and_text(
        icon_add_btn,
        egui::RichText::new("Загрузить файл .toml")
            .size(11.5)
            .strong()
            .family(egui::FontFamily::Name("Inter-V".into())),
    )
    .fill(egui::Color32::from_rgb(32, 35, 45))
    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(60, 65, 80)))
    .corner_radius(8.0);

    let add_btn_resp = ui.add_sized([ui.available_width(), 36.0], add_btn);
    if add_btn_resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
        app.open_file_dialog();
    }

    ui.add_space(12.0);

    if total_count == 0 {
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
                            .family(egui::FontFamily::Name("Inter-V".into())),
                    );
                    ui.add_space(2.0);
                    ui.label(
                        egui::RichText::new("Укажите ссылку на серверный конфиг или выберите .toml файл")
                            .size(10.0)
                            .color(egui::Color32::from_rgb(100, 105, 115)),
                    );
                });
            });
        return;
    }

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if show_server_config_card {
                let is_server_active = active_id.as_deref() == Some(SERVER_CONFIG_ID);
                let card_id = ui.id().with("config_card_server");
                let is_hovered: bool = ui.data(|d| d.get_temp(card_id)).unwrap_or(false);

                let bg_color = if is_server_active {
                    egui::Color32::from_rgb(28, 38, 33)
                } else if is_hovered {
                    egui::Color32::from_rgb(32, 35, 45)
                } else {
                    egui::Color32::from_rgb(22, 24, 30)
                };

                let border_color = if is_server_active {
                    egui::Color32::from_rgb(76, 175, 80)
                } else if is_hovered {
                    Colors::GOLD
                } else {
                    egui::Color32::from_rgb(60, 65, 80)
                };

                egui::Frame::NONE
                    .fill(bg_color)
                    .stroke(egui::Stroke::new(1.0, border_color))
                    .corner_radius(8.0)
                    .inner_margin(egui::Margin::symmetric(12, 10))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            let right_buttons_width = 80.0;
                            let left_width = (ui.available_width() - right_buttons_width).max(80.0);

                            let (left_rect, left_response) = ui.allocate_exact_size(
                                egui::vec2(left_width, 36.0),
                                egui::Sense::click(),
                            );

                            if left_response.hovered() != is_hovered {
                                ui.data_mut(|d| d.insert_temp(card_id, left_response.hovered()));
                                ui.ctx().request_repaint();
                            }

                            if left_response
                                .on_hover_cursor(egui::CursorIcon::PointingHand)
                                .clicked()
                            {
                                if !is_server_active {
                                    if lock_ignore_poison(&app.shared).state != crate::types::ConnectionState::Disconnected {
                                        app.show_toast("Нельзя сменить конфигурацию при активном подключении");
                                    } else {
                                        app.select_config(SERVER_CONFIG_ID);
                                    }
                                }
                            }

                            let center_y = left_rect.center().y;
                            let dot_pos = egui::pos2(left_rect.left() + 6.0, center_y);
                            let dot_color = if is_server_active {
                                egui::Color32::from_rgb(76, 175, 80)
                            } else {
                                Colors::GOLD
                            };
                            ui.painter().circle_filled(dot_pos, 4.5, dot_color);

                            let title_pos = egui::pos2(left_rect.left() + 20.0, if is_server_active {
                                center_y - 7.0
                            } else {
                                center_y
                            });
                            ui.painter().text(
                                title_pos,
                                egui::Align2::LEFT_CENTER,
                                SERVER_CONFIG_DISPLAY_NAME,
                                egui::FontId::new(13.0, egui::FontFamily::Name("Inter-V".into())),
                                if is_server_active { egui::Color32::WHITE } else { Colors::GOLD },
                            );

                            if is_server_active {
                                let sub_pos = egui::pos2(left_rect.left() + 20.0, center_y + 8.0);
                                ui.painter().text(
                                    sub_pos,
                                    egui::Align2::LEFT_CENTER,
                                    "АКТИВНЫЙ (ШИФРОВАННЫЙ СЕРВЕРНЫЙ КОНФИГ)",
                                    egui::FontId::new(8.5, egui::FontFamily::Name("Inter-V".into())),
                                    egui::Color32::from_rgb(76, 175, 80),
                                );
                            }

                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                let refresh_btn = ui.add(
                                    egui::Button::new(
                                        egui::RichText::new("🔄").size(13.0).color(Colors::GOLD),
                                    )
                                    .frame(false),
                                );
                                if refresh_btn
                                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                                    .on_hover_text("Обновить по ссылке")
                                    .clicked()
                                {
                                    app.fetch_and_apply_server_config(true);
                                }
                            });
                        });
                    });

                ui.add_space(8.0);
            }

            for config in &configs {
                let is_active = active_id.as_deref() == Some(config.id.as_str());
                let is_editing = editing_id.as_deref() == Some(config.id.as_str());

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
                            ui.horizontal(|ui| {
                                let (dot_rect, _) = ui.allocate_exact_size(
                                    egui::vec2(10.0, 10.0),
                                    egui::Sense::hover(),
                                );
                                ui.painter().circle_filled(dot_rect.center(), 4.0, Colors::GOLD);

                                ui.add_space(4.0);

                                let input_width = (ui.available_width() - 36.0).max(100.0);
                                let response = ui.add(
                                    egui::TextEdit::singleline(&mut app.edit_name_buffer)
                                        .desired_width(input_width)
                                        .font(egui::FontId::new(12.5, egui::FontFamily::Name("Inter-V".into()))),
                                );

                                if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                                    app.finish_edit_name();
                                }

                                if ui
                                    .add(
                                        egui::Button::new(
                                            egui::RichText::new("✔").size(12.0).color(Colors::GOLD),
                                        )
                                        .fill(egui::Color32::from_rgb(40, 44, 55))
                                        .min_size(egui::vec2(28.0, 24.0))
                                        .corner_radius(4.0),
                                    )
                                    .clicked()
                                {
                                    app.finish_edit_name();
                                }
                            });
                        } else {
                            ui.horizontal(|ui| {
                                let right_buttons_width = 68.0;
                                let left_width = (ui.available_width() - right_buttons_width).max(80.0);

                                let (left_rect, left_response) = ui.allocate_exact_size(
                                    egui::vec2(left_width, 34.0),
                                    egui::Sense::click(),
                                );

                                if left_response
                                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                                    .clicked()
                                {
                                    if !is_active {
                                        if lock_ignore_poison(&app.shared).state != crate::types::ConnectionState::Disconnected {
                                            app.show_toast("Нельзя сменить конфигурацию при активном подключении");
                                        } else {
                                            app.select_config(&config.id);
                                        }
                                    }
                                }

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

                                let title_pos = egui::pos2(left_rect.left() + 20.0, if is_active {
                                    center_y - 7.0
                                } else {
                                    center_y
                                });
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
                                        "АКТИВНЫЙ ПРОФИЛЬ",
                                        egui::FontId::new(9.0, egui::FontFamily::Name("Inter-V".into())),
                                        egui::Color32::from_rgb(76, 175, 80),
                                    );
                                }

                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.spacing_mut().item_spacing.x = 20.0;

                                        let red = egui::Color32::from_rgb(240, 80, 80);

                                        let del_btn = ui.scope(|ui| {
                                            let w = &mut ui.visuals_mut().widgets;
                                            w.inactive.fg_stroke.color = Colors::GREY;
                                            w.hovered.fg_stroke.color = red;
                                            w.active.fg_stroke.color = red;

                                            ui.add(
                                                egui::Button::new(egui::RichText::new("🗑").size(13.0))
                                                    .frame(false),
                                            )
                                        }).inner;

                                        if del_btn
                                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                                            .on_hover_text("Удалить конфиг")
                                            .clicked()
                                        {
                                            app.delete_config(&config.id);
                                        }

                                        let edit_btn = ui.scope(|ui| {
                                            let w = &mut ui.visuals_mut().widgets;
                                            w.inactive.fg_stroke.color = Colors::GREY;
                                            w.hovered.fg_stroke.color = Colors::GOLD;
                                            w.active.fg_stroke.color = Colors::GOLD;

                                            ui.add(
                                                egui::Button::new(egui::RichText::new("✏").size(13.0))
                                                    .frame(false),
                                            )
                                        }).inner;

                                        if edit_btn
                                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                                            .on_hover_text("Переименовать")
                                            .clicked()
                                        {
                                            app.start_edit_name(&config.id, &config.name);
                                        }
                                    },
                                );
                            });
                        }
                    });

                ui.add_space(8.0);
            }
        });
}


pub fn render_routing_overrides_settings(app: &mut ANetApp, ui: &mut egui::Ui) {
    ui.label(
        egui::RichText::new("Локальные исключения [routing.overrides]")
            .size(13.0)
            .strong()
            .color(Colors::GOLD)
            .family(egui::FontFamily::Name("Inter-V".into())),
    );
    ui.add_space(3.0);
    ui.add(
        egui::Label::new(
            egui::RichText::new(
                "Управление списками прямого доступа мимо VPN (Direct), локальной блокировки (Block) \
                 и принудительного проксирования (Proxy). Изменения применяются при возврате ⏴.",
            )
            .size(11.0)
            .color(Colors::GREY)
            .family(egui::FontFamily::Name("Inter-V".into())),
        )
        .wrap(),
    );

    ui.add_space(10.0);

    // 1. Вкладки категорий правил (Direct / Block / Proxy)
ui.horizontal(|ui| {
    let direct_cnt = app.routing_overrides.direct.len();
    let block_cnt = app.routing_overrides.block.len();
    let proxy_cnt = app.routing_overrides.proxy.len();

    // Равномерная ширина: делим доступное место на 3 с учётом промежутков
    let spacing = ui.spacing().item_spacing.x;
    let btn_w = ((ui.available_width() - spacing * 2.0) / 3.0).max(60.0);

    let tab_btn = |ui: &mut egui::Ui, is_sel: bool, title: &str, count: usize, color: egui::Color32| {
        let text = format!("{} ({})", title, count);
        let btn = egui::Button::new(
            egui::RichText::new(text)
                .size(11.0)
                .strong()
                .color(if is_sel { egui::Color32::BLACK } else { color }),
        )
        .fill(if is_sel { color } else { egui::Color32::from_rgb(32, 35, 45) })
        .min_size(egui::vec2(btn_w, 28.0))
        .corner_radius(6.0);
        ui.add(btn).clicked()
    };

    if tab_btn(ui, app.routing_overrides_tab == OverrideTab::Direct, "мимо Vpn", direct_cnt, Colors::GREEN) {
        app.routing_overrides_tab = OverrideTab::Direct;
    }
    if tab_btn(ui, app.routing_overrides_tab == OverrideTab::Block, "Блокировка", block_cnt, Colors::RED) {
        app.routing_overrides_tab = OverrideTab::Block;
    }
    if tab_btn(ui, app.routing_overrides_tab == OverrideTab::Proxy, "в VPN", proxy_cnt, Colors::GOLD) {
        app.routing_overrides_tab = OverrideTab::Proxy;
    }
});

    ui.add_space(6.0);

    let desc_text = match app.routing_overrides_tab {
        OverrideTab::Direct => "Трафик направляется строго напрямую через локальный шлюз мимо VPN.",
        OverrideTab::Block => "Домены и IP блокируются локально DNS-перехватчиком (заглушка 0.0.0.0).",
        OverrideTab::Proxy => "Трафик принудительно направляется в шифрованный туннель.",
    };
    ui.label(egui::RichText::new(desc_text).size(10.5).color(Colors::GREY));

    ui.add_space(10.0);

    // 2. Поле ввода и добавления
    let mut item_to_add: Option<String> = None;
    ui.horizontal(|ui| {
        let row_height = 32.0;
        let btn_width = 90.0;
        let spacing = 8.0;
        ui.spacing_mut().item_spacing.x = spacing;

        let input_width = (ui.available_width() - btn_width - spacing).max(120.0);

        let response = ui.scope(|ui| {
            let radius = egui::CornerRadius::same(6);
            let w = &mut ui.visuals_mut().widgets;
            w.inactive.corner_radius = radius;
            w.hovered.corner_radius = radius;
            w.active.corner_radius = radius;
            ui.visuals_mut().widgets.open.corner_radius = radius;

            let hint = match app.routing_overrides_tab {
                OverrideTab::Direct => "*.home.arpa, 192.168.1.0/24",
                OverrideTab::Block => "metrics.telemetry.com, 198.51.100.0/24",
                OverrideTab::Proxy => "dev-portal.io, restricted-api.io",
            };

            ui.add_sized(
                [input_width, row_height],
                egui::TextEdit::singleline(&mut app.routing_override_input)
                    .hint_text(hint)
                    .vertical_align(egui::Align::Center)
                    .margin(egui::Margin::symmetric(8, 0)),
            )
        }).inner;

        let add_btn = ui.add_sized(
            [btn_width, row_height],
            egui::Button::new(
                egui::RichText::new("ДОБАВИТЬ")
                    .size(11.0)
                    .strong()
                    .color(egui::Color32::BLACK),
            )
            .fill(Colors::GOLD)
            .corner_radius(6.0),
        ).on_hover_cursor(egui::CursorIcon::PointingHand);

        let enter_pressed = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

        if add_btn.clicked() || enter_pressed {
            let target = app.routing_override_input.trim().to_string();
            if !target.is_empty() {
                item_to_add = Some(target);
            }
        }
    });

    // Обработка добавления (НЕ вызывает сохранение/реконнект, только ставит флаг)
    if let Some(target) = item_to_add {
        if validate_routing_override_target(&target) {
            let target_list = match app.routing_overrides_tab {
                OverrideTab::Direct => &mut app.routing_overrides.direct,
                OverrideTab::Block => &mut app.routing_overrides.block,
                OverrideTab::Proxy => &mut app.routing_overrides.proxy,
            };

            if !target_list.contains(&target) {
                target_list.push(target);
                app.routing_override_input.clear();
                app.routing_overrides_changed = true;
                app.show_toast("Правило добавлено");
            } else {
                app.show_toast("Правило уже присутствует в списке");
            }
        } else {
            app.show_toast("Некорректный адрес (укажите домен, *.wildcard, IP или CIDR)");
        }
    }

    ui.add_space(10.0);

    // 3. Список добавленных правил
    let tab = app.routing_overrides_tab;
    let mut remove_idx = None;

    egui::Frame::NONE
        .fill(egui::Color32::from_rgb(22, 24, 30))
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(45, 48, 58)))
        .corner_radius(8.0)
        .inner_margin(egui::Margin::same(6))
        .show(ui, |ui| {
            ui.set_max_width(ui.available_width());

            let current_items = match tab {
                OverrideTab::Direct => &app.routing_overrides.direct,
                OverrideTab::Block => &app.routing_overrides.block,
                OverrideTab::Proxy => &app.routing_overrides.proxy,
            };

            if current_items.is_empty() {
                ui.vertical_centered(|ui| {
                    ui.add_space(16.0);
                    ui.label(egui::RichText::new("Список пуст").size(11.0).color(Colors::GREY));
                    ui.add_space(16.0);
                });
            } else {
                egui::ScrollArea::vertical()
                    .max_height(240.0)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for (idx, item) in current_items.iter().enumerate() {
                            egui::Frame::NONE
                                .fill(if idx % 2 == 0 { egui::Color32::from_rgb(28, 30, 38) } else { egui::Color32::TRANSPARENT })
                                .corner_radius(6.0)
                                .inner_margin(egui::Margin::symmetric(8, 6))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        let badge_color = match tab {
                                            OverrideTab::Direct => Colors::GREEN,
                                            OverrideTab::Block => Colors::RED,
                                            OverrideTab::Proxy => Colors::GOLD,
                                        };
                                        ui.label(egui::RichText::new("•").size(12.0).color(badge_color));
                                        ui.label(
                                            egui::RichText::new(item)
                                                .size(11.5)
                                                .color(egui::Color32::WHITE)
                                                .family(egui::FontFamily::Monospace),
                                        );

                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            if ui.add(
                                                egui::Button::new(
                                                    egui::RichText::new("🗑").size(11.0).color(egui::Color32::from_rgb(240, 80, 80)),
                                                ).frame(false),
                                            ).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                                                remove_idx = Some(idx);
                                            }
                                        });
                                    });
                                });
                        }
                    });
            }
        });

    // Обработка удаления (НЕ вызывает сохранение/реконнект, только ставит флаг)
    if let Some(idx) = remove_idx {
        match app.routing_overrides_tab {
            OverrideTab::Direct => { app.routing_overrides.direct.remove(idx); }
            OverrideTab::Block => { app.routing_overrides.block.remove(idx); }
            OverrideTab::Proxy => { app.routing_overrides.proxy.remove(idx); }
        };
        app.routing_overrides_changed = true;
        app.show_toast("Правило удалено");
    }
}

fn render_routing_settings(app: &mut ANetApp, ui: &mut egui::Ui) {
    ui.set_max_width(ui.available_width());

    ui.label(
        egui::RichText::new("Пользовательские DNS-серверы")
            .size(13.0)
            .strong()
            .color(Colors::GOLD)
            .family(egui::FontFamily::Name("Inter-V".into())),
    );
    ui.add_space(3.0);
    ui.add(
        egui::Label::new(
            egui::RichText::new(
                "Указанные DNS применяются поверх Server config и предотвращают утечки DNS.",
            )
            .size(11.0)
            .color(Colors::GREY)
            .family(egui::FontFamily::Name("Inter-V".into())),
        )
        .wrap(),
    );

    ui.add_space(10.0);

    ui.horizontal(|ui| {
        let dot_color = if app.is_dns_overridden {
            egui::Color32::from_rgb(76, 175, 80)
        } else {
            Colors::GREY
        };
        let (dot_rect, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
        ui.painter().circle_filled(dot_rect.center(), 3.5, dot_color);

        let status_text = if app.is_dns_overridden {
            "Кастомный оверлей активен"
        } else {
            "По умолчанию из сервера"
        };
        ui.label(egui::RichText::new(status_text).size(10.5).color(dot_color));
    });

    ui.add_space(10.0);

    ui.label(egui::RichText::new("БЫСТРЫЕ ПРЕСЕТЫ:").size(10.0).strong().color(Colors::GREY));
    ui.add_space(4.0);

    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = egui::vec2(6.0, 6.0);

        if ui
            .add(
                egui::Button::new(egui::RichText::new("Cloudflare").size(11.0))
                    .fill(egui::Color32::from_rgb(34, 38, 48))
                    .min_size(egui::vec2(90.0, 32.0))
                    .corner_radius(6.0),
            )
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked()
        {
            app.custom_dns_list = vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()];
            app.save_dns_settings();
        }

        if ui
            .add(
                egui::Button::new(egui::RichText::new("Google").size(11.0))
                    .fill(egui::Color32::from_rgb(34, 38, 48))
                    .min_size(egui::vec2(90.0, 32.0))
                    .corner_radius(6.0),
            )
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked()
        {
            app.custom_dns_list = vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()];
            app.save_dns_settings();
        }

        if ui
            .add(
                egui::Button::new(egui::RichText::new("Quad9").size(11.0))
                    .fill(egui::Color32::from_rgb(34, 38, 48))
                    .min_size(egui::vec2(90.0, 32.0))
                    .corner_radius(6.0),
            )
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked()
        {
            app.custom_dns_list = vec!["9.9.9.9".to_string(), "149.112.112.112".to_string()];
            app.save_dns_settings();
        }
    });

    ui.add_space(12.0);

    ui.horizontal(|ui| {
        let row_height = 32.0;
        let btn_width = 90.0;
        let spacing = 8.0;
        ui.spacing_mut().item_spacing.x = spacing;

        let input_width = (ui.available_width() - btn_width - spacing).max(120.0);

        let response = ui.scope(|ui| {
            let radius = egui::CornerRadius::same(6);
            let w = &mut ui.visuals_mut().widgets;
            w.inactive.corner_radius = radius;
            w.hovered.corner_radius = radius;
            w.active.corner_radius = radius;
            ui.visuals_mut().widgets.open.corner_radius = radius;

            ui.add_sized(
                [input_width, row_height],
                egui::TextEdit::singleline(&mut app.dns_input_buffer)
                    .hint_text("Напр: 1.1.1.1")
                    .vertical_align(egui::Align::Center)
                    .margin(egui::Margin::symmetric(8, 0)),
            )
        }).inner;

        let add_clicked = ui
            .add_sized(
                [btn_width, row_height],
                egui::Button::new(
                    egui::RichText::new("ДОБАВИТЬ")
                        .size(11.0)
                        .strong()
                        .color(egui::Color32::BLACK),
                )
                .fill(Colors::GOLD)
                .corner_radius(6.0),
            )
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked();

        let enter_pressed = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

        if add_clicked || enter_pressed {
            let input_ip = app.dns_input_buffer.trim().to_string();
            if input_ip.parse::<std::net::IpAddr>().is_err() {
                app.show_toast("Некорректный IP-адрес DNS");
            } else if app.custom_dns_list.iter().any(|ip| ip == &input_ip) {
                app.show_toast("Этот DNS-сервер уже добавлен");
            } else {
                app.custom_dns_list.push(input_ip);
                app.dns_input_buffer.clear();
                app.save_dns_settings();
            }
        }
    });

    ui.add_space(12.0);

    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("СПИСОК DNS").size(11.0).strong().color(Colors::GOLD));
        ui.label(
            egui::RichText::new(format!("({})", app.custom_dns_list.len()))
                .size(10.0)
                .color(Colors::GREY),
        );

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .add(
                    egui::Button::new(
                        egui::RichText::new("Сбросить")
                            .size(11.0)
                            .color(egui::Color32::from_rgb(240, 100, 100)),
                    )
                    .fill(egui::Color32::from_rgb(34, 38, 48))
                    .min_size(egui::vec2(90.0, 32.0))
                    .corner_radius(6.0),
                )
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .on_hover_text("Сбросить к значениям сервера")
                .clicked()
            {
                app.reset_dns_settings();
            }
        });
    });

    ui.add_space(6.0);

    egui::Frame::NONE
        .fill(egui::Color32::from_rgb(22, 24, 30))
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(45, 48, 58)))
        .corner_radius(8.0)
        .inner_margin(egui::Margin::same(6))
        .show(ui, |ui| {
            ui.set_max_width(ui.available_width());

            if app.custom_dns_list.is_empty() {
                ui.vertical_centered(|ui| {
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new("Список DNS пуст").size(11.0).color(Colors::GREY));
                    ui.add_space(8.0);
                });
            } else {
                let mut remove_idx = None;
                for (idx, ip_str) in app.custom_dns_list.iter().enumerate() {
                    egui::Frame::NONE
                        .fill(
                            if idx % 2 == 0 {
                                egui::Color32::from_rgb(28, 30, 38)
                            } else {
                                egui::Color32::TRANSPARENT
                            },
                        )
                        .corner_radius(6.0)
                        .inner_margin(egui::Margin::symmetric(8, 5))
                        .show(ui, |ui| {
                            ui.set_max_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new(format!("{}.", idx + 1))
                                        .size(10.5)
                                        .color(Colors::GOLD),
                                );
                                ui.label(
                                    egui::RichText::new(ip_str)
                                        .size(11.5)
                                        .color(egui::Color32::WHITE)
                                        .family(egui::FontFamily::Monospace),
                                );

                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui
                                            .add(
                                                egui::Button::new(
                                                    egui::RichText::new("🗑")
                                                        .size(11.0)
                                                        .color(egui::Color32::from_rgb(240, 80, 80)),
                                                )
                                                .frame(false),
                                            )
                                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                                            .on_hover_text("Удалить DNS")
                                            .clicked()
                                        {
                                            remove_idx = Some(idx);
                                        }
                                    },
                                );
                            });
                        });
                }

                if let Some(idx) = remove_idx {
                    app.custom_dns_list.remove(idx);
                    app.save_dns_settings();
                }
            }
        });
}

fn render_updates_settings(ui: &mut egui::Ui) {
    ui.label(
        egui::RichText::new("• Автоматическая проверка релизов GitHub: Включено")
            .size(11.5)
            .color(egui::Color32::WHITE),
    );
}