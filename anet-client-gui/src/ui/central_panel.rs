//! Центральная панель с главными элементами управления

use eframe::egui;
use egui::text::{ LayoutJob, TextFormat };
use egui::RichText;

use crate::{
    app::ANetApp,
    theme::Colors,
    types::ConnectionState,
    ui::{
        connect_button::render_connect_button,
        node_selector::render_node_selector,
        tariff_card::render_tariff_card,
    },
    utils::helpers::lock_ignore_poison,
};

pub fn render_central_panel(app: &mut ANetApp, ctx: &egui::Context) {
    let margin = 20.0;
    let button_size = egui::vec2(32.0, 32.0);
    let button_icon_size = egui::vec2(26.0, 26.0);
    let label_size = 10.0;

    let main_frame = egui::Frame::NONE.fill(Colors::DARK).inner_margin(margin);

    egui::CentralPanel::default()
        .frame(main_frame)
        .show(ctx, |ui| {
            let state = lock_ignore_poison(&app.shared).state;

            // Верхняя шапка: Кнопка Update, Заголовок по центру, Кнопка Settings
            ui.horizontal(|ui| {
                // Кнопка Update
                ui.allocate_ui_with_layout(
                    egui::vec2(60.0, ui.available_height()),
                    egui::Layout::top_down(egui::Align::Center),
                    |ui| {
                        let anim_id = ui.id().with("update_btn_color");
                        let hover_t: f32 = ui.data(|d| d.get_temp(anim_id)).unwrap_or(0.0);

                        let current_color = lerp_color(Colors::WHITE, Colors::GOLD, hover_t);

                        let icon = egui::Image::new(egui::include_image!("../assets/update.svg"))
                            .fit_to_exact_size(button_icon_size)
                            .tint(current_color);

                        let menu_button = egui::Button::image(icon)
                            .min_size(button_size)
                            .stroke(egui::Stroke::NONE)
                            .frame(false)
                            .rounding(button_size.y / 2.0);

                        let response = ui.add(menu_button).on_hover_cursor(egui::CursorIcon::PointingHand);

                        let target_t = if response.hovered() { 1.0 } else { 0.0 };
                        let dt = ui.input(|i| i.stable_dt);
                        let speed = 1.0 / 0.2;
                        let new_t = if hover_t < target_t {
                            (hover_t + speed * dt).min(target_t)
                        } else {
                            (hover_t - speed * dt).max(target_t)
                        };

                        ui.data_mut(|d| d.insert_temp(anim_id, new_t));

                        if new_t != target_t {
                            ui.ctx().request_repaint();
                        }

                        if response.clicked() {
                            app.check_for_updates();
                        }

                        ui.add_space(2.0);
                        ui.label(RichText::new("UPDATE").size(label_size).color(Colors::GREY));
                    }
                );

                #[cfg(target_os = "windows")]
                let center_width = (ui.available_width() - 60.0).max(0.0);
                #[cfg(not(target_os = "windows"))]
                let center_width = ui.available_width();

                // Логотип ANet VPN
                ui.allocate_ui_with_layout(
                    egui::vec2(center_width, ui.available_height()),
                    egui::Layout::centered_and_justified(egui::Direction::LeftToRight),
                    |ui| {
                        let mut job = LayoutJob::default();
                        let font_id = egui::FontId::new(24.0, egui::FontFamily::Name("Inter-V".into()));

                        job.append("ANET ", 0.0, TextFormat {
                            font_id: font_id.clone(),
                            color: Colors::IVORY,
                            ..Default::default()
                        });

                        job.append("VPN", 0.0, TextFormat {
                            font_id,
                            color: Colors::GOLD,
                            ..Default::default()
                        });

                        ui.add(egui::Label::new(job));
                    }
                );

                // Кнопка Settings
                ui.allocate_ui_with_layout(
                    egui::vec2(60.0, ui.available_height()),
                    egui::Layout::top_down(egui::Align::Center),
                    |ui| {
                        let anim_id = ui.id().with("settings_gear_btn_color");
                        let hover_t: f32 = ui.data(|d| d.get_temp(anim_id)).unwrap_or(0.0);

                        let current_color = lerp_color(Colors::WHITE, Colors::GOLD, hover_t);

                        let icon = egui::Image::new(egui::include_image!("../assets/gear_3.svg"))
                            .fit_to_exact_size(button_icon_size)
                            .tint(current_color);

                        let menu_button = egui::Button::image(icon)
                            .min_size(button_size)
                            .stroke(egui::Stroke::NONE)
                            .frame(false)
                            .rounding(button_size.y / 2.0);

                        let response = ui.add(menu_button).on_hover_cursor(egui::CursorIcon::PointingHand);

                        let target_t = if response.hovered() { 1.0 } else { 0.0 };
                        let dt = ui.input(|i| i.stable_dt);
                        let speed = 1.0 / 0.2;
                        let new_t = if hover_t < target_t {
                            (hover_t + speed * dt).min(target_t)
                        } else {
                            (hover_t - speed * dt).max(target_t)
                        };

                        ui.data_mut(|d| d.insert_temp(anim_id, new_t));

                        if new_t != target_t {
                            ui.ctx().request_repaint();
                        }

                        if response.clicked() {  
                            app.settingsbar_open = !app.settingsbar_open;
                            if app.settingsbar_open {
                                app.sidebar_open = false;                                    
                                app.logbar_open = false;
                                app.exclbar_open = false;
                            }
                        }

                        ui.add_space(2.0);
                        ui.label(RichText::new("SETTINGS").size(label_size).color(Colors::GREY));                            
                    } 
                );
            });

            // Карточка тарифа
            ui.add_space(8.0);
            render_tariff_card(app, ui);

            ui.add_space((ui.available_height() * 0.1).max(18.0));

            // Большая круглая кнопка подключения
            render_connect_button(app, ui, ctx, state);

            ui.add_space(16.0);

            // Имя текущего конфига или статус ошибки
            ui.vertical_centered(|ui| {
                if let Some(err) = &app.config_err {
                    ui.label(egui::RichText::new(err).color(egui::Color32::RED));
                } else {
                    ui.label(egui::RichText::new(&app.config_name).color(Colors::GOLD));
                }
                if lock_ignore_poison(&app.shared).client.is_none() && app.config_err.is_none() {
                    ui.label(
                        egui::RichText::new("(Выберите конфиг в настройках или добавьте новый)")
                            .size(13.0)
                            .strong()
                            .color(egui::Color32::from_gray(100))
                    );
                }
            });

            // Выпадающий список выбора ноды
            render_node_selector(app, ui, state);

            ui.add_space(20.0);
        });
}

fn lerp_color(c1: egui::Color32, c2: egui::Color32, t: f32) -> egui::Color32 {
    let r = ((c1.r() as f32) * (1.0 - t) + (c2.r() as f32) * t) as u8;
    let g = ((c1.g() as f32) * (1.0 - t) + (c2.g() as f32) * t) as u8;
    let b = ((c1.b() as f32) * (1.0 - t) + (c2.b() as f32) * t) as u8;
    egui::Color32::from_rgb(r, g, b)
}
