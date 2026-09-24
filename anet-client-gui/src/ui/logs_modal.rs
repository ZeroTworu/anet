//! Модальное окно просмотра системного журнала и сохранения в файл

use eframe::egui;
use egui::Stroke;
use crate::{ app::ANetApp, theme::Colors, utils::helpers::lock_ignore_poison };

pub fn render_logs_modal(app: &mut ANetApp, ctx: &egui::Context) {
    if !app.logbar_open {
        return;
    }

    let margin = 20.0;
    let button_size = egui::vec2(32.0, 32.0);

    egui::Area::new(egui::Id::new("config_logbar"))
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
                        app.logbar_open = false;
                    }

                    ui.horizontal(|ui| {
                        let circle_button = egui::Button::new("⏴")
                            .min_size(button_size)
                            .stroke(Stroke::NONE)
                            .rounding(button_size.y / 2.0);

                        let response = ui.add(circle_button).on_hover_cursor(egui::CursorIcon::PointingHand);
                        if response.clicked() {
                            app.logbar_open = false;
                        }

                        ui.heading("Log");

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let btn = ui.add(
                                egui::Button::new(
                                    egui::RichText::new("СОХРАНИТЬ В ФАЙЛ")
                                        .size(11.0)
                                        .strong()
                                        .color(Colors::GOLD)
                                        .family(egui::FontFamily::Name("Inter-V".into()))
                                )
                                .min_size(egui::vec2(170.0, 28.0))
                                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(60, 63, 72)))
                            );

                            if btn.hovered() {
                                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                            }
                            if btn.clicked() {
                                app.save_logs_to_file();
                            }
                        });
                    });
                    ui.separator();

                    egui::Frame::NONE.show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .stick_to_bottom(true)
                            .show(ui, |ui| {
                                let logs = lock_ignore_poison(&app.logs);

                                for line in logs.iter() {
                                    let mut color = Colors::GREY;

                                    if line.contains("Error")
                                        || line.contains("Failed")
                                        || line.contains("Connection lost")
                                    {
                                        color = Colors::RED;
                                    } else if line.contains("Tunnel UP") {
                                        color = Colors::GREEN;
                                    } else if line.contains("Config loaded") {
                                        color = Colors::GOLD;
                                    } else if line.contains("Cleaning up dead session") {
                                        color = Colors::ORANGE;
                                    }

                                    ui.horizontal(|ui| {
                                        ui.add(
                                            egui::Label::new(
                                                egui::RichText::new(line)
                                                    .family(egui::FontFamily::Monospace)
                                                    .size(11.0)
                                                    .color(color)
                                            )
                                            .selectable(true)
                                            .wrap()
                                        );
                                    });
                                }
                            });
                    });
                });
        });
}
