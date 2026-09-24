//! Нижняя панель консоли и счетчиков трафика

use eframe::egui;
use crate::{ app::ANetApp, theme::Colors };

pub fn render_bottom_console(app: &mut ANetApp, ctx: &egui::Context) {
    let panel_frame = egui::Frame::NONE.fill(Colors::CONSOLE_BG).corner_radius(egui::CornerRadius {
        nw: 0,
        ne: 0,
        sw: 14,
        se: 14,
    });

    let border_color = Colors::BORDER;
    let text_muted = egui::Color32::from_rgb(140, 145, 155);
    let text_white = egui::Color32::WHITE;

    egui::TopBottomPanel::bottom("stalker_console")
        .resizable(false)
        .min_height(170.0)
        .default_height(170.0)
        .show_separator_line(false)
        .frame(panel_frame)
        .show(ctx, |ui| {
            egui::Frame::NONE
                .fill(Colors::DARK)
                .stroke(egui::Stroke::new(1.0, border_color))
                .corner_radius(egui::CornerRadius { nw: 14, ne: 14, sw: 14, se: 14 })
                .outer_margin(egui::Margin::same(10))
                .inner_margin(egui::Margin::same(12))
                .show(ui, |ui| {
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            let text_muted = egui::Color32::GRAY;
                            ui.label(
                                egui::RichText::new(&app.status_text)
                                    .family(egui::FontFamily::Name("Inter-V".into()))
                                    .size(11.0)
                                    .color(app.status_color)
                                    .strong()
                            );

                            if let Ok(logs) = app.logs.try_lock() {
                                if let Some((text, color)) = logs.iter().rev().find_map(|line| {
                                    if line.contains("Error")
                                        || line.contains("Failed")
                                        || line.contains("Connection lost")
                                    {
                                        Some((line.clone(), Colors::RED))
                                    } else if line.contains("Tunnel UP") {
                                        Some((line.clone(), Colors::GREEN))
                                    } else if line.contains("Config loaded") || line.contains("Найдено обновление") {
                                        Some((line.clone(), Colors::GOLD))
                                    } else if line.contains("Cleaning up dead session")
                                        || line.contains("добавлен")
                                        || line.contains("удален")
                                    {
                                        Some((line.clone(), Colors::ORANGE))
                                    } else {
                                        None
                                    }
                                }) {
                                    app.status_text = text;
                                    app.status_color = color;
                                }
                            }

                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                let btn = ui.add(
                                    egui::Label::new(
                                        egui::RichText::new("VIEW LOG →")
                                            .family(egui::FontFamily::Name("Inter-V".into()))
                                            .size(11.0)
                                            .color(text_muted)
                                    )
                                    .sense(egui::Sense::click())
                                );

                                if btn.hovered() {
                                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                                }
                                if btn.clicked() {
                                    app.logbar_open = !app.logbar_open;
                                }
                            });
                        });

                        ui.add_space(6.0);
                        let (rect, _) = ui.allocate_exact_size(
                            egui::vec2(ui.available_width(), 1.0),
                            egui::Sense::hover()
                        );
                        ui.painter().line_segment(
                            [rect.left_center(), rect.right_center()],
                            egui::Stroke::new(1.0, border_color)
                        );
                        ui.add_space(6.0);

                        ui.columns(3, |cols| {
                            cols[0].vertical(|ui| {
                                ui.label(egui::RichText::new("RTT").size(10.0).color(text_muted).family(egui::FontFamily::Name("Inter-V".into())));
                                ui.add_space(2.0);
                                ui.label(egui::RichText::new(format!("{}", app.total_rtt)).size(15.0).color(text_white).strong().family(egui::FontFamily::Name("Inter-V".into())));
                            });

                            cols[1].vertical(|ui| {
                                ui.label(egui::RichText::new("↓ DOWNLOAD").size(10.0).color(text_muted).family(egui::FontFamily::Name("Inter-V".into())));
                                ui.add_space(2.0);
                                ui.label(egui::RichText::new(&app.total_rxm).size(15.0).color(text_white).strong().family(egui::FontFamily::Name("Inter-V".into())));
                            });

                            cols[2].vertical(|ui| {
                                ui.label(egui::RichText::new("↑ UPLOAD").size(10.0).color(text_muted).family(egui::FontFamily::Name("Inter-V".into())));
                                ui.add_space(2.0);
                                ui.label(egui::RichText::new(&app.total_txm).size(15.0).color(text_white).strong().family(egui::FontFamily::Name("Inter-V".into())));
                            });
                        });

                        ui.add_space(6.0);
                        let (rect, _) = ui.allocate_exact_size(
                            egui::vec2(ui.available_width(), 1.0),
                            egui::Sense::hover()
                        );
                        ui.painter().line_segment(
                            [rect.left_center(), rect.right_center()],
                            egui::Stroke::new(1.0, border_color)
                        );
                        ui.add_space(6.0);

                        ui.columns(2, |cols| {
                            cols[0].vertical(|ui| {
                                ui.label(egui::RichText::new("↓ TOTAL RX").size(10.0).color(text_muted).family(egui::FontFamily::Name("Inter-V".into())));
                                ui.add_space(2.0);
                                ui.label(egui::RichText::new(format!("{}", app.total_rx)).size(15.0).color(text_white).strong().family(egui::FontFamily::Name("Inter-V".into())));
                            });

                            cols[1].vertical(|ui| {
                                ui.label(egui::RichText::new("↑ TOTAL TX").size(10.0).color(text_muted).family(egui::FontFamily::Name("Inter-V".into())));
                                ui.add_space(2.0);
                                ui.label(egui::RichText::new(format!("{}", app.total_tx)).size(15.0).color(text_white).strong().family(egui::FontFamily::Name("Inter-V".into())));
                            });
                        });
                    });
                });
        });
}
