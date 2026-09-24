//! Диалоговое окно критической ошибки

use eframe::egui;
use crate::{ app::ANetApp, theme::Colors };

pub fn render_error_modal(app: &mut ANetApp, ctx: &egui::Context) {
    if let Some(err_msg) = app.error_modal.clone() {
        let modal_bg = egui::Color32::from_rgb(32, 32, 32);
        egui::Window::new("ERROR_SYSTEM")
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .collapsible(false)
            .resizable(false)
            .title_bar(false)
            .frame(
                egui::Frame::NONE
                    .fill(modal_bg)
                    .stroke(egui::Stroke::new(3.0, Colors::GOLD))
                    .inner_margin(24.0)
                    .corner_radius(14.0)
            )
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("ОШИБКА").size(22.0).strong().color(Colors::GOLD));
                    ui.add_space(16.0);
                    ui.label(
                        egui::RichText::new(&err_msg)
                            .size(14.0)
                            .color(Colors::GOLD)
                            .family(egui::FontFamily::Monospace)
                    );
                    ui.add_space(24.0);
                    if ui.add(
                        egui::Button::new(egui::RichText::new("ЗАКРЫТЬ").size(16.0).strong().color(egui::Color32::BLACK))
                            .fill(Colors::GOLD)
                            .min_size(egui::vec2(120.0, 36.0))
                    ).clicked() {
                        app.error_modal = None;
                    }
                });
            });
    }
}
