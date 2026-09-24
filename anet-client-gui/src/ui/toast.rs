//! Всплывающие информационные тосты

use eframe::egui;
use crate::app::ANetApp;

pub fn render_toast(app: &mut ANetApp, ctx: &egui::Context) {
    if let (Some(message), Some(until)) = (&app.toast_message, app.toast_until) {
        let now = std::time::Instant::now();
        if now < until {
            egui::Area::new(egui::Id::new("toast_notification"))
                .anchor(egui::Align2::CENTER_BOTTOM, egui::vec2(0.0, -30.0))
                .order(egui::Order::Foreground)
                .show(ctx, |ui| {
                    egui::Frame::NONE
                        .fill(egui::Color32::from_rgb(35, 37, 44))
                        .corner_radius(8.0)
                        .inner_margin(egui::Margin::symmetric(16, 10))
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(60, 63, 72)))
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new(message).size(11.0).color(egui::Color32::WHITE));
                        });
                });
            ctx.request_repaint_after(until.duration_since(now));
        } else {
            app.toast_message = None;
            app.toast_until = None;
        }
    }
}
