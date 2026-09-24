//! Виджет карточки активного тарифа и расхода квоты

use eframe::egui;
use crate::{ app::ANetApp, theme::Colors };

pub fn render_tariff_card(app: &ANetApp, ui: &mut egui::Ui) {
    let text_muted = egui::Color32::from_rgb(140, 145, 155);
    let text_white = egui::Color32::WHITE;

    egui::Frame::NONE
        .fill(Colors::CONSOLE_BG)
        .stroke(egui::Stroke::new(1.0, Colors::BORDER))
        .corner_radius(egui::CornerRadius::same(10))
        .inner_margin(egui::Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    let (dot_rect, _) = ui.allocate_exact_size(egui::vec2(6.0, 6.0), egui::Sense::hover());
                    ui.painter().circle_filled(dot_rect.center(), 3.0, Colors::GOLD);
                    ui.add_space(4.0);

                    let billing_title = if !app.tariff_group.is_empty() && app.tariff_group != "—" {
                        format!("{} • {}", app.tariff_billing, app.tariff_group)
                    } else if !app.tariff_billing.is_empty() && app.tariff_billing != "—" {
                        app.tariff_billing.clone()
                    } else {
                        "ТАРИФ".to_string()
                    };

                    ui.label(
                        egui::RichText::new(billing_title)
                            .size(11.5)
                            .strong()
                            .color(Colors::GOLD)
                            .family(egui::FontFamily::Name("Inter-V".into()))
                    );

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let expires_text = if app.tariff_expires == "Бессрочно" || app.tariff_expires == "—" {
                            app.tariff_expires.clone()
                        } else {
                            format!("до {}", app.tariff_expires)
                        };
                        ui.label(
                            egui::RichText::new(expires_text)
                                .size(11.0)
                                .color(
                                    if app.tariff_expires == "Бессрочно" { Colors::GREEN } else { text_muted }
                                )
                                .family(egui::FontFamily::Name("Inter-V".into()))
                        );
                    });
                });

                ui.add_space(6.0);

                let (sep_rect, _) = ui.allocate_exact_size(
                    egui::vec2(ui.available_width(), 1.0),
                    egui::Sense::hover(),
                );
                ui.painter().line_segment(
                    [sep_rect.left_center(), sep_rect.right_center()],
                    egui::Stroke::new(1.0, Colors::BORDER),
                );

                ui.add_space(6.0);

                ui.columns(3, |cols| {
                    cols[0].vertical(|ui| {
                        ui.label(egui::RichText::new("ТРАФИК").size(9.0).color(text_muted).family(egui::FontFamily::Name("Inter-V".into())));
                        ui.add_space(2.0);
                        ui.label(egui::RichText::new(&app.tariff_consumed).size(12.5).strong().color(text_white).family(egui::FontFamily::Name("Inter-V".into())));
                        ui.label(egui::RichText::new(format!("/ {}", app.tariff_limit)).size(9.5).color(text_muted).family(egui::FontFamily::Name("Inter-V".into())));
                    });

                    cols[1].vertical(|ui| {
                        ui.label(egui::RichText::new("СКОРОСТЬ").size(9.0).color(text_muted).family(egui::FontFamily::Name("Inter-V".into())));
                        ui.add_space(2.0);
                        ui.label(egui::RichText::new(&app.tariff_speed).size(12.5).strong().color(text_white).family(egui::FontFamily::Name("Inter-V".into())));
                    });

                    cols[2].vertical(|ui| {
                        ui.label(egui::RichText::new("СЕССИИ").size(9.0).color(text_muted).family(egui::FontFamily::Name("Inter-V".into())));
                        ui.add_space(2.0);
                        ui.label(egui::RichText::new(&app.tariff_sessions).size(12.5).strong().color(text_white).family(egui::FontFamily::Name("Inter-V".into())));
                    });
                });

                if let Some(info) = &app.account_info {
                    if let (Some(consumed), Some(limit)) = (info.traffic_consumed_bytes, info.traffic_limit_bytes) {
                        if limit > 0 {
                            ui.add_space(6.0);
                            let progress = (consumed as f32 / limit as f32).clamp(0.0, 1.0);
                            let bar_height = 3.0;
                            let (bar_rect, _) = ui.allocate_exact_size(
                                egui::vec2(ui.available_width(), bar_height),
                                egui::Sense::hover(),
                            );
                            ui.painter().rect_filled(bar_rect, egui::CornerRadius::same(2), Colors::BORDER);
                            let filled_width = bar_rect.width() * progress;
                            if filled_width > 0.0 {
                                let filled_rect = egui::Rect::from_min_size(
                                    bar_rect.min,
                                    egui::vec2(filled_width, bar_height),
                                );
                                let bar_color = if progress > 0.9 {
                                    Colors::RED
                                } else if progress > 0.75 {
                                    Colors::ORANGE
                                } else {
                                    Colors::GOLD
                                };
                                ui.painter().rect_filled(filled_rect, egui::CornerRadius::same(2), bar_color);
                            }
                        }
                    }
                }
            });
        });
}
