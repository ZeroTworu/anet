//! Модальное окно обновления приложения

use eframe::egui;
use egui::scroll_area::ScrollBarVisibility;
use anet_client_core::updater::Updater;
use crate::{ app::ANetApp, theme::Colors, types::UpdateStatus, utils::helpers::push_log };

pub fn render_update_modal(app: &mut ANetApp, ctx: &egui::Context) {
    let (show_upd, release_data, progress) = match &app.update_status {
        UpdateStatus::Available(r) => (true, Some(r.clone()), None),
        UpdateStatus::Downloading(p) => (true, None, Some(*p)),
        _ => (false, None, None),
    };

    if !show_upd {
        return;
    }

    let modal_bg = egui::Color32::from_rgb(32, 32, 32);

    egui::Window::new("UPDATE_SYSTEM")
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .collapsible(false)
        .resizable(false)
        .title_bar(false)
        .order(egui::Order::Foreground)
        .frame(
            egui::Frame::NONE
                .fill(modal_bg)
                .stroke(egui::Stroke::new(3.0, Colors::GOLD))
                .inner_margin(24.0)
                .corner_radius(4.0)
        )
        .show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.label(
                    egui::RichText::new("SYSTEM UPDATE")
                        .size(22.0)
                        .strong()
                        .color(Colors::GOLD)
                );

                if let Some(rel) = release_data {
                    ui.label(
                        egui::RichText::new(format!("Доступна версия: {}", rel.tag_name))
                            .size(16.0)
                            .color(Colors::GOLD)
                    );
                    ui.add_space(16.0);
                    ui.label(
                        egui::RichText::new("Список изменений:")
                            .size(14.0)
                            .color(Colors::GOLD)
                            .strong()
                    );
                    ui.add_space(4.0);

                    egui::ScrollArea::vertical()
                        .max_height(180.0)
                        .auto_shrink([false, true])
                        .scroll_bar_visibility(ScrollBarVisibility::AlwaysVisible)
                        .show(ui, |ui| {
                            let changelog = rel.body.as_deref().unwrap_or("Описание изменений отсутствует.");
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(changelog)
                                        .size(13.0)
                                        .color(Colors::GOLD)
                                        .family(egui::FontFamily::Monospace)
                                )
                                .wrap()
                            );
                        });
                    ui.add_space(24.0);
                    ui.horizontal(|ui| {
                        ui.add_space(ui.available_width() / 6.0);

                        let btn_update = egui::Button::new(
                            egui::RichText::new("ОБНОВИТЬ")
                                .size(16.0)
                                .strong()
                                .color(egui::Color32::BLACK)
                        )
                        .fill(Colors::GOLD)
                        .min_size(egui::vec2(120.0, 36.0));

                        if ui.add(btn_update).clicked() {
                            let r_clone = rel.clone();
                            push_log(&app.logs, &format!("> Обновляемся на {}", rel.tag_name));
                            app.update_status = UpdateStatus::Downloading(0.0);
                            app.rt.spawn(async move {
                                if let Err(e) = Updater::download_and_apply(r_clone).await {
                                    anet_client_core::events::err(format!("Ошибка загрузки: {}", e));
                                }
                            });
                        }

                        ui.add_space(20.0);

                        let btn_cancel = egui::Button::new(
                            egui::RichText::new("ПОЗДНЕЕ")
                                .size(16.0)
                                .strong()
                                .color(egui::Color32::BLACK)
                        )
                        .fill(Colors::GOLD)
                        .min_size(egui::vec2(120.0, 36.0));

                        if ui.add(btn_cancel).clicked() {
                            app.update_status = UpdateStatus::Idle;
                        }
                    });
                } else if let Some(p) = progress {
                    ui.add_space(20.0);
                    ui.label(
                        egui::RichText::new("СКАЧИВАНИЕ НОВЫХ БИНАРНИКОВ...")
                            .color(Colors::GOLD)
                            .strong()
                    );
                    ui.add_space(12.0);

                    ui.add(
                        egui::ProgressBar::new(p)
                            .text(format!("{:.1}%", p * 100.0))
                            .desired_width(260.0)
                            .fill(Colors::GOLD)
                    );

                    ui.add_space(20.0);
                    ui.label(
                        egui::RichText::new("Пожалуйста, не закрывайте приложение")
                            .size(11.0)
                            .italics()
                            .color(Colors::GOLD)
                    );
                }
            });
        });
}
