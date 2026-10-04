//! Модальное окно ввода ссылки на конфигурацию (Server config URL)

use eframe::egui;
use crate::{app::ANetApp, theme::Colors};
use anet_client_core::server_config::validate_server_config_url;

pub fn render_url_modal(app: &mut ANetApp, ctx: &egui::Context) {
    if !app.show_url_modal {
        return;
    }

    let modal_bg = egui::Color32::from_rgb(26, 28, 34);
    let screen_width = ctx.screen_rect().width();
    // Адаптивная ширина с гарантированными отступами по бокам
    let modal_width = (screen_width - 48.0).clamp(280.0, 340.0);

    egui::Window::new("URL_CONFIG_INPUT")
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .collapsible(false)
        .resizable(false)
        .title_bar(false)
        .order(egui::Order::Foreground)
        .frame(
            egui::Frame::NONE
                .fill(modal_bg)
                .stroke(egui::Stroke::new(1.5, Colors::GOLD))
                .inner_margin(egui::Margin::symmetric(20, 20))
                .corner_radius(12.0)
        )
        .show(ctx, |ui| {
            ui.set_width(modal_width);
            ui.set_max_width(modal_width);

            ui.vertical(|ui| {
                ui.label(
                    egui::RichText::new("СЕРВЕРНЫЙ КОНФИГ")
                        .size(16.0)
                        .strong()
                        .color(Colors::GOLD)
                        .family(egui::FontFamily::Name("Inter-V".into()))
                );
                ui.add_space(6.0);
                ui.add(
                    egui::Label::new(
                        egui::RichText::new("Введите ссылку на файл конфигурации или выберите локальный .toml файл:")
                            .size(11.0)
                            .color(Colors::GREY)
                            .family(egui::FontFamily::Name("Inter-V".into()))
                    )
                    .wrap()
                );
                ui.add_space(14.0);

                let input_response = ui.add(
                    egui::TextEdit::singleline(&mut app.url_input_buffer)
                        .hint_text("example.com/config или https://...")
                        .desired_width(ui.available_width())
                        .font(egui::FontId::new(12.0, egui::FontFamily::Monospace))
                );

                if let Some(err) = &app.url_modal_error {
                    ui.add_space(6.0);
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(err)
                                .size(11.0)
                                .color(Colors::RED)
                        )
                        .wrap()
                    );
                }

                ui.add_space(16.0);

                ui.horizontal(|ui| {
                    let btn_file = egui::Button::new(
                        egui::RichText::new("📂 КОНФИГ")
                            .size(11.0)
                            .strong()
                            .color(Colors::GOLD)
                    )
                    .fill(egui::Color32::from_rgb(34, 38, 48))
                    .min_size(egui::vec2(84.0, 32.0))
                    .corner_radius(6.0);

                    if ui.add(btn_file).on_hover_text("Загрузить локальный .toml конфиг из файла").clicked() {
                        app.show_url_modal = false;
                        app.url_modal_error = None;
                        app.open_file_dialog();
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let btn_ok = egui::Button::new(
                            egui::RichText::new("СКАЧАТЬ")
                                .size(11.5)
                                .strong()
                                .color(egui::Color32::BLACK)
                        )
                        .fill(Colors::GOLD)
                        .min_size(egui::vec2(96.0, 32.0))
                        .corner_radius(6.0);

                        let enter_pressed = input_response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        if ui.add(btn_ok).clicked() || enter_pressed {
                            let raw_url = app.url_input_buffer.trim();
                            match validate_server_config_url(raw_url) {
                                Ok(normalized_url) => {
                                    app.url_modal_error = None;
                                    app.download_and_set_config_url(normalized_url);
                                }
                                Err(err_msg) => {
                                    app.url_modal_error = Some(err_msg.to_string());
                                }
                            }
                        }
                    });
                });
            });
        });
}