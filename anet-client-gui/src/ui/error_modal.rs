//! Диалоговое окно критической ошибки

use eframe::egui;
use crate::{app::ANetApp, theme::Colors};

pub fn render_error_modal(app: &mut ANetApp, ctx: &egui::Context) {
    let Some(err_msg) = app.error_modal.clone() else {
        return;
    };

    // Закрытие по нажатию клавиши Escape
    if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
        app.error_modal = None;
        return;
    }

    let screen_rect = ctx.content_rect();

    // Отступы от границ родительского окна:
    // 16 px по бокам (слева/справа) и 20 px сверху/снизу
    let margin_x = 16.0;
    let margin_y = 20.0;

    let modal_width = (screen_rect.width() - margin_x * 2.0).clamp(260.0, 360.0);
    let max_modal_height = (screen_rect.height() - margin_y * 2.0).max(200.0);

    // 1. Полупрозрачное затемнение фона (Backdrop)
    egui::Area::new(egui::Id::new("error_modal_backdrop"))
        .order(egui::Order::Foreground)
        .fixed_pos(egui::pos2(0.0, 0.0))
        .interactable(true)
        .show(ctx, |ui| {
            ui.allocate_exact_size(screen_rect.size(), egui::Sense::click());
            ui.painter().rect_filled(
                screen_rect,
                14.0, // Скругление под безрамочное окно
                egui::Color32::from_rgba_unmultiplied(10, 12, 16, 200),
            );
        });

    // 2. Основная карточка модального окна с гарантированными отступами
    egui::Window::new("ERROR_SYSTEM_WINDOW")
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .collapsible(false)
        .resizable(false)
        .title_bar(false)
        .order(egui::Order::Foreground)
        .frame(
            egui::Frame::NONE
                .fill(egui::Color32::from_rgb(24, 26, 33))
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(50, 55, 68)))
                .inner_margin(egui::Margin::symmetric(18, 18))
                .corner_radius(14.0),
        )
        .show(ctx, |ui| {
            // Ограничиваем ширину и высоту карточки, чтобы она не прилипала к краям
            ui.set_width(modal_width);
            ui.set_max_width(modal_width);
            ui.set_max_height(max_modal_height);

            ui.vertical(|ui| {
                // Шапка: Иконка в круге + Заголовок
                ui.horizontal(|ui| {
                    let badge_size = egui::vec2(34.0, 34.0);
                    let (badge_rect, _) = ui.allocate_exact_size(badge_size, egui::Sense::hover());

                    ui.painter().circle_filled(
                        badge_rect.center(),
                        17.0,
                        egui::Color32::from_rgba_unmultiplied(239, 68, 68, 35),
                    );
                    ui.painter().circle_stroke(
                        badge_rect.center(),
                        17.0,
                        egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(239, 68, 68, 90)),
                    );

                    ui.painter().text(
                        badge_rect.center(),
                        egui::Align2::CENTER_CENTER,
                        "⚠",
                        egui::FontId::new(16.0, egui::FontFamily::Proportional),
                        egui::Color32::from_rgb(248, 113, 113),
                    );

                    ui.add_space(8.0);

                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new("Сбой подключения")
                                .size(15.0)
                                .strong()
                                .color(Colors::WHITE)
                                .family(egui::FontFamily::Name("Inter-V".into())),
                        );
                        ui.label(
                            egui::RichText::new("Сетевой стек сообщил об ошибке")
                                .size(10.5)
                                .color(Colors::GREY)
                                .family(egui::FontFamily::Name("Inter-V".into())),
                        );
                    });
                });

                ui.add_space(14.0);

                // Адаптивная высота блока текста ошибки: никогда не вытолкнет окно за экран
                let scroll_max_height = (max_modal_height - 180.0).clamp(80.0, 200.0);

                // Контейнер с текстом ошибки
                egui::Frame::NONE
                    .fill(egui::Color32::from_rgb(17, 19, 25))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(38, 42, 53)))
                    .corner_radius(8.0)
                    .inner_margin(egui::Margin::symmetric(12, 10))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());

                        egui::ScrollArea::vertical()
                            .max_height(scroll_max_height)
                            .auto_shrink([false, true])
                            .show(ui, |ui| {
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(&err_msg)
                                            .size(11.5)
                                            .color(egui::Color32::from_rgb(240, 200, 200))
                                            .family(egui::FontFamily::Monospace),
                                    )
                                    .selectable(true)
                                    .wrap(),
                                );
                            });
                    });

                ui.add_space(18.0);

                // Кнопки управления: «Копировать» и «Понятно»
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 10.0;

                    let copy_btn = egui::Button::new(
                        egui::RichText::new("Скопировать")
                            .size(11.0)
                            .color(egui::Color32::from_rgb(210, 215, 225))
                            .family(egui::FontFamily::Name("Inter-V".into())),
                    )
                    .fill(egui::Color32::from_rgb(34, 38, 48))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(52, 58, 72)))
                    .min_size(egui::vec2(100.0, 32.0))
                    .corner_radius(6.0);

                    if ui.add(copy_btn).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                        ctx.copy_text(err_msg.clone());
                        app.show_toast("Текст ошибки скопирован");
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let close_btn = egui::Button::new(
                            egui::RichText::new("Ок")
                                .size(11.5)
                                .strong()
                                .color(egui::Color32::BLACK)
                                .family(egui::FontFamily::Name("Inter-V".into())),
                        )
                        .fill(Colors::GOLD)
                        .min_size(egui::vec2(110.0, 32.0))
                        .corner_radius(6.0);

                        let clicked = ui.add(close_btn).on_hover_cursor(egui::CursorIcon::PointingHand).clicked();
                        let enter_pressed = ui.input(|i| i.key_pressed(egui::Key::Enter));

                        if clicked || enter_pressed {
                            app.error_modal = None;
                        }
                    });
                });
            });
        });
}