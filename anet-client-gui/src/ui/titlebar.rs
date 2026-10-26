//! Кастомный заголовок окна (Titlebar)

use eframe::egui;
use egui::text::{ LayoutJob, TextFormat };
use crate::{ app::ANetApp, theme::Colors, tray::TrayCommand, GIT_TAG, COMMIT_HASH };

pub fn render_titlebar(app: &mut ANetApp, ctx: &egui::Context) {
    let titlebar_button = egui::vec2(42.0, 38.0);

    egui::TopBottomPanel::top("custom_titlebar")
        .frame(egui::Frame::NONE)
        .exact_height(38.0)
        .show(ctx, |ui| {
            let mut rect = ui.max_rect();
            rect.min.x = ctx.content_rect().min.x;
            rect.max.x = ctx.content_rect().max.x;
            rect.max.y = rect.min.y + 38.0;

            ui.painter().rect_filled(
                rect,
                egui::CornerRadius { nw: 14, ne: 14, sw: 0, se: 0 },
                Colors::TITLE_BG
            );

            // Исключаем область кнопок свернуть/закрыть справа (84px) из зоны перетаскивания.
            // ВАЖНО для Wayland / KDE (KWin): нельзя использовать `Sense::click_and_drag()` для
            // системного перетаскивания окна (`ViewportCommand::StartDrag` -> `xdg_toplevel::move`),
            // так как композитор забирает фокус указателя себе и НЕ возвращает событие отпускания ЛКМ
            // обратно в winit/egui. Из-за этого egui навечно остаётся в состоянии `dragged_id = Some(...)`
            // (с курсором руки `CursorIcon::Grabbing`) и при каждом возврате курсора в окно снова шлёт StartDrag.
            let mut drag_rect = rect;
            drag_rect.max.x = (rect.max.x - 84.0).max(rect.min.x);
            let drag_armed_id = ui.id().with("title_bar_drag_armed");
            let mut drag_armed = ctx.data_mut(|d| d.get_temp::<bool>(drag_armed_id).unwrap_or(false));

            let should_start_drag = ctx.input(|i| {
                if !i.pointer.primary_down() || i.pointer.button_released(egui::PointerButton::Primary) {
                    drag_armed = false;
                }
                if i.pointer.button_pressed(egui::PointerButton::Primary) {
                    if let Some(pos) = i.pointer.interact_pos().or_else(|| i.pointer.hover_pos()) {
                        if drag_rect.contains(pos) {
                            drag_armed = true;
                        }
                    }
                }
                if drag_armed && i.pointer.primary_down() && i.pointer.delta() != egui::Vec2::ZERO {
                    drag_armed = false;
                    true
                } else {
                    false
                }
            });

            ctx.data_mut(|d| d.insert_temp(drag_armed_id, drag_armed));

            if should_start_drag {
                ctx.stop_dragging();
                ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
            }

            ui.scope_builder(egui::UiBuilder::new().max_rect(rect), |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
                    let available_height = 38.0;

                    let left_width = ui.available_width() - 80.0;
                    let left_rect = egui::Rect::from_min_size(
                        rect.min + egui::vec2(6.0, 0.0),
                        egui::vec2(left_width, available_height)
                    );

                    ui.scope_builder(egui::UiBuilder::new().max_rect(left_rect), |ui| {
                        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                            ui.set_min_height(available_height);
                            ui.add_space(8.0);
                            ui.ctx().style_mut(|style| {
                                style.interaction.selectable_labels = false;
                            });

                            let indicator_color = egui::Color32::from_rgb(76, 175, 80);
                            let (dot_rect, _) = ui.allocate_exact_size(
                                egui::vec2(8.0, 8.0),
                                egui::Sense::hover()
                            );
                            ui.painter().circle_filled(dot_rect.center(), 4.0, indicator_color);

                            ui.add_space(8.0);

                            let mut job = LayoutJob::default();
                            let font_id = egui::FontId::new(
                                12.0,
                                egui::FontFamily::Name("Inter-V".into())
                            );

                            job.append("ANet VPN ", 0.0, TextFormat {
                                font_id: font_id.clone(),
                                color: Colors::WHITE,
                                ..Default::default()
                            });

                            let version_str = format!("{} ({})", GIT_TAG, COMMIT_HASH);
                            job.append(&version_str, 0.0, TextFormat {
                                font_id,
                                color: Colors::GREY,
                                ..Default::default()
                            });

                            ui.add(egui::Label::new(job));
                        });
                    });

                    let right_rect = egui::Rect::from_min_size(
                        rect.right_top() - egui::vec2(80.0, 0.0),
                        egui::vec2(80.0, available_height)
                    );

                   ui.scope_builder(egui::UiBuilder::new().max_rect(right_rect), |ui| {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.set_min_height(available_height);
                            ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);

                            let size = titlebar_button;

                            let (close_rect, close_response) = ui.allocate_exact_size(
                                size,
                                egui::Sense::click()
                            );

                            if close_response.hovered() {
                                ui.painter().rect_filled(
                                    close_rect,
                                    egui::CornerRadius { nw: 0, ne: 14, sw: 0, se: 0 },
                                    egui::Color32::from_rgb(205, 39, 39)
                                );
                            }

                            let close_img = egui::Image::new(egui::include_image!("../assets/close.svg"))
                                .fit_to_exact_size(egui::vec2(14.0, 14.0));
                            let close_img_rect = egui::Rect::from_center_size(
                                close_rect.center(),
                                egui::vec2(14.0, 14.0)
                            );
                            close_img.paint_at(ui, close_img_rect);

                            if close_response.clicked() {
                                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                            }

                            let (min_rect, min_response) = ui.allocate_exact_size(
                                size,
                                egui::Sense::click()
                            );

                            if min_response.hovered() {
                                ui.painter().rect_filled(
                                    min_rect,
                                    0.0,
                                    egui::Color32::from_rgb(98, 98, 98)
                                );
                            }

                            let minimize_img = egui::Image::new(egui::include_image!("../assets/minimize.svg"))
                                .fit_to_exact_size(egui::vec2(14.0, 14.0));
                            let min_img_rect = egui::Rect::from_center_size(
                                min_rect.center(),
                                egui::vec2(14.0, 14.0)
                            );
                            minimize_img.paint_at(ui, min_img_rect);

                            if min_response.clicked() {
                                if app.tray_value {
                                    app.is_in_tray = true;
                                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                                    let _ = app.tray_cmd_tx.send(TrayCommand::WindowVisible(false));
                                    let _ = app.tray_cmd_tx.send(TrayCommand::NotifyHidden);
                                } else {
                                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                                }
                            }
                        });
                    });
                });
            });

            let painter = ui.painter();
            painter.line_segment(
                [rect.left_bottom(), rect.right_bottom()],
                egui::Stroke::new(1.0, ui.style().visuals.window_stroke.color)
            );
        });
}
