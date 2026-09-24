//! Виджет главной круглой кнопки подключения VPN

use eframe::egui;
use crate::{ app::ANetApp, theme::Colors, types::ConnectionState, utils::helpers::lock_ignore_poison };

pub fn render_connect_button(
    app: &mut ANetApp,
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    state: ConnectionState,
) {
    ui.vertical_centered(|ui| {
        let btn_size = egui::vec2(180.0, 180.0);

        let (btn_text, color_top, color_bottom) = match state {
            ConnectionState::Disconnected => (
                "CONNECT",
                egui::Color32::from_rgb(16, 185, 129),
                egui::Color32::from_rgb(132, 204, 22),
            ),
            ConnectionState::Connecting => {
                let time = ctx.input(|i| i.time);
                let factor = (time.sin() + 1.0) / 2.0;
                ctx.request_repaint();

                let g = (140.0 + (80.0 - 140.0) * factor) as u8;
                (
                    "CONNECTING",
                    egui::Color32::from_rgb(247, g, 46),
                    egui::Color32::from_rgb(244, 46, 82),
                )
            }
            ConnectionState::Connected => (
                "STOP",
                egui::Color32::from_rgb(255, 43, 68),
                egui::Color32::from_rgb(131, 140, 251),
            ),
        };

        let (rect, response) = ui.allocate_exact_size(btn_size, egui::Sense::click());
        response.clone().on_hover_cursor(egui::CursorIcon::PointingHand);
        let center = rect.center();
        let radius = btn_size.x / 2.0;

        // Эффект мягкого свечения при наведении
        let hover_animation_id = response.id.with("hover_glow");
        let hover_t = ui.ctx().animate_bool_with_time(hover_animation_id, response.hovered(), 0.5);

        if hover_t > 0.0 {
            for glow_i in (1..=6).rev() {
                let glow_radius = radius + (glow_i as f32) * 2.5;
                let alpha = ((55.0 - (glow_i as f32) * 3.0) * hover_t) as u8;

                if alpha > 0 {
                    ui.painter().circle_stroke(
                        center,
                        glow_radius,
                        egui::Stroke::new(
                            2.5,
                            egui::Color32::from_rgba_unmultiplied(
                                color_top.r(),
                                color_top.g(),
                                color_top.b(),
                                alpha,
                            ),
                        ),
                    );
                }
            }
        }

        // Отрисовка цветного градиентного кольца
        let stroke_width = 5.0;
        let segments = 128;

        for i in 0..segments {
            let a0 = ((i as f32) / (segments as f32)) * std::f32::consts::TAU;
            let a1 = (((i + 1) as f32) / (segments as f32)) * std::f32::consts::TAU;

            let p0 = center + radius * egui::vec2(a0.cos(), a0.sin());
            let p1 = center + radius * egui::vec2(a1.cos(), a1.sin());

            let y_mid = (p0.y + p1.y) / 2.0;
            let t = ((y_mid - center.y + radius) / (radius * 2.0)).clamp(0.0, 1.0);

            let r_col = ((color_top.r() as f32) * (1.0 - t) + (color_bottom.r() as f32) * t) as u8;
            let g_col = ((color_top.g() as f32) * (1.0 - t) + (color_bottom.g() as f32) * t) as u8;
            let b_col = ((color_top.b() as f32) * (1.0 - t) + (color_bottom.b() as f32) * t) as u8;

            ui.painter().line_segment(
                [p0, p1],
                egui::Stroke::new(stroke_width, egui::Color32::from_rgb(r_col, g_col, b_col)),
            );
        }

        // Главный текст кнопки
        let btn_galley = ui.painter().layout_no_wrap(
            btn_text.to_string(),
            egui::FontId::proportional(24.0),
            egui::Color32::WHITE,
        );

        let (status_text, status_color, status_icon_type) = match state {
            ConnectionState::Connected => ("CONNECTED", Colors::GREY, 0),
            ConnectionState::Disconnected => ("DISCONNECTED", Colors::GREY, 1),
            ConnectionState::Connecting => ("CONNECTING", Colors::GREY, 2),
        };

        let status_galley = egui::WidgetText::from(
            egui::RichText::new(status_text)
                .size(9.0)
                .strong()
                .color(status_color),
        )
        .into_galley(ui, Some(egui::TextWrapMode::Extend), f32::INFINITY, egui::FontSelection::Default);

        let btn_text_size = btn_galley.size();
        let status_size = status_galley.size();

        let icon_size = egui::vec2(8.0, 8.0);
        let icon_spacing = 3.0;
        let space_below = 3.0;

        let status_total_width = icon_size.x + icon_spacing + status_size.x;
        let status_height = icon_size.y.max(status_size.y);

        let btn_text_pos = egui::pos2(
            center.x - btn_text_size.x / 2.0,
            center.y - btn_text_size.y / 2.0,
        );
        ui.painter().galley(btn_text_pos, btn_galley, egui::Color32::WHITE);

        let status_center_y = center.y + btn_text_size.y / 2.0 + space_below + status_height / 2.0;
        let status_start_x = center.x - status_total_width / 2.0;

        let i_rect = egui::Rect::from_min_size(
            egui::pos2(status_start_x, status_center_y - icon_size.y / 2.0),
            icon_size,
        );

        // Иконка индикатора статуса
        let ind_color = match status_icon_type {
            0 => egui::Color32::from_rgb(76, 175, 80),
            1 => Colors::GREY,
            _ => Colors::ORANGE,
        };

        ui.painter().circle_filled(i_rect.center(), 3.5, ind_color);

        let status_text_pos = egui::pos2(
            status_start_x + icon_size.x + icon_spacing,
            status_center_y - status_size.y / 2.0,
        );
        ui.painter().galley(status_text_pos, status_galley, status_color);

        if response.clicked() {
            match state {
                ConnectionState::Disconnected => {
                    if lock_ignore_poison(&app.shared).client.is_none() {
                        app.open_file_dialog();
                    } else {
                        app.start_vpn();
                    }
                }
                _ => {
                    app.stop_vpn();
                }
            }
        }
    });
}
