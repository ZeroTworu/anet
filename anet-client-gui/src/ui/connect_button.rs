//! Виджет главной круглой кнопки подключения VPN с градиентами и анимацией

use eframe::egui;
use std::f32::consts::TAU;
use crate::{
    app::ANetApp,
    theme::Colors,
    types::ConnectionState,
    utils::helpers::lock_ignore_poison,
};

#[inline]
fn lerp_color(c1: egui::Color32, c2: egui::Color32, t: f32) -> egui::Color32 {
    let t = t.clamp(0.0, 1.0);
    let r = ((c1.r() as f32) * (1.0 - t) + (c2.r() as f32) * t) as u8;
    let g = ((c1.g() as f32) * (1.0 - t) + (c2.g() as f32) * t) as u8;
    let b = ((c1.b() as f32) * (1.0 - t) + (c2.b() as f32) * t) as u8;
    let a = ((c1.a() as f32) * (1.0 - t) + (c2.a() as f32) * t) as u8;
    egui::Color32::from_rgba_unmultiplied(r, g, b, a)
}

pub fn render_connect_button(
    app: &mut ANetApp,
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    state: ConnectionState,
) {
    ui.vertical_centered(|ui| {
        let btn_size = egui::vec2(184.0, 184.0);
        let (rect, response) = ui.allocate_exact_size(btn_size, egui::Sense::click());
        response.clone().on_hover_cursor(egui::CursorIcon::PointingHand);

        let center = rect.center();
        let outer_radius = btn_size.x / 2.0;
        let ring_radius = outer_radius - 3.0;
        let inner_radius = outer_radius - 8.5;
        let stroke_width = 4.5;

        let time = ctx.input(|i| i.time) as f32;

        // Градиентные пары цветов (Top -> Bottom) для каждого состояния
        let (color_top, color_bottom, btn_title, sub_label) = match state {
            ConnectionState::Disconnected => (
                egui::Color32::from_rgb(105,105,105), 
                egui::Color32::from_rgb(192,192,192),  
                "CONNECT",
                "НАЖМИТЕ ДЛЯ СТАРТА",
            ),
            ConnectionState::Connecting => {
                ctx.request_repaint(); // 60 FPS для плавной анимации
                (
                    egui::Color32::from_rgb(251, 191, 36), // Amber / Gold
                    egui::Color32::from_rgb(244, 63, 94),  // Neon Rose
                    "CONNECTING",
                    "УСТАНОВКА СВЯЗИ...",
                )
            }
            ConnectionState::Connected => (
                egui::Color32::from_rgb(16, 185, 129),  // Emerald
                egui::Color32::from_rgb(132, 204, 22),  // Lime
                "STOP",
                "ЗАЩИТА АКТИВНА",
            ),
        };

        // 1. Анимация мягкого свечения при наведении (Hover Glow)
        let hover_animation_id = response.id.with("button_hover_glow");
        let hover_t = ctx.animate_bool_with_time(hover_animation_id, response.hovered(), 0.3);

        if hover_t > 0.0 {
            for i in (1..=5).rev() {
                let r = outer_radius + (i as f32) * 2.8;
                let alpha = ((40.0 - (i as f32) * 6.0) * hover_t) as u8;
                let glow_top = egui::Color32::from_rgba_unmultiplied(color_top.r(), color_top.g(), color_top.b(), alpha);
                let glow_bot = egui::Color32::from_rgba_unmultiplied(color_bottom.r(), color_bottom.g(), color_bottom.b(), alpha);

                // Отрисовка внешнего градиентного гало
                let glow_segments = 32;
                for j in 0..glow_segments {
                    let a0 = (j as f32 / glow_segments as f32) * TAU;
                    let a1 = ((j + 1) as f32 / glow_segments as f32) * TAU;
                    let p0 = center + r * egui::vec2(a0.cos(), a0.sin());
                    let p1 = center + r * egui::vec2(a1.cos(), a1.sin());

                    let y_mid = (p0.y + p1.y) / 2.0;
                    let t = ((y_mid - center.y + r) / (r * 2.0)).clamp(0.0, 1.0);
                    let col = lerp_color(glow_top, glow_bot, t);

                    ui.painter().line_segment([p0, p1], egui::Stroke::new(2.5, col));
                }
            }
        }

        // 2. АНИМАЦИЯ CONNECTING: Пульсирующая расходящаяся градиентная волна сонара
        if state == ConnectionState::Connecting {
            let wave_progress = (time * 1.1).fract(); // 0.0 -> 1.0
            let wave_radius = ring_radius + wave_progress * 18.0;
            let wave_alpha = ((1.0 - wave_progress).powi(2) * 120.0) as u8;

            let wave_top = egui::Color32::from_rgba_unmultiplied(color_top.r(), color_top.g(), color_top.b(), wave_alpha);
            let wave_bot = egui::Color32::from_rgba_unmultiplied(color_bottom.r(), color_bottom.g(), color_bottom.b(), wave_alpha);

            let segments = 48;
            for i in 0..segments {
                let a0 = (i as f32 / segments as f32) * TAU;
                let a1 = ((i + 1) as f32 / segments as f32) * TAU;
                let p0 = center + wave_radius * egui::vec2(a0.cos(), a0.sin());
                let p1 = center + wave_radius * egui::vec2(a1.cos(), a1.sin());

                let y_mid = (p0.y + p1.y) / 2.0;
                let t = ((y_mid - center.y + wave_radius) / (wave_radius * 2.0)).clamp(0.0, 1.0);
                let col = lerp_color(wave_top, wave_bot, t);

                ui.painter().line_segment([p0, p1], egui::Stroke::new(1.8, col));
            }
        }

        // 3. Базовый фоновый трек кольца
        ui.painter().circle_stroke(
            center,
            ring_radius,
            egui::Stroke::new(stroke_width, egui::Color32::from_rgb(28, 31, 40)),
        );

        // 4. Отрисовка основного цветного градиентного кольца
        if state == ConnectionState::Connecting {
            // В режиме Connecting: приглушенный градиентный фон + вращающаяся градиентная комета
            let dim_top = egui::Color32::from_rgba_unmultiplied(color_top.r(), color_top.g(), color_top.b(), 45);
            let dim_bot = egui::Color32::from_rgba_unmultiplied(color_bottom.r(), color_bottom.g(), color_bottom.b(), 45);
            let segments = 64;

            for i in 0..segments {
                let a0 = (i as f32 / segments as f32) * TAU;
                let a1 = ((i + 1) as f32 / segments as f32) * TAU;
                let p0 = center + ring_radius * egui::vec2(a0.cos(), a0.sin());
                let p1 = center + ring_radius * egui::vec2(a1.cos(), a1.sin());

                let y_mid = (p0.y + p1.y) / 2.0;
                let t = ((y_mid - center.y + ring_radius) / (ring_radius * 2.0)).clamp(0.0, 1.0);
                let col = lerp_color(dim_top, dim_bot, t);

                ui.painter().line_segment([p0, p1], egui::Stroke::new(stroke_width, col));
            }

            // Вращающаяся комета с собственным градиентом и угасающим хвостом
            let head_angle = (time * 3.8) % TAU;
            let arc_len = TAU * 0.72; // дуга 260 градусов
            let comet_segments = 72;

            for i in 0..comet_segments {
                let t_tail = i as f32 / comet_segments as f32; // 0.0 у хвоста -> 1.0 у головы
                let a0 = head_angle - (1.0 - t_tail) * arc_len;
                let a1 = head_angle - (1.0 - (i + 1) as f32 / comet_segments as f32) * arc_len;

                let p0 = center + ring_radius * egui::vec2(a0.cos(), a0.sin());
                let p1 = center + ring_radius * egui::vec2(a1.cos(), a1.sin());

                // Градиент от color_top к color_bottom по вертикали
                let y_mid = (p0.y + p1.y) / 2.0;
                let grad_t = ((y_mid - center.y + ring_radius) / (ring_radius * 2.0)).clamp(0.0, 1.0);
                let base_col = lerp_color(color_top, color_bottom, grad_t);

                // Альфа-затухание по длине хвоста
                let alpha = (t_tail.powf(1.6) * 255.0) as u8;
                let segment_col = egui::Color32::from_rgba_unmultiplied(
                    base_col.r(),
                    base_col.g(),
                    base_col.b(),
                    alpha,
                );

                ui.painter().line_segment([p0, p1], egui::Stroke::new(stroke_width, segment_col));
            }

            // Яркий точечный маяк на голове кометы
            let head_pos = center + ring_radius * egui::vec2(head_angle.cos(), head_angle.sin());
            ui.painter().circle_filled(head_pos, 3.8, color_top);
            ui.painter().circle_filled(head_pos, 2.0, egui::Color32::WHITE);
        } else {
            // Для состояний Disconnected и Connected — полный 360° вертикальный градиент
            let segments = 128;
            for i in 0..segments {
                let a0 = (i as f32 / segments as f32) * TAU;
                let a1 = ((i + 1) as f32 / segments as f32) * TAU;

                let p0 = center + ring_radius * egui::vec2(a0.cos(), a0.sin());
                let p1 = center + ring_radius * egui::vec2(a1.cos(), a1.sin());

                let y_mid = (p0.y + p1.y) / 2.0;
                let t = ((y_mid - center.y + ring_radius) / (ring_radius * 2.0)).clamp(0.0, 1.0);
                let col = lerp_color(color_top, color_bottom, t);

                ui.painter().line_segment([p0, p1], egui::Stroke::new(stroke_width, col));
            }
        }

        // 5. Внутренний матовый диск кнопки
        let disc_fill = if response.hovered() {
            egui::Color32::from_rgb(27, 30, 40)
        } else {
            egui::Color32::from_rgb(20, 22, 29)
        };

        ui.painter().circle_filled(center, inner_radius, disc_fill);

        // Тонкая внутренняя фаска
        ui.painter().circle_stroke(
            center,
            inner_radius,
            egui::Stroke::new(1.0, egui::Color32::from_rgb(40, 44, 56)),
        );


        // 7. Главный текст кнопки (CONNECT / CONNECTING / STOP)
        let title_font = egui::FontId::new(20.0, egui::FontFamily::Name("Inter-V".into()));
        let title_pos = egui::pos2(center.x, center.y);
        ui.painter().text(
            title_pos,
            egui::Align2::CENTER_CENTER,
            btn_title,
            title_font,
            Colors::WHITE,
        );

        // 8. Нижняя статусная подпись с цветным индикатором
        let sub_font = egui::FontId::new(8.5, egui::FontFamily::Name("Inter-V".into()));
        let sub_y = center.y + 26.0;

        let sub_galley = ui.painter().layout_no_wrap(
            sub_label.to_string(),
            sub_font.clone(),
            Colors::GREY,
        );
        let sub_width = sub_galley.size().x;
        let total_badge_w = 6.0 + 4.0 + sub_width;
        let start_x = center.x - (total_badge_w / 2.0);

        // Точка индикатора (в цвет верхней части градиента)
        ui.painter().circle_filled(
            egui::pos2(start_x + 3.0, sub_y),
            2.5,
            color_top,
        );

        // Текст
        ui.painter().text(
            egui::pos2(start_x + 10.0, sub_y),
            egui::Align2::LEFT_CENTER,
            sub_label,
            sub_font,
            Colors::GREY,
        );

        // Клик по кнопке
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