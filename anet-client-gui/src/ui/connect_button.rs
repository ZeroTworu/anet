//! Виджет главной круглой кнопки подключения VPN с градиентами, радиальными мешами и анимацией

use eframe::egui;
use std::f32::consts::{PI, TAU};
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

#[inline]
fn with_alpha(c: egui::Color32, alpha: u8) -> egui::Color32 {
    egui::Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), alpha)
}

/// Мягкий радиальный ореол (свечение) за пределами кольца с плавным затуханием в прозрачность
fn draw_outer_aura_mesh(
    painter: &egui::Painter,
    center: egui::Pos2,
    inner_r: f32,
    outer_r: f32,
    color_top: egui::Color32,
    color_bot: egui::Color32,
    max_alpha: f32,
) {
    if max_alpha <= 0.5 || outer_r <= inner_r {
        return;
    }
    let segments = 64usize;
    let mid_r = inner_r + (outer_r - inner_r) * 0.42;
    let mut mesh = egui::Mesh::default();

    for i in 0..=segments {
        let angle = (i as f32 / segments as f32) * TAU;
        let dir = egui::vec2(angle.cos(), angle.sin());
        let grad_t = ((dir.y + 1.0) * 0.5).clamp(0.0, 1.0);
        let base_col = lerp_color(color_top, color_bot, grad_t);

        let p_in = center + dir * inner_r;
        let p_mid = center + dir * mid_r;
        let p_out = center + dir * outer_r;

        mesh.colored_vertex(p_in, with_alpha(base_col, max_alpha.clamp(0.0, 255.0) as u8));
        mesh.colored_vertex(p_mid, with_alpha(base_col, (max_alpha * 0.38).clamp(0.0, 255.0) as u8));
        mesh.colored_vertex(p_out, with_alpha(base_col, 0));

        if i > 0 {
            let prev = ((i - 1) * 3) as u32;
            let curr = (i * 3) as u32;

            mesh.add_triangle(prev, prev + 1, curr);
            mesh.add_triangle(prev + 1, curr + 1, curr);

            mesh.add_triangle(prev + 1, prev + 2, curr + 1);
            mesh.add_triangle(prev + 2, curr + 2, curr + 1);
        }
    }

    painter.add(egui::Shape::mesh(mesh));
}

/// Внутренний стеклянно-металлический диск кнопки с плавным радиальным градиентом
fn draw_radial_disc_mesh(
    painter: &egui::Painter,
    center: egui::Pos2,
    radius: f32,
    center_col: egui::Color32,
    mid_col: egui::Color32,
    edge_col: egui::Color32,
) {
    let segments = 72usize;
    let mid_r = radius * 0.62;
    let mut mesh = egui::Mesh::default();

    mesh.colored_vertex(center, center_col);

    for i in 0..=segments {
        let angle = (i as f32 / segments as f32) * TAU;
        let dir = egui::vec2(angle.cos(), angle.sin());

        let p_mid = center + dir * mid_r;
        let p_edge = center + dir * radius;

        mesh.colored_vertex(p_mid, mid_col);
        mesh.colored_vertex(p_edge, edge_col);

        if i > 0 {
            let prev = 1 + ((i - 1) * 2) as u32;
            let curr = 1 + (i * 2) as u32;

            mesh.add_triangle(0, prev, curr);
            mesh.add_triangle(prev, prev + 1, curr);
            mesh.add_triangle(prev + 1, curr + 1, curr);
        }
    }

    painter.add(egui::Shape::mesh(mesh));
}

/// Тонкий верхний блик (rim light) для эффекта объёмного стекла
fn draw_top_specular_arc(
    painter: &egui::Painter,
    center: egui::Pos2,
    radius: f32,
    color: egui::Color32,
    max_alpha: f32,
) {
    let steps = 32usize;
    let start_angle = -PI * 0.82;
    let end_angle = -PI * 0.18;

    for i in 0..steps {
        let t0 = i as f32 / steps as f32;
        let t1 = (i + 1) as f32 / steps as f32;
        let a0 = start_angle + (end_angle - start_angle) * t0;
        let a1 = start_angle + (end_angle - start_angle) * t1;

        let env = ((t0 + t1) * 0.5 * PI).sin().powf(1.4);
        let alpha = (max_alpha * env).clamp(0.0, 255.0) as u8;
        if alpha == 0 {
            continue;
        }

        let p0 = center + radius * egui::vec2(a0.cos(), a0.sin());
        let p1 = center + radius * egui::vec2(a1.cos(), a1.sin());
        painter.line_segment([p0, p1], egui::Stroke::new(1.4, with_alpha(color, alpha)));
    }
}

/// Иконка питания (для состояния Disconnected)
fn draw_power_icon(painter: &egui::Painter, center: egui::Pos2, color: egui::Color32) {
    let r = 6.2;
    let segments = 20usize;
    let gap = 0.55; // Верхний зазор для вертикальной линии
    let start_a = -PI * 0.5 + gap;
    let end_a = -PI * 0.5 + TAU - gap;

    for i in 0..segments {
        let t0 = i as f32 / segments as f32;
        let t1 = (i + 1) as f32 / segments as f32;
        let a0 = start_a + (end_a - start_a) * t0;
        let a1 = start_a + (end_a - start_a) * t1;
        let p0 = center + r * egui::vec2(a0.cos(), a0.sin());
        let p1 = center + r * egui::vec2(a1.cos(), a1.sin());
        painter.line_segment([p0, p1], egui::Stroke::new(1.7, color));
    }

    painter.line_segment(
        [
            egui::pos2(center.x, center.y - r - 1.2),
            egui::pos2(center.x, center.y - 0.5),
        ],
        egui::Stroke::new(1.8, color),
    );
}

/// Иконка защитного щита с галочкой (для состояния Connected)
fn draw_shield_check_icon(painter: &egui::Painter, center: egui::Pos2, color: egui::Color32) {
    let w = 6.2;
    let top = center.y - 6.8;
    let mid_y = center.y + 0.6;
    let bot = center.y + 7.2;

    let pts = vec![
        egui::pos2(center.x, top),
        egui::pos2(center.x + w, top + 2.2),
        egui::pos2(center.x + w - 0.8, mid_y),
        egui::pos2(center.x, bot),
        egui::pos2(center.x - w + 0.8, mid_y),
        egui::pos2(center.x - w, top + 2.2),
    ];

    painter.add(egui::Shape::convex_polygon(
        pts,
        with_alpha(color, 34),
        egui::Stroke::new(1.4, color),
    ));

    painter.line_segment(
        [
            egui::pos2(center.x - 2.6, center.y + 0.3),
            egui::pos2(center.x - 0.6, center.y + 2.4),
        ],
        egui::Stroke::new(1.6, color),
    );
    painter.line_segment(
        [
            egui::pos2(center.x - 0.6, center.y + 2.4),
            egui::pos2(center.x + 3.0, center.y - 1.9),
        ],
        egui::Stroke::new(1.6, color),
    );
}

pub fn render_connect_button(
    app: &mut ANetApp,
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    state: ConnectionState,
) {
    ui.vertical_centered(|ui| {
        let btn_size = egui::vec2(144.0, 144.0);
        let (rect, response) = ui.allocate_exact_size(btn_size, egui::Sense::click());
        if state != ConnectionState::Stopping {
            response.clone().on_hover_cursor(egui::CursorIcon::PointingHand);
        }

        let center = rect.center();
        let outer_radius = btn_size.x / 2.0;
        let ring_radius = outer_radius - 3.0;
        let inner_radius = outer_radius - 8.5;
        let stroke_width = 4.5;

        let time = ctx.input(|i| i.time) as f32;

        // Плавная анимация наведения и тактильного нажатия
        let hover_animation_id = response.id.with("button_hover_glow");
        let hover_t = ctx.animate_bool_with_time(
            hover_animation_id,
            response.hovered() && state != ConnectionState::Stopping,
            0.25,
        );

        let press_animation_id = response.id.with("button_press_depth");
        let press_t = ctx.animate_bool_with_time(
            press_animation_id,
            response.is_pointer_button_down_on() && state != ConnectionState::Stopping,
            0.1,
        );

        let breath = 0.5 + 0.5 * (time * 1.85).sin();

        // Палитры и метаданные для каждого состояния
        let (color_top, color_bottom, btn_title, sub_label) = match state {
            ConnectionState::Disconnected => {
                // Титаново-обсидиановый стиль в покое -> благородное золото при наведении
                let top = lerp_color(
                    egui::Color32::from_rgb(168, 178, 198),
                    Colors::GOLD,
                    hover_t,
                );
                let bot = lerp_color(
                    egui::Color32::from_rgb(78, 86, 104),
                    egui::Color32::from_rgb(205, 134, 52),
                    hover_t,
                );
                (top, bot, "CONNECT", "НАЖМИТЕ ДЛЯ СТАРТА")
            }
            ConnectionState::Connecting => {
                ctx.request_repaint(); // 60 FPS для плавной анимации кометы
                (
                    egui::Color32::from_rgb(251, 191, 36), // Amber / Gold
                    egui::Color32::from_rgb(244, 63, 94),  // Neon Rose
                    "CONNECTING",
                    "УСТАНОВКА СВЯЗИ...",
                )
            }
            ConnectionState::Connected => {
                ctx.request_repaint_after(std::time::Duration::from_millis(33));
                (
                    egui::Color32::from_rgb(56, 201, 118), // Primary Emerald Green
                    egui::Color32::from_rgb(32, 150, 86),  // Deep Emerald
                    "STOP",
                    "ЗАЩИТА АКТИВНА",
                )
            }
            ConnectionState::Stopping => {
                ctx.request_repaint();
                (
                    egui::Color32::from_rgb(251, 191, 36),
                    egui::Color32::from_rgb(244, 63, 94),
                    "STOPPING",
                    "ОСТАНОВКА...",
                )
            }
        };

        // 1. Внешний объёмный ореол (Ambient Aura Mesh)
        let aura_alpha = match state {
            ConnectionState::Disconnected => 12.0 + hover_t * 48.0,
            ConnectionState::Connected => 30.0 + breath * 18.0 + hover_t * 28.0,
            ConnectionState::Connecting | ConnectionState::Stopping => 16.0 + hover_t * 36.0,
        };
        let aura_outer_r = match state {
            ConnectionState::Connected => outer_radius + 14.0 + breath * 3.5 + hover_t * 4.0,
            _ => outer_radius + 10.0 + hover_t * 8.0,
        };
        draw_outer_aura_mesh(
            ui.painter(),
            center,
            ring_radius + 1.0,
            aura_outer_r,
            color_top,
            color_bottom,
            aura_alpha,
        );

        // 2. Анимация волны сонара в режимах Connecting / Stopping
        if matches!(state, ConnectionState::Connecting | ConnectionState::Stopping) {
            let wave_progress = (time * 1.1).fract(); // 0.0 -> 1.0
            let wave_radius = ring_radius + wave_progress * 18.0;
            let wave_alpha = ((1.0 - wave_progress).powi(2) * 120.0) as u8;

            let wave_top = with_alpha(color_top, wave_alpha);
            let wave_bot = with_alpha(color_bottom, wave_alpha);

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
            egui::Stroke::new(stroke_width + 1.0, egui::Color32::from_rgb(18, 20, 27)),
        );

        // 4. Отрисовка основного цветового градиентного кольца
        if matches!(state, ConnectionState::Connecting | ConnectionState::Stopping) {
            // В режиме Connecting / Stopping: приглушённый градиентный фон + вращающаяся комета
            let dim_top = with_alpha(color_top, 45);
            let dim_bot = with_alpha(color_bottom, 45);
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

            let head_angle = (time * 3.8) % TAU;
            let arc_len = TAU * 0.72;
            let comet_segments = 72;

            for i in 0..comet_segments {
                let t_tail = i as f32 / comet_segments as f32;
                let a0 = head_angle - (1.0 - t_tail) * arc_len;
                let a1 = head_angle - (1.0 - (i + 1) as f32 / comet_segments as f32) * arc_len;

                let p0 = center + ring_radius * egui::vec2(a0.cos(), a0.sin());
                let p1 = center + ring_radius * egui::vec2(a1.cos(), a1.sin());

                let y_mid = (p0.y + p1.y) / 2.0;
                let grad_t = ((y_mid - center.y + ring_radius) / (ring_radius * 2.0)).clamp(0.0, 1.0);
                let base_col = lerp_color(color_top, color_bottom, grad_t);

                let alpha = (t_tail.powf(1.6) * 255.0) as u8;
                let segment_col = with_alpha(base_col, alpha);

                ui.painter().line_segment([p0, p1], egui::Stroke::new(stroke_width, segment_col));
            }

            let head_pos = center + ring_radius * egui::vec2(head_angle.cos(), head_angle.sin());
            ui.painter().circle_filled(head_pos, 3.8, color_top);
            ui.painter().circle_filled(head_pos, 2.0, egui::Color32::WHITE);
        } else {
            // Для Disconnected и Connected: многослойное 360° градиентное кольцо с живым переливом
            let segments = 128;
            let phase_a = time * 0.85;
            let phase_b = phase_a + PI;

            for i in 0..segments {
                let a0 = (i as f32 / segments as f32) * TAU;
                let a1 = ((i + 1) as f32 / segments as f32) * TAU;

                let p0 = center + ring_radius * egui::vec2(a0.cos(), a0.sin());
                let p1 = center + ring_radius * egui::vec2(a1.cos(), a1.sin());

                let y_mid = (p0.y + p1.y) / 2.0;
                let t = ((y_mid - center.y + ring_radius) / (ring_radius * 2.0)).clamp(0.0, 1.0);
                let mut col = lerp_color(color_top, color_bottom, t);

                if state == ConnectionState::Connected {
                    // Спокойный двусторонний перелив энергии по кольцу
                    let a_mid = (a0 + a1) * 0.5;
                    let shimmer_a = (a_mid - phase_a).cos().max(0.0).powi(6);
                    let shimmer_b = (a_mid - phase_b).cos().max(0.0).powi(6);
                    let energy = (shimmer_a + shimmer_b).min(1.0);
                    col = lerp_color(col, egui::Color32::from_rgb(138, 235, 178), energy * 0.65);
                } else if state == ConnectionState::Disconnected {
                    // Верхний металлический блик для состояния ожидания
                    let highlight = (1.0 - t).powf(2.4) * 0.35;
                    col = lerp_color(col, Colors::IVORY, highlight);
                }

                ui.painter().line_segment([p0, p1], egui::Stroke::new(stroke_width, col));
            }
        }

        // 5. Внутренний объёмный стеклянно-металлический диск (Radial Mesh)
        let active_inner_r = inner_radius - press_t * 1.4;
        let (disc_center_col, disc_mid_col, disc_edge_col) = match state {
            ConnectionState::Disconnected => (
                lerp_color(
                    egui::Color32::from_rgb(33, 37, 49),
                    egui::Color32::from_rgb(44, 41, 36),
                    hover_t,
                ),
                lerp_color(
                    egui::Color32::from_rgb(22, 25, 34),
                    egui::Color32::from_rgb(28, 28, 35),
                    hover_t,
                ),
                lerp_color(
                    egui::Color32::from_rgb(14, 16, 22),
                    egui::Color32::from_rgb(38, 32, 24),
                    hover_t * 0.7,
                ),
            ),
            ConnectionState::Connected => (
                lerp_color(
                    egui::Color32::from_rgb(20, 48, 34),
                    egui::Color32::from_rgb(26, 62, 42),
                    hover_t,
                ),
                egui::Color32::from_rgb(14, 30, 22),
                lerp_color(
                    egui::Color32::from_rgb(14, 38, 26),
                    egui::Color32::from_rgb(22, 64, 42),
                    hover_t,
                ),
            ),
            ConnectionState::Connecting | ConnectionState::Stopping => (
                egui::Color32::from_rgb(30, 27, 36),
                egui::Color32::from_rgb(20, 22, 30),
                egui::Color32::from_rgb(14, 15, 22),
            ),
        };

        // При нажатии слегка затемняем ядро для тактильного отклика
        let disc_center_col = lerp_color(disc_center_col, egui::Color32::from_rgb(12, 14, 19), press_t * 0.35);
        draw_radial_disc_mesh(
            ui.painter(),
            center,
            active_inner_r,
            disc_center_col,
            disc_mid_col,
            disc_edge_col,
        );

        // Тонкая внутренняя фаска и верхний стеклянный блик
        let bevel_color = match state {
            ConnectionState::Disconnected => lerp_color(
                egui::Color32::from_rgba_unmultiplied(148, 163, 184, 55),
                with_alpha(Colors::GOLD, 145),
                hover_t,
            ),
            ConnectionState::Connected => lerp_color(
                with_alpha(color_top, 110 + (breath * 45.0) as u8),
                egui::Color32::from_rgba_unmultiplied(138, 235, 178, 210),
                hover_t,
            ),
            ConnectionState::Connecting | ConnectionState::Stopping => {
                egui::Color32::from_rgb(46, 48, 60)
            }
        };
        ui.painter().circle_stroke(
            center,
            active_inner_r,
            egui::Stroke::new(1.1, bevel_color),
        );

        let specular_color = match state {
            ConnectionState::Connected => egui::Color32::from_rgb(138, 235, 178),
            ConnectionState::Disconnected => lerp_color(Colors::WHITE, Colors::GOLD, hover_t * 0.6),
            _ => Colors::WHITE,
        };
        draw_top_specular_arc(
            ui.painter(),
            center,
            active_inner_r - 2.0,
            specular_color,
            26.0 + hover_t * 22.0,
        );

        // 6. Верхний векторный микро-индикатор состояния
        let icon_center = egui::pos2(center.x, center.y - 24.0);
        match state {
            ConnectionState::Disconnected => {
                let icon_col = lerp_color(
                    egui::Color32::from_rgb(190, 198, 214),
                    Colors::GOLD,
                    hover_t,
                );
                draw_power_icon(ui.painter(), icon_center, icon_col);
            }
            ConnectionState::Connected => {
                let icon_col = lerp_color(
                    egui::Color32::from_rgb(56, 201, 118),
                    egui::Color32::from_rgb(138, 235, 178),
                    0.35 * breath + hover_t * 0.4,
                );
                draw_shield_check_icon(ui.painter(), icon_center, icon_col);
            }
            ConnectionState::Connecting | ConnectionState::Stopping => {
                let pulse_r = 3.0 + breath * 2.2;
                ui.painter().circle_filled(icon_center, pulse_r + 2.5, with_alpha(color_top, 45));
                ui.painter().circle_filled(icon_center, 3.0, color_top);
            }
        }

        // 7. Главный текст кнопки (CONNECT / CONNECTING / STOP / STOPPING)
        let title_font = egui::FontId::new(16.5, egui::FontFamily::Name("Inter-V".into()));
        let title_pos = egui::pos2(center.x, center.y - 1.5);
        let title_color = match state {
            ConnectionState::Disconnected => lerp_color(Colors::IVORY, Colors::WHITE, hover_t),
            ConnectionState::Connected => Colors::WHITE,
            ConnectionState::Connecting | ConnectionState::Stopping => Colors::WHITE,
        };
        ui.painter().text(
            title_pos,
            egui::Align2::CENTER_CENTER,
            btn_title,
            title_font,
            title_color,
        );

        // 8. Нижний статусный бейдж-пилюля с цветным индикатором
        let sub_font = egui::FontId::new(8.0, egui::FontFamily::Name("Inter-V".into()));
        let sub_y = center.y + 23.0;

        let sub_text_color = match state {
            ConnectionState::Disconnected => lerp_color(
                egui::Color32::from_rgb(165, 172, 186),
                Colors::GOLD,
                hover_t * 0.85,
            ),
            ConnectionState::Connected => egui::Color32::from_rgb(152, 238, 186),
            ConnectionState::Connecting | ConnectionState::Stopping => Colors::GREY,
        };

        let sub_galley = ui.painter().layout_no_wrap(
            sub_label.to_string(),
            sub_font.clone(),
            sub_text_color,
        );
        let sub_width = sub_galley.size().x;
        let dot_dia = 5.0;
        let dot_gap = 4.0;
        let content_w = dot_dia + dot_gap + sub_width;
        let pill_w = content_w + 14.0;
        let pill_h = 16.0;
        let pill_rect = egui::Rect::from_center_size(
            egui::pos2(center.x, sub_y),
            egui::vec2(pill_w, pill_h),
        );

        let (pill_fill, pill_stroke, dot_col) = match state {
            ConnectionState::Disconnected => (
                lerp_color(
                    egui::Color32::from_rgba_unmultiplied(255, 255, 255, 10),
                    egui::Color32::from_rgba_unmultiplied(238, 188, 122, 22),
                    hover_t,
                ),
                lerp_color(
                    egui::Color32::from_rgba_unmultiplied(255, 255, 255, 24),
                    with_alpha(Colors::GOLD, 95),
                    hover_t,
                ),
                lerp_color(
                    egui::Color32::from_rgb(148, 163, 184),
                    Colors::GOLD,
                    hover_t,
                ),
            ),
            ConnectionState::Connected => (
                egui::Color32::from_rgba_unmultiplied(56, 201, 118, 30),
                egui::Color32::from_rgba_unmultiplied(56, 201, 118, 95),
                egui::Color32::from_rgb(56, 201, 118),
            ),
            ConnectionState::Connecting | ConnectionState::Stopping => (
                egui::Color32::from_rgba_unmultiplied(251, 191, 36, 16),
                egui::Color32::from_rgba_unmultiplied(251, 191, 36, 55),
                color_top,
            ),
        };

        ui.painter().rect_filled(pill_rect, egui::CornerRadius::same(8), pill_fill);
        ui.painter().rect_stroke(
            pill_rect,
            egui::CornerRadius::same(8),
            egui::Stroke::new(0.8, pill_stroke),
            egui::StrokeKind::Inside,
        );

        let start_x = center.x - (content_w / 2.0);
        let dot_pos = egui::pos2(start_x + dot_dia * 0.5, sub_y);
        if state == ConnectionState::Connected {
            ui.painter().circle_filled(dot_pos, 4.0, with_alpha(dot_col, (45.0 + breath * 55.0) as u8));
        }
        ui.painter().circle_filled(dot_pos, 2.3, dot_col);

        ui.painter().text(
            egui::pos2(start_x + dot_dia + dot_gap, sub_y),
            egui::Align2::LEFT_CENTER,
            sub_label,
            sub_font,
            sub_text_color,
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
                ConnectionState::Connecting | ConnectionState::Connected => {
                    app.stop_vpn();
                }
                ConnectionState::Stopping => {}
            }
        }
    });
}
