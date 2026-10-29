//! Нижняя панель консоли: 3-уровневый блок телеметрии (Щит сети, Линейный пульс RTT, График скорости/трафика)

use anet_client_core::connectivity_monitor::ConnectivityMonitor;
use anet_common::connectivity::{NetworkCondition, PulseColor};
use eframe::egui::{self, Color32, CornerRadius, FontFamily, Mesh, Pos2, Rect, RichText, Sense, Shape, Stroke, Vec2};

use crate::{app::ANetApp, theme::Colors};

pub fn render_bottom_console(app: &mut ANetApp, ctx: &egui::Context) {
    // Плавная анимация бегущего импульса (~30 FPS)
    ctx.request_repaint_after(std::time::Duration::from_millis(33));

    let panel_frame = egui::Frame::NONE
        .fill(Colors::CONSOLE_BG)
        .corner_radius(CornerRadius {
            nw: 0,
            ne: 0,
            sw: 14,
            se: 14,
        });

    let border_color = Colors::BORDER;

    egui::TopBottomPanel::bottom("stalker_console")
        .resizable(false)
        .min_height(286.0)
        .default_height(288.0)
        .show_separator_line(false)
        .frame(panel_frame)
        .show(ctx, |ui| {
            egui::Frame::NONE
                .fill(Colors::DARK)
                .stroke(Stroke::new(1.0, border_color))
                .corner_radius(CornerRadius::same(14))
                .outer_margin(egui::Margin::symmetric(8, 6))
                .inner_margin(egui::Margin::symmetric(10, 8))
                .show(ui, |ui| {
                    ui.vertical(|ui| {
                        // 1. Актуализируем строку последнего лог-события
                        update_status_line_from_logs(app);

                        // 2. Верхняя полоса: статус лога + кнопка VIEW LOG →
                        render_log_header_row(app, ui);

                        ui.add_space(5.0);

                        // 3. Уровень 1 — Щит диагностики состояния сети + сегментная шкала маршрутов
                        render_connectivity_shield_card(app, ui);

                        ui.add_space(5.0);

                        // 4. Уровень 2 — Линейный индикатор пульса (RTT мс + бегущая ЭКГ-волна)
                        render_pulse_line_card(app, ui, ctx);

                        ui.add_space(5.0);

                        // 5. Уровень 3 — Карточка скорости и трафика за сессию с двойным sparkline-графиком
                        render_speed_sparkline_card(app, ui);
                    });
                });
        });
}

fn update_status_line_from_logs(app: &mut ANetApp) {
    if let Ok(logs) = app.logs.try_lock() {
        if let Some((text, color)) = logs.iter().rev().find_map(|line| {
            if line.contains("Error")
                || line.contains("Failed")
                || line.contains("Connection lost")
            {
                Some((line.clone(), Colors::RED))
            } else if line.contains("Tunnel UP") {
                Some((line.clone(), Colors::GREEN))
            } else if line.contains("Config loaded") || line.contains("Найдено обновление") {
                Some((line.clone(), Colors::GOLD))
            } else if line.contains("Cleaning up dead session")
                || line.contains("добавлен")
                || line.contains("удален")
            {
                Some((line.clone(), Colors::ORANGE))
            } else {
                None
            }
        }) {
            app.status_text = text;
            app.status_color = color;
        }
    }
}

fn render_log_header_row(app: &mut ANetApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        let text_muted = Color32::from_rgb(140, 145, 155);
        let button_width = 78.0;
        let max_label_width = (ui.available_width() - button_width - 8.0).max(60.0);

        ui.allocate_ui_with_layout(
            egui::vec2(max_label_width, 16.0),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.set_max_width(max_label_width);
                ui.add(
                    egui::Label::new(
                        RichText::new(&app.status_text)
                            .family(FontFamily::Name("Inter-V".into()))
                            .size(10.5)
                            .color(app.status_color)
                            .strong(),
                    )
                    .truncate(),
                );
            },
        );

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let btn = ui.add(
                egui::Label::new(
                    RichText::new("VIEW LOG →")
                        .family(FontFamily::Name("Inter-V".into()))
                        .size(10.5)
                        .color(text_muted),
                )
                .sense(Sense::click()),
            );

            if btn.hovered() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            }
            if btn.clicked() {
                app.logbar_open = !app.logbar_open;
            }
        });
    });
}

fn pulse_palette(color: PulseColor) -> (Color32, Color32, Color32) {
    match color {
        PulseColor::Green => (
            Color32::from_rgb(34, 197, 94),                 // Основной (#22C55E)
            Color32::from_rgba_unmultiplied(34, 197, 94, 42), // Мягкая обводка
            Color32::from_rgba_unmultiplied(16, 40, 29, 170), // Тёмная подложка
        ),
        PulseColor::Yellow => (
            Color32::from_rgb(245, 158, 11),                 // Основной (#F59E0B)
            Color32::from_rgba_unmultiplied(245, 158, 11, 45),
            Color32::from_rgba_unmultiplied(44, 31, 14, 170),
        ),
        PulseColor::Red => (
            Color32::from_rgb(239, 68, 68),                  // Основной (#EF4444)
            Color32::from_rgba_unmultiplied(239, 68, 68, 48),
            Color32::from_rgba_unmultiplied(45, 18, 22, 170),
        ),
    }
}

/// Уровень 1: Виджет «Щит диагностики сети» с динамическим сегментным индикатором маршрутов РФ / Мир
fn render_connectivity_shield_card(app: &mut ANetApp, ui: &mut egui::Ui) {
    let snap = app.connectivity_snapshot.clone();
    let vpn_state = crate::utils::helpers::lock_ignore_poison(&app.shared).state;
    let shield_pulse = match vpn_state {
        crate::types::ConnectionState::Disconnected => PulseColor::Red,
        crate::types::ConnectionState::Connecting
        | crate::types::ConnectionState::Stopping => PulseColor::Yellow,
        crate::types::ConnectionState::Connected => {
            if snap.condition == NetworkCondition::TunnelFullOnline || snap.global_ok > 0 {
                PulseColor::Green
            } else {
                PulseColor::Yellow
            }
        }
    };
    let (shield_accent, _, _) = pulse_palette(shield_pulse);
    let (accent, stroke_col, bg_col) = pulse_palette(snap.pulse_color);
    let text_sub = Color32::from_rgb(168, 176, 190);
    let is_checking = snap.title.starts_with("Сверяем");

    let mut trigger_manual_recheck = false;

    egui::Frame::NONE
        .fill(bg_col)
        .stroke(Stroke::new(1.0, stroke_col))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(egui::Margin::symmetric(10, 7))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.vertical(|ui| {
                // Верхняя строка: Иконка щита + Заголовок состояния | Бейдж РФ/Мир + Кнопка обновления
                ui.horizontal(|ui| {
                    let (shield_rect, _) =
                        ui.allocate_exact_size(egui::vec2(16.0, 16.0), Sense::hover());
                    draw_shield_icon(ui.painter(), shield_rect, shield_accent, shield_pulse);

                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(&snap.title)
                            .family(FontFamily::Name("Inter-V".into()))
                            .size(12.0)
                            .strong()
                            .color(Color32::WHITE),
                    );

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // Кнопка принудительного переопроса контрольных точек
                        let (refresh_rect, refresh_resp) =
                            ui.allocate_exact_size(egui::vec2(18.0, 18.0), Sense::click());
                        if refresh_resp.hovered() {
                            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                        }
                        let refresh_bg = if is_checking || refresh_resp.hovered() {
                            Color32::from_rgba_unmultiplied(accent.r(), accent.g(), accent.b(), 48)
                        } else {
                            Color32::from_rgba_unmultiplied(255, 255, 255, 14)
                        };
                        ui.painter()
                            .rect_filled(refresh_rect, CornerRadius::same(5), refresh_bg);
                        if is_checking {
                            ui.painter().rect_stroke(
                                refresh_rect,
                                CornerRadius::same(5),
                                Stroke::new(1.0, accent),
                                egui::StrokeKind::Inside,
                            );
                        }
                        ui.painter().text(
                            refresh_rect.center(),
                            egui::Align2::CENTER_CENTER,
                            if is_checking { "…" } else { "↻" },
                            egui::FontId::proportional(11.5),
                            accent,
                        );
                        if refresh_resp
                            .on_hover_text("Проверить маршруты сейчас")
                            .clicked()
                        {
                            trigger_manual_recheck = true;
                        }

                        ui.add_space(4.0);

                        // Плашка РФ X/Y • Мир A/B (строго по количеству точек из активного конфига)
                        let dom_tot = snap.domestic_total.max(1);
                        let glob_tot = snap.global_total.max(1);
                        let routes_badge = format!(
                            "РФ {}/{} • Мир {}/{}",
                            snap.domestic_ok.min(dom_tot),
                            dom_tot,
                            snap.global_ok.min(glob_tot),
                            glob_tot
                        );
                        egui::Frame::NONE
                            .fill(Color32::from_rgba_unmultiplied(15, 20, 28, 175))
                            .stroke(Stroke::new(
                                1.0,
                                Color32::from_rgba_unmultiplied(255, 255, 255, 18),
                            ))
                            .corner_radius(CornerRadius::same(5))
                            .inner_margin(egui::Margin::symmetric(6, 2))
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new(routes_badge)
                                        .family(FontFamily::Name("JetBrainsMono".into()))
                                        .size(9.5)
                                        .color(accent),
                                );
                            });
                    });
                });

                ui.add_space(2.0);

                // Подзаголовок с описанием состояния
                ui.add(
                    egui::Label::new(
                        RichText::new(&snap.subtitle)
                            .family(FontFamily::Name("Inter-V".into()))
                            .size(10.0)
                            .color(text_sub),
                    )
                    .truncate(),
                );

                ui.add_space(5.0);

                // Сегментная шкала контрольных точек (по числу РФ + Мир из конфига)
                let dom_total = snap.domestic_total.max(1);
                let glob_total = snap.global_total.max(1);
                let total_segments = (dom_total + glob_total).max(1);
                let bar_height = 4.0;
                let (bar_rect, _) = ui.allocate_exact_size(
                    egui::vec2(ui.available_width(), bar_height),
                    Sense::hover(),
                );

                let gap = 3.0;
                let seg_w = ((bar_rect.width() - gap * ((total_segments - 1) as f32))
                    / (total_segments as f32))
                    .max(2.0);
                let unlit_col = Color32::from_rgba_unmultiplied(255, 255, 255, 24);
                let dom_lit_col = match snap.condition {
                    NetworkCondition::Offline | NetworkCondition::TunnelLost => {
                        Color32::from_rgba_unmultiplied(239, 68, 68, 95)
                    }
                    _ => accent,
                };
                let glob_lit_col = accent;

                for i in 0..total_segments {
                    let x0 = bar_rect.left() + (i as f32) * (seg_w + gap);
                    let seg_rect =
                        Rect::from_min_size(Pos2::new(x0, bar_rect.top()), Vec2::new(seg_w, bar_height));
                    let col = if i < dom_total {
                        if i < snap.domestic_ok {
                            dom_lit_col
                        } else {
                            unlit_col
                        }
                    } else {
                        let g_idx = i - dom_total;
                        if g_idx < snap.global_ok {
                            glob_lit_col
                        } else {
                            unlit_col
                        }
                    };
                    ui.painter()
                        .rect_filled(seg_rect, CornerRadius::same(2), col);
                }
            });
        });

    if trigger_manual_recheck {
        app.log("Внеочередная проверка контрольных точек связности...");
        app.show_toast("Проверка маршрутов...");
        let rt_handle = app.rt.handle().clone();
        rt_handle.spawn(async move {
            ConnectivityMonitor::trigger_check_now();
        });
    }
}

fn draw_shield_icon(painter: &egui::Painter, rect: Rect, color: Color32, pulse: PulseColor) {
    let cx = rect.center().x;
    let top = rect.top() + 1.0;
    let bot = rect.bottom() - 1.0;
    let left = rect.left() + 1.5;
    let right = rect.right() - 1.5;
    let mid_y = top + (bot - top) * 0.55;

    let pts = vec![
        Pos2::new(cx, top),
        Pos2::new(right, top + 2.5),
        Pos2::new(right - 1.0, mid_y),
        Pos2::new(cx, bot),
        Pos2::new(left + 1.0, mid_y),
        Pos2::new(left, top + 2.5),
    ];

    let fill = Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 40);
    painter.add(Shape::convex_polygon(
        pts,
        fill,
        Stroke::new(1.3, color),
    ));

    let c = rect.center();
    match pulse {
        PulseColor::Green => {
            painter.line_segment(
                [Pos2::new(c.x - 2.6, c.y + 0.2), Pos2::new(c.x - 0.6, c.y + 2.2)],
                Stroke::new(1.5, color),
            );
            painter.line_segment(
                [Pos2::new(c.x - 0.6, c.y + 2.2), Pos2::new(c.x + 3.0, c.y - 2.0)],
                Stroke::new(1.5, color),
            );
        }
        PulseColor::Yellow => {
            painter.line_segment(
                [Pos2::new(c.x, c.y - 2.8), Pos2::new(c.x, c.y + 0.6)],
                Stroke::new(1.6, color),
            );
            painter.circle_filled(Pos2::new(c.x, c.y + 2.6), 0.9, color);
        }
        PulseColor::Red => {
            painter.line_segment(
                [Pos2::new(c.x - 2.2, c.y - 2.2), Pos2::new(c.x + 2.2, c.y + 2.2)],
                Stroke::new(1.5, color),
            );
            painter.line_segment(
                [Pos2::new(c.x + 2.2, c.y - 2.2), Pos2::new(c.x - 2.2, c.y + 2.2)],
                Stroke::new(1.5, color),
            );
        }
    }
}

/// Уровень 2: Линейный пульс (RTT в мс + бегущая ЭКГ-волна с подсветкой)
fn render_pulse_line_card(app: &ANetApp, ui: &mut egui::Ui, ctx: &egui::Context) {
    let snap = &app.connectivity_snapshot;
    let (accent, _, _) = pulse_palette(snap.pulse_color);
    let text_muted = Color32::from_rgb(140, 145, 155);

    let rtt_opt = snap.display_rtt_ms.or(app.telemetry_snapshot.rtt_ms);
    let rtt_text = match rtt_opt {
        Some(ms) => format!("{ms} мс"),
        None => "— мс".to_string(),
    };

    let state_tag = match snap.pulse_color {
        PulseColor::Green => "СТАБИЛЬНО",
        PulseColor::Yellow => "ОГРАНИЧЕНО",
        PulseColor::Red => "НЕТ ОТКЛИКА",
    };

    egui::Frame::NONE
        .fill(Color32::from_rgb(17, 20, 27))
        .stroke(Stroke::new(1.0, Colors::BORDER))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    let (dot_rect, _) = ui.allocate_exact_size(egui::vec2(7.0, 7.0), Sense::hover());
                    ui.painter().circle_filled(dot_rect.center(), 3.2, accent);
                    ui.add_space(3.0);
                    ui.label(
                        RichText::new("ПУЛЬС КАНАЛА")
                            .family(FontFamily::Name("Inter-V".into()))
                            .size(9.5)
                            .strong()
                            .color(text_muted),
                    );

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(rtt_text)
                                .family(FontFamily::Name("JetBrainsMono".into()))
                                .size(12.5)
                                .strong()
                                .color(Color32::WHITE),
                        );
                        ui.add_space(6.0);
                        egui::Frame::NONE
                            .fill(Color32::from_rgba_unmultiplied(
                                accent.r(),
                                accent.g(),
                                accent.b(),
                                28,
                            ))
                            .corner_radius(CornerRadius::same(4))
                            .inner_margin(egui::Margin::symmetric(5, 1))
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new(state_tag)
                                        .family(FontFamily::Name("Inter-V".into()))
                                        .size(8.5)
                                        .strong()
                                        .color(accent),
                                );
                            });
                    });
                });

                ui.add_space(4.0);

                // Полотно линейного ЭКГ-пульса
                let wave_height = 24.0;
                let (rect, _) = ui.allocate_exact_size(
                    egui::vec2(ui.available_width(), wave_height),
                    Sense::hover(),
                );
                let painter = ui.painter_at(rect);

                // Тонкая базовая сетка
                let baseline_y = rect.center().y + 2.0;
                painter.line_segment(
                    [
                        Pos2::new(rect.left(), baseline_y),
                        Pos2::new(rect.right(), baseline_y),
                    ],
                    Stroke::new(1.0, Color32::from_rgba_unmultiplied(255, 255, 255, 16)),
                );

                let t = ctx.input(|i| i.time) as f32;
                let speed = match snap.pulse_color {
                    PulseColor::Green => 0.55,
                    PulseColor::Yellow => 0.38,
                    PulseColor::Red => 0.18,
                };
                let phase = (t * speed).fract();
                let width = rect.width().max(1.0);
                let head_x = rect.left() + phase * width;

                let steps = 96usize;
                let mut pts = Vec::with_capacity(steps + 1);
                let amp = (wave_height * 0.44).max(6.0);

                for i in 0..=steps {
                    let frac = (i as f32) / (steps as f32);
                    let x = rect.left() + frac * width;

                    // Расстояние позади бегущей головки импульса (с учётом зацикливания)
                    let mut dist = phase - frac;
                    if dist < 0.0 {
                        dist += 1.0;
                    }

                    let y_offset = if snap.pulse_color == PulseColor::Red {
                        // При обрыве — почти прямая линия с лёгким тревожным дрожанием у курсора
                        if dist < 0.08 {
                            ((dist * 90.0).sin() * 1.8) * (1.0 - dist / 0.08)
                        } else {
                            0.0
                        }
                    } else {
                        // Классический P-Q-R-S-T комплекс позади головки импульса
                        ecg_waveform(dist) * amp
                    };

                    pts.push(Pos2::new(x, (baseline_y - y_offset).clamp(rect.top() + 1.0, rect.bottom() - 1.0)));
                }

                // Внешнее неоновое свечение
                let glow_col = Color32::from_rgba_unmultiplied(accent.r(), accent.g(), accent.b(), 50);
                painter.add(Shape::line(pts.clone(), Stroke::new(4.5, glow_col)));

                // Основная яркая линия пульса
                painter.add(Shape::line(pts, Stroke::new(1.8, accent)));

                // Светящаяся головка бегущего импульса
                let head_y = if snap.pulse_color == PulseColor::Red {
                    baseline_y
                } else {
                    (baseline_y - ecg_waveform(0.02) * amp).clamp(rect.top() + 2.0, rect.bottom() - 2.0)
                };
                let head_pos = Pos2::new(head_x, head_y);
                painter.circle_filled(
                    head_pos,
                    5.5,
                    Color32::from_rgba_unmultiplied(accent.r(), accent.g(), accent.b(), 65),
                );
                painter.circle_filled(head_pos, 2.5, Color32::WHITE);
            });
        });
}

/// Форма кардио-импульса (P-Q-R-S-T) на интервале отставания `dist` от головки `[0.0..1.0]`
fn ecg_waveform(dist: f32) -> f32 {
    if dist > 0.28 {
        return 0.0;
    }
    let u = dist / 0.28; // 0.0 — сразу у головки, 1.0 — хвост затухания
    let r_peak = (-((u - 0.18) / 0.045).powi(2)).exp() * 1.0;
    let q_dip = -(-((u - 0.10) / 0.030).powi(2)).exp() * 0.35;
    let s_dip = -(-((u - 0.27) / 0.040).powi(2)).exp() * 0.45;
    let t_wave = (-((u - 0.48) / 0.095).powi(2)).exp() * 0.28;
    r_peak + q_dip + s_dip + t_wave
}

/// Уровень 3: Карточка «СКОРОСТЬ / ТРАФИК» с двойным сглаженным графиком (Download + Upload)
fn render_speed_sparkline_card(app: &ANetApp, ui: &mut egui::Ui) {
    let tel = &app.telemetry_snapshot;
    let rx_col = Color32::from_rgb(34, 197, 94); // Изумрудный (#22C55E) для Download
    let tx_col = Color32::from_rgb(56, 189, 248); // Небесно-голубой (#38BDF8) для Upload
    let text_muted = Color32::from_rgb(140, 145, 155);

    let rx_speed_display = if !tel.rx_speed_str.is_empty() {
        tel.rx_speed_str.as_str()
    } else {
        app.total_rxm.as_str()
    };
    let tx_speed_display = if !tel.tx_speed_str.is_empty() {
        tel.tx_speed_str.as_str()
    } else {
        app.total_txm.as_str()
    };
    let total_rx_display = if !tel.total_rx_str.is_empty() {
        tel.total_rx_str.as_str()
    } else {
        app.total_rx.as_str()
    };
    let total_tx_display = if !tel.total_tx_str.is_empty() {
        tel.total_tx_str.as_str()
    } else {
        app.total_tx.as_str()
    };

    egui::Frame::NONE
        .fill(Color32::from_rgb(17, 20, 27))
        .stroke(Stroke::new(1.0, Colors::BORDER))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(egui::Margin::symmetric(10, 7))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.vertical(|ui| {
                // Шапка: 2 колонки (Download слева, Upload справа) + суммарный трафик за сессию
                ui.columns(2, |cols| {
                    cols[0].horizontal(|ui| {
                        let (dot_rect, _) =
                            ui.allocate_exact_size(egui::vec2(6.0, 6.0), Sense::hover());
                        ui.painter().circle_filled(dot_rect.center(), 3.0, rx_col);
                        ui.label(
                            RichText::new("↓ ПРИЁМ")
                                .family(FontFamily::Name("Inter-V".into()))
                                .size(9.0)
                                .strong()
                                .color(text_muted),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(
                                RichText::new(format!("Σ {total_rx_display}"))
                                    .family(FontFamily::Name("JetBrainsMono".into()))
                                    .size(9.0)
                                    .color(text_muted),
                            );
                        });
                    });

                    cols[1].horizontal(|ui| {
                        let (dot_rect, _) =
                            ui.allocate_exact_size(egui::vec2(6.0, 6.0), Sense::hover());
                        ui.painter().circle_filled(dot_rect.center(), 3.0, tx_col);
                        ui.label(
                            RichText::new("↑ ОТДАЧА")
                                .family(FontFamily::Name("Inter-V".into()))
                                .size(9.0)
                                .strong()
                                .color(text_muted),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(
                                RichText::new(format!("Σ {total_tx_display}"))
                                    .family(FontFamily::Name("JetBrainsMono".into()))
                                    .size(9.0)
                                    .color(text_muted),
                            );
                        });
                    });
                });

                ui.add_space(2.0);

                ui.columns(2, |cols| {
                    cols[0].label(
                        RichText::new(rx_speed_display)
                            .family(FontFamily::Name("JetBrainsMono".into()))
                            .size(13.5)
                            .strong()
                            .color(Color32::WHITE),
                    );
                    cols[1].label(
                        RichText::new(tx_speed_display)
                            .family(FontFamily::Name("JetBrainsMono".into()))
                            .size(13.5)
                            .strong()
                            .color(Color32::WHITE),
                    );
                });

                ui.add_space(5.0);

                // Область двойного графика скоростей за 60 секунд
                let chart_height = 42.0;
                let (chart_rect, _) = ui.allocate_exact_size(
                    egui::vec2(ui.available_width(), chart_height),
                    Sense::hover(),
                );
                let painter = ui.painter_at(chart_rect);

                // Горизонтальные направляющие сетки
                for frac in [0.25_f32, 0.65_f32, 1.0_f32] {
                    let y = chart_rect.top() + chart_rect.height() * frac;
                    painter.line_segment(
                        [Pos2::new(chart_rect.left(), y), Pos2::new(chart_rect.right(), y)],
                        Stroke::new(1.0, Color32::from_rgba_unmultiplied(255, 255, 255, 12)),
                    );
                }

                // Отрисовка кривой Upload (на заднем плане) и Download (на переднем плане)
                draw_sparkline_curve(&painter, chart_rect, &tel.tx_curve, tx_col);
                draw_sparkline_curve(&painter, chart_rect, &tel.rx_curve, rx_col);
            });
        });
}

fn draw_sparkline_curve(
    painter: &egui::Painter,
    rect: Rect,
    samples: &[f32],
    color: Color32,
) {
    let n = samples.len();
    let pad_top = 3.0;
    let pad_bot = 2.0;
    let usable_h = (rect.height() - pad_top - pad_bot).max(4.0);
    let bottom_y = rect.bottom() - pad_bot;

    if n < 2 {
        // Если точек ещё нет — рисуем спокойную базовую линию внизу
        painter.line_segment(
            [
                Pos2::new(rect.left(), bottom_y),
                Pos2::new(rect.right(), bottom_y),
            ],
            Stroke::new(
                1.2,
                Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 90),
            ),
        );
        return;
    }

    let w = rect.width().max(1.0);
    let mut pts = Vec::with_capacity(n);
    for (idx, &val) in samples.iter().enumerate() {
        let x = rect.left() + (idx as f32 / (n - 1) as f32) * w;
        let v = val.clamp(0.0, 1.0);
        let y = bottom_y - v * usable_h;
        pts.push(Pos2::new(x, y));
    }

    // Строим вертикальную градиентную заливку под кривой через egui::Mesh
    let top_fill = Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 72);
    let bot_fill = Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 4);

    let mut mesh = Mesh::default();
    for (i, &p) in pts.iter().enumerate() {
        mesh.colored_vertex(p, top_fill);
        mesh.colored_vertex(Pos2::new(p.x, bottom_y), bot_fill);
        if i > 0 {
            let base = ((i - 1) * 2) as u32;
            mesh.add_triangle(base, base + 1, base + 2);
            mesh.add_triangle(base + 1, base + 3, base + 2);
        }
    }
    painter.add(Shape::mesh(mesh));

    // Верхняя сглаженная линия графика
    painter.add(Shape::line(pts.clone(), Stroke::new(1.7, color)));

    // Светящаяся точка последнего актуального значения справа
    if let Some(&last_pt) = pts.last() {
        painter.circle_filled(
            last_pt,
            3.8,
            Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 65),
        );
        painter.circle_filled(last_pt, 1.8, Color32::WHITE);
    }
}