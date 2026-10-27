//! Выпадающий селектор серверной ноды с индикацией реальной доступности транспортов

use anet_common::probe_nodes::{NodeGroupProbeSummary, NodeProbeStatus};
use eframe::egui;
use crate::{
    app::ANetApp,
    theme::Colors,
    types::ConnectionState,
    utils::helpers::lock_ignore_poison,
};

fn probe_status_color(status: NodeProbeStatus) -> egui::Color32 {
    match status {
        NodeProbeStatus::Available => egui::Color32::from_rgb(56, 201, 118),
        NodeProbeStatus::Degraded => egui::Color32::from_rgb(245, 166, 35),
        NodeProbeStatus::Unavailable => egui::Color32::from_rgb(229, 83, 75),
        NodeProbeStatus::Checking => egui::Color32::from_rgb(120, 124, 132),
    }
}

fn render_group_probe_tooltip(ui: &mut egui::Ui, summary: &NodeGroupProbeSummary) {
    ui.set_min_width(220.0);
    let title_color = egui::Color32::from_rgb(242, 243, 246);
    let muted_color = egui::Color32::from_rgb(160, 164, 172);

    ui.horizontal(|ui| {
        let dot_color = probe_status_color(summary.status);
        let (dot_rect, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
        ui.painter().circle_filled(dot_rect.center(), 4.0, dot_color);
        ui.label(
            egui::RichText::new(format!("В группе {}:", summary.group_name))
                .size(12.0)
                .strong()
                .color(title_color),
        );
    });

    ui.add_space(3.0);
    let summary_line = match summary.status {
        NodeProbeStatus::Checking => "Проверка доступности узлов (полный / чистый пинг)...".to_string(),
        NodeProbeStatus::Available => format!(
            "Все транспорты доступны ({}/{}) • [полный / чистый]",
            summary.reachable_endpoints, summary.total_endpoints
        ),
        NodeProbeStatus::Degraded => format!(
            "Частичная доступность ({}/{}) • [полный / чистый]",
            summary.reachable_endpoints, summary.total_endpoints
        ),
        NodeProbeStatus::Unavailable => format!(
            "Узел недоступен (0/{})",
            summary.total_endpoints
        ),
    };
    ui.label(egui::RichText::new(summary_line).size(11.0).color(muted_color));

    if !summary.protocols.is_empty() {
        ui.add_space(4.0);
        for proto in &summary.protocols {
            ui.horizontal(|ui| {
                let p_color = probe_status_color(proto.status);
                let (p_rect, _) =
                    ui.allocate_exact_size(egui::vec2(7.0, 7.0), egui::Sense::hover());
                ui.painter().circle_filled(p_rect.center(), 3.5, p_color);
                ui.label(
                    egui::RichText::new(format!("{:<5}", proto.protocol.as_str()))
                        .size(11.0)
                        .color(title_color),
                );
                let right_txt = match proto.status {
                    NodeProbeStatus::Available => match (proto.full_rtt_ms, proto.rtt_ms) {
                        (Some(full), Some(pure)) => format!("{} / {} мс", full.max(pure), pure),
                        (None, Some(pure)) => format!("{} мс", pure),
                        (Some(full), None) => format!("{} мс", full),
                        (None, None) => "OK".to_string(),
                    },
                    NodeProbeStatus::Degraded => match (proto.full_rtt_ms, proto.rtt_ms) {
                        (Some(full), Some(pure)) => format!("~{} / {} мс", full.max(pure), pure),
                        (None, Some(pure)) => format!("~{} мс", pure),
                        (Some(full), None) => format!("~{} мс", full),
                        (None, None) => "частично".to_string(),
                    },
                    NodeProbeStatus::Unavailable => "недоступен".to_string(),
                    NodeProbeStatus::Checking => "...".to_string(),
                };
                ui.label(egui::RichText::new(right_txt).size(11.0).color(p_color));
            });
        }
    }
}

pub fn render_node_selector(app: &mut ANetApp, ui: &mut egui::Ui, state: ConnectionState) {
    let mut selected_server_name = String::new();
    let mut selected_display_name = String::new();

    {
        let settings = lock_ignore_poison(&app.settings);
        if let Some(active_cfg) = settings.get_active_config_with_overrides(&app.storage_key) {
            let active_cfg_id = active_cfg.id.clone();
            let active_cfg_content = active_cfg.content.clone();
            drop(settings);

            app.refresh_server_names_cache(&active_cfg_id, &active_cfg_content);

            if app.node_probe_snapshot.groups.is_empty() && !active_cfg_content.is_empty() {
                anet_client_core::connectivity_monitor::NodeProbeMonitor::update_config_toml(
                    &active_cfg_content,
                );
                app.node_probe_snapshot =
                    anet_client_core::connectivity_monitor::NodeProbeMonitor::get_last_snapshot();
            }

            let settings = lock_ignore_poison(&app.settings);
            selected_server_name = settings
                .selected_servers
                .get(&active_cfg_id)
                .filter(|id| {
                    app.server_names_cache
                        .iter()
                        .any(|(cid, cname)| cid == *id || cname == *id)
                })
                .cloned()
                .unwrap_or_else(|| {
                    app.server_names_cache
                        .first()
                        .map(|(id, _)| id.clone())
                        .unwrap_or_default()
                });

            selected_display_name = app
                .server_names_cache
                .iter()
                .find(|(id, name)| id == &selected_server_name || name == &selected_server_name)
                .map(|(_, name)| name.clone())
                .unwrap_or_else(|| selected_server_name.clone());
        } else {
            app.server_names_cache.clear();
            app.server_names_cache_key = None;
        }
    }

    let server_names = app.server_names_cache.clone();
    if server_names.is_empty() {
        return;
    }

    let selected_probe = app
        .node_probe_snapshot
        .group_for_key(&selected_display_name)
        .or_else(|| app.node_probe_snapshot.group_for_key(&selected_server_name))
        .cloned();

    ui.add_space(3.0);
    ui.vertical_centered(|ui| {
        let sub_label_size = 8.5;
        let header_text = if state == ConnectionState::Disconnected {
            "Подключение к:"
        } else {
            "Активная нода:"
        };
        ui.label(
            egui::RichText::new(header_text)
                .size(sub_label_size)
                .color(if state == ConnectionState::Disconnected {
                    Colors::GREY
                } else {
                    Colors::IVORY
                })
                .family(egui::FontFamily::Name("Inter-V".into())),
        );
        ui.add_space(4.0);

        const NODE_WIDTH: f32 = 278.0;
        const NODE_HEIGHT: f32 = 34.0;
        const NODE_RADIUS: u8 = 17;
        const ITEM_HEIGHT: f32 = 34.0;

        let orange = egui::Color32::from_rgb(235, 140, 52);
        let raw_selected_status = selected_probe
            .as_ref()
            .map(|p| p.status)
            .unwrap_or(NodeProbeStatus::Checking);
        // Если туннель уже успешно поднят на этой ноде, она гарантированно доступна
        let selected_status = if state == ConnectionState::Connected
            && matches!(
                raw_selected_status,
                NodeProbeStatus::Unavailable | NodeProbeStatus::Checking
            )
        {
            NodeProbeStatus::Available
        } else {
            raw_selected_status
        };
        let indicator = if selected_probe.is_some() || state == ConnectionState::Connected {
            probe_status_color(selected_status)
        } else {
            match state {
                ConnectionState::Connected => orange,
                ConnectionState::Disconnected | ConnectionState::Connecting => {
                    probe_status_color(NodeProbeStatus::Checking)
                }
            }
        };
        let bg = egui::Color32::from_rgb(25, 28, 36);
        let hover_bg = egui::Color32::from_rgb(31, 35, 44);
        let border = egui::Color32::from_rgb(50, 54, 66);
        let text = egui::Color32::from_rgb(242, 243, 246);
        let muted = egui::Color32::from_rgb(160, 164, 172);

        let was_popup_open = app.node_popup_open;

        let (rect, response) = ui.allocate_exact_size(
            egui::vec2(NODE_WIDTH, NODE_HEIGHT),
            if state == ConnectionState::Disconnected {
                egui::Sense::click()
            } else {
                egui::Sense::hover()
            },
        );
        if state == ConnectionState::Disconnected {
            response
                .clone()
                .on_hover_cursor(egui::CursorIcon::PointingHand);
        }

        // Кнопка принудительной перепроверки статуса серверов справа от селектора
        let refresh_rect = egui::Rect::from_min_size(
            egui::pos2(rect.right() + 8.0, rect.top()),
            egui::vec2(NODE_HEIGHT, NODE_HEIGHT),
        );
        let refresh_resp = ui.interact(
            refresh_rect,
            egui::Id::new("btn_refresh_nodes_status"),
            egui::Sense::click(),
        );
        if refresh_resp.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
        let is_probing_nodes = app.node_probe_snapshot.is_checking;
        let refresh_fill = if refresh_resp.hovered() || is_probing_nodes {
            hover_bg
        } else {
            bg
        };
        let refresh_border = if is_probing_nodes {
            egui::Color32::from_rgb(56, 201, 118)
        } else if refresh_resp.hovered() {
            orange
        } else {
            border
        };
        ui.painter().rect_filled(
            refresh_rect,
            egui::CornerRadius::same(NODE_RADIUS),
            refresh_fill,
        );
        ui.painter().rect_stroke(
            refresh_rect,
            egui::CornerRadius::same(NODE_RADIUS),
            egui::Stroke::new(1.0, refresh_border),
            egui::StrokeKind::Inside,
        );
        ui.painter().text(
            refresh_rect.center(),
            egui::Align2::CENTER_CENTER,
            if is_probing_nodes { "…" } else { "↻" },
            egui::FontId::proportional(14.5),
            if is_probing_nodes {
                egui::Color32::from_rgb(56, 201, 118)
            } else if refresh_resp.hovered() {
                text
            } else {
                muted
            },
        );
        if refresh_resp
            .clone()
            .on_hover_text("Принудительно перепроверить доступность и пинг серверов")
            .clicked()
        {
            anet_client_core::connectivity_monitor::NodeProbeMonitor::trigger_probe_now();
            app.node_probe_snapshot =
                anet_client_core::connectivity_monitor::NodeProbeMonitor::get_last_snapshot();
            app.node_probe_snapshot.is_checking = true;
            ui.ctx().request_repaint();
        }

        if state != ConnectionState::Disconnected {
            app.node_popup_open = false;
        }

        if state == ConnectionState::Disconnected && response.clicked() {
            app.node_popup_open = !app.node_popup_open;
        }

        let popup_open = app.node_popup_open;

        if !popup_open {
            if let Some(ref probe) = selected_probe {
                response.clone().on_hover_ui(|tip_ui| {
                    render_group_probe_tooltip(tip_ui, probe);
                });
            }
        }

        let field_fill = if response.hovered() && state == ConnectionState::Disconnected {
            hover_bg
        } else {
            bg
        };
        ui.painter()
            .rect_filled(rect, egui::CornerRadius::same(NODE_RADIUS), field_fill);
        ui.painter().rect_stroke(
            rect,
            egui::CornerRadius::same(NODE_RADIUS),
            egui::Stroke::new(1.0, border),
            egui::StrokeKind::Inside,
        );

        let center_y = rect.center().y;
        let dot_center = egui::pos2(rect.left() + 18.0, center_y);
        ui.painter().circle_filled(dot_center, 4.5, indicator);
        ui.painter().circle_stroke(
            dot_center,
            7.0,
            egui::Stroke::new(1.0, indicator.gamma_multiply(0.35)),
        );

        ui.painter().text(
            egui::pos2(rect.left() + 32.0, center_y),
            egui::Align2::LEFT_CENTER,
            &selected_display_name,
            egui::FontId::new(13.0, egui::FontFamily::Name("Inter-V".into())),
            text,
        );

        let badge_text = if state == ConnectionState::Connected
            && raw_selected_status == NodeProbeStatus::Unavailable
        {
            app.connectivity_snapshot
                .display_rtt_ms
                .filter(|&ms| ms > 0)
                .map(|ms| format!("{} мс", ms))
                .unwrap_or_else(|| "В СЕТИ".to_string())
        } else {
            selected_probe
                .as_ref()
                .map(|p| p.short_badge_text())
                .unwrap_or_else(|| "...".to_string())
        };
        let badge_color = probe_status_color(selected_status);
        let badge_x = if state == ConnectionState::Disconnected {
            rect.right() - 28.0
        } else {
            rect.right() - 14.0
        };
        ui.painter().text(
            egui::pos2(badge_x, center_y),
            egui::Align2::RIGHT_CENTER,
            badge_text,
            egui::FontId::new(10.0, egui::FontFamily::Name("Inter-V".into())),
            badge_color,
        );

        if state == ConnectionState::Disconnected {
            let cx = rect.right() - 16.0;
            let cy = center_y;
            ui.painter().add(egui::Shape::convex_polygon(
                vec![
                    egui::pos2(cx - 5.0, cy - 2.0),
                    egui::pos2(cx + 5.0, cy - 2.0),
                    egui::pos2(cx, cy + 4.0),
                ],
                muted,
                egui::Stroke::NONE,
            ));
        }

        // Визуальный прогресс-бар «ПРОВЕРКА УЗЛОВ X/Y» при активном опросе
        if app.node_probe_snapshot.is_checking && app.node_probe_snapshot.total_endpoints > 0 {
            let done = app
                .node_probe_snapshot
                .completed_endpoints
                .min(app.node_probe_snapshot.total_endpoints);
            let total = app.node_probe_snapshot.total_endpoints.max(1);
            let ratio = (done as f32 / total as f32).clamp(0.06, 1.0);

            ui.add_space(4.0);
            let (prog_rect, _) =
                ui.allocate_exact_size(egui::vec2(NODE_WIDTH - 12.0, 14.0), egui::Sense::hover());
            let bar_rect = egui::Rect::from_min_size(
                egui::pos2(prog_rect.left(), prog_rect.top() + 1.0),
                egui::vec2(prog_rect.width(), 3.0),
            );
            ui.painter().rect_filled(
                bar_rect,
                egui::CornerRadius::same(2),
                egui::Color32::from_rgb(38, 42, 54),
            );
            let fill_rect = egui::Rect::from_min_size(
                bar_rect.min,
                egui::vec2(bar_rect.width() * ratio, bar_rect.height()),
            );
            ui.painter().rect_filled(
                fill_rect,
                egui::CornerRadius::same(2),
                egui::Color32::from_rgb(56, 201, 118),
            );
            ui.painter().text(
                egui::pos2(prog_rect.center().x, prog_rect.bottom() - 2.0),
                egui::Align2::CENTER_BOTTOM,
                format!("ПРОВЕРКА УЗЛОВ {}/{}", done, total),
                egui::FontId::new(8.5, egui::FontFamily::Name("Inter-V".into())),
                muted,
            );
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(80));
        }

        if state == ConnectionState::Disconnected && popup_open {
            let max_visible_items = 6.0_f32;
            let visible_count = (server_names.len() as f32).min(max_visible_items);
            let popup_height = 12.0 + visible_count * ITEM_HEIGHT;
            let screen_bottom = ui.ctx().content_rect().bottom();
            let popup_y = if rect.bottom() + 6.0 + popup_height > screen_bottom - 10.0 {
                (rect.top() - 6.0 - popup_height).max(44.0)
            } else {
                rect.bottom() + 6.0
            };
            let popup_pos = egui::pos2(rect.left(), popup_y);
            let popup_rect =
                egui::Rect::from_min_size(popup_pos, egui::vec2(NODE_WIDTH, popup_height))
                    .expand(4.0);
            let popup_area_id = egui::Id::new("node_selection_popup");

            // Закрываем выпадающий список при клике вне селектора/списка или по нажатию Escape (как в вебе)
            if was_popup_open {
                let esc_pressed = ui.input(|i| i.key_pressed(egui::Key::Escape));
                let clicked_outside = ui.input(|i| {
                    if i.pointer.any_pressed() {
                        if let Some(pos) = i.pointer.interact_pos() {
                            !rect.contains(pos)
                                && !refresh_rect.contains(pos)
                                && !popup_rect.contains(pos)
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                });
                if esc_pressed || clicked_outside {
                    app.node_popup_open = false;
                }
            }

            egui::Area::new(popup_area_id)
                .order(egui::Order::Foreground)
                .fixed_pos(popup_pos)
                .interactable(true)
                .show(ui.ctx(), |popup_ui| {
                    popup_ui.set_min_size(egui::vec2(NODE_WIDTH, popup_height));
                    popup_ui.set_max_size(egui::vec2(NODE_WIDTH, popup_height));

                    egui::Frame::NONE
                        .fill(bg)
                        .stroke(egui::Stroke::new(1.0, border))
                        .corner_radius(egui::CornerRadius::same(14))
                        .inner_margin(egui::Margin::symmetric(6, 6))
                        .show(popup_ui, |popup_ui| {
                            egui::ScrollArea::vertical()
                                .max_height(visible_count * ITEM_HEIGHT)
                                .show(popup_ui, |popup_ui| {
                                    for (id, name) in &server_names {
                                        let selected = id == &selected_server_name
                                            || name == &selected_display_name;
                                        let item_probe = app
                                            .node_probe_snapshot
                                            .group_for_key(name)
                                            .or_else(|| app.node_probe_snapshot.group_for_key(id))
                                            .cloned();

                                        let (item_rect, item_response) = popup_ui
                                            .allocate_exact_size(
                                                egui::vec2(NODE_WIDTH - 12.0, ITEM_HEIGHT),
                                                egui::Sense::click(),
                                            );

                                        if let Some(ref probe) = item_probe {
                                            item_response.clone().on_hover_ui(|tip_ui| {
                                                render_group_probe_tooltip(tip_ui, probe);
                                            });
                                        }

                                        if item_response.hovered() {
                                            popup_ui.painter().rect_filled(
                                                item_rect,
                                                egui::CornerRadius::same(9),
                                                hover_bg,
                                            );
                                        }

                                        let item_status = item_probe
                                            .as_ref()
                                            .map(|p| p.status)
                                            .unwrap_or(NodeProbeStatus::Checking);
                                        let c = probe_status_color(item_status);
                                        let dot_pos = egui::pos2(
                                            item_rect.left() + 13.0,
                                            item_rect.center().y,
                                        );
                                        popup_ui.painter().circle_filled(dot_pos, 4.2, c);
                                        if selected {
                                            popup_ui.painter().circle_stroke(
                                                dot_pos,
                                                6.8,
                                                egui::Stroke::new(1.3, orange),
                                            );
                                        } else {
                                            popup_ui.painter().circle_stroke(
                                                dot_pos,
                                                6.2,
                                                egui::Stroke::new(0.8, c.gamma_multiply(0.3)),
                                            );
                                        }

                                        popup_ui.painter().text(
                                            egui::pos2(
                                                item_rect.left() + 25.0,
                                                item_rect.center().y,
                                            ),
                                            egui::Align2::LEFT_CENTER,
                                            name,
                                            egui::FontId::new(
                                                13.0,
                                                egui::FontFamily::Name("Inter-V".into()),
                                            ),
                                            if selected { text } else { muted },
                                        );

                                        let item_badge_text = item_probe
                                            .as_ref()
                                            .map(|p| p.short_badge_text())
                                            .unwrap_or_else(|| "...".to_string());
                                        popup_ui.painter().text(
                                            egui::pos2(
                                                item_rect.right() - 10.0,
                                                item_rect.center().y,
                                            ),
                                            egui::Align2::RIGHT_CENTER,
                                            item_badge_text,
                                            egui::FontId::new(
                                                10.5,
                                                egui::FontFamily::Name("Inter-V".into()),
                                            ),
                                            c,
                                        );

                                        if item_response.clicked() {
                                            app.node_popup_open = false;
                                            let selected_id = id.clone();
                                            {
                                                let mut settings =
                                                    lock_ignore_poison(&app.settings);
                                                if let Some(active_cfg) = settings
                                                    .get_active_config_with_overrides(
                                                        &app.storage_key,
                                                    )
                                                {
                                                    settings
                                                        .selected_servers
                                                        .insert(active_cfg.id.clone(), selected_id);
                                                    settings.save();
                                                }
                                            }

                                            let active_cfg_data: Option<(String, String, String)> = {
                                                let settings = lock_ignore_poison(&app.settings);
                                                settings
                                                    .get_active_config_with_overrides(
                                                        &app.storage_key,
                                                    )
                                                    .map(|cfg| {
                                                        (
                                                            cfg.id.clone(),
                                                            cfg.content.clone(),
                                                            cfg.name.clone(),
                                                        )
                                                    })
                                            };

                                            if let Some((id, content, name)) = active_cfg_data {
                                                app.load_config_from_content(
                                                    &id, &content, &name, false,
                                                );
                                            }
                                        }
                                    }
                                });
                        });
                });
        }
    });
}