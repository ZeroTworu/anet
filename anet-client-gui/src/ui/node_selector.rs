//! Выпадающий селектор серверной ноды

use eframe::egui;
use crate::{
    app::ANetApp,
    theme::Colors,
    types::ConnectionState,
    utils::helpers::lock_ignore_poison,
};

pub fn render_node_selector(app: &mut ANetApp, ui: &mut egui::Ui, state: ConnectionState) {
    let mut selected_server_name = String::new();
    let mut selected_display_name = String::new();

    {
        let settings = lock_ignore_poison(&app.settings);
        if let Some(active_cfg) = settings.get_active_config() {
            let active_cfg_id = active_cfg.id.clone();
            let active_cfg_content = active_cfg.content.clone();
            drop(settings);

            app.refresh_server_names_cache(&active_cfg_id, &active_cfg_content);

            let settings = lock_ignore_poison(&app.settings);
            selected_server_name = settings.selected_servers
                .get(&active_cfg_id)
                .filter(|id| app.server_names_cache.iter().any(|(cid, _)| cid == *id))
                .cloned()
                .unwrap_or_else(|| app.server_names_cache.first().map(|(id, _)| id.clone()).unwrap_or_default());
                
            selected_display_name = app.server_names_cache.iter()
                .find(|(id, _)| id == &selected_server_name)
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

    ui.add_space(10.0);
    ui.vertical_centered(|ui| {
        let sub_label_size = 8.0;
        let header_text = if state == ConnectionState::Disconnected {
            "Подключение к:"
        } else {
            "Активная нода:"
        };
        ui.label(
            egui::RichText::new(header_text)
                .size(sub_label_size)
                .color(if state == ConnectionState::Disconnected { Colors::GREY } else { Colors::IVORY })
                .family(egui::FontFamily::Name("Inter-V".into()))
        );
        ui.add_space(7.0);

        const NODE_WIDTH: f32 = 266.0;
        const NODE_HEIGHT: f32 = 36.0;
        const NODE_RADIUS: u8 = 18;
        const ITEM_HEIGHT: f32 = 34.0;

        let orange = egui::Color32::from_rgb(235, 140, 52);
        let indicator = match state {
            ConnectionState::Connected => orange,
            ConnectionState::Disconnected | ConnectionState::Connecting => {
                egui::Color32::from_rgb(120, 124, 132)
            }
        };
        let bg = egui::Color32::from_rgb(25, 28, 36);
        let hover_bg = egui::Color32::from_rgb(31, 35, 44);
        let border = egui::Color32::from_rgb(50, 54, 66);
        let text = egui::Color32::from_rgb(242, 243, 246);
        let muted = egui::Color32::from_rgb(160, 164, 172);

        let (rect, response) = ui.allocate_exact_size(
            egui::vec2(NODE_WIDTH, NODE_HEIGHT),
            if state == ConnectionState::Disconnected {
                egui::Sense::click()
            } else {
                egui::Sense::hover()
            }
        );

        if state != ConnectionState::Disconnected {
            app.node_popup_open = false;
        }

        if state == ConnectionState::Disconnected && response.clicked() {
            app.node_popup_open = !app.node_popup_open;
        }

        let popup_open = app.node_popup_open;

        let field_fill = if response.hovered() && state == ConnectionState::Disconnected {
            hover_bg
        } else {
            bg
        };
        ui.painter().rect_filled(
            rect,
            egui::CornerRadius::same(NODE_RADIUS),
            field_fill
        );
        ui.painter().rect_stroke(
            rect,
            egui::CornerRadius::same(NODE_RADIUS),
            egui::Stroke::new(1.0, border),
            egui::StrokeKind::Inside
        );

        let center_y = rect.center().y;
        let dot_center = egui::pos2(rect.left() + 18.0, center_y);
        ui.painter().circle_filled(dot_center, 5.0, indicator);

        ui.painter().text(
            egui::pos2(rect.left() + 32.0, center_y),
            egui::Align2::LEFT_CENTER,
            &selected_display_name,
            egui::FontId::new(13.0, egui::FontFamily::Name("Inter-V".into())),
            text
        );

        if state == ConnectionState::Disconnected {
            let cx = rect.right() - 17.0;
            let cy = center_y;
            ui.painter().add(
                egui::Shape::convex_polygon(
                    vec![
                        egui::pos2(cx - 5.0, cy - 2.0),
                        egui::pos2(cx + 5.0, cy - 2.0),
                        egui::pos2(cx, cy + 4.0)
                    ],
                    muted,
                    egui::Stroke::NONE
                )
            );
        }

        if state == ConnectionState::Disconnected && popup_open {
            let popup_height = 12.0 + (server_names.len() as f32) * ITEM_HEIGHT;
            let popup_pos = egui::pos2(rect.left(), rect.bottom() + 6.0);
            let popup_area_id = egui::Id::new("node_selection_popup");

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
                            for (id, name) in &server_names {
                                let selected = id == &selected_server_name;
                                let (item_rect, item_response) = popup_ui.allocate_exact_size(
                                    egui::vec2(NODE_WIDTH - 12.0, ITEM_HEIGHT),
                                    egui::Sense::click()
                                );

                                if item_response.hovered() {
                                    popup_ui.painter().rect_filled(
                                        item_rect,
                                        egui::CornerRadius::same(9),
                                        hover_bg
                                    );
                                }

                                if selected {
                                    popup_ui.painter().circle_filled(
                                        egui::pos2(item_rect.left() + 13.0, item_rect.center().y),
                                        4.0,
                                        orange
                                    );
                                }

                                popup_ui.painter().text(
                                    egui::pos2(item_rect.left() + 25.0, item_rect.center().y),
                                    egui::Align2::LEFT_CENTER,
                                    name,
                                    egui::FontId::new(13.0, egui::FontFamily::Name("Inter-V".into())),
                                    if selected { text } else { muted }
                                );

                                if item_response.clicked() {
                                    app.node_popup_open = false;
                                    let selected_id = id.clone();
                                    {
                                        let mut settings = lock_ignore_poison(&app.settings);
                                        if let Some(active_cfg) = settings.get_active_config() {
                                            settings.selected_servers.insert(active_cfg.id.clone(), selected_id);
                                            settings.save();
                                        }
                                    }

                                    let active_cfg_data = {
                                        let settings = lock_ignore_poison(&app.settings);
                                        settings.get_active_config().map(|cfg| {
                                            (cfg.id.clone(), cfg.content.clone(), cfg.name.clone())
                                        })
                                    };

                                    if let Some((id, content, name)) = active_cfg_data {
                                        app.load_config_from_content(&id, &content, &name, false);
                                    }
                                }
                            }
                        });
                });
        }
    });
}
