//! Оформление, шрифты и цветовая палитра UI

use eframe::egui;

/// Цветовая палитра темы ANet VPN
pub struct Colors;

impl Colors {
    pub const IVORY: egui::Color32 = egui::Color32::from_rgb(234, 233, 235);
    pub const GOLD: egui::Color32 = egui::Color32::from_rgb(238, 188, 122);
    pub const LIGHT_BLUE: egui::Color32 = egui::Color32::from_rgb(128, 172, 202);
    pub const WHITE: egui::Color32 = egui::Color32::from_rgb(255, 255, 255);
    pub const TITLE_BG: egui::Color32 = egui::Color32::from_rgb(23, 25, 31);
    pub const DARK: egui::Color32 = egui::Color32::from_rgb(22, 24, 31);
    pub const CONSOLE_BG: egui::Color32 = egui::Color32::from_rgb(21, 26, 35);
    pub const GREY: egui::Color32 = egui::Color32::from_rgb(128, 128, 128);
    pub const GREEN: egui::Color32 = egui::Color32::from_rgb(65, 180, 65);
    pub const ORANGE: egui::Color32 = egui::Color32::from_rgb(218, 130, 0);
    pub const RED: egui::Color32 = egui::Color32::from_rgb(220, 60, 60);
    pub const BORDER: egui::Color32 = egui::Color32::from_rgb(38, 41, 50);
}

/// Настройка шрифтов JetBrains Mono и Inter
pub fn load_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    let jetbrains_font_data = include_bytes!("./assets/fonts/JetBrainsMono.ttf");
    let inter_font_data = include_bytes!("./assets/fonts/Inter/Inter-Light.otf");

    fonts.font_data.insert(
        "JetBrainsMono".to_owned(),
        std::sync::Arc::new(egui::FontData::from_static(jetbrains_font_data)),
    );
    fonts.font_data.insert(
        "Inter-V".to_owned(),
        std::sync::Arc::new(egui::FontData::from_static(inter_font_data)),
    );

    fonts.families
        .entry(egui::FontFamily::Name("Inter-V".into()))
        .or_default()
        .push("Inter-V".to_owned());

    fonts.families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .insert(0, "Inter-V".to_owned());

    fonts.families
        .entry(egui::FontFamily::Name("JetBrainsMono".into()))
        .or_default()
        .push("JetBrainsMono".to_owned());

    ctx.set_fonts(fonts);
}

/// Применение кастомной темной темы
pub fn apply_dark_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.window_fill = Colors::DARK;
    visuals.window_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(50, 50, 50));
    visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(20, 20, 20);
    visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(30, 30, 30);
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(45, 45, 45);
    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(40, 80, 60);
    ctx.set_visuals(visuals);
}

/// Настройка стилей (Onyx Black & Green/Gold)
pub fn configure_styles(ctx: &egui::Context) {
    let style = (*ctx.style()).clone();
    let mut visuals = egui::Visuals::dark();

    // Цвета фона (Onyx Black)
    let dark_bg = egui::Color32::from_rgb(18, 18, 18);
    visuals.window_fill = dark_bg;
    visuals.panel_fill = dark_bg;

    // Настройка виджетов
    visuals.widgets.noninteractive.bg_fill = egui::Color32::TRANSPARENT;
    visuals.widgets.inactive.bg_fill = egui::Color32::from_gray(40);

    // Акцентный зеленый
    visuals.selection.bg_fill = egui::Color32::from_rgb(76, 175, 80);
    visuals.selection.stroke = egui::Stroke::new(1.0f32, egui::Color32::WHITE);

    ctx.set_visuals(visuals);
    ctx.set_style(style);
}
