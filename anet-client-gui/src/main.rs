use anet_client_gui::app::ANetApp;
use eframe::egui;

fn main() -> Result<(), eframe::Error> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 600.0]) // Мобильный форм-фактор
            .with_resizable(false), // Фиксированный размер
        ..Default::default()
    };

    eframe::run_native(
        "ANet VPN",
        options,
        Box::new(|cc| {
            // Настройка стилей при старте
            configure_styles(&cc.egui_ctx);
            Ok(Box::new(ANetApp::new()))
        }),
    )
}

fn configure_styles(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.window_fill = egui::Color32::from_rgb(18, 18, 18); // Onyx Black #121212
    visuals.panel_fill = egui::Color32::from_rgb(18, 18, 18);

    // Настройка цветов виджетов
    visuals.widgets.noninteractive.bg_fill = egui::Color32::TRANSPARENT;
    visuals.widgets.inactive.bg_fill = egui::Color32::from_gray(40);

    ctx.set_visuals(visuals);
}
