use tray_icon::Icon;

pub fn load_tray_icon() -> Icon {
    let (icon_rgba, icon_width, icon_height) = load_icon_file();

    Icon::from_rgba(icon_rgba, icon_width, icon_height).expect("Failed to open icon")
}

pub fn load_icon() -> egui::IconData {
    let (icon_rgba, icon_width, icon_height) = load_icon_file();

    egui::IconData {
        rgba: icon_rgba,
        width: icon_width,
        height: icon_height,
    }
}

fn load_icon_file() -> (Vec<u8>, u32, u32) {
    let (icon_rgba, icon_width, icon_height) = {
        // Укажи правильный путь к иконке
        let image = image::load_from_memory(include_bytes!("../icon.ico"))
            .expect("Failed to open icon path")
            .into_rgba8();
        let (width, height) = image.dimensions();
        let rgba = image.into_raw();
        (rgba, width, height)
    };
    (icon_rgba, icon_width, icon_height)
}