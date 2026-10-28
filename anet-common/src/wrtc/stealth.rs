use rand::Rng;

const COMMON_GUEST_NAMES: &[&str] = &[
    "Алексей", "Дмитрий", "Михаил", "Сергей", "Иван", "Андрей",
    "Константин", "Елена", "Анна", "Мария", "Ольга", "Екатерина",
    "Павел", "Артем", "Максим", "Роман", "Денис", "Владимир",
];

/// Generates a realistic guest name for Ktalk conference without any VPN or node indicators.
pub fn generate_random_guest_name() -> String {
    let mut rng = rand::thread_rng();
    let style = rng.gen_range(0..3);
    match style {
        0 => {
            // "Гость 4821" style (standard anonymous guest in Kontur.Talk)
            let num: u16 = rng.gen_range(1000..9999);
            format!("Гость {num}")
        }
        1 => {
            // Realistic given name
            let idx = rng.gen_range(0..COMMON_GUEST_NAMES.len());
            COMMON_GUEST_NAMES[idx].to_string()
        }
        _ => {
            // "Пользователь 528" style
            let num: u16 = rng.gen_range(100..999);
            format!("Пользователь {num}")
        }
    }
}

/// Generates a standard RFC 4122 UUIDv4 string for WebRTC MediaStream and MediaStreamTrack IDs.
pub fn generate_random_uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}


