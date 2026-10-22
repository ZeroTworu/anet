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

