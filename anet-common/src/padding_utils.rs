use rand::Rng;

/// Рассчитывает, сколько байт нужно добавить, чтобы `current_len` стало кратным `step`.
pub fn calculate_padding_needed(current_len: usize, step: u16) -> u16 {
    if step == 0 {
        return 0;
    }
    let step = step as usize;

    // Округляем вверх: ((x + step - 1) / step) * step
    let target = ((current_len + step - 1) / step) * step;

    target.saturating_sub(current_len) as u16
}

/// Генерирует вектор случайных байт для Protobuf (где паддинг виден или просто XOR-ен).
pub fn generate_random_padding(needed: u16) -> Vec<u8> {
    if needed == 0 {
        return Vec::new();
    }
    let mut rng = rand::thread_rng();
    let mut buf = vec![0u8; needed as usize];
    rng.fill(&mut buf[..]);
    buf
}
