//! Валидаторы сетевых адресов

/// Проверка валидности IP, подсети (CIDR) или доменного имени для исключений
pub fn validate_exclude_route(value: &str) -> bool {
    let value = value.trim();

    if value.is_empty() || value.chars().any(|c| c.is_whitespace()) {
        return false;
    }

    if value.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }

    if let Some((ip, prefix)) = value.split_once('/') {
        if let (Ok(addr), Ok(prefix)) = (ip.parse::<std::net::IpAddr>(), prefix.parse::<u8>()) {
            let max_prefix = match addr {
                std::net::IpAddr::V4(_) => 32,
                std::net::IpAddr::V6(_) => 128,
            };
            return prefix <= max_prefix;
        }
    }

    if value.contains("://")
        || value.contains(':')
        || value.contains('*')
        || value.starts_with('.')
        || value.ends_with('.')
    {
        return false;
    }

    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}
