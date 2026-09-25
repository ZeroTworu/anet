use crate::http_help::{BrowserProfile, CHROME_BRANDS, CHROME_PLATFORMS};
use http::header::{ACCEPT, ACCEPT_LANGUAGE, CACHE_CONTROL, ORIGIN, PRAGMA, USER_AGENT};
use http::HeaderValue;
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

/// Applies browser stealth headers to a reqwest RequestBuilder.
pub fn apply_reqwest_browser_headers(
    builder: reqwest::RequestBuilder,
    profile: &BrowserProfile,
    origin: Option<&str>,
    referer: Option<&str>,
) -> reqwest::RequestBuilder {
    let mut builder = builder
        .header("User-Agent", profile.user_agent)
        .header("Accept-Language", profile.accept_language)
        .header("Cache-Control", "no-cache")
        .header("Pragma", "no-cache")
        .header("Sec-Fetch-Dest", "empty")
        .header("Sec-Fetch-Mode", "cors")
        .header("Sec-Fetch-Site", "same-origin");

    if let Some(orig) = origin {
        builder = builder.header("Origin", orig);
    }
    if let Some(ref_url) = referer {
        builder = builder.header("Referer", ref_url);
    }

    if let Some(index) = profile.chrome_profile {
        builder = builder
            .header("sec-ch-ua", CHROME_BRANDS[index])
            .header("sec-ch-ua-mobile", "?0")
            .header("sec-ch-ua-platform", CHROME_PLATFORMS[index]);
    }

    builder
}

/// Applies browser stealth headers to an http::Request (e.g. for Tungstenite WebSocket).
pub fn apply_ws_browser_headers<T>(
    request: &mut http::Request<T>,
    profile: &BrowserProfile,
    origin: &str,
) -> anyhow::Result<()> {
    let headers = request.headers_mut();

    headers.insert(USER_AGENT, HeaderValue::from_str(profile.user_agent)?);
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_str(profile.accept_language)?);
    headers.insert(ORIGIN, HeaderValue::from_str(origin)?);
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(ACCEPT, HeaderValue::from_static("*/*"));

    if let Some(index) = profile.chrome_profile {
        headers.insert("sec-ch-ua", HeaderValue::from_static(CHROME_BRANDS[index]));
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert("sec-ch-ua-platform", HeaderValue::from_static(CHROME_PLATFORMS[index]));
    }

    Ok(())
}
