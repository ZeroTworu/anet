use http::HeaderValue;
use http::header::{
    ACCEPT_ENCODING, ACCEPT_LANGUAGE, CACHE_CONTROL, ORIGIN, PRAGMA, REFERER, USER_AGENT,
};
use rand::seq::SliceRandom;
use std::net::{IpAddr, SocketAddr};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

/// Допустимые языковые локали для заголовка Accept-Language
pub const ACCEPT_LANGUAGES: &[&str] = &[
    "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
    "en-US,en;q=0.9",
];

/// Профиль браузера для маскировки HTTP-трафика клиента под легитимный веб-серфинг.
/// Обеспечивает консистентность L7 (HTTP) и L4 (TCP-отпечаток ОС).
#[derive(Clone, Debug)]
pub struct BrowserProfile {
    /// Значение заголовка User-Agent, строго соответствующее ОС клиента
    pub user_agent: &'static str,
    /// Значение заголовка Accept-Language
    pub accept_language: &'static str,
    /// Значение заголовка Accept-Encoding (всегда включает zstd, br, gzip)
    pub accept_encoding: &'static str,
    /// Бренд браузера для заголовка sec-ch-ua (например, "Chromium")
    pub ch_brand: &'static str,
    /// Платформа для заголовка sec-ch-ua-platform (например, "Windows" или "Android")
    pub ch_platform: &'static str,
    /// Флаг мобильного устройства для заголовка sec-ch-ua-mobile ("?0" или "?1")
    pub ch_mobile: &'static str,
}

impl BrowserProfile {
    /// Генерирует профиль браузера, строго соответствующий ОС, под которую скомпилирован клиент.
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let accept_language = *ACCEPT_LANGUAGES.choose(&mut rng).unwrap();
        // Строгое соответствие Chrome 153+
        let accept_encoding = "gzip, deflate, br, zstd";

        #[cfg(target_os = "windows")]
        {
            use rand::Rng;
            let uas = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36 Edg/153.0.0.0",
            ];
            let brands = [
                "\"Chromium\";v=\"153\", \"Google Chrome\";v=\"153\", \"Not_A Brand\";v=\"8\"",
                "\"Chromium\";v=\"153\", \"Microsoft Edge\";v=\"153\", \"Not_A Brand\";v=\"8\"",
            ];
            let idx = rng.gen_range(0..uas.len());
            Self {
                user_agent: uas[idx],
                accept_language,
                accept_encoding,
                ch_brand: brands[idx],
                ch_platform: "\"Windows\"",
                ch_mobile: "?0",
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Профиль на основе реального дампа Chromium на Linux (без Google Chrome в брендах)
            Self {
                user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
                accept_language,
                accept_encoding,
                ch_brand: "\"Chromium\";v=\"153\", \"Not_A Brand\";v=\"8\"",
                ch_platform: "\"Linux\"",
                ch_mobile: "?0",
            }
        }

        #[cfg(target_os = "macos")]
        {
            Self {
                user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
                accept_language,
                accept_encoding,
                ch_brand: "\"Chromium\";v=\"153\", \"Google Chrome\";v=\"153\", \"Not_A Brand\";v=\"8\"",
                ch_platform: "\"macOS\"",
                ch_mobile: "?0",
            }
        }

        #[cfg(target_os = "android")]
        {
            Self {
                user_agent: "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Mobile Safari/537.36",
                accept_language,
                accept_encoding,
                ch_brand: "\"Chromium\";v=\"153\", \"Google Chrome\";v=\"153\", \"Not_A Brand\";v=\"8\"",
                ch_platform: "\"Android\"",
                ch_mobile: "?1",
            }
        }

        #[cfg(target_os = "ios")]
        {
            // На iOS все браузеры работают на движке WebKit (Safari). Client Hints не отправляются.
            Self {
                user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
                accept_language,
                accept_encoding: "gzip, deflate, br",
                ch_brand: "",
                ch_platform: "",
                ch_mobile: "",
            }
        }

        #[cfg(not(any(
            target_os = "windows",
            target_os = "linux",
            target_os = "macos",
            target_os = "android",
            target_os = "ios"
        )))]
        {
            Self {
                user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
                accept_language,
                accept_encoding,
                ch_brand: "\"Chromium\";v=\"153\", \"Not_A Brand\";v=\"8\"",
                ch_platform: "\"Linux\"",
                ch_mobile: "?0",
            }
        }
    }

    /// Применяет маскировочные заголовки к запросу reqwest (AHTTP / WRTC Ktalk).
    pub fn apply_to_reqwest(
        &self,
        mut builder: reqwest::RequestBuilder,
        origin: Option<&str>,
        referer: Option<&str>,
    ) -> reqwest::RequestBuilder {
        builder = builder
            .header(USER_AGENT, self.user_agent)
            .header(ACCEPT_LANGUAGE, self.accept_language)
            .header(CACHE_CONTROL, "no-cache")
            .header(PRAGMA, "no-cache")
            .header("Priority", "u=1, i")
            .header("Sec-Fetch-Dest", "empty")
            .header("Sec-Fetch-Mode", "cors")
            .header("Sec-Fetch-Site", "same-origin");

        if !self.ch_brand.is_empty() {
            builder = builder
                .header("sec-ch-ua", self.ch_brand)
                .header("sec-ch-ua-platform", self.ch_platform)
                .header("sec-ch-ua-mobile", self.ch_mobile);
        }

        if let Some(orig) = origin {
            builder = builder.header(ORIGIN, orig);
        }
        if let Some(ref_url) = referer {
            builder = builder.header(REFERER, ref_url);
        }
        builder
    }

    /// Создает сконфигурированный `reqwest::ClientBuilder` со встроенным TLS-отпечатком BoringSSL Chrome Mimicry,
    /// поддержкой сессионного Cookie Jar и базовыми браузерными параметрами.
    /// Это ЕДИНСТВЕННАЯ разрешенная точка создания HTTP-клиентов `reqwest` во всей системе.
    pub fn build_reqwest_builder(&self, cookie_jar: std::sync::Arc<reqwest::cookie::Jar>) -> anyhow::Result<reqwest::ClientBuilder> {
        let ssl_builder = crate::boring_tls::build_chrome_ssl_connector()?;
        let builder = reqwest::Client::builder()
            .use_preconfigured_tls(ssl_builder.build())
            .user_agent(self.user_agent)
            .cookie_provider(cookie_jar)
            .tcp_nodelay(true);
        Ok(builder)
    }

    /// Применяет маскировочные заголовки к запросу tokio-tungstenite (WebSocket / WRTC XMPP).
    pub fn apply_to_ws_request<T>(
        &self,
        request: &mut http::Request<T>,
        origin: Option<&str>,
    ) -> anyhow::Result<()> {
        let uri = request.uri().clone();
        let target_host = uri.host();
        let effective_origin = origin.map(|s| s.to_string()).unwrap_or_else(|| {
            let scheme = match uri.scheme_str() {
                Some(s) if s.eq_ignore_ascii_case("wss") || s.eq_ignore_ascii_case("https") => {
                    "https"
                }
                _ => "http",
            };
            format!(
                "{}://{}",
                scheme,
                uri.authority().map(|a| a.as_str()).unwrap_or("localhost")
            )
        });

        let sec_fetch_site = compute_sec_fetch_site(target_host, &effective_origin);

        let headers = request.headers_mut();
        headers.insert(USER_AGENT, HeaderValue::from_static(self.user_agent));
        headers.insert(
            ACCEPT_LANGUAGE,
            HeaderValue::from_static(self.accept_language),
        );
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static(self.accept_encoding),
        );
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
        headers.insert(ORIGIN, HeaderValue::try_from(effective_origin)?);
        headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("websocket"));
        headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("websocket"));
        headers.insert("Sec-Fetch-Site", HeaderValue::from_static(sec_fetch_site));

        if !self.ch_brand.is_empty() {
            headers.insert("sec-ch-ua", HeaderValue::from_static(self.ch_brand));
            headers.insert(
                "sec-ch-ua-platform",
                HeaderValue::from_static(self.ch_platform),
            );
            headers.insert("sec-ch-ua-mobile", HeaderValue::from_static(self.ch_mobile));
        }

        Ok(())
    }

    /// Формирует готовый HTTP-запрос для WebSocket с примененными заголовками
    pub fn build_ws_request(
        &self,
        ws_url: &str,
        origin: Option<&str>,
    ) -> anyhow::Result<http::Request<()>> {
        let mut request = ws_url.into_client_request()?;
        self.apply_to_ws_request(&mut request, origin)?;
        Ok(request)
    }
}

/// Вычисляет корректное значение `Sec-Fetch-Site` (`same-origin`, `same-site` или `cross-site`)
/// при сопоставлении целевого хоста запроса и заголовка `Origin`.
pub fn compute_sec_fetch_site(target_host: Option<&str>, origin_url: &str) -> &'static str {
    let Some(target) = target_host else {
        return "same-origin";
    };
    let Ok(origin_uri) = origin_url.parse::<http::Uri>() else {
        return "same-origin";
    };
    let Some(orig_host) = origin_uri.host() else {
        return "same-origin";
    };
    if target.eq_ignore_ascii_case(orig_host) {
        return "same-origin";
    }
    if is_same_registrable_domain(target, orig_host) {
        return "same-site";
    }
    "cross-site"
}

fn is_same_registrable_domain(h1: &str, h2: &str) -> bool {
    if h1.parse::<IpAddr>().is_ok() || h2.parse::<IpAddr>().is_ok() {
        return false;
    }
    let mut p1 = h1.rsplit('.');
    let mut p2 = h2.rsplit('.');
    match (p1.next(), p1.next(), p2.next(), p2.next()) {
        (Some(tld1), Some(sld1), Some(tld2), Some(sld2)) => {
            tld1.eq_ignore_ascii_case(tld2) && sld1.eq_ignore_ascii_case(sld2)
        }
        _ => false,
    }
}

/// Извлекает реальный IP клиента из заголовков `X-Real-IP` или `X-Forwarded-For`,
/// выставленных обратным прокси (`nginx`), с откатом на `fallback` (адрес TCP-пира).
pub fn extract_real_ip(headers: &http::HeaderMap, fallback: SocketAddr) -> SocketAddr {
    for header_name in ["x-real-ip", "x-forwarded-for"] {
        if let Some(val) = headers.get(header_name) {
            if let Ok(ip_str) = val.to_str() {
                if let Some(ip) = parse_first_ip(ip_str) {
                    return SocketAddr::new(ip, fallback.port());
                }
            }
        }
    }
    fallback
}

/// Извлекает реальный IP клиента из сырых пар заголовков (например, `httparse::Header` в `http_stream.rs`).
pub fn extract_real_ip_from_raw<'a, I>(headers: I, fallback: SocketAddr) -> SocketAddr
where
    I: IntoIterator<Item = (&'a str, &'a [u8])>,
{
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("x-real-ip") || name.eq_ignore_ascii_case("x-forwarded-for") {
            if let Ok(ip_str) = std::str::from_utf8(value) {
                if let Some(ip) = parse_first_ip(ip_str) {
                    return SocketAddr::new(ip, 0);
                }
            }
        }
    }
    SocketAddr::new(fallback.ip(), 0)
}

fn parse_first_ip(ip_str: &str) -> Option<IpAddr> {
    let first = ip_str.split(',').next()?.trim();
    first.parse::<IpAddr>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_request_mimicry_and_sec_fetch_site() {
        let profile = BrowserProfile::random();

        // 1. Default same-origin derived from wss:// URL
        let req_same = profile
            .build_ws_request("wss://vpn.example.com:8443/socket", None)
            .unwrap();
        assert_eq!(
            req_same.headers().get("Origin").unwrap(),
            "https://vpn.example.com:8443"
        );
        assert_eq!(
            req_same.headers().get("Sec-Fetch-Site").unwrap(),
            "same-origin"
        );
        assert_eq!(
            req_same.headers().get("Sec-Fetch-Mode").unwrap(),
            "websocket"
        );
        assert_eq!(
            req_same.headers().get("Sec-Fetch-Dest").unwrap(),
            "websocket"
        );
        if !profile.ch_brand.is_empty() {
            assert!(req_same.headers().contains_key("sec-ch-ua"));
        }

        // 2. Subdomain (same-site), e.g. Colibri-WS on JVB subdomain with room domain Origin
        let req_sub = profile
            .build_ws_request(
                "wss://jvb-node-1.ktalk.host/colibri-ws/123",
                Some("https://company.ktalk.host"),
            )
            .unwrap();
        assert_eq!(
            req_sub.headers().get("Origin").unwrap(),
            "https://company.ktalk.host"
        );
        assert_eq!(
            req_sub.headers().get("Sec-Fetch-Site").unwrap(),
            "same-site"
        );

        // 3. Cross-site when connecting to raw IP with domain Origin
        let req_cross = profile
            .build_ws_request(
                "wss://89.169.16.6:443/colibri-ws/123",
                Some("https://company.ktalk.host"),
            )
            .unwrap();
        assert_eq!(
            req_cross.headers().get("Origin").unwrap(),
            "https://company.ktalk.host"
        );
        assert_eq!(
            req_cross.headers().get("Sec-Fetch-Site").unwrap(),
            "cross-site"
        );
    }
}
