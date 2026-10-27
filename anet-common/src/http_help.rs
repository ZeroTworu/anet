use crate::boring_tls::{
    build_ssl_connector_with_config, connect_ws_tls_with_config, get_default_tls_config,
    TlsClientConfig, TlsFingerprint,
};
use http::{HeaderValue, Request};
use rand::seq::SliceRandom;
use rand::Rng;
use std::net::{IpAddr, SocketAddr};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

/// Профиль браузера, жёстко синхронизирующий L7 (HTTP/1.1, HTTP/2, WebSocket заголовки)
/// и L4 (TLS-отпечаток BoringSSL ClientHello и защиту от активного спуфинга ТСПУ).
#[derive(Debug, Clone)]
pub struct BrowserProfile {
    pub user_agent: &'static str,
    pub sec_ch_ua: Option<&'static str>,
    pub sec_ch_ua_mobile: &'static str,
    pub sec_ch_ua_platform: &'static str,
    pub accept_language: &'static str,
    pub accept_encoding: &'static str,
    pub tls_config: TlsClientConfig,
}

#[derive(Debug, Clone, Copy)]
struct StaticBrowserTemplate {
    family: TlsFingerprint,
    user_agent: &'static str,
    sec_ch_ua: Option<&'static str>,
    sec_ch_ua_mobile: &'static str,
    sec_ch_ua_platform: &'static str,
    accept_language: &'static str,
    accept_encoding: &'static str,
}

#[cfg(target_os = "windows")]
const CHROME_TEMPLATES: &[StaticBrowserTemplate] = &[
    StaticBrowserTemplate {
        family: TlsFingerprint::Chrome,
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        sec_ch_ua: Some("\"Google Chrome\";v=\"135\", \"Not-A.Brand\";v=\"8\", \"Chromium\";v=\"135\""),
        sec_ch_ua_mobile: "?0",
        sec_ch_ua_platform: "\"Windows\"",
        accept_language: "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        accept_encoding: "gzip, deflate, br, zstd",
    },
    StaticBrowserTemplate {
        family: TlsFingerprint::Chrome,
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0",
        sec_ch_ua: Some("\"Microsoft Edge\";v=\"136\", \"Chromium\";v=\"136\", \"Not_A Brand\";v=\"24\""),
        sec_ch_ua_mobile: "?0",
        sec_ch_ua_platform: "\"Windows\"",
        accept_language: "ru,en;q=0.9,en-GB;q=0.8,en-US;q=0.7",
        accept_encoding: "gzip, deflate, br, zstd",
    },
    StaticBrowserTemplate {
        family: TlsFingerprint::Chrome,
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 YaBrowser/25.2.0.0 Safari/537.36",
        sec_ch_ua: Some("\"Chromium\";v=\"134\", \"Not:A-Brand\";v=\"24\", \"YaBrowser\";v=\"25.2\""),
        sec_ch_ua_mobile: "?0",
        sec_ch_ua_platform: "\"Windows\"",
        accept_language: "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        accept_encoding: "gzip, deflate, br, zstd",
    },
];

#[cfg(target_os = "windows")]
const FIREFOX_TEMPLATES: &[StaticBrowserTemplate] = &[
    StaticBrowserTemplate {
        family: TlsFingerprint::Firefox,
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0",
        sec_ch_ua: None,
        sec_ch_ua_mobile: "?0",
        sec_ch_ua_platform: "\"Windows\"",
        accept_language: "ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3",
        accept_encoding: "gzip, deflate, br, zstd",
    },
    StaticBrowserTemplate {
        family: TlsFingerprint::Firefox,
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
        sec_ch_ua: None,
        sec_ch_ua_mobile: "?0",
        sec_ch_ua_platform: "\"Windows\"",
        accept_language: "ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3",
        accept_encoding: "gzip, deflate, br, zstd",
    },
];

#[cfg(target_os = "macos")]
const CHROME_TEMPLATES: &[StaticBrowserTemplate] = &[
    StaticBrowserTemplate {
        family: TlsFingerprint::Chrome,
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        sec_ch_ua: Some("\"Google Chrome\";v=\"135\", \"Not-A.Brand\";v=\"8\", \"Chromium\";v=\"135\""),
        sec_ch_ua_mobile: "?0",
        sec_ch_ua_platform: "\"macOS\"",
        accept_language: "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        accept_encoding: "gzip, deflate, br, zstd",
    },
    StaticBrowserTemplate {
        family: TlsFingerprint::Chrome,
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        sec_ch_ua: Some("\"Chromium\";v=\"136\", \"Google Chrome\";v=\"136\", \"Not_A Brand\";v=\"24\""),
        sec_ch_ua_mobile: "?0",
        sec_ch_ua_platform: "\"macOS\"",
        accept_language: "ru-RU,ru;q=0.9,en;q=0.8",
        accept_encoding: "gzip, deflate, br, zstd",
    },
];

#[cfg(target_os = "macos")]
const FIREFOX_TEMPLATES: &[StaticBrowserTemplate] = &[
    StaticBrowserTemplate {
        family: TlsFingerprint::Firefox,
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:136.0) Gecko/20100101 Firefox/136.0",
        sec_ch_ua: None,
        sec_ch_ua_mobile: "?0",
        sec_ch_ua_platform: "\"macOS\"",
        accept_language: "ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3",
        accept_encoding: "gzip, deflate, br, zstd",
    },
];

#[cfg(target_os = "android")]
const CHROME_TEMPLATES: &[StaticBrowserTemplate] = &[
    StaticBrowserTemplate {
        family: TlsFingerprint::Chrome,
        user_agent: "Mozilla/5.0 (Linux; Android 14; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
        sec_ch_ua: Some("\"Google Chrome\";v=\"135\", \"Not-A.Brand\";v=\"8\", \"Chromium\";v=\"135\""),
        sec_ch_ua_mobile: "?1",
        sec_ch_ua_platform: "\"Android\"",
        accept_language: "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        accept_encoding: "gzip, deflate, br, zstd",
    },
    StaticBrowserTemplate {
        family: TlsFingerprint::Chrome,
        user_agent: "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Mobile Safari/537.36",
        sec_ch_ua: Some("\"Chromium\";v=\"136\", \"Google Chrome\";v=\"136\", \"Not_A Brand\";v=\"24\""),
        sec_ch_ua_mobile: "?1",
        sec_ch_ua_platform: "\"Android\"",
        accept_language: "ru-RU,ru;q=0.9,en;q=0.8",
        accept_encoding: "gzip, deflate, br, zstd",
    },
];

#[cfg(target_os = "android")]
const FIREFOX_TEMPLATES: &[StaticBrowserTemplate] = &[
    StaticBrowserTemplate {
        family: TlsFingerprint::Firefox,
        user_agent: "Mozilla/5.0 (Android 14; Mobile; rv:136.0) Gecko/136.0 Firefox/136.0",
        sec_ch_ua: None,
        sec_ch_ua_mobile: "?1",
        sec_ch_ua_platform: "\"Android\"",
        accept_language: "ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3",
        accept_encoding: "gzip, deflate, br, zstd",
    },
];

#[cfg(target_os = "ios")]
const CHROME_TEMPLATES: &[StaticBrowserTemplate] = &[
    StaticBrowserTemplate {
        family: TlsFingerprint::Safari,
        user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/135.0.7049.53 Mobile/15E148 Safari/604.1",
        sec_ch_ua: None,
        sec_ch_ua_mobile: "?1",
        sec_ch_ua_platform: "\"iOS\"",
        accept_language: "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        accept_encoding: "gzip, deflate, br",
    },
];

#[cfg(target_os = "ios")]
const FIREFOX_TEMPLATES: &[StaticBrowserTemplate] = &[
    StaticBrowserTemplate {
        family: TlsFingerprint::Safari,
        user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/136.0 Mobile/15E148 Safari/605.1.15",
        sec_ch_ua: None,
        sec_ch_ua_mobile: "?1",
        sec_ch_ua_platform: "\"iOS\"",
        accept_language: "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        accept_encoding: "gzip, deflate, br",
    },
];

#[cfg(not(any(
    target_os = "windows",
    target_os = "macos",
    target_os = "android",
    target_os = "ios"
)))]
const CHROME_TEMPLATES: &[StaticBrowserTemplate] = &[
    StaticBrowserTemplate {
        family: TlsFingerprint::Chrome,
        user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        sec_ch_ua: Some("\"Google Chrome\";v=\"135\", \"Not-A.Brand\";v=\"8\", \"Chromium\";v=\"135\""),
        sec_ch_ua_mobile: "?0",
        sec_ch_ua_platform: "\"Linux\"",
        accept_language: "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        accept_encoding: "gzip, deflate, br, zstd",
    },
    StaticBrowserTemplate {
        family: TlsFingerprint::Chrome,
        user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        sec_ch_ua: Some("\"Chromium\";v=\"136\", \"Google Chrome\";v=\"136\", \"Not_A Brand\";v=\"24\""),
        sec_ch_ua_mobile: "?0",
        sec_ch_ua_platform: "\"Linux\"",
        accept_language: "ru,en-US;q=0.9,en;q=0.8",
        accept_encoding: "gzip, deflate, br, zstd",
    },
];

#[cfg(not(any(
    target_os = "windows",
    target_os = "macos",
    target_os = "android",
    target_os = "ios"
)))]
const FIREFOX_TEMPLATES: &[StaticBrowserTemplate] = &[
    StaticBrowserTemplate {
        family: TlsFingerprint::Firefox,
        user_agent: "Mozilla/5.0 (X11; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0",
        sec_ch_ua: None,
        sec_ch_ua_mobile: "?0",
        sec_ch_ua_platform: "\"Linux\"",
        accept_language: "ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3",
        accept_encoding: "gzip, deflate, br, zstd",
    },
    StaticBrowserTemplate {
        family: TlsFingerprint::Firefox,
        user_agent: "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0",
        sec_ch_ua: None,
        sec_ch_ua_mobile: "?0",
        sec_ch_ua_platform: "\"Linux\"",
        accept_language: "ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3",
        accept_encoding: "gzip, deflate, br, zstd",
    },
];

const SAFARI_TEMPLATES: &[StaticBrowserTemplate] = &[
    #[cfg(target_os = "ios")]
    StaticBrowserTemplate {
        family: TlsFingerprint::Safari,
        user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
        sec_ch_ua: None,
        sec_ch_ua_mobile: "?1",
        sec_ch_ua_platform: "\"iOS\"",
        accept_language: "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        accept_encoding: "gzip, deflate, br",
    },
    #[cfg(not(target_os = "ios"))]
    StaticBrowserTemplate {
        family: TlsFingerprint::Safari,
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
        sec_ch_ua: None,
        sec_ch_ua_mobile: "?0",
        sec_ch_ua_platform: "\"macOS\"",
        accept_language: "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        accept_encoding: "gzip, deflate, br",
    },
];

impl BrowserProfile {
    /// Возвращает случайный профиль браузера, синхронизированный с текущей глобальной конфигурацией TLS (`[stealth]`).
    pub fn random() -> Self {
        let cfg = get_default_tls_config();
        Self::with_tls_config(cfg)
    }

    /// Создаёт профиль браузера с явно указанным режимом TLS-отпечатка и глобальными настройками верификации.
    pub fn for_fingerprint(fingerprint: TlsFingerprint) -> Self {
        let mut cfg = get_default_tls_config();
        cfg.fingerprint = fingerprint;
        Self::with_tls_config(cfg)
    }

    /// Создаёт профиль браузера с полной синхронизацией L4 (TLS ClientHello) и L7 (HTTP-заголовки)
    /// по переданному `TlsClientConfig`.
    pub fn with_tls_config(mut tls_config: TlsClientConfig) -> Self {
        let mut rng = rand::thread_rng();
        if tls_config.random_seed == 0 {
            tls_config.random_seed = rng.r#gen();
        }

        let concrete = tls_config.fingerprint.resolve_for_os(tls_config.random_seed);
        let template = match concrete {
            TlsFingerprint::Chrome | TlsFingerprint::Auto => CHROME_TEMPLATES
                .choose(&mut rng)
                .copied()
                .unwrap_or(CHROME_TEMPLATES[0]),
            TlsFingerprint::Firefox => FIREFOX_TEMPLATES
                .choose(&mut rng)
                .copied()
                .unwrap_or(FIREFOX_TEMPLATES[0]),
            TlsFingerprint::Safari => SAFARI_TEMPLATES
                .choose(&mut rng)
                .copied()
                .unwrap_or(SAFARI_TEMPLATES[0]),
            TlsFingerprint::Randomized => {
                // В режиме Randomized выбираем между шаблонами Chrome и Firefox для текущей ОС,
                // сохраняя сам режим TLS как Randomized (полиморфный отпечаток).
                if (tls_config.random_seed & 1) == 0 {
                    CHROME_TEMPLATES
                        .choose(&mut rng)
                        .copied()
                        .unwrap_or(CHROME_TEMPLATES[0])
                } else {
                    FIREFOX_TEMPLATES
                        .choose(&mut rng)
                        .copied()
                        .unwrap_or(FIREFOX_TEMPLATES[0])
                }
            }
        };

        // Если был выбран Auto, фиксируем конкретный TLS-профиль шаблона (Chrome/Firefox/Safari или Randomized),
        // чтобы НЕ возникло рассинхрона между L7 User-Agent и L4 TLS ClientHello!
        if tls_config.fingerprint == TlsFingerprint::Auto {
            tls_config.fingerprint = if concrete == TlsFingerprint::Randomized {
                TlsFingerprint::Randomized
            } else {
                template.family
            };
        }

        Self {
            user_agent: template.user_agent,
            sec_ch_ua: template.sec_ch_ua,
            sec_ch_ua_mobile: template.sec_ch_ua_mobile,
            sec_ch_ua_platform: template.sec_ch_ua_platform,
            accept_language: template.accept_language,
            accept_encoding: template.accept_encoding,
            tls_config,
        }
    }

    /// Создает сконфигурированный `reqwest::ClientBuilder` со встроенным TLS-отпечатком BoringSSL,
    /// синхронизированным с этим `BrowserProfile`, защитой от активного спуфинга и сессионным Cookie Jar.
    /// Это ЕДИНСТВЕННАЯ разрешенная точка создания HTTP-клиентов `reqwest` во всей системе.
    pub fn build_reqwest_builder(
        &self,
        cookie_jar: std::sync::Arc<reqwest::cookie::Jar>,
    ) -> anyhow::Result<reqwest::ClientBuilder> {
        let ssl_builder = build_ssl_connector_with_config(&self.tls_config)?;
        let verify_hostname = self.tls_config.verify_peer
            && self
                .tls_config
                .pin_sha256
                .as_ref()
                .is_none_or(|p| p.trim().is_empty());
        let builder = reqwest::Client::builder()
            .use_preconfigured_tls(ssl_builder.build())
            .tls_danger_accept_invalid_certs(!self.tls_config.verify_peer)
            .tls_danger_accept_invalid_hostnames(!verify_hostname)
            .user_agent(self.user_agent)
            .cookie_provider(cookie_jar)
            .tcp_nodelay(true);
        Ok(builder)
    }

    /// Выполняет асинхронный клиентский TLS-хендшейк для WebSocket (`ALPN: http/1.1`),
    /// используя профиль TLS и политику защиты от спуфинга данного `BrowserProfile`.
    pub async fn connect_ws_tls<S>(
        &self,
        domain: &str,
        stream: S,
    ) -> anyhow::Result<tokio_boring::SslStream<S>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        connect_ws_tls_with_config(domain, stream, &self.tls_config).await
    }

    /// Накладывает браузерные заголовки на HTTP-запрос `reqwest::RequestBuilder`.
    /// Для профилей Firefox и Safari заголовки `sec-ch-ua*` НЕ отправляются (так как эти браузеры не поддерживают Client Hints).
    /// Примечание: `Accept-Encoding` намеренно НЕ выставляется вручную, так как `reqwest` собран без фич
    /// декомпрессии (`gzip`, `brotli`, `zstd`), и при отправке `Accept-Encoding: gzip, deflate, br, zstd`
    /// серверы (например, Ktalk / Envoy / Nginx) возвращают сжатое тело (`Content-Encoding: br`),
    /// что приводит к ошибке `error decoding response body` при парсинге JSON.
    pub fn apply_to_reqwest(
        &self,
        mut req: reqwest::RequestBuilder,
        origin: Option<&str>,
        referer: Option<&str>,
    ) -> reqwest::RequestBuilder {
        req = req
            .header("User-Agent", self.user_agent)
            .header("Accept-Language", self.accept_language)
            .header("Cache-Control", "no-cache")
            .header("Pragma", "no-cache")
            .header("Sec-Fetch-Dest", "empty")
            .header("Sec-Fetch-Mode", "cors")
            .header("Sec-Fetch-Site", "same-origin")
            .header("Priority", "u=1, i");

        if let Some(ch_ua) = self.sec_ch_ua {
            req = req
                .header("sec-ch-ua", ch_ua)
                .header("sec-ch-ua-mobile", self.sec_ch_ua_mobile)
                .header("sec-ch-ua-platform", self.sec_ch_ua_platform);
        }

        if let Some(orig) = origin {
            req = req.header("Origin", orig);
        }
        if let Some(refr) = referer {
            req = req.header("Referer", refr);
        }
        req
    }

    /// Строит WebSocket Upgrade-запрос с полным комплектом браузерных заголовков,
    /// строго соответствующих выбранному профилю браузера.
    pub fn build_ws_request(&self, url: &str, origin: Option<&str>) -> anyhow::Result<Request<()>> {
        let mut req = url.into_client_request()?;
        let uri = req.uri().clone();
        let target_host = uri.host();

        let effective_origin = origin.map(|s| s.to_string()).unwrap_or_else(|| {
            let scheme = match uri.scheme_str() {
                Some(s) if s.eq_ignore_ascii_case("ws") || s.eq_ignore_ascii_case("http") => "http",
                _ => "https",
            };
            match uri.port_u16() {
                Some(p) if p != 80 && p != 443 => {
                    format!("{scheme}://{}:{p}", target_host.unwrap_or("localhost"))
                }
                _ => format!("{scheme}://{}", target_host.unwrap_or("localhost")),
            }
        });

        let sec_fetch_site = compute_sec_fetch_site(target_host, &effective_origin);
        let headers = req.headers_mut();

        headers.insert("User-Agent", HeaderValue::from_static(self.user_agent));
        headers.insert(
            "Accept-Language",
            HeaderValue::from_static(self.accept_language),
        );
        headers.insert(
            "Accept-Encoding",
            HeaderValue::from_static(self.accept_encoding),
        );
        headers.insert("Cache-Control", HeaderValue::from_static("no-cache"));
        headers.insert("Pragma", HeaderValue::from_static("no-cache"));
        headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("websocket"));
        headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("websocket"));
        headers.insert("Sec-Fetch-Site", HeaderValue::from_static(sec_fetch_site));

        if let Some(ch_ua) = self.sec_ch_ua {
            headers.insert("sec-ch-ua", HeaderValue::from_static(ch_ua));
            headers.insert(
                "sec-ch-ua-mobile",
                HeaderValue::from_static(self.sec_ch_ua_mobile),
            );
            headers.insert(
                "sec-ch-ua-platform",
                HeaderValue::from_static(self.sec_ch_ua_platform),
            );
        }

        if let Ok(val) = HeaderValue::from_str(&effective_origin) {
            headers.insert("Origin", val);
        }

        Ok(req)
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
    fn test_l4_l7_profile_synchronization_no_header_leaks() {
        // 1. Профиль Chrome обязан иметь sec-ch-ua* и TLS Chrome
        let chrome = BrowserProfile::for_fingerprint(TlsFingerprint::Chrome);
        assert_eq!(chrome.tls_config.fingerprint, TlsFingerprint::Chrome);
        assert!(chrome.user_agent.contains("Chrome/") || chrome.user_agent.contains("CriOS/"));
        let ws_req_chrome = chrome
            .build_ws_request("wss://vpn.example.com/socket", None)
            .unwrap();
        if chrome.sec_ch_ua.is_some() {
            assert!(ws_req_chrome.headers().contains_key("sec-ch-ua"));
            assert!(ws_req_chrome.headers().contains_key("sec-ch-ua-mobile"));
            assert!(ws_req_chrome.headers().contains_key("sec-ch-ua-platform"));
        }

        // 2. Профиль Firefox обязан иметь TLS Firefox и НЕ ДОЛЖЕН отправлять sec-ch-ua*
        let ff = BrowserProfile::for_fingerprint(TlsFingerprint::Firefox);
        assert_eq!(ff.tls_config.fingerprint, TlsFingerprint::Firefox);
        assert!(
            ff.sec_ch_ua.is_none(),
            "Firefox profile must never set sec_ch_ua"
        );
        let ws_req_ff = ff
            .build_ws_request("wss://vpn.example.com/socket", None)
            .unwrap();
        assert!(
            !ws_req_ff.headers().contains_key("sec-ch-ua"),
            "Firefox must not send sec-ch-ua"
        );
        assert!(
            !ws_req_ff.headers().contains_key("sec-ch-ua-mobile"),
            "Firefox must not leak sec-ch-ua-mobile"
        );
        assert!(
            !ws_req_ff.headers().contains_key("sec-ch-ua-platform"),
            "Firefox must not leak sec-ch-ua-platform"
        );

        // 3. Профиль Safari обязан иметь TLS Safari, Accept-Encoding без zstd и НЕ ДОЛЖЕН отправлять sec-ch-ua*
        let safari = BrowserProfile::for_fingerprint(TlsFingerprint::Safari);
        assert_eq!(safari.tls_config.fingerprint, TlsFingerprint::Safari);
        assert!(safari.sec_ch_ua.is_none());
        assert_eq!(safari.accept_encoding, "gzip, deflate, br");
        let ws_req_safari = safari
            .build_ws_request("wss://vpn.example.com/socket", None)
            .unwrap();
        assert!(!ws_req_safari.headers().contains_key("sec-ch-ua"));
        assert!(!ws_req_safari.headers().contains_key("sec-ch-ua-mobile"));
        assert!(!ws_req_safari.headers().contains_key("sec-ch-ua-platform"));

        // 4. Профиль Auto всегда разрешается в конкретный синхронизированный отпечаток (не остаётся Auto)
        for _ in 0..20 {
            let auto_prof = BrowserProfile::for_fingerprint(TlsFingerprint::Auto);
            assert_ne!(
                auto_prof.tls_config.fingerprint,
                TlsFingerprint::Auto,
                "Auto profile must resolve to a concrete TLS fingerprint matching L7 headers"
            );
            if auto_prof.tls_config.fingerprint == TlsFingerprint::Firefox {
                assert!(auto_prof.sec_ch_ua.is_none());
                assert!(auto_prof.user_agent.contains("Firefox") || auto_prof.user_agent.contains("FxiOS"));
            }
        }
    }

    #[test]
    fn real_ip_extraction_behind_nginx() {
        let fallback: SocketAddr = "127.0.0.1:45120".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "X-Forwarded-For",
            HeaderValue::from_static("203.0.113.42, 10.0.0.1"),
        );
        let extracted = extract_real_ip(&headers, fallback);
        assert_eq!(extracted.ip().to_string(), "203.0.113.42");
        assert_eq!(extracted.port(), 45120);

        let raw_headers = [("X-Real-IP", b"198.51.100.7" as &[u8])];
        let extracted_raw = extract_real_ip_from_raw(raw_headers, fallback);
        assert_eq!(extracted_raw.ip().to_string(), "198.51.100.7");
        assert_eq!(extracted_raw.port(), 0);
    }
}
