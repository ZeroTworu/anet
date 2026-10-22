use http::HeaderValue;
use http::header::{
    ACCEPT_ENCODING, ACCEPT_LANGUAGE, CACHE_CONTROL, ORIGIN, PRAGMA, REFERER, USER_AGENT,
};
use rand::{Rng, seq::SliceRandom};
use std::net::{IpAddr, SocketAddr};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

pub const CHROME_USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
];

pub const FIREFOX_USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:156.0) Gecko/20100101 Firefox/156.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:155.0) Gecko/20100101 Firefox/155.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:154.0) Gecko/20100101 Firefox/154.0",
];

pub const SAFARI_USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Mobile/15E148 Safari/604.1",
];

pub const CHROME_BRANDS: &[&str] = &[
    "\"Chromium\";v=\"153\", \"Google Chrome\";v=\"153\", \"Not-A.Brand\";v=\"99\"",
    "\"Chromium\";v=\"153\", \"Google Chrome\";v=\"153\", \"Not-A.Brand\";v=\"99\"",
    "\"Google Chrome\";v=\"152\", \"Chromium\";v=\"152\", \"Not_A Brand\";v=\"24\"",
    "\"Google Chrome\";v=\"151\", \"Chromium\";v=\"151\", \"Not_A Brand\";v=\"24\"",
];

pub const CHROME_PLATFORMS: &[&str] = &["\"Windows\"", "\"Linux\"", "\"macOS\"", "\"Windows\""];

pub const ACCEPT_LANGUAGES: &[&str] = &[
    "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,en-US;q=0.8,en;q=0.7",
];

#[derive(Clone, Debug)]
pub struct BrowserProfile {
    pub user_agent: &'static str,
    pub accept_language: &'static str,
    pub accept_encoding: &'static str,
    pub chrome_profile: Option<usize>,
}

impl BrowserProfile {
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let family = rng.gen_range(0..3);
        let (user_agent, accept_encoding, chrome_profile) = match family {
            0 => {
                let index = rng.gen_range(0..CHROME_USER_AGENTS.len());
                (
                    CHROME_USER_AGENTS[index],
                    "gzip, deflate, br, zstd",
                    Some(index),
                )
            }
            1 => (
                *FIREFOX_USER_AGENTS
                    .choose(&mut rng)
                    .unwrap_or(&FIREFOX_USER_AGENTS[0]),
                "gzip, deflate, br, zstd",
                None,
            ),
            _ => (
                *SAFARI_USER_AGENTS
                    .choose(&mut rng)
                    .unwrap_or(&SAFARI_USER_AGENTS[0]),
                "gzip, deflate, br",
                None,
            ),
        };
        Self {
            user_agent,
            accept_language: *ACCEPT_LANGUAGES
                .choose(&mut rng)
                .unwrap_or(&ACCEPT_LANGUAGES[0]),
            accept_encoding,
            chrome_profile,
        }
    }

    /// Применяет браузерные заголовки к запросу `reqwest::RequestBuilder` (для `AHTTP` и `WRTC` REST).
    /// Не переопределяет `Host` и `Connection`, позволяя `hyper`/`reqwest` корректно работать
    /// как по HTTP/2 (`:authority` без `Connection`), так и по HTTP/1.1 (`Host` + `Connection: keep-alive`).
    pub fn apply_to_reqwest(
        &self,
        builder: reqwest::RequestBuilder,
        origin: Option<&str>,
        referer: Option<&str>,
    ) -> reqwest::RequestBuilder {
        let mut builder = builder
            .header(USER_AGENT, self.user_agent)
            .header(ACCEPT_LANGUAGE, self.accept_language)
            .header(ACCEPT_ENCODING, self.accept_encoding)
            .header(CACHE_CONTROL, "no-cache")
            .header(PRAGMA, "no-cache")
            .header("Priority", "u=1, i")
            .header("Sec-Fetch-Dest", "empty")
            .header("Sec-Fetch-Mode", "cors")
            .header("Sec-Fetch-Site", "same-origin");

        if let Some(orig) = origin {
            builder = builder.header(ORIGIN, orig);
        }
        if let Some(ref_url) = referer {
            builder = builder.header(REFERER, ref_url);
        }

        if let Some(index) = self.chrome_profile {
            builder = builder
                .header("sec-ch-ua", CHROME_BRANDS[index])
                .header("sec-ch-ua-mobile", "?0")
                .header("sec-ch-ua-platform", CHROME_PLATFORMS[index]);
        }

        builder
    }

    /// Применяет браузерные заголовки к `http::Request` для апгрейда WebSocket (`tokio-tungstenite`).
    /// Если `origin` не передан, автоматически вычисляет его из URI запроса (`wss://` -> `https://`, `ws://` -> `http://`).
    pub fn apply_to_ws_request<T>(
        &self,
        request: &mut http::Request<T>,
        origin: Option<&str>,
    ) -> anyhow::Result<()> {
        let uri = request.uri().clone();
        let target_host = uri.host();

        let computed_origin;
        let effective_origin = match origin {
            Some(orig) => orig,
            None => {
                let scheme = match uri.scheme_str() {
                    Some(s) if s.eq_ignore_ascii_case("wss") || s.eq_ignore_ascii_case("https") => {
                        "https"
                    }
                    _ => "http",
                };
                let authority = uri
                    .authority()
                    .map(|a| a.as_str())
                    .unwrap_or("localhost");
                computed_origin = format!("{scheme}://{authority}");
                computed_origin.as_str()
            }
        };

        let sec_fetch_site = compute_sec_fetch_site(target_host, effective_origin);

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
        headers.insert(ORIGIN, HeaderValue::from_str(effective_origin)?);
        headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("websocket"));
        headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("websocket"));
        headers.insert("Sec-Fetch-Site", HeaderValue::from_static(sec_fetch_site));

        if let Some(index) = self.chrome_profile {
            headers.insert("sec-ch-ua", HeaderValue::from_static(CHROME_BRANDS[index]));
            headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
            headers.insert(
                "sec-ch-ua-platform",
                HeaderValue::from_static(CHROME_PLATFORMS[index]),
            );
        }

        Ok(())
    }

    /// Создаёт готовый `http::Request<()>` для `tokio-tungstenite` со всеми обязательными
    /// заголовками RFC 6455 (`Host`, `Upgrade`, `Connection`, `Sec-WebSocket-*`) и браузерной мимикрией.
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
fn compute_sec_fetch_site(target_host: Option<&str>, origin_url: &str) -> &'static str {
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
        let profile = BrowserProfile {
            user_agent: CHROME_USER_AGENTS[0],
            accept_language: ACCEPT_LANGUAGES[0],
            accept_encoding: "gzip, deflate, br, zstd",
            chrome_profile: Some(0),
        };

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
        assert!(req_same.headers().contains_key("sec-ch-ua"));

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
            req_cross.headers().get("Sec-Fetch-Site").unwrap(),
            "cross-site"
        );
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
    }
}


