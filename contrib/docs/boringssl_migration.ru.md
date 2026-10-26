# Спецификация: Миграция на BoringSSL и маскировка TLS-отпечатка (Chrome Mimicry)

Документация актуальна для ветки `master` и ветки `dev/boringssl`.

## 1. Введение и проблематика
Текущая реализация транспортов `AHTTP`, `WebSocket` и сигнальных каналов `WRTC` опирается на криптографическую библиотеку `rustls`. По умолчанию `rustls` формирует специфический TLS-отпечаток (JA3/JA4), который кардинально отличается от отпечатков популярных веб-браузеров (отсутствуют диагностические GREASE-расширения, изменен порядок Cipher Suites).

**Уязвимости текущего подхода в сложных сетях:**
1. **Пассивный анализ (IDS/IPS):** Системы глубокой инспекции пакетов классифицируют трафик `rustls` как машинный (нестандартный) и применяют к нему жесткие корпоративные политики маршрутизации (сброс сессий, троттлинг).
2. **Проактивная защита CDN (Cloudflare, Akamai) и TCP Fingerprinting:** Системы защиты от сетевых аномалий сверяют HTTP-заголовок `User-Agent` с реальным TLS-отпечатком и TCP-отпечатком операционной системы. Несовпадение (например, Android-клиент с заголовком Windows) приводит к разрыву соединения (TCP Reset).
3. **Отсутствие HTTP State:** Текущие транспорты не сохраняют сессионные маркеры (`Set-Cookie`), что воспринимается балансировщиками CDN как поведение примитивного скрипта и приводит к выдаче CAPTCHA/403 Forbidden при штатных переподключениях.

**Решение:**
1. **На стороне клиента:** Полный отказ от `rustls` в TCP-транспортах и сигнальных каналах в пользу библиотеки `boring` (биндинги к BoringSSL от Google). Строгая привязка HTTP-заголовков к ОС компиляции клиента. Реализация хранилища Cookie (Cookie Jar с привязкой по доменам).
2. **На стороне сервера:** Полный отказ от терминации TLS внутри `anet-server` для TCP-транспортов. Сервер всегда должен работать за Reverse Proxy (Nginx, HAProxy) или CDN, которые снимают HTTPS и передают в ANet чистый HTTP/WS трафик.

---

## 2. Изменения зависимостей (`Cargo.toml`)
Необходимо обновить зависимости в воркспейсе, отключив `rustls` для целевых библиотек и добавив `boring`.

В корневом `Cargo.toml` (секция `[workspace.dependencies]`):
```toml
# Биндинги к BoringSSL от Google для точного соответствия TLS-отпечатку Chromium
boring = "4.4"
tokio-boring = "4.4"

# Переключаем reqwest на boring-tls, отключаем rustls, добавляем поддержку cookies
reqwest = { version = "0.12.28", default-features = false, features = ["json", "boring-tls", "http2", "cookies"] }

# Отключаем rustls в tokio-tungstenite (оставляем только базовые фичи connect и handshake)
tokio-tungstenite = { version = "0.28.0", default-features = false, features = ["connect", "handshake"] }
```

---

## 3. Обновление сборочного конвейера (CI/CD)
Поскольку крейт `boring` компилирует C/C++ код BoringSSL из исходников (используя Go для кодогенерации и CMake для сборки), необходимо обновить файл `.github/workflows/build-components.yml`.

Внесите следующие изменения в соответствующие `jobs`:

1.  **Во все jobs (`build-linux-server`, `build-linux-client`, `build-windows-client`, `build-macos-client`):**
    Добавить шаг установки Go перед установкой системных зависимостей:
    ```yaml
      - name: "Install Go (Required for BoringSSL)"
        uses: actions/setup-go@v5
        with:
          go-version: '>=1.20'
    ```
2.  **В `build-linux-server` и `build-linux-client` (шаг `Install dependencies`):**
    Добавить `cmake` и `clang`:
    ```bash
    sudo apt-get install -y musl-tools protobuf-compiler gcc-aarch64-linux-gnu mingw-w64 cmake clang
    ```
    Для кросс-компиляции под musl:
    ```yaml
    env:
      CC_x86_64_unknown_linux_musl: musl-gcc
    ```
3.  **В `build-windows-client` (шаг `Install Build Tools (Windows)`):**
    Добавить `cmake` и `nasm` (критично для сборки под MSVC):
    ```powershell
    run: "choco install protoc cmake nasm -y"
    ```
4.  **В `build-macos-client` (шаг `Install Dependencies`):**
    Добавить `cmake`:
    ```bash
    run: brew install protobuf cmake
    ```
5.  **Для Android-сборки (`anet-mobile`):**
    Убедиться в наличии установленного Android NDK с переменными окружения `ANDROID_NDK_HOME` / `ANDROID_NDK_ROOT`.

---

## 4. Унификация HTTP-профиля (`anet-common/src/http_help.rs`)
Клиент должен мимикрировать строго под современные версии Chromium (v153+). `User-Agent`, `sec-ch-ua` и `sec-ch-ua-platform` должны **строго соответствовать операционной системе**, под которую скомпилирован бинарный файл клиента.

```rust
use http::HeaderValue;
use http::header::{
    ACCEPT_ENCODING, ACCEPT_LANGUAGE, CACHE_CONTROL, ORIGIN, PRAGMA, REFERER, USER_AGENT,
};
use rand::{Rng, seq::SliceRandom};
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
            let uas = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36 Edg/153.0.0.0"
            ];
            let brands = [
                "\"Chromium\";v=\"153\", \"Google Chrome\";v=\"153\", \"Not_A Brand\";v=\"8\"",
                "\"Chromium\";v=\"153\", \"Microsoft Edge\";v=\"153\", \"Not_A Brand\";v=\"8\""
            ];
            let idx = rng.gen_range(0..uas.len());
            Self { user_agent: uas[idx], accept_language, accept_encoding, ch_brand: brands[idx], ch_platform: "\"Windows\"", ch_mobile: "?0" }
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
                ch_mobile: "?0" 
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
                ch_mobile: "?0" 
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
                ch_mobile: "?1" 
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
                ch_mobile: "" 
            }
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos", target_os = "android", target_os = "ios")))]
        {
            Self { 
                user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36", 
                accept_language, 
                accept_encoding, 
                ch_brand: "\"Chromium\";v=\"153\", \"Not_A Brand\";v=\"8\"", 
                ch_platform: "\"Linux\"", 
                ch_mobile: "?0" 
            }
        }
    }

    /// Применяет маскировочные заголовки к запросу reqwest (AHTTP / WRTC Ktalk).
    pub fn apply_to_reqwest(&self, mut builder: reqwest::RequestBuilder, origin: Option<&str>, referer: Option<&str>) -> reqwest::RequestBuilder {
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

        if let Some(orig) = origin { builder = builder.header(ORIGIN, orig); }
        if let Some(ref_url) = referer { builder = builder.header(REFERER, ref_url); }
        builder
    }

    /// Применяет маскировочные заголовки к запросу tokio-tungstenite (WebSocket / WRTC XMPP).
    pub fn apply_to_ws_request<T>(&self, request: &mut http::Request<T>, origin: Option<&str>) -> anyhow::Result<()> {
        let uri = request.uri().clone();
        let target_host = uri.host();
        let effective_origin = origin.map(|s| s.to_string()).unwrap_or_else(|| {
            let scheme = match uri.scheme_str() {
                Some(s) if s.eq_ignore_ascii_case("wss") || s.eq_ignore_ascii_case("https") => "https",
                _ => "http",
            };
            format!("{}://{}", scheme, uri.authority().map(|a| a.as_str()).unwrap_or("localhost"))
        });

        let sec_fetch_site = crate::http_help::compute_sec_fetch_site(target_host, &effective_origin);
        
        let headers = request.headers_mut();
        headers.insert(USER_AGENT, HeaderValue::from_static(self.user_agent));
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static(self.accept_language));
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static(self.accept_encoding));
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
        headers.insert(ORIGIN, HeaderValue::try_from(effective_origin)?);
        headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("websocket"));
        headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("websocket"));
        headers.insert("Sec-Fetch-Site", HeaderValue::from_static(sec_fetch_site));

        if !self.ch_brand.is_empty() {
            headers.insert("sec-ch-ua", HeaderValue::from_static(self.ch_brand));
            headers.insert("sec-ch-ua-platform", HeaderValue::from_static(self.ch_platform));
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
```

---

## 5. Криптографический движок Chrome (`anet-common/src/boring_tls.rs`)
Создать новый файл `anet-common/src/boring_tls.rs`. Размещение в `anet-common` обязательно, так как он используется и в `anet-client-core`, и в `anet-common/src/wrtc`.

```rust
use boring::ssl::{SslConnector, SslConnectorBuilder, SslMethod, SslVerifyMode};

/// Создает конфигурацию BoringSSL, идеально мимикрирующую под Google Chrome.
/// Включает поддержку GREASE, строгий порядок шифров и ALPN.
pub fn build_chrome_ssl_connector() -> anyhow::Result<SslConnectorBuilder> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;

    // Включаем GREASE-расширения (ключевой маркер Chrome для обхода IDS/IPS)
    builder.set_grease_enabled(true);

    // ALPN: Заявляем поддержку HTTP/2 и HTTP/1.1
    builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;

    // Порядок шифров TLS 1.3 (Приоритет AES-GCM)
    builder.set_ciphersuites(
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
    )?;

    // Порядок шифров TLS 1.2
    builder.set_cipher_list(
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
         ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
         ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
    )?;

    // Доверие узлу ANet обеспечивается ASTP-хендшейком внутри туннеля.
    // Отключаем валидацию TLS сертификатов.
    builder.set_verify_callback(SslVerifyMode::NONE, |_preverify_ok, _x509_ctx| true);

    Ok(builder)
}
```

---

## 6. Интеграция в транспорты клиента и Управление Состоянием (Cookies)

### 6.1. AHTTP Транспорт (`anet-client-core/src/transport/ahttp.rs`)
Использовать встроенный Cookie Jar из `reqwest`. Имя хоста для TLS/SNI берётся из `server.host` (Domain Fronting) или домена URI.

```rust
use anet_common::boring_tls::build_chrome_ssl_connector;
use reqwest::cookie::Jar;
use std::sync::Arc;

// Внутри AHttpTransport::connect():
let cookie_jar = Arc::new(Jar::default());

let build_http_client = || -> Result<Client> {
    let ssl_builder = build_chrome_ssl_connector()?;
    let ssl_connector = ssl_builder.build();

    let mut builder = Client::builder()
        .resolve(&target_host, resolved_addr)
        .use_preconfigured_tls(ssl_connector)
        .cookie_provider(cookie_jar.clone()) // Включаем поддержку Cookie!
        .pool_max_idle_per_host(self.config.ahttp.pool_max_idle_per_host.max(2))
        // ... остальной код (http2 настройки) ...

    builder.build().map_err(|e| anyhow::anyhow!("Cannot build AHTTP client: {}", e))
};
```

### 6.2. WebSocket Транспорт (`anet-client-core/src/transport/websocket.rs`)
Реализовать Cookie Jar с привязкой по доменам (`host`) и TLS-рукопожатие через `tokio-boring`.

```rust
use tokio_boring::SslConnectorExt;
use anet_common::boring_tls::build_chrome_ssl_connector;
use anet_common::transport_trait::VpnStream;
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::net::TcpStream;

lazy_static::lazy_static! {
    /// Глобальное хранилище Cookie для WebSocket транспорта с разделением по хостам
    static ref WS_COOKIE_JAR: Mutex<HashMap<String, HashMap<String, String>>> = Mutex::new(HashMap::new());
}

async fn connect_authenticated(
    // ... параметры ...
) -> Result<(tokio_tungstenite::WebSocketStream<Box<dyn VpnStream>>, AuthResponse, [u8; 32], Option<std::net::IpAddr>)> {
    let url = server.websocket_url()?;
    let mut request = profile.build_ws_request(&url, None)?;
    let target_host = url.parse::<http::Uri>()?.host().unwrap_or("").to_string();
    
    // 1. ПОДСТАВЛЯЕМ СОХРАНЕННЫЕ КУКИ ДЛЯ ДАННОГО ХОСТА
    {
        let jar = WS_COOKIE_JAR.lock().unwrap();
        if let Some(host_cookies) = jar.get(&target_host) {
            if !host_cookies.is_empty() {
                let cookie_str = host_cookies.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("; ");
                request.headers_mut().insert(http::header::COOKIE, http::HeaderValue::from_str(&cookie_str)?);
            }
        }
    }

    let endpoint = server.endpoint()?;
    let tcp_stream = TcpStream::connect(&endpoint).await?;
    let peer_ip = tcp_stream.peer_addr().ok().map(|sa| sa.ip());
    tcp_stream.set_nodelay(true)?;

    let scheme = server.dsn.parse::<http::Uri>()?.scheme_str().unwrap_or("").to_ascii_lowercase();
    
    // 2. ИНИЦИАЛИЗАЦИЯ СТРИМА (Plain или BoringSSL)
    let stream: Box<dyn VpnStream> = if scheme == "wss" || scheme == "https" {
        let ssl_connector = build_chrome_ssl_connector()?.build();
        let sni_host = server.host.as_deref().unwrap_or(&target_host);
        let tls_stream = ssl_connector.connect_async(sni_host, tcp_stream).await.context("BoringSSL TLS handshake failed")?;
        Box::new(tls_stream)
    } else {
        Box::new(tcp_stream)
    };

    let (ws_stream, response) = tokio_tungstenite::client_async_with_config(request, stream, Some(ws_config)).await?;
    
    // 3. ПЕРЕХВАТЫВАЕМ SET-COOKIE ИЗ ОТВЕТА СЕРВЕРА
    {
        let mut jar = WS_COOKIE_JAR.lock().unwrap();
        let host_cookies = jar.entry(target_host).or_default();
        for cookie_header in response.headers().get_all(http::header::SET_COOKIE) {
            if let Ok(cookie_str) = cookie_header.to_str() {
                if let Some(key_val) = cookie_str.split(';').next() {
                    if let Some((key, val)) = key_val.split_once('=') {
                        host_cookies.insert(key.trim().to_string(), val.trim().to_string());
                    }
                }
            }
        }
    }

    let channel = WebSocketAuthChannel { socket: tokio::sync::Mutex::new(ws_stream) };
    let auth = AuthHandler::new_with_resume(config, server.server_pub_key.as_deref(), resume_session_id)?;
    let (auth_response, key) = auth.authenticate_once(&channel).await?;
    Ok((channel.socket.into_inner(), auth_response, key, peer_ip))
}
```

### 6.3. WRTC Сигналинг (Ktalk API, XMPP, Colibri-WS)
Транспорт WRTC использует HTTP и WS для сигнальных каналов. Они также должны мимикрировать под Chrome.

**Изменения в `anet-common/src/wrtc/ktalk.rs` (HTTP REST):**
```rust
use crate::boring_tls::build_chrome_ssl_connector;
use reqwest::cookie::Jar;
use std::sync::Arc;

impl KtalkClient {
    pub fn new(profile: BrowserProfile, wrtc_cfg: &WrtcConfig) -> Self {
        let cookie_jar = Arc::new(Jar::default());
        let ssl_connector = build_chrome_ssl_connector().unwrap().build();

        Self {
            http: reqwest::Client::builder()
                .use_preconfigured_tls(ssl_connector)
                .cookie_provider(cookie_jar)
                .connect_timeout(std::time::Duration::from_secs(wrtc_cfg.http_connect_timeout_secs))
                .timeout(std::time::Duration::from_secs(wrtc_cfg.http_request_timeout_secs))
                .build()
                .unwrap_or_default(),
            profile,
        }
    }
}
```

**Изменения в `anet-common/src/wrtc/xmpp.rs` (XMPP WebSocket):**
```rust
use crate::boring_tls::build_chrome_ssl_connector;
use tokio_boring::SslConnectorExt;
use crate::transport_trait::VpnStream;

// Внутри XmppSession::connect():
let tcp_stream = tokio::net::TcpStream::connect((domain, 443)).await?;
tcp_stream.set_nodelay(true)?;

let ssl_connector = build_chrome_ssl_connector()?.build();
let tls_stream = ssl_connector.connect_async(domain, tcp_stream).await?;

let stream: Box<dyn VpnStream> = Box::new(tls_stream);
let (ws_stream, response) = tokio_tungstenite::client_async_with_config(request, stream, None).await?;
```

**Изменения в `anet-client-core/src/transport/wrtc.rs` (Colibri-WS Fallback):**
При инициализации резервного `Colibri-WS` канала (в блоке `if let Some(ref ws_url) = session.transport.colibri_ws_url`) необходимо заменить `tokio_tungstenite::connect_async` на ручную установку `TcpStream`, обертку в `build_chrome_ssl_connector().connect_async()` и передачу абстрагированного `Box<dyn VpnStream>` в `client_async_with_config`.

---

## 7. Требования к архитектуре Сервера (Reverse Proxy)

**Критическое архитектурное правило:**
Сервер `anet-server` **НИКОГДА** не терминирует TLS-соединения для TCP-транспортов (AHTTP, WebSocket). 
Встроенная поддержка TLS (через `rustls` или `boring`) на стороне сервера **не требуется и должна отсутствовать**.

Сервер ANet всегда работает за Reverse Proxy (Nginx, HAProxy) или CDN (Cloudflare/TimeWeb).
* Reverse Proxy принимает HTTPS/WSS трафик на порту 443, расшифровывает его с использованием валидных публичных сертификатов (Let's Encrypt).
* Reverse Proxy проксирует чистый HTTP/WS трафик на локальные порты `anet-server` (например, `127.0.0.1:8080` для WS и `127.0.0.1:8081` для AHTTP).
* `anet-server` читает заголовки `X-Real-IP` или `X-Forwarded-For` для определения реального IP-адреса клиента.

---

## 8. Строгие требования к реализации (AI Prompts)

При написании и модификации кода ИИ-ассистент обязан соблюдать следующие директивы:

1. **Полное удаление `rustls` из HTTP-транспортов клиента:** В файлах `ahttp.rs`, `websocket.rs`, `ktalk.rs`, `xmpp.rs` не должно остаться импортов или структур, связанных с `rustls`.
2. **Типизация WebSocket:** Библиотека `tokio-tungstenite` с отключенной фичей `rustls` больше не предоставляет `MaybeTlsStream::Rustls`. ИИ должен абстрагировать базовый TCP/TLS стрим через `Box<dyn anet_common::transport_trait::VpnStream>` перед передачей его в `client_async_with_config`.
3. **GREASE Extensions:** В `boring_tls.rs` вызов `set_grease_enabled(true)` строго обязателен. Это ключевой механизм маскировки.
4. **Унификация HTTP-заголовков (OS-Aware):** В `http_help.rs` должны остаться ТОЛЬКО профили браузеров на движке Chromium (и Safari для iOS). Использование макросов `#[cfg(target_os = "...")]` обязательно для соответствия TCP-отпечатку ОС. Заголовки `sec-ch-ua` и `sec-ch-ua-platform` обязательны.
5. **Cookie Management:** Внедрение `reqwest::cookie::Jar` для AHTTP (и `KtalkClient`) и кастомного `WS_COOKIE_JAR` с разделением по хостам для WebSocket строго обязательно для корректной работы через промежуточные узлы защиты (CDN).
6. **Отсутствие TLS на Сервере:** Код серверной части (`anet-server/src/servers/websocket.rs` и `ahttp.rs`) должен использовать только `TcpListener` и не должен содержать логики терминации TLS.
7. **Размещение `boring_tls.rs`:** Файл должен быть создан в директории `anet-common/src/boring_tls.rs`, чтобы его могли использовать как транспорты из `anet-client-core`, так и модули WRTC из `anet-common`.
8. **Обновление CI/CD:** Убедиться, что инструкции из Раздела 3 применены к `build-components.yml` для обеспечения успешной компиляции C/C++ зависимостей BoringSSL.
