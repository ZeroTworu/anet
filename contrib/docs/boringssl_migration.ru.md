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
boring = "4.22"
tokio-boring = "4.22"

# Переключаем reqwest на reqwest-boring с нативной поддержкой BoringSSL (фича "boring")
reqwest = { package = "reqwest-boring", version = "0.13.5", default-features = false, features = ["json", "boring", "http2", "cookies"] }

# Отключаем rustls в tokio-tungstenite (оставляем только базовые фичи connect и handshake)
tokio-tungstenite = { version = "0.28.0", default-features = false, features = ["connect", "handshake"] }
```

---

## 3. Обновление сборочного конвейера (CI/CD и Docker)
Поскольку крейт `boring-sys` компилирует C/C++ код BoringSSL из исходников (используя Go для кодогенерации, CMake и Clang для сборки), необходимо обновить `.github/workflows/build-components.yaml` и `contrib/docker/Dockerfile.auth`.

Внесите следующие изменения в соответствующие `jobs` файла `.github/workflows/build-components.yaml`:

1.  **Во все сборочные jobs (`build-linux-server`, `build-linux-client`, `build-windows-client`, `build-macos-client`, `build-android-libs`, `build-linux-gui`):**
    Добавить шаг установки Go перед установкой системных зависимостей:
    ```yaml
      - name: "Install Go (Required for BoringSSL)"
        uses: actions/setup-go@v5
        with:
          go-version: '>=1.20'
    ```
2.  **В `build-linux-server`, `build-linux-client`, `build-android-libs` и `build-linux-gui` (шаг `Install dependencies`):**
    Добавить `cmake` и `clang`:
    ```bash
    sudo apt-get install -y musl-tools protobuf-compiler gcc-aarch64-linux-gnu mingw-w64 cmake clang
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
5.  **Для Android-сборки (`build-android-libs` / `anet-mobile`):**
    Помимо Go, `cmake` и `clang`, убедиться в наличии установленного Android NDK (`nttld/setup-ndk@v1`).
6.  **В `contrib/docker/Dockerfile.auth`:**
    Добавить `cmake`, `clang` и `golang-go` в `apt-get install`, так как `anet-auth` транзитивно собирает `anet-common`.

---

## 4. Единая точка входа для HTTP и WS (`anet-common/src/http_help.rs`)

> **АБСОЛЮТНОЕ АРХИТЕКТУРНОЕ ПРАВИЛО:**
> Для **любого** клиентского HTTP-соединения в системе (транспорт `AHTTP`, сигналинг `WRTC Ktalk`, обновление конфигурации `Updater`, обновление правил маршрутизации `RuleCacheManager` и любые будущие HTTP-запросы) **строго обязательно** использовать **ТОЛЬКО** связку:
> 1. `BrowserProfile::build_reqwest_builder(cookie_jar)` — для создания `reqwest::ClientBuilder` с преднастроенным TLS-коннектором BoringSSL Chrome Mimicry, `User-Agent`, `tcp_nodelay(true)` и `cookie_provider`.
> 2. `BrowserProfile::apply_to_reqwest(request_builder, origin, referer)` — для навешивания полного набора браузерных заголовков (`User-Agent`, `Accept-Language`, `Sec-Fetch-*`, `Priority`, `sec-ch-ua*`) на каждый исходящий HTTP-запрос.
>
> **Прямой вызов `reqwest::Client::builder()` или `reqwest::Client::new()` в обход `BrowserProfile::build_reqwest_builder` категорически запрещен!**

Клиент мимикрирует строго под современные версии Chromium (v153+). `User-Agent`, `sec-ch-ua` и `sec-ch-ua-platform` **строго соответствуют операционной системе**, под которую скомпилирован бинарный файл клиента.

```rust
    /// Создает сконфигурированный `reqwest::ClientBuilder` со встроенным TLS-отпечатком BoringSSL Chrome Mimicry,
    /// поддержкой сессионного Cookie Jar и базовыми браузерными параметрами.
    /// Это ЕДИНСТВЕННАЯ разрешенная точка создания HTTP-клиентов `reqwest` во всей системе.
    pub fn build_reqwest_builder(
        &self,
        cookie_jar: std::sync::Arc<reqwest::cookie::Jar>,
    ) -> anyhow::Result<reqwest::ClientBuilder> {
        let ssl_builder = crate::boring_tls::build_chrome_ssl_connector()?;
        let builder = reqwest::Client::builder()
            .use_preconfigured_tls(ssl_builder.build())
            .user_agent(self.user_agent)
            .cookie_provider(cookie_jar)
            .tcp_nodelay(true);
        Ok(builder)
    }
```

---

## 5. Криптографический движок Chrome (`anet-common/src/boring_tls.rs`)
Файл размещается в `anet-common/src/boring_tls.rs`, так как он используется и в `anet-client-core`, и в `anet-common/src/wrtc`.

Предоставляются **два явных метода без параметров**:
1. `build_chrome_ssl_connector()` — для HTTP-клиентов (`reqwest`), анонсирует ALPN `h2` и `http/1.1` (`b"\x02h2\x08http/1.1"`).
2. `build_chrome_ws_ssl_connector()` — для WebSocket (`tokio-tungstenite`) и потоковых TLS-соединений (`turns_proxy`), анонсирует в ALPN строго `http/1.1` (`b"\x08http/1.1"`). Это критично, так как при анонсе `h2` CDN/Reverse Proxy (Cloudflare, Nginx) выбирает в TLS-рукопожатии протокол HTTP/2, после чего HTTP/1.1-запрос `Upgrade: websocket` от `tokio-tungstenite` отвергается сервером как синтаксическая ошибка фрейминга HTTP/2.

> **Примечание о формате `set_alpn_protos`:**
> Метод `SslConnectorBuilder::set_alpn_protos` в BoringSSL принимает список протоколов в бинарном **wire-формате TLS RFC 7301** (последовательность строк с однобайтовым префиксом длины перед каждой строкой):
> * `\x02h2` — байт длины `0x02` (2 байта) + строка `"h2"` (протокол **HTTP/2**).
> * `\x08http/1.1` — байт длины `0x08` (8 байт) + строка `"http/1.1"` (протокол **HTTP/1.1**).
> Таким образом, строка `b"\x02h2\x08http/1.1"` одновременно включает в ClientHello оба протокола в порядке приоритета Chrome: сначала `HTTP/2`, затем `HTTP/1.1`.

```rust
use boring::ssl::{SslConnector, SslConnectorBuilder, SslMethod, SslVerifyMode, SslVersion};

/// Базовая конфигурация BoringSSL, мимикрирующая под TLS-отпечаток Google Chrome (JA3/JA4):
/// GREASE, кривые X25519/P-256/P-384, версии TLS 1.2..=1.3, OCSP Stapling, SCT и порядок шифров.
fn build_chrome_ssl_connector_base() -> anyhow::Result<SslConnectorBuilder> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;

    // Включаем GREASE-расширения (ключевой маркер Chrome для обхода IDS/IPS)
    builder.set_grease_enabled(true);

    // Ограничиваем версии протокола строго TLS 1.2 .. TLS 1.3 (современный Chromium)
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    // Задаем точный список и порядок эллиптических кривых (Supported Groups) как в Chrome
    builder.set_curves_list("X25519:P-256:P-384")?;

    // Включаем расширения status_request (OCSP stapling) и signed_certificate_timestamp (SCT)
    builder.enable_ocsp_stapling();
    builder.enable_signed_cert_timestamps();

    // Порядок шифров TLS 1.3 (Приоритет AES-GCM)
    builder.set_ciphersuites(
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
    )?;

    // Порядок шифров TLS 1.2
    builder.set_cipher_list(
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
         ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
         ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
    )?;

    // Доверие узлу ANet обеспечивается ASTP-хендшейком внутри туннеля.
    // Отключаем валидацию TLS сертификатов.
    builder.set_verify_callback(SslVerifyMode::NONE, |_preverify_ok, _x509_ctx| true);

    Ok(builder)
}

/// Создает конфигурацию BoringSSL для HTTP-клиентов (`reqwest`), идеально мимикрирующую под Google Chrome.
/// Заявляет в ALPN поддержку `h2` (HTTP/2) и `http/1.1` (в wire-формате с префиксами длины: `\x02h2\x08http/1.1`).
pub fn build_chrome_ssl_connector() -> anyhow::Result<SslConnectorBuilder> {
    let mut builder = build_chrome_ssl_connector_base()?;
    builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;
    Ok(builder)
}

/// Создает конфигурацию BoringSSL для WebSocket (`tokio-tungstenite`) и потоковых TLS-соединений (`TURNS`).
/// Заявляет в ALPN строго `http/1.1` (`\x08http/1.1`), чтобы Reverse Proxy / CDN не согласовывал HTTP/2
/// перед отправкой HTTP/1.1 заголовка `Upgrade: websocket`.
pub fn build_chrome_ws_ssl_connector() -> anyhow::Result<SslConnectorBuilder> {
    let mut builder = build_chrome_ssl_connector_base()?;
    builder.set_alpn_protos(b"\x08http/1.1")?;
    Ok(builder)
}
```

---

## 6. Интеграция в транспорты, фоновые службы и Управление Состоянием (Cookies)

### 6.1. AHTTP Транспорт (`anet-client-core/src/transport/ahttp.rs`)
Использует единую точку `profile.build_reqwest_builder(cookie_jar.clone())` и `profile.apply_to_reqwest(...)`. Имя хоста для TLS/SNI берётся из `server.host` (Domain Fronting) или домена URI:

```rust
let cookie_jar = Arc::new(reqwest::cookie::Jar::default());

let build_http_client = || -> Result<Client> {
    let mut builder = profile
        .build_reqwest_builder(cookie_jar.clone())?
        .resolve(&target_host, resolved_addr)
        .pool_max_idle_per_host(self.config.ahttp.pool_max_idle_per_host.max(2))
        // ... настройки HTTP/2 и таймаутов ...
    builder.build().map_err(|e| anyhow::anyhow!("Cannot build AHTTP client: {}", e))
};
```

### 6.2. WebSocket Транспорт (`anet-client-core/src/transport/websocket.rs`)
Реализует Cookie Jar с привязкой по доменам (`host`) и TLS-рукопожатие через `tokio-boring` с использованием `build_chrome_ws_ssl_connector()`:

```rust
    let stream: Box<dyn VpnStream> = if scheme == "wss" || scheme == "https" {
        let ssl_connector = build_chrome_ws_ssl_connector()?.build();
        let sni_host = server.host.as_deref().unwrap_or(&target_host);
        let tls_stream = ssl_connector
            .connect_async(sni_host, tcp_stream)
            .await
            .context("BoringSSL TLS handshake failed")?;
        Box::new(tls_stream)
    } else {
        Box::new(tcp_stream)
    };
```

### 6.3. WRTC Сигналинг и TURNS-мост (`ktalk.rs`, `xmpp.rs`, `peer.rs`, `turns_proxy.rs`)
* **`anet-common/src/wrtc/ktalk.rs` (HTTP REST):** Использует `profile.build_reqwest_builder(cookie_jar)` и `profile.apply_to_reqwest(...)`.
* **`anet-common/src/wrtc/xmpp.rs` (XMPP WebSocket):** Использует `build_chrome_ws_ssl_connector()?.build()` и `profile.build_ws_request(...)`.
* **`anet-common/src/wrtc/peer.rs` (Colibri-WS Fallback):** При установке резервного канала `Colibri-WS` оборачивает `TcpStream` через `crate::boring_tls::build_chrome_ws_ssl_connector()?.build().connect_async(...)` в `Box<dyn VpnStream>` и передает в `tokio_tungstenite::client_async_with_config`.
* **`anet-common/src/wrtc/turns_proxy.rs` (Локальный UDP-to-TURNS мост):** Поскольку `webrtc-rs` для `turns:` внутри использует `rustls`, клиент поднимает локальный UDP-прокси и оборачивает внешний TCP-поток к TURN-серверу в `build_chrome_ws_ssl_connector()` через `tokio-boring`.

### 6.4. Фоновые HTTP-службы клиента (`updater.rs` и `rule_updater.rs`)
Все вспомогательные HTTP-запросы в `anet-client-core/src/updater.rs` (загрузка удалённого конфига, проверка релизов на GitHub, скачивание обновлений) и `anet-client-core/src/rule_updater.rs` (загрузка `rules.abc`) также обязаны проходить строго через `BrowserProfile::random()`, `profile.build_reqwest_builder(...)` и `profile.apply_to_reqwest(...)`. Никаких кастомных `User-Agent: ANet-*` в сети быть не должно.

---

## 7. Требования к архитектуре Сервера (Reverse Proxy)

**Критическое архитектурное правило:**
Сервер `anet-server` **НИКОГДА** не терминирует TLS-соединения для TCP-транспортов (AHTTP, WebSocket). 
Встроенная поддержка TLS (через `rustls` или `boring`) на стороне сервера для TCP-транспортов **не требуется и должна отсутствовать**.

Сервер ANet всегда работает за Reverse Proxy (Nginx, HAProxy) или CDN (Cloudflare/TimeWeb):
* Reverse Proxy принимает HTTPS/WSS трафик на порту 443, расшифровывает его с использованием валидных публичных сертификатов (Let's Encrypt).
* Reverse Proxy проксирует чистый HTTP/WS трафик на локальные порты `anet-server` (например, `127.0.0.1:8080` для WS и `127.0.0.1:8081` для AHTTP).
* `anet-server` читает заголовки `X-Real-IP` или `X-Forwarded-For` через `anet_common::http_help::extract_real_ip` / `extract_real_ip_from_raw` для определения реального IP-адреса клиента.

---

## 8. Строгие требования к реализации (AI Prompts)

При написании и модификации кода ИИ-ассистент обязан соблюдать следующие директивы:

1. **Единая точка для любого HTTP:** Для **любого** HTTP-запроса на клиенте использовать **ТОЛЬКО** `BrowserProfile::build_reqwest_builder` и `BrowserProfile::apply_to_reqwest`. Прямое создание `reqwest::Client::builder()` вне `http_help.rs` запрещено.
2. **Разделение TLS-коннекторов для HTTP и WebSocket:** Для HTTP (`reqwest`) использовать `build_chrome_ssl_connector()` (ALPN `h2`, `http/1.1`), а для всех WebSocket (`websocket.rs`, `xmpp.rs`, `peer.rs`) и потоковых TLS (`turns_proxy.rs`) — строго `build_chrome_ws_ssl_connector()` (ALPN `http/1.1`).
3. **Полное удаление `rustls` из TCP/HTTP/WS-транспортов клиента:** В файлах `ahttp.rs`, `websocket.rs`, `ktalk.rs`, `xmpp.rs`, `peer.rs`, `turns_proxy.rs`, `updater.rs`, `rule_updater.rs` не должно быть импортов или структур, связанных с `rustls`. (`rustls` остается в `anet-common` исключительно для QUIC/ASTP через `quinn`).
4. **Типизация WebSocket:** Библиотека `tokio-tungstenite` с отключенной фичей `rustls` больше не предоставляет `MaybeTlsStream::Rustls`. ИИ должен абстрагировать базовый TCP/TLS стрим через `Box<dyn anet_common::transport_trait::VpnStream>` перед передачей его в `client_async_with_config`.
5. **GREASE и расширения Chrome:** В `boring_tls.rs` вызовы `set_grease_enabled(true)`, `set_curves_list("X25519:P-256:P-384")`, `enable_ocsp_stapling()` и `enable_signed_cert_timestamps()` строго обязательны.
6. **Унификация HTTP-заголовков (OS-Aware):** В `http_help.rs` должны остаться ТОЛЬКО профили браузеров на движке Chromium (и Safari для iOS). Использование макросов `#[cfg(target_os = "...")]` обязательно для соответствия TCP-отпечатку ОС. Заголовки `sec-ch-ua` и `sec-ch-ua-platform` обязательны.
7. **Cookie Management:** Внедрение `reqwest::cookie::Jar` (через `build_reqwest_builder`) и кастомного `WS_COOKIE_JAR` с разделением по хостам для WebSocket строго обязательно для корректной работы через промежуточные узлы защиты (CDN).
8. **Отсутствие TLS на Сервере:** Код серверной части (`anet-server/src/servers/websocket.rs` и `ahttp.rs`) должен использовать только `TcpListener` и не должен содержать логики терминации TLS.

