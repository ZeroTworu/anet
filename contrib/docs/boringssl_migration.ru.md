## 1. Введение и модель угроз ТСПУ (`tspu-detect.svg`)

Все клиентские TCP/TLS-транспорты (`AHTTP`, `WebSocket`, сигнальные и резервные каналы `WRTC`: REST API Контур.Толк, XMPP-WS, Colibri-WS, локальный мост `TURNS`, а также фоновые службы `Updater` и `RuleCacheManager`) работают поверх нативной криптографической библиотеки Google **`boring` (BoringSSL)**.

Согласно актуальной архитектуре детектов ТСПУ и результатам полевых тестов, TLS-клиент должен защищаться от четырёх векторов обнаружения:

1. **Сверка L3/L4/L6/L7 и детект «гибридных» (синтетических) отпечатков:**
   * Если `BrowserProfile` выбирает HTTP-заголовки `Firefox` (или отправляет `sec-ch-ua*` при `User-Agent: Firefox/Safari`), а на уровне TLS отправляется `ClientHello` со скелетом расширений `Chrome/BoringSSL`, DPI фиксирует рассинхрон L6/L7.
   * Если на ОС Linux/Windows (`IP TTL = 64/128`, TCP Options Linux/Windows) отправляется TLS-отпечаток `Safari` (существующий только на macOS/iOS с ядром Darwin/XNU), пассивный OS-фингерпринтинг (`p0f` / `JA4T`) фиксирует конфликт `L3/L4 != L6/L7`.
   * Использование редких в РФ профилей (например, китайского `qq`) или несуществующих в природе комбинаций кривых/шифров в режиме `randomized` мгновенно выделяет трафик из фонового шума провайдера.
2. **Проблема двухсегментного `ClientHello` (Post-Quantum Kyber / ML-KEM) и сигнатур `uTLS`:**
   * В популярных прокси-клиентах (Xray / sing-box с `uTLS fp=chrome`) включение гибридной постквантовой группы `X25519MLKEM768` (`0x11ec`) раздувает `ClientHello` с ~517 байт до ~1750–1900 байт, разбивая его на **2 TCP-сегмента** (`> 1460 MSS`). В сочетании с чужим «ворованным» SNI (VLESS Reality) это стало основным триггером блокировки `fp=chrome` на ТСПУ.
   * В `anet` классический набор кривых (`X25519:P-256:P-384`) удерживает `ClientHello` в пределах **517 байт (ровно 1 TCP-сегмент)**, а соединение устанавливается к собственному реальному TLS-серверу/CDN.
3. **Анализ кадра HTTP/2 `SETTINGS` (Akamai HTTP/2 Fingerprint) и пула TCP-соединений:**
   * При использовании транспорта `AHTTP` (`ALPN = ["h2", "http/1.1"]`) антибот-системы CDN и DPI проверяют параметры первого кадра `HTTP/2 SETTINGS` (`INITIAL_WINDOW_SIZE`, `MAX_HEADER_LIST_SIZE`) и количество одновременно открываемых TCP-соединений к одному `SNI`. Стандартные дефолты Rust-крейта `h2`/`hyper` отличаются от браузерных и требуют явного переопределения.
4. **Активный спуфинг ТСПУ / MITM на этапе TLS Handshake:**
   * При подозрении на прокси/selfsteal ТСПУ перехватывает исходящий TCP-поток и инжектирует собственный `ServerHello` с подменным сертификатом (самоподписанным, выданным промежуточным DPI-центром или реальным сертификатом от чужого домена-заглушки).
   * Если на клиенте отключена проверка сертификата (`SslVerifyMode::NONE`), клиент завершает TLS-рукопожатие с сенсором ТСПУ и отправляет внутрь перехваченной сессии первый HTTP/2 или WebSocket запрос (`POST /api/v2/telemetry/handshake`, `Upgrade: websocket` на секретный путь `/socket` и т.д.). Сенсор ТСПУ расшифровывает этот первый пакет, видит сигнатуру VPN и мгновенно отправляет IP сервера в блэкхол.

---

## 2. Матрица профилей `Chrome`, `Firefox`, `Safari`, `Randomized` и синхронизация L4/L7

В модулях `anet-common/src/boring_tls.rs` и `anet-common/src/http_help.rs` реализована жёсткая сцепка между профилем TLS (`TlsFingerprint`) и HTTP-шаблоном (`BrowserProfile`):

| Профиль (`tls_fingerprint`) | GREASE | `permute_extensions` | Эллиптические кривые (`Supported Groups`) | Расширения OCSP / SCT / Ticket | Порядок шифров TLS 1.2 и хэш `JA4_b` | HTTP-заголовки L7 (`sec-ch-ua*` и `Accept-Encoding`) |
| :--- | :---: | :---: | :--- | :---: | :--- | :--- |
| **`chrome`** | Да | Да (`true`) | `X25519:P-256:P-384` (1 TCP-сегмент 517 B) или с `X25519MLKEM768` | OCSP (`0x0005`) + SCT (`0x0012`) + Ticket (`0x0023`) | `AES128-GCM` $\to$ `AES256-GCM` $\to$ `CHACHA20` (`JA4_b = 8daaf6152771`) | Отправляет `sec-ch-ua`, `sec-ch-ua-mobile`, `sec-ch-ua-platform`; `gzip, deflate, br, zstd` |
| **`firefox`** | **Нет** | **Нет (`false`)** | `X25519:P-256:P-384:P-521` (`0x0019`) | Только OCSP (`0x0005`), **без SCT (`0x0012`)** | `AES128-GCM` $\to$ **`CHACHA20`** $\to$ `AES256-GCM`, `c00a` перед `c009` (`JA4_b = 5b57614c22b0`) | **НЕ отправляет** `sec-ch-ua*` (в соответствии с NSS/Gecko); `gzip, deflate, br, zstd` |
| **`safari`** | Да | **Нет (`false`)** | `X25519:P-256:P-384:P-521` (`0x0019`) | OCSP (`0x0005`) + SCT (`0x0012`), **без Ticket (`NO_TICKET`)** | **`AES256-GCM`** $\to$ `AES128-GCM` $\to$ `CHACHA20` + RSA/3DES (20 шифров) | **НЕ отправляет** `sec-ch-ua*` (в соответствии с WebKit); `gzip, deflate, br` (без `zstd`) |
| **`randomized`** | **Всегда Да** | **Всегда Да (`true`)** | Валидные пресеты (`29-23-24` или `29-23-24-25`, **строго `P-256` перед `P-384`**) | OCSP + SCT | Валидные браузерные матрицы под текущую ОС (без Safari на Linux/Win) | Синхронизируется с выбранным шаблоном браузера для текущей сессии |
| **`auto`** *(по умолчанию)* | Авто | Авто | Авто (под текущую ОС компиляции) | Авто | На Linux/Windows/Android приоритет `Chrome`; на iOS — `Safari`; на macOS — `Chrome`/`Safari` | Намертво привязывает L4 к L7 и исключает конфликт ОС |

### Разделение ALPN для HTTP/2 и WebSocket
* **`BrowserProfile::build_reqwest_builder`** (`build_ssl_connector_with_config`): всегда анонсирует в ALPN оба протокола `h2` и `http/1.1` (`b"\x02h2\x08http/1.1"`). Префикс JA4 имеет вид `t13d...h2`.
* **`BrowserProfile::connect_ws_tls`** (`build_ws_ssl_connector_with_config`): для всех WebSocket-соединений (`websocket.rs`, `xmpp.rs`, `peer.rs` Colibri-WS) и потокового `turns_proxy.rs` анонсирует в ALPN строго `http/1.1` (`b"\x08http/1.1"`). Префикс JA4 имеет вид `t13d...h1`.

---

## 3. Защита от активного спуфинга ТСПУ (`tls_verify_peer` и `tls_pin_sha256`)

Защита от активного спуфинга **включена по умолчанию (`tls_verify_peer = true`)** и управляется из секции `[stealth]` либо индивидуально для каждого сервера в `[[servers]]`.

### Как работает перехват на этапе TLS Handshake:
1. **Режим стандартной WebPKI + SNI верификации (`tls_verify_peer = true`, по умолчанию):**
   * При старте клиент однократно загружает системные корневые сертификаты ОС (`rustls-native-certs`: Windows CryptoAPI/`schannel`, macOS/iOS `Security.framework`, Linux `/etc/ssl/certs`, Android `/system/etc/security/cacerts` и `/apex/com.android.conscrypt/cacerts`) в кэш `SYSTEM_ROOT_CERTS` и добавляет опциональный `tls_ca_cert`.
   * В BoringSSL активируется режим `SslVerifyMode::PEER` и строгая проверка имени хоста `set_verify_hostname(true)` (сверка домена SNI с `SubjectAltName` сертификата).
   * Если ТСПУ пытается выполнить активный спуфинг, коллбэк верификации BoringSSL возвращает `false` **во время TLS-рукопожатия**. Соединение разрывается до завершения `tokio_boring::connect`, поэтому **в сеть не уходит ни одного байта HTTP-заголовков, путей `/handshake` или `/socket` и пакетов ASTP**.
2. **Режим криптографического пиннинга (`tls_verify_peer = true` + `tls_pin_sha256 = "..."`):**
   * На глубине `depth == 0` (листовой сертификат сервера) клиент вычисляет `SHA-256` как от полного DER-сертификата, так и от его публичного ключа `SPKI` (`SubjectPublicKeyInfo`).
   * Если любой из двух хешей совпадает с `tls_pin_sha256` (Hex или Base64), соединение разрешается; при несовпадении — мгновенно обрывается с предупреждением `[TLS Anti-Spoof] Certificate SHA-256 pin mismatch!`.
3. **Явное отключение (`tls_verify_peer = false`):**
   * Переводит BoringSSL в `SslVerifyMode::NONE`. Допускается только для локальной отладки на стендах без `tls_pin_sha256`.

### Настройка в `client.toml`:

```toml
[stealth]
# Профиль TLS и HTTP: "auto" (по умолчанию) | "chrome" | "firefox" | "safari" | "randomized"
tls_fingerprint = "auto"

# Защита от активного спуфинга ТСПУ (по умолчанию: true)
tls_verify_peer = true

# Опциональный SHA-256 пин сертификата или SPKI публичного ключа (Hex или Base64):
# tls_pin_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# Опциональный пользовательский корневой/серверный сертификат (путь к PEM или inline PEM):
# tls_ca_cert = "/etc/anet/ca.pem"

[[servers]]
name = "Pinned Chrome AHTTP Node"
dsn = "https://example.com/api/v2/telemetry"
tls_fingerprint = "chrome"
tls_verify_peer = true
tls_pin_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

### Команды `openssl` для получения `tls_pin_sha256` вашего сервера:

```bash
# Вариант А (рекомендуемый): SHA-256 пин публичного ключа (SPKI) — не меняется при продлении Let's Encrypt
openssl x509 -in /etc/letsencrypt/live/example.com/cert.pem -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -hex

# Вариант Б: SHA-256 отпечаток самого сертификата (с удалением двоеточий)
openssl x509 -in /etc/letsencrypt/live/example.com/cert.pem -noout -fingerprint -sha256 \
  | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f'

# Вариант В: Снятие SPKI SHA-256 пина напрямую с удалённого боевого сервера
openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -hex
```

---

## 4. Инструкции для ИИ-агента: обязательные доработки текущего стека (`boring` + `reqwest-boring`)

> **Контекст для ИИ-агента разработчика:**
> При выполнении задач по модификации TLS и HTTP-транспортов в репозитории `anet` строго соблюдай приведённые ниже правила. Твоя цель — исключить появление синтетических («Франкенштейн») отпечатков JA3 / JA4 / Akamai HTTP/2 при сохранении работоспособности всех тестов.

### Задача 4.1. Исправление `SAFARI_CIPHERS`, `NO_TICKET` и `SIGALGS` в `anet-common/src/boring_tls.rs`
1. **Проблема:**
   * Настоящий Safari на iOS и macOS использует собственный форк BoringSSL (`libboringssl.dylib` в `Network.framework`), поэтому его порядок расширений при `permute_extensions(false)` и `set_grease_enabled(true)` совпадает с BoringSSL, **кроме** расширения `session_ticket (0x0023)`, которое Apple принудительно отключает флагом `SSL_OP_NO_TICKET`.
   * В текущей константе `SAFARI_CIPHERS` указаны неподдерживаемые BoringSSL шифры `ECDHE-ECDSA-AES256-SHA384`, `ECDHE-RSA-AES256-SHA384`, `ECDHE-ECDSA-AES128-SHA256` (из-за чего остаётся одинокий `0xc027`) и пропущен блок `RSA` / `3DES` (в итоге в ClientHello уходит 14 шифров вместо 20, и хэш `JA4_b` не совпадает с Safari).
   * В `FIREFOX_SIGALGS` и `SAFARI_SIGALGS` отсутствуют завершающие алгоритмы `:ecdsa_sha1:rsa_pkcs1_sha1` (`0x0203:0x0201`), из-за чего в `signature_algorithms` передаётся 9 алгоритмов (как в дефолтном Go `crypto/tls`) вместо 11 браузерных.
2. **Требуемое изменение в `anet-common/src/boring_tls.rs`:**
   * Обновить константы шифров и алгоритмов подписи:
     ```rust
     const SAFARI_CIPHERS: &str = "\
         ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:\
         ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:\
         ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:\
         ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:\
         ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:\
         AES256-GCM-SHA384:AES128-GCM-SHA256:\
         AES256-SHA:AES128-SHA:\
         ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:DES-CBC3-SHA";

     const FIREFOX_SIGALGS: &str = "\
         ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:\
         rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:\
         rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512:\
         ecdsa_sha1:rsa_pkcs1_sha1";

     const SAFARI_SIGALGS: &str = "\
         ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:\
         ecdsa_secp384r1_sha384:ecdsa_sha1:rsa_pss_rsae_sha384:\
         rsa_pkcs1_sha384:ecdsa_secp521r1_sha512:rsa_pss_rsae_sha512:\
         rsa_pkcs1_sha512:rsa_pkcs1_sha1";
     ```
   * В `build_ssl_connector_base_with_config` для ветки `TlsFingerprint::Safari` обязательно добавить отключение TLS 1.2 Session Ticket:
     ```rust
     TlsFingerprint::Safari => {
         builder.set_grease_enabled(true);
         builder.set_permute_extensions(false);
         builder.set_options(boring::ssl::SslOptions::NO_TICKET);
         builder.set_curves_list("X25519:P-256:P-384:P-521")?;
         builder.enable_ocsp_stapling();
         builder.enable_signed_cert_timestamps();
         builder.set_cipher_list(SAFARI_CIPHERS)?;
         let _ = builder.set_sigalgs_list(SAFARI_SIGALGS);
     }
     ```

### Задача 4.2. Защита `TlsFingerprint::Auto` и `TlsFingerprint::Randomized` от генерации мутантов
1. **Проблема:**
   * В `TlsFingerprint::resolve_for_os` на Linux, Windows и Android выбор `Firefox` или `Randomized` по умолчанию в `Auto` приводит к тому, что 66% соединений на движке BoringSSL используют неродной для него профиль.
   * В `TlsFingerprint::Randomized` выбор кривых `"X25519:P-384:P-256"` (`29-24-23`), отключение GREASE и подстановка `SAFARI_CIPHERS` на Linux/Windows создают аномальные отпечатки, отсутствующие в белых списках браузеров.
2. **Требуемое изменение в `anet-common/src/boring_tls.rs`:**
   * В `TlsFingerprint::resolve_for_os`:
      * На `ios` возвращать `Self::Safari`.
      * На `macos` выбирать между `Self::Chrome` и `Self::Safari`.
      * На `linux`, `windows`, `android` в режиме `Auto` возвращать **`Self::Chrome`** (так как BoringSSL является нативным движком Chromium и даёт 100% консистентный отпечаток без единого конфликта).
   * В `TlsFingerprint::Randomized`:
      * Всегда оставлять `builder.set_grease_enabled(true)` и `builder.set_permute_extensions(true)`.
      * Использовать только валидный порядок кривых (`"X25519:P-256:P-384"` или `"X25519:P-256:P-384:P-521"` — никогда не ставить `P-384` перед `P-256`).
      * Не выбирать `SAFARI_CIPHERS` на не-Apple платформах (`#[cfg(not(target_vendor = "apple"))]`).

### Задача 4.3. Выравнивание Akamai HTTP/2 Fingerprint и TCP-пула в `AHTTP` (`anet-client-core/src/config.rs`, `ahttp.rs`)
1. **Проблема:**
   * В `AhttpConfig::default()` (`anet-client-core/src/config.rs:431`) установлено `http2_adaptive_window: true` и `http2_max_header_list_size: Some(16384)`. Из-за этого крейт `h2` отправляет в кадре `SETTINGS` нетипичный для браузера лимит заголовков `16384` и стандартное окно `65535`, выдавая Rust `hyper`/`h2`.
   * Кроме того, `tcp_pool_size: Some(4)` открывает сразу 4 параллельных TLS-соединения к одному `SNI` в одну секунду, тогда как браузеры по RFC 9113 открывают строго 1 HTTP/2 соединение на origin.
2. **Требуемое изменение в `AhttpConfig::default()` (`anet-client-core/src/config.rs`):**
   * Установить дефолтные параметры HTTP/2 в соответствии с профилем Google Chrome:
     ```rust
     tcp_pool_size: Some(1),
     http2_adaptive_window: false,
     http2_initial_stream_window_size: Some(6_291_456),      // 6 MiB (Chrome SETTINGS_INITIAL_WINDOW_SIZE)
     http2_initial_connection_window_size: Some(15_728_640), // 15 MiB (Chrome Connection WINDOW_UPDATE)
     http2_max_frame_size: None,                             // Chrome не отправляет MAX_FRAME_SIZE (оставляет 16384 по умолчанию без явной записи в SETTINGS)
     http2_max_header_list_size: Some(262_144),              // 256 KiB (Chrome SETTINGS_MAX_HEADER_LIST_SIZE)
     ```
   * При активном флаге `?cdn=1` в DSN сохранять возможность занижения окна (`49152`), если это необходимо для прохождения специфичных буферов CDN.

### Задача 4.4. Нативные расширения BoringSSL FFI (`0xfe0d` ECH GREASE, `0x001b` `compress_certificate`, `0x4469` ALPS) и `SessionCache` в `reqwest-boring`
1. **Проблема:**
   * Без FFI-вызовов `boring_sys` в `ClientHello` отсутствуют три ключевых браузерных расширения: `encrypted_client_hello` GREASE (`0xfe0d`), `compress_certificate` (`0x001b`, RFC 8879 — Brotli у Chrome, Zlib у Safari, Zlib+Brotli у Firefox) и `application_settings` / ALPS (`0x4469` для `h2` у Chrome).
   * В `patches/reqwest-boring/src/boring_tls.rs` метод `Config::preconfigured` (используемый при вызове `.tls_built_in_boring_connector`) не инициализирует `SessionCache` (из-за чего при повторных соединениях к тому же хосту не отправляется `pre_shared_key` `0x0029`) и жёстко ставит `verify_hostname: true` даже при `SslVerifyMode::NONE` (ломая `verify_peer = false` и IP-подключения).
2. **Реализация в `anet-common/src/boring_tls.rs` и `patches/reqwest-boring/src/boring_tls.rs`:**
   * Через `boring_sys` активированы:
     * `SSL_set_enable_ech_grease(ssl, 1)` для профилей `Chrome`, `Firefox` и `Randomized`;
     * `SSL_CTX_add_cert_compression_alg` с распаковкой Brotli (`2`, через крейт `brotli`) и Zlib (`1`, через крейт `flate2`);
     * `SSL_add_application_settings` (`h2`) для HTTP/2 коннектора профиля `Chrome`.
   * В `patches/reqwest-boring/src/boring_tls.rs` в `Config::preconfigured` подключён `SessionCache` (`SslSessionCacheMode::CLIENT` + `set_new_session_callback`), а флаг `verify_hostname` автоматически синхронизируется с `ssl.verify_mode() != SslVerifyMode::NONE`.

---

## 5. Пользовательская конфигурация профилей `[[browser_profiles]]` в `client.toml` и `server.toml`

Помимо встроенных в бинарник эталонных профилей (`Chrome`, `Firefox`, `Safari`), конфигурационные файлы `client.toml`, `server.toml` и `contrib/client_template.toml` поддерживают массив таблиц **`[[browser_profiles]]`**.
Это позволяет переопределять параметры существующих профилей (по имени `name = "Chrome" | "Firefox" | "Safari"`) или добавлять собственные кастомные профили без пересборки бинарников.

### 5.1. Поддерживаемые поля `[[browser_profiles]]`
* `name` — имя профиля (`"Chrome"`, `"Firefox"`, `"Safari"` или произвольное имя).
* `cipher_list` — строка шифров TLS 1.2 в формате BoringSSL (`SSL_CTX_set_cipher_list`).
* `curves` — список эллиптических кривых / групп (`"X25519:P-256:P-384"` или `"X25519:P-256:P-384:P-521"`).
* `sigalgs` — список алгоритмов подписи (`SSL_CTX_set_sigalgs_list`).
* `grease` — включение GREASE (`true` / `false`).
* `permute_extensions` — случайная перестановка порядка расширений TLS (`true` / `false`).
* `session_ticket` — отправка расширения `session_ticket (0x0023)` (`true` для Chrome/Firefox, `false` для Safari).
* `ocsp_stapling` и `signed_cert_timestamps` — управление расширениями `status_request (0x0005)` и `SCT (0x0012)`.
* `ech_grease` — отправка расширения `encrypted_client_hello` GREASE (`0xfe0d`).
* `alps_h2` — отправка расширения `application_settings / ALPS (0x4469)` для протокола `h2`.
* `cert_compression` — массив алгоритмов сжатия сертификатов RFC 8879 (`["brotli"]`, `["zlib"]`, `["zlib", "brotli"]`).
* `user_agents` — список строк `User-Agent` (при создании профиля выбирается случайная строка из списка).
* `headers` — упорядоченный список дополнительных HTTP-заголовков в формате `"Header-Name: value"` (применяется к HTTP/HTTPS запросам в указанном порядке).
* `ws_headers_order` — порядок заголовков HTTP/1.1 WebSocket Upgrade.
* `h2_initial_stream_window_size`, `h2_initial_connection_window_size`, `h2_max_header_list_size` — синхронизированные с браузером параметры кадра HTTP/2 `SETTINGS`.

### 5.2. Синхронизация HTTP/2 `SETTINGS` и порядка заголовков WebSocket Upgrade
* **`AHTTP` (`anet-client-core/src/transport/ahttp.rs`):** если в `[ahttp]` не заданы ручные переопределения окон, транспорт автоматически берёт `h2_initial_stream_window_size`, `h2_initial_connection_window_size` и `h2_max_header_list_size` из активного профиля браузера (`Chrome`: `6 MiB / 15 MiB / 256 KiB`; `Firefox`: `131072 / 12 MiB / 65536`; `Safari`: `4 MiB / 10 MiB / 65536`).
* **`WebSocket` (`websocket.rs`, `wrtc/xmpp.rs`, `wrtc/peer.rs`):** порядок заголовков в HTTP/1.1 `GET ... Upgrade: websocket` формируется строго по `ws_headers_order` выбранного профиля (`Chrome` включает `Pragma: no-cache`, `Cache-Control: no-cache`, `User-Agent`, `Upgrade`, `Origin`, `Sec-WebSocket-Version`, `Accept-Encoding`, `Accept-Language`, `Sec-WebSocket-Key`, `Sec-WebSocket-Extensions`; `Firefox` и `Safari` используют свой нативный порядок без нехарактерных заголовков).
* **100% покрытие HTTP-трафика:** все исходящие HTTP/HTTPS-запросы в рабочей области (`ahttp`, `websocket`, `wrtc/ktalk`, `updater`, `rule_updater`, `connectivity`, `probe_nodes`, `auth_provider`, `control_plane`, `anet-auth/compiler_worker`) создаются исключительно через `BrowserProfile::build_reqwest_builder` + `apply_to_reqwest`.

---

## 6. Аудит и проверка TLS-отпечатка: автотесты, `tcpdump` / `tshark` и промпт для ИИ

### 6.1. Запуск встроенных модульных тестов
```bash
cargo test --package anet-common boring_tls::tests -- --nocapture
cargo test --package anet-common http_help::tests -- --nocapture
cargo test --package anet-client-core config::tests::tls_fingerprint_and_verify_config_resolution -- --nocapture
```

### 6.2. Перехват реального `ClientHello` на боевом клиенте через `tcpdump` и `tshark`

#### Шаг 1. Захват только пакетов `TLS ClientHello` через `tcpdump`
```bash
# Вывод HEX + ASCII дампа пакета ClientHello прямо в терминал для копирования в ИИ:
sudo tcpdump -i any -nn -XX -s 0 -c 2 \
  'tcp port 443 and host <SERVER_IP> and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16) and (tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x01)'
```

#### Шаг 2. Детальная расшифровка структуры `ClientHello` через `tshark` (опционально)
```bash
tshark -r anet_client_hello.pcap -Y "tls.handshake.type == 1" \
  -T fields \
  -e ip.ttl \
  -e tcp.window_size_value \
  -e tls.handshake.version \
  -e tls.handshake.ciphersuite \
  -e tls.handshake.extension.type \
  -e tls.handshake.extensions_supported_group \
  -e tls.handshake.extensions_alpn_str \
  -e tls.handshake.extensions_server_name \
  -e tls.handshake.sig_hash_alg
```

---

### 6.3. Эталонный Промпт для ИИ-аудитора дампа `tcpdump` / `tshark`

Скопируйте следующий промпт и вставьте после него вывод команды `tcpdump -XX` или `tshark -V`:

```text
Ты — ведущий специалист по сетевой безопасности, анализу TLS-фингерпринтинга (JA3 / JA4 / Akamai HTTP/2) и системам DPI/ТСПУ.
Ниже приведён дамп пакета TLS ClientHello (и/или HTTP-заголовков), захваченный с моего клиента.
Если я не указал явно ОС, профиль tls_fingerprint и транспорт — определи их самостоятельно по заголовкам L2/L3/L4, структуре шифров/расширений и полю ALPN в дампе.

Проведи строгий побайтовый технический аудит дампа (с вычислением точных строк и хешей JA3 и JA4) по следующим 8 пунктам:
1. GREASE и перестановка расширений (Extension Permutation): присутствуют ли GREASE-значения (0x?a?a) во всех 5 точках (Cipher Suites, Extensions, Supported Groups, Key Share, Supported Versions)? Совпадает ли GREASE-группа в Key Share с первой GREASE-группой в Supported Groups? Соответствует ли наличие/отсутствие GREASE и перестановки расширений заявленному браузеру (Chrome — GREASE + permutation; Safari — GREASE без permutation; Firefox — без классических GREASE)?
2. Порядок и состав Cipher Suites (JA3 vs JA4_b): соответствует ли список и приоритет шифров TLS 1.3 и TLS 1.2 реальному браузеру? Проверь, нет ли гибридного конфликта (например, порядка TLS 1.3 0x1301->0x1302->0x1303 от BoringSSL при шифрах TLS 1.2 от Firefox, или урезанного списка шифров Safari без RSA-блока). Совпадает ли вычисленный JA4_b с эталонным хешем браузера (8daaf6152771 для Chrome, 5b57614c22b0 для Firefox)?
3. Supported Groups и Signature Algorithms: присутствуют ли корректные кривые (29-23-24 для Chrome; наличие P-521 = 0x0019 для Firefox/Safari; нет ли аномального порядка P-384 перед P-256)? Проверь список signature_algorithms (0x000d): 8 алгоритмов у Chrome, 11 алгоритмов (включая legacy 0x0203/0x0201) у Firefox и Safari. Не обрезан ли список до 9 алгоритмов (маркер Go crypto/tls)?
4. Набор и скелет TLS-расширений (JA4_c): проверь наличие status_request (OCSP, 0x0005), signed_certificate_timestamp (SCT, 0x0012 — обязан быть у Chrome/Safari и отсутствовать у Firefox), отсутствие session_ticket (0x0023) у Safari, наличие compress_certificate (0x001b) / ALPS (0x4469) / ECH (0xfe0d) / padding (0x0015).
5. Размер пакета и сегментация TCP (BoringSSL Padding & Post-Quantum): проверь общий размер TLS Record и TCP-пейлоада. Укладывается ли ClientHello в один TCP-сегмент (< 1460 байт MSS, например 517 байт при выравнивании BoringSSL padding до 512 байт), и уместно ли наличие padding (0x0015) для выбранного профиля?
6. ALPN (0x0010): проверь, что для HTTP/2-транспорта (AHTTP/REST) анонсируется ["h2", "http/1.1"] (JA4 префикс h2), а для WebSocket (WSS/XMPP/Colibri/TURNS) — строго ["http/1.1"] без "h2" (JA4 префикс h1).
7. Синхронизация L3/L4/L6/L7 (OS & Browser Consistency): совпадает ли IP TTL, флаг DF и TCP Window / Options с ОС и выбранным браузером (например, нет ли отправки профиля Safari с Linux/Windows TCP-стека, или утечки заголовков sec-ch-ua* при профиле Firefox/Safari)?
8. Итоговый вердикт по схеме детектов ТСПУ / DPI: оцени по 10-балльной шкале стойкость пакета против пассивного DPI (чёрные списки библиотек Go/rustls/OpenSSL vs белые списки браузерных JA3/JA4) и укажи точные строки кода в boring_tls.rs / http_help.rs, если требуются исправления.

Вот дамп:
[ВСТАВЬТЕ ВЫВОД TCPDUMP -XX ИЛИ TSHARK -V СЮДА]
```