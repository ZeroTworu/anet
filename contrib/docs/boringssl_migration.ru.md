# Спецификация: Полиморфная мимикрия BoringSSL (Chrome / Firefox / Safari / Randomized) и защита от активного спуфинга ТСПУ

Документация актуальна для ветки `dev/boringssl` и `master`.

---

## 1. Введение и модель угроз ТСПУ (`tspu-detect.svg`)

Все клиентские TCP/TLS-транспорты (`AHTTP`, `WebSocket`, сигнальные и резервные каналы `WRTC`: REST API Контур.Толк, XMPP-WS, Colibri-WS, локальный мост `TURNS`, а также фоновые службы `Updater` и `RuleCacheManager`) работают поверх нативной криптографической библиотеки Google **`boring` (BoringSSL)**.

Однако, согласно актуальной архитектуре детектов ТСПУ, статический одиночный профиль Chrome без верификации сертификата уязвим сразу в двух точках:
1. **Сверка L4/L7 и сигнатурный детект статического отпечатка (Строка 1 схемы ТСПУ):**
   * Если `BrowserProfile` случайно выбирает HTTP-заголовки `Firefox` (или отправляет `sec-ch-ua*` при `User-Agent: Firefox/Safari`), а на уровне TLS отправляется фиксированный `ClientHello` от `Chrome`, DPI мгновенно фиксирует аномалию рассинхрона L4/L7.
   * Если все клиенты используют один и тот же захардкоженный JA3/JA4-хеш `uTLS Chrome`, ТСПУ использует его как составной триггер блокировки в связке с эвристиками потока.
2. **Активный спуфинг ТСПУ / MITM на этапе TLS Handshake (Строка 2 схемы ТСПУ):**
   * При подозрении на прокси/selfsteal ТСПУ перехватывает исходящий TCP-поток и инжектирует собственный `ServerHello` с подменным сертификатом (самоподписанным, выданным промежуточным DPI-центром или реальным сертификатом от чужого домена-заглушки).
   * Если на клиенте отключена проверка сертификата (`SslVerifyMode::NONE`), клиент завершает TLS-рукопожатие с сенсором ТСПУ и отправляет внутрь перехваченной сессии первый HTTP/2 или WebSocket запрос (`POST /api/v2/telemetry/handshake`, `Upgrade: websocket` на секретный путь `/socket` и т.д.). Сенсор ТСПУ расшифровывает этот первый пакет, видит сигнатуру VPN и мгновенно отправляет IP сервера в блэкхол.

---

## 2. Приоритет 1: Честные профили `Chrome`, `Firefox`, `Safari`, `Randomized` и синхронизация L4/L7

В модулях `anet-common/src/boring_tls.rs` и `anet-common/src/http_help.rs` реализована жёсткая сцепка между профилем TLS (`TlsFingerprint`) и HTTP-шаблоном (`BrowserProfile`):

| Профиль (`tls_fingerprint`) | GREASE | `permute_extensions` | Эллиптические кривые (`Supported Groups`) | Расширения OCSP / SCT | Порядок шифров TLS 1.2 | HTTP-заголовки L7 (`sec-ch-ua*` и `Accept-Encoding`) |
| :--- | :---: | :---: | :--- | :---: | :--- | :--- |
| **`chrome`** | Да | Да (`true`) | `X25519MLKEM768:X25519:P-256:P-384` (fallback `X25519:P-256:P-384`) | OCSP + SCT (`0x0005`, `0x0012`) | `AES128-GCM` $\to$ `AES256-GCM` $\to$ `CHACHA20` | Отправляет `sec-ch-ua`, `sec-ch-ua-mobile`, `sec-ch-ua-platform`; `gzip, deflate, br, zstd` |
| **`firefox`** | **Нет** | **Нет (`false`)** | `X25519:P-256:P-384:P-521` (включая `secp521r1` = `0x0019`) | Только OCSP (`0x0005`), **без SCT** | `AES128-GCM` $\to$ **`CHACHA20`** $\to$ `AES256-GCM` | **НЕ отправляет** `sec-ch-ua*` (в соответствии с NSS/Gecko); `gzip, deflate, br, zstd` |
| **`safari`** | Да | **Нет (`false`)** | `X25519:P-256:P-384:P-521` | OCSP + SCT (`0x0005`, `0x0012`) | **`AES256-GCM`** $\to$ `AES128-GCM` $\to$ `CHACHA20` | **НЕ отправляет** `sec-ch-ua*` (в соответствии с WebKit); `gzip, deflate, br` (без `zstd`) |
| **`randomized`** | Случайно (75%/25%) | Случайно (`true`/`false`) | Случайная браузерная комбинация кривых из 4 пресетов | OCSP + случайный SCT | Случайный браузерный порядок из 4 матриц | Синхронизируется с выбранным шаблоном браузера для текущей сессии |
| **`auto`** *(по умолчанию)* | Авто | Авто | Авто (под текущую ОС компиляции) | Авто | Авто | Случайно выбирает `Chrome`, `Firefox`, `Safari` (на macOS/iOS) или `Randomized` и намертво привязывает L4 к L7 |

### Разделение ALPN для HTTP/2 и WebSocket
* **`BrowserProfile::build_reqwest_builder`** (`build_ssl_connector_with_config`): всегда анонсирует в ALPN оба протокола `h2` и `http/1.1` (`b"\x02h2\x08http/1.1"`).
* **`BrowserProfile::connect_ws_tls`** (`build_ws_ssl_connector_with_config`): для всех WebSocket-соединений (`websocket.rs`, `xmpp.rs`, `peer.rs` Colibri-WS) и потокового `turns_proxy.rs` анонсирует в ALPN строго `http/1.1` (`b"\x08http/1.1"`), чтобы Reverse Proxy / CDN не согласовывал HTTP/2 перед отправкой HTTP/1.1 `Upgrade: websocket`.

---

## 3. Приоритет 2: Защита от активного спуфинга ТСПУ (`tls_verify_peer` и `tls_pin_sha256`)

Защита от активного спуфинга **включена по умолчанию (`tls_verify_peer = true`)** и управляется из секции `[stealth]` либо индивидуально для каждого сервера в `[[servers]]`.

### Как работает перехват на этапе TLS Handshake:
1. **Режим стандартной WebPKI + SNI верификации (`tls_verify_peer = true`, по умолчанию):**
   * При старте клиент однократно загружает системные корневые сертификаты ОС (`rustls-native-certs`: Windows CryptoAPI/`schannel`, macOS/iOS `Security.framework`, Linux `/etc/ssl/certs`, Android `/system/etc/security/cacerts` и `/apex/com.android.conscrypt/cacerts`) в кэш `SYSTEM_ROOT_CERTS` и добавляет опциональный `tls_ca_cert`.
   * В BoringSSL активируется режим `SslVerifyMode::PEER` и строгая проверка имени хоста `set_verify_hostname(true)` (сверка домена SNI с `SubjectAltName` сертификата).
   * Если ТСПУ пытается выполнить активный спуфинг (подсовывает самоподписанный сертификат, сертификат неизвестного УЦ или валидный сертификат от чужого домена), коллбэк верификации BoringSSL возвращает `false` **во время TLS-рукопожатия**.
   * Соединение разрывается до завершения `tokio_boring::connect`, поэтому **в сеть не уходит ни одного байта HTTP-заголовков, путей `/handshake` или `/socket` и пакетов ASTP**.
2. **Режим криптографического пиннинга (`tls_verify_peer = true` + `tls_pin_sha256 = "..."`):**
   * Позволяет защититься даже от скомпрометированных корневых УЦ или безопасно использовать собственный самоподписанный сертификат без отключения защиты от ТСПУ.
   * На глубине `depth == 0` (листовой сертификат сервера) клиент вычисляет `SHA-256` как от полного DER-сертификата, так и от его публичного ключа `SPKI` (`SubjectPublicKeyInfo`).
   * Если любой из двух хешей совпадает с `tls_pin_sha256` (поддерживаются форматы Hex с двоеточиями/без и Base64), соединение разрешается; при несовпадении — мгновенно обрывается с предупреждением `[TLS Anti-Spoof] Certificate SHA-256 pin mismatch!`.
3. **Явное отключение (`tls_verify_peer = false`):**
   * Переводит BoringSSL в `SslVerifyMode::NONE`. Допускается только для локальной отладки на стендах с самоподписанными сертификатами без настроенного `tls_pin_sha256`.

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

# Точечное переопределение на уровне конкретной ноды в [[servers]]:
[[servers]]
name = "Pinned Firefox AHTTP Node"
dsn = "https://example.com/api/v2/telemetry"
tls_fingerprint = "firefox"
tls_verify_peer = true
tls_pin_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# Либо прямо через query-параметры в строке DSN:
# dsn = "wss://example.com/socket?fp=randomized&verify=1&pin=0123456789abcdef..."
```

### Команды `openssl` для получения `tls_pin_sha256` вашего сервера:

```bash
# Вариант А (рекомендуемый): SHA-256 пин публичного ключа (SPKI) — не меняется при продлении сертификата Let's Encrypt с тем же ключом
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

## 4. Аудит и проверка TLS-отпечатка: автотесты, `tcpdump` / `tshark` и промпт для ИИ

### 4.1. Запуск встроенных модульных тестов
В `anet-common` и `anet-client-core` встроены интеграционные тесты, которые поднимают локальный TCP/TLS-стенд, перехватывают реальные бинарные пакеты `ClientHello` от BoringSSL и проверяют:
* Наличие/отсутствие GREASE, `SCT`, `P-521`, порядок шифров и ALPN для профилей `Chrome`, `Firefox`, `Safari`, `Randomized`;
* Отсутствие утечки заголовков `sec-ch-ua*` при выборе профилей `Firefox` и `Safari`;
* Мгновенный разрыв соединения при подмене сертификата (активный спуфинг) с гарантией **0 переданных байт** полезной нагрузки при `tls_verify_peer = true`.

```bash
cargo test --package anet-common boring_tls::tests -- --nocapture
cargo test --package anet-common http_help::tests -- --nocapture
cargo test --package anet-client-core config::tests::tls_fingerprint_and_verify_config_resolution -- --nocapture
```

### 4.2. Перехват реального `ClientHello` на боевом клиенте через `tcpdump` и `tshark`

Чтобы снять реальный сетевой дамп TLS-рукопожатия клиента и отдать его на аудит ИИ:

#### Шаг 1. Захват только пакетов `TLS ClientHello` через `tcpdump`
Запустите на клиенте (или на сервере перед Nginx) захват с точным BPF-фильтром, который отбирает только TCP-пакеты, содержащие TLS Handshake (`0x16`) типа `ClientHello` (`0x01`):

```bash
# Замените <SERVER_IP> на IP вашего VPN-сервера (или уберите host <SERVER_IP> для захвата всех внешних 443)
sudo tcpdump -i any -nn -s 0 -c 5 \
  'tcp port 443 and host <SERVER_IP> and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16) and (tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x01)' \
  -w anet_client_hello.pcap
```

Если `tshark` не установлен, можно сразу вывести HEX + ASCII дамп пакета `ClientHello` прямо в терминал одной командой `tcpdump` (этот текстовый вывод можно сразу копировать в ИИ):

```bash
sudo tcpdump -i any -nn -XX -s 0 -c 2 \
  'tcp port 443 and host <SERVER_IP> and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16) and (tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x01)'
```

#### Шаг 2. Детальная расшифровка структуры `ClientHello` и JA3/JA4 через `tshark` (если установлен)

```bash
# Вывод полного дерева TLS ClientHello (Cipher Suites, Extensions, Supported Groups, ALPN, SNI, Signature Algorithms):
tshark -r anet_client_hello.pcap -Y "tls.handshake.type == 1" -V > client_hello_decoded.txt

# Компактная сводка ключевых полей для быстрой вставки в чат с ИИ:
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

#### Шаг 3. Как проверить срабатывание защиты от активного спуфинга (`tls_verify_peer = true`)
Сэмулируйте перехват ТСПУ, подняв на локальном порту `openssl s_server` с самоподписанным сертификатом, и направьте на него клиент:

```bash
# 1. Генерируем одноразовый самоподписанный сертификат "ТСПУ-спуфера"
openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/spoof.key -out /tmp/spoof.crt -days 1 -subj "/CN=spoof.local"

# 2. Запускаем фейковый TLS-сервер на 127.0.0.1:8443
openssl s_server -accept 127.0.0.1:8443 -cert /tmp/spoof.crt -key /tmp/spoof.key -www
```
При подключении клиента с `tls_verify_peer = true` в логах клиента мгновенно появится:
`[TLS Anti-Spoof] Peer certificate verification failed at depth 0 ... aborting handshake before sending payload`
а в консоли `openssl s_server` будет зафиксирован разрыв TLS-рукопожатия (`tlsv1 alert unknown ca`) **без единого переданного байта HTTP-запроса**.

---

### 4.3. Готовый Промпт для ИИ-аудита дампа `tcpdump` / `tshark`

Скопируйте следующий промпт и вставьте после него вывод команды `tcpdump -XX` или `tshark -V`:

```text
Ты — ведущий специалист по сетевой безопасности, анализу TLS-фингерпринтинга (JA3 / JA4 / Akamai HTTP/2) и системам DPI/ТСПУ.
Ниже приведён дамп пакета TLS ClientHello (и/или HTTP-заголовков), захваченный с моего клиента на ОС [УКАЖИТЕ ОС: Linux / Windows / macOS / Android] при установленном профиле tls_fingerprint = "[УКАЖИТЕ: auto / chrome / firefox / safari / randomized]" для транспорта [УКАЖИТЕ: AHTTP (HTTP/2) / WebSocket (WSS) / WRTC].

Проведи строгий технический аудит дампа по следующим 7 пунктам:
1. GREASE и перестановка расширений: присутствуют ли GREASE-значения (0x?a?a) в Cipher Suites, Extensions, Supported Groups и Key Share? Соответствует ли их наличие/отсутствие заявленному браузеру (Chrome/Safari — да, Firefox — нет)?
2. Порядок Cipher Suites: соответствует ли список и приоритет шифров TLS 1.3 и TLS 1.2 реальному браузеру (например, для Chrome: AES_128_GCM -> AES_256_GCM -> CHACHA20_POLY1305; для Firefox: ChaCha20 перед AES-256 в TLS 1.2)?
3. Supported Groups (Elliptic Curves) и Signature Algorithms: присутствуют ли корректные кривые (X25519MLKEM768 / X25519 / P-256 / P-384 для Chrome; наличие P-521 = 0x0019 для Firefox/Safari)? Нет ли нетипичных для браузера групп?
4. Набор TLS-расширений: проверь наличие status_request (OCSP, 0x0005), signed_certificate_timestamp (SCT, 0x0012 — должен быть у Chrome/Safari и отсутствовать у Firefox), compress_certificate / ALPS / ECH / padding.
5. ALPN (0x0010): проверь, что для HTTP-транспорта (AHTTP/DoH/REST) анонсируется ["h2", "http/1.1"], а для WebSocket (WSS/XMPP/Colibri) — строго ["http/1.1"] (без "h2").
6. Синхронизация L3/L4/L7 (OS & Browser Consistency): совпадает ли IP TTL / TCP Window Size с заявленной ОС, и нет ли конфликта между TLS ClientHello и HTTP-заголовками (например, утечки заголовков sec-ch-ua* при профиле Firefox/Safari)?
7. Вердикт по схеме детектов ТСПУ: есть ли в этом пакете какие-либо аномалии или маркеры нестандартного TLS-клиента (rustls / Go crypto/tls / OpenSSL default), за которые может зацепиться пассивный анализатор DPI?

Вот дамп:
[ВСТАВЬТЕ ВЫВОД TCPDUMP -XX ИЛИ TSHARK -V СЮДА]
```
