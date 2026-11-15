# Транспорт `ws://` / `wss://` (WebSocket): топология, режимы работы и настройка

> Актуально на @64295da

## 1. Режимы развёртывания: напрямую и через CDN / Edge-прокси

Транспорт WebSocket (`ws://` и `wss://`) поддерживает **оба режима эксплуатации** без необходимости пересборки клиента или сервера:

### Режим А: Прямое подключение к серверу (Direct Mode — без CDN)
Клиент подключается напрямую к целевому VPN-серверу:
1. **Через Nginx на самом VPN-сервере (`wss://example.com:443/socket`):**
   ```text
   [клиент] --wss:// (TLS 1.3 + ALPN) --> [Nginx на целевом сервере :443]
                                          --ws:// (loopback 127.0.0.1:8080)--> [anet-server] --> [интернет]
   ```
   Это основной рекомендуемый вариант для прямого подключения: трафик идёт без посредников с минимальным RTT, а снаружи порт `443` выглядит как обычный веб-сайт с валидным сертификатом Let's Encrypt и сайтом-прикрытием (decoy) на корневом пути `/`.
2. **Напрямую в сокет `anet-server` (`ws://203.0.113.10:8080/socket`):**
   ```text
   [клиент] --ws://--> [anet-server :8080] --> [интернет]
   ```
   Может использоваться во внутренних сетях, при отладке или за внешним L4/TLS-балансировщиком. Так как полезная нагрузка уже зашифрована на уровне ASTP (`X25519` + `ChaCha20-Poly1305`), отсутствие внешнего TLS не снижает криптографическую стойкость данных.

### Режим Б: Работа через CDN или промежуточный узел (CDN / Relay Mode)
Изначально транспорт проектировался также для прохождения через облачные CDN (Cloudflare, CDNVideo и аналоги) или промежуточные reverse-proxy в «белой» зоне:
```text
[клиент] --wss://--> [ТСПУ / фильтрация]
         --wss://--> [Edge-нода CDN или белый IP с Nginx + TLS]
         --ws(s)://--> [anet-server] --> [интернет]
```

`anet-server` **не завершает TLS внутри себя** — он всегда слушает обычный `ws://` на внутреннем адресе (`server.websocket_bind_to`). Вся TLS-терминация и отдача сайта-прикрытия вынесены на Nginx (или Caddy).

---

## 2. Почему TLS вынесен на Nginx, а не встроен в `anet-server`

С точки зрения защиты от активного зондирования (Active Probing со стороны ТСПУ и систем DPI) выделенный веб-сервер перед `anet-server` решает две критические задачи:

1. **Настоящий сертификат вместо самоподписанного.** Системы активного зондирования подключаются к IP:443 и проверяют цепочку доверия сертификата. Сертификат Let's Encrypt, автоматически обслуживаемый Nginx/Certbot, неотличим от обычного коммерческого веб-ресурса.
2. **Сайт-прикрытие (Decoy Content).** На всех путях, кроме секретного пути WebSocket (`websocket_path`), Nginx отдаёт полноценный статический сайт или веб-приложение. Кроме того, даже при обращении на сам путь `/socket` обычным браузером (без заголовка `Upgrade: websocket`) Nginx возвращает стандартный `404 Not Found`.

---

## 3. Архитектура конвейера данных и оптимизации производительности

Для достижения высокой пропускной способности (как напрямую, так и через прокси/CDN) в транспорте реализован полнодуплексный конвейер:

1. **Полнодуплексный Split-конвейер (Full-Duplex Reader/Writer):**
   * Каждый сокет пула делится (`StreamExt::split`) на полностью независимые асинхронные задачи чтения и записи: чтение входящих кадров больше не блокируется на время записи/ожидания ответа, а доставка в TUN идёт через честный асинхронный `tun_tx.send(...).await` (естественный TCP backpressure без дропов `try_send`).
   * Буферы сокета WebSocket расширены (`read_buffer_size = 128 КБ`, `write_buffer_size = 128 КБ`, `max_write_buffer_size = 512 КБ`, `MAX_WS_MESSAGE_SIZE = 256 КБ`).
2. **Отсутствие двойного фреймирования (Zero Redundant Framing):**
   * Протокол WebSocket (RFC 6455) уже содержит собственную длину каждого бинарного фрейма (`Message::Binary`).
   * Поэтому между клиентом и сервером в каждом `Message::Binary` передаётся один или несколько склеенных пакетов с 2-байтовым префиксом длины `[len: u16 BE][encrypted_astp_packet]` без лишних внешних обёрток.
3. **Адаптивная агрегация пакетов на отправке (Coalescing 16–64 КБ):**
   * Если в очереди накопилась пачка пакетов, воркер отправки вычитывает их через `try_recv()` и отправляет **одним** WebSocket-фреймом за один системный вызов.
   * При одном активном сокете используется бюджет **64 КБ** (`COALESCE_BUDGET_BYTES`); при активном мульти-сокетном пуле (`active_sockets > 1`) — **16 КБ** (`WS_POOL_COALESCE_BUDGET_BYTES`), чтобы пачки равномерно разбирались несколькими воркерами, а не уходили целиком в один сокет.
4. **Раздельные AEAD-полупространства и Reassembly-окно:**
   * Клиент нумерует исходящие пакеты начиная с `CLIENT_SEQUENCE_START = 1 << 63`, сервер — с `SERVER_SEQUENCE_START = 0`, что полностью исключает коллизию `(Key, Nonce)` при параллельной передаче через несколько сокетов.
   * На принимающей стороне `ReassemblyQueue` (окно `2048` пакетов, `gap_timeout = 60 мс`) восстанавливает порядок IP-пакетов, если соседние кадры пришли по разным сокетам пула с отличающимся RTT.
5. **Принудительный `TCP_NODELAY = true`:**
   * И на клиенте (`connect_async_with_config(..., true)`), и на сервере (`stream.set_nodelay(true)`) алгоритм Нейгла принудительно отключён, что исключает 40-миллисекундные задержки TCP ACK при обмене мелкими фреймами.
6. **Пул параллельных WebSocket-соединений (`?pool=N` / `?mux=N`):**
   * Клиент по умолчанию открывает пул из **4 параллельных WebSocket-соединений** (максимум `8`) в рамках одной ASTP-сессии.
   * Первый слот выполняет полное ASTP-рукопожатие, а остальные подключаются за **1 RTT** по протоколу `WS_MUX_BIND` (`ANETMUX1` / `ANETOK01`) с привязкой к уже существующей сессии — без вытеснения клиента в `ClientRegistry`. Плановая ротация слотов смещена по времени, чтобы туннель не терял пропускную способность при переподключении одного из сокетов.

### 3.1. Зачем вообще нужен пул параллельных соединений («нафига параллелиться»)

На первый взгляд может показаться, что раз VPN уже инкапсулирует десятки TCP/UDP-потоков пользователя (браузер, `iperf3 -P 2` и т. д.) внутрь одного IP-туннеля, достаточно одного WebSocket или одного HTTP/2-соединения. На практике при работе через прокси, CDN (Cloudflare) и ТСПУ **одиночный TCP-поток упирается в физические и протокольные ограничения**:

1. **TCP-over-TCP Head-of-Line (HoL) Blocking:** в одиночном WebSocket все пакеты всех приложений едут по одному внешнему TCP-соединению. Потеря даже одного TCP-сегмента на участке `клиент ↔ Cloudflare ↔ сервер` замораживает доставку *всех* следующих WebSocket-фреймов в ядре до завершения SACK/ретрансмита (~1–2 RTT). Внутренние TCP-потоки внутри туннеля видят скачок задержки и сразу режут окно (`cwnd`), проваливая скорость до 1–2 Мбит/с с провалами в `0.00 bits/sec`.
2. **HTTP/2 не спасает для WebSocket:** даже при наличии HTTP/2 (`RFC 8441`) несколько логических стримов всё равно делят **одно и то же** подлежащее TCP-соединение и буферы edge-прокси. Потеря TCP-пакета точно так же останавливает все H2-стримы одновременно. Именно поэтому Xray / v2ray и другие прокси-туннели при работе поверх `WS`/`gRPC`/`SplitHTTP` через CDN открывают пул **отдельных физических TCP+TLS-соединений**.
3. **Ограничение полосы и буферов на 1 соединение со стороны CDN/ТСПУ:** edge-прокси и промежуточные фильтры ограничивают размер окна, скорость сглаживания и буферизацию *на каждый TCP-сокет* (например, одиночный HTTPS-поток через CF до сервера может выдавать ~60–70 Мбит/с, а 4 параллельных потока — уже 100+ Мбит/с). При нескольких сокетах в пуле пока одно соединение ждёт ретрансмита или ротируется, остальные 3 продолжают качать данные без остановки конвейера.
4. **Почему оптимум — `?pool=4`, а не `?pool=8`:**
   * При тестировании через Cloudflare (`RU -> CF FRA -> NL VPS`, `iperf3 -P 2`) пул `?pool=4` дал лучший баланс: скачивание (downlink) выросло с ~1–2 Мбит/с до **66–75 Мбит/с** средних (пики **88 Мбит/с**), а отдача (uplink) разогналась до **50 Мбит/с** в пике.
   * При увеличении до `?pool=6..8` (8 — жёсткий потолок) растёт разброс RTT между 6–8 независимыми TCP-соединениями: пакеты одного внутреннего потока чаще приходят вразнобой, упираются в окно ожидания `ReassemblyQueue` (`60 мс`), что увеличивает TCP-ретрансмиты внутри туннеля и снижает среднюю скорость отдачи.

### 3.2. Возможная дальнейшая оптимизация (Known Trade-offs & Future Work)

Текущая балансировка пула (`work-stealing / round-robin` по батчам) отлично ускоряет многопоточные и одиночные загрузки, но имеет известный компромисс на отдаче (uplink): соседние пакеты одного внутреннего TCP-потока могут уходить по разным WS-сокетам пула, приходить на сервер с разным RTT и ждать восстановления порядка в `ReassemblyQueue`. Из-за этого `cwnd` внутреннего TCP на аплинке разгоняется ступенчато (в тестах `iperf3` — до 50 Мбит/с в пике при ~18 Мбит/с средних).

**Потенциальное улучшение на будущее:** добавить режим **5-tuple Flow-Affinity** (например, опцией `?sched=flow` рядом с текущим режимом по умолчанию):
* хэш `(src_ip, dst_ip, proto, src_port, dst_port)` закрепляет каждый внутренний TCP/UDP-поток за конкретным слотом пула `0..pool_size`;
* все пакеты одного внутреннего TCP-соединения всегда идут строго через один внешний WebSocket **без межсокетного переупорядочивания** и задержек `ReassemblyQueue`, а разные потоки (разные вкладки, `-P 4`, торрент) параллелятся по разным сокетам пула;
* **компромисс такого режима:** один одиночный внутренний поток (`iperf3 -P 1`) в режиме `flow-affinity` будет ограничен пропускной способностью одного WS-сокета, тогда как при текущей балансировке он может утилизировать весь пул.

---

## 4. Примеры настройки Nginx

Ниже приведены готовые конфигурации Nginx для размещения непосредственно на VPN-сервере (прямой режим) или на промежуточном прокси-узле.

### 4.1. Полный конфиг Nginx с TLS (HTTPS :443 + сайт-прикрытие)

Файл `/etc/nginx/sites-available/ws-node.conf`:

```nginx
# Опциональный пул постоянных соединений к локальному anet-server
upstream anet_ws_backend {
    server 127.0.0.1:8080;
    keepalive 64;
}

server {
    listen 80;
    listen [::]:80;
    server_name example.com;

    # Редирект всего HTTP-трафика на HTTPS
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name example.com;

    # Сертификаты Let's Encrypt (certbot)
    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # Отключаем алгоритм Нейгла на уровне TLS/TCP сокета Nginx
    tcp_nodelay on;

    # 1. Сайт-прикрытие (Decoy) для браузеров и сканеров ТСПУ
    location / {
        root /var/www/html;
        index index.html index.htm;
        try_files $uri $uri/ =404;
    }

    # 2. Маршрут WebSocket-транспорта (должен совпадать с websocket_path в server.toml)
    location /socket {
        # Скрываем эндпоинт от обычных GET-запросов без заголовка WebSocket Upgrade
        if ($http_upgrade !~* "websocket") {
            return 404;
        }

        proxy_pass http://anet_ws_backend;
        proxy_http_version 1.1;

        # Обязательные заголовки переключения протокола (RFC 6455)
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";

        # Проброс реального IP клиента
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # КРИТИЧНО: полностью отключаем буферизацию пакетов в Nginx
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_socket_keepalive on;

        # Длинные таймауты, чтобы Nginx не рвал туннель в моменты простоя
        proxy_connect_timeout 60s;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;

        # Запрет буферизации и кэширования для вышестоящих CDN (если используются)
        add_header X-Accel-Buffering "no" always;
        add_header Cache-Control "private, no-store, no-cache, max-age=0, must-revalidate" always;
    }
}
```

### 4.2. Конфиг Nginx за CDN или в режиме чистого HTTP (:80)

Если TLS терминируется на стороне CDN (или на внешнем фронтенде), достаточно секции `server` на порту `80`:

```nginx
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    tcp_nodelay on;

    location / {
        root /var/www/html;
        index index.html;
    }

    location /socket {
        if ($http_upgrade !~* "websocket") {
            return 404;
        }

        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;

        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;

        add_header X-Accel-Buffering "no" always;
        add_header Cache-Control "private, no-store, no-cache, max-age=0, must-revalidate" always;
    }
}
```

---

## 5. Настройка `client.toml` и `server.toml`

### 5.1. Клиент (`client.toml`)

```toml
[stealth]
# Профиль TLS ClientHello (ALPN: strictly "http/1.1" для WSS) и синхронизированных HTTP Upgrade заголовков:
# "auto" (по умолчанию) | "chrome" | "firefox" | "safari" | "randomized"
tls_fingerprint = "auto"
# Защита от активного спуфинга ТСПУ (по умолчанию: true — разрывает соединение на этапе TLS Handshake
# при подмене сертификата до отправки HTTP Upgrade / Sec-WebSocket-Key и пути /socket)
tls_verify_peer = true
# L4 TCP-фрагментация TLS ClientHello (`tlshello`) для обхода DPI по открытому SNI:
# режет первый пакет 0x16 0x03 на фрагменты заданного диапазона байт (синтаксис Xcore "X..Y")
tls_frag_enabled = false
tls_frag_length = "10..20"
tls_frag_delay_ms = "0"

[[servers]]
name = "Direct or CDN Node [WSS]"
# Схема wss:// (через Nginx/CDN с TLS) или ws:// (без TLS)
# Дополнительные query-параметры (опционально):
#   ?pool=4            — количество параллельных WebSocket-соединений в пуле (по умолчанию 4, макс. 8)
#   ?fp=firefox        — переопределение TLS-профиля ("auto", "chrome", "firefox", "safari", "randomized")
#   ?verify=1          — управление проверкой сертификата (по умолчанию включена)
#   ?pin=<SHA256>      — SHA-256 пиннинг сертификата или SPKI публичного ключа
#   ?tls_frag=1        — включить L4 TCP-фрагментацию ClientHello (`tlshello`) для этой ноды
#   ?tfrag=10..20      — диапазон длины фрагмента в байтах (`X..Y` или `N`)
#   ?tdelay=0          — задержка между фрагментами ClientHello в мс (`X..Y` или `N`)
dsn = "wss://example.com/socket?pool=4"
timeout_secs = 10
server_pub_key = "<BASE64_ED25519_PUBLIC_KEY>"
# Опциональные переопределения на уровне ноды:
# tls_fingerprint = "randomized"
# tls_verify_peer = true
# tls_pin_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
# tls_frag_enabled = true
# tls_frag_length = "10..20"
# tls_frag_delay_ms = "0"

# Интервал плановой ротации долгоживущих WebSocket-соединений (в секундах)
websocket_min_session_secs = 900
websocket_max_session_secs = 1800
```

*Примечание по проверке сертификата, порядку заголовков Upgrade и защите от активного спуфинга ТСПУ:* клиентский TLS-коннектор WebSocket на базе BoringSSL анонсирует в ALPN строго `["http/1.1"]`, формирует порядок HTTP/1.1 Upgrade-заголовков строго по профилю браузера (`ws_headers_order` из `[[browser_profiles]]`) и по умолчанию (`tls_verify_peer = true`) проверяет цепочку доверия сертификата (WebPKI + совпадение домена SNI) либо сверяет криптографический пин `tls_pin_sha256`. Если ТСПУ пытается перехватить TLS-сессию поддельным сертификатом, рукопожатие обрывается на уровне TLS до отправки заголовка `Upgrade: websocket` и пути `/socket`. Подробные команды `tcpdump` / `tshark` и описание `[[browser_profiles]]` приведены в [`boringssl_migration.ru.md`](./boringssl_migration.ru.md).

### 5.2. Сервер (`server.toml`)

```toml
[server]
# Локальный адрес, на который Nginx проксирует запросы (или 0.0.0.0:8080 при прямом ws://)
websocket_bind_to = "127.0.0.1:8080"
# Путь должен совпадать с location в Nginx и путём в dsn клиента
websocket_path = "/socket"
```
