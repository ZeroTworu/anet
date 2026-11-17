# Транспорт `ahttp` (`http://` / `https://`): архитектура, режимы работы и настройка

> Актуально на @6cc9319

## 1. Назначение и режимы работы (Напрямую, Cloudflare и CDNVideo)

Транспорт `ahttp` (`Asymmetric HTTP Stream` / Stateless Packet-Exchange) инкапсулирует шифрованный трафик ASTP в серию стандартных HTTP/1.1 и HTTP/2 запросов (`POST`, `GET`, `PUT`) без использования заголовков `Upgrade: websocket`. Для внешнего наблюдателя, корпоративного прокси, WAF или ТСПУ обмен выглядит как обычная отправка телеметрии или подгрузка медиа-фрагментов (`video/mp4`, `application/octet-stream`) современным браузером.

Хотя изначально `ahttp` создавался для прохождения через жёсткие HTTP-прокси и облачные **CDN**, не поддерживающие WebSocket или режущие длинные стримы, **транспорт штатно и стабильно работает в трёх сценариях**:

### Режим 1: Напрямую до сервера (Direct Mode — без CDN)
```text
[клиент] --https:// (HTTP/2, TLS 1.3)--> [Nginx на VPN-сервере :443]
                                         --http:// (127.0.0.1:8081)--> [anet-server] --> [интернет]
```
*(либо напрямую `http://203.0.113.10:8081/api/v2/telemetry` без Nginx)*

В прямом режиме отсутствуют промежуточные буферы и rate-лимитеры CDN-нод:
* Включается автоматическое масштабирование окон HTTP/2 (`http2_adaptive_window = true`), позволяющее окну соединения расширяться под реальный Bandwidth-Delay Product (BDP) канала.
* Размер HTTP/2 DATA-фрейма поднимается до `65536` байт (64 КБ), а бюджет одного батча (`coalesce_budget_bytes`) составляет `65536`–`131072` байт (64–128 КБ).
* Снятие искусственных лимитов окна HTTP/2 позволяет развивать полную скорость канала как на скачивание (Downlink), так и на выгрузку (Uplink).

### Режим 2: Через Cloudflare Proxy (`CF`)
```text
[клиент] --https:// (HTTP/2, TLS 1.3)--> [Cloudflare Edge] --http(s):// (HTTP/1.1 / chunked)--> [Nginx на сервере]
                                                                                                --> [anet-server]
```
Cloudflare поддерживает WebSocket (`wss://`), однако также активно используется для `ahttp` (`https://`), где раньше классический polling быстро упирался в `429 Too Many Requests` или ломал парсинг на сервере при конвертации HTTP/2 $\to$ HTTP/1.1. В обновлённой реализации учтены все особенности Cloudflare:
* **Инкрементальный парсер `Transfer-Encoding: chunked` (RFC 9112 §7.1):** `anet-server` корректно принимает POST-запросы как с `Content-Length`, так и в `chunked`-кодировании (с chunk extensions, трейлерами и защитой от превышения `max_body_bytes`).
* **Smart Long-Poll в простое (`max_idle_polls = 1` + серверный `idle_poll_timeout_ms = 1500`):** вместо флуда сотнями пустых запросов в секунду клиент держит не более `1` фонового long-poll запроса с адаптивным backoff (`25..500 мс`), а сервер удерживает его до `1500 мс` (глубоко внутри лимита Cloudflare в 100 секунд), просыпаясь за `0 мс` при появлении первого downlink-пакета. В покое нагрузка падает до `< 1 RPS`.
* **Учёт `429` / `503` и `Retry-After`:** при срабатывании rate-limiter CDN клиент синхронизирует общий backoff-гейт на весь пул воркеров (`pool_backoff_ms`) и повторяет запрос с экспоненциальной задержкой и джиттером (`max_retries`, `retry_base_ms..retry_max_ms`).
* **Профиль для CF:** обычно достаточно `concurrency = 8`, `tcp_pool_size = 2`, `coalesce_budget_bytes = 65536`, `http2_adaptive_window = true` и `send_session_in_header = true` (скрывает `?session_id=` из access-логов CDN/Nginx).

### Режим 3: Через строгие CDN (CDNVideo и др.)
```text
[клиент] --https:// (HTTP/2)--> [Edge-нода CDN] --http(s):// (HTTP/1.1)--> [Nginx на сервере]
                                                                           --> [anet-server]
```
На пограничных узлах ряда CDN (например, CDNVideo) действует жёсткое стартовое окно потока HTTP/2 по RFC 7540 (`65535` байт) и буферизация крупных POST-тел при конвертации HTTP/2 $\to$ HTTP/1.1:
* Достаточно добавить параметр `?cdn=1` в `dsn` сервера (например, `https://example.com/api/v2/telemetry?cdn=1`) либо задать `uplink_coalesce_budget_bytes = 49152` (48 КБ) и `http2_adaptive_window = false` в `[ahttp]`.
* Тогда каждый исходящий POST-батч клиента гарантированно укладывается в стартовое окно `65535` байт и уходит за один RTT без паузы на ожидание кадра `WINDOW_UPDATE`.

---

## 2. Архитектура конвейера данных (`AHTTP` Data Plane)

### 2.1. Фазы соединения и восстановление сессии
Весь обмен разделён на три HTTP-пути относительно базового префикса из `dsn` (например, `/api/v2/telemetry`):
1. **`POST .../handshake` (Phase I–II):** клиент отправляет `ClientHello`, сервер отвечает подписанным `ServerHello` и создаёт запись в `PendingHandshakes`.
2. **`POST .../auth` (Phase III–IV):** клиент отправляет зашифрованные учётные данные (при реконнекте — с `resume_session_id`), сервер валидирует их, выделяет/восстанавливает туннельный IP и возвращает параметры сессии (`session_id`, `nonce_prefix`, `ip`, `gateway`).
3. **`POST .../traffic` (Data Plane):** двусторонний обмен батчами. Идентификатор сессии передаётся в HTTP-заголовке с настраиваемым именем `session_id_header` (по умолчанию `X-Session-Id`, если `send_session_in_header = true`) либо в настраиваемом query-параметре `session_id_query_param` (по умолчанию `?session_id=<HEX>`); сервер принимает оба варианта.

**Автоматическое восстановление (`resume_session_id`):**
* Если сервер вернул `401 Unauthorized` / `404 Not Found` (например, сессия вытеснена после простоя или рестарта) или число подряд проваленных транзакций достигло `max_consecutive_failures`, клиент сериализованно (под `reauth_lock`) запускает `try_reconnect_ahttp` с `resume_session_id`.
* При успешном resume/переавторизации с тем же IP/шлюзом воркеры и `ReassemblyQueue` плавно переходят на новое поколение сессии (`gen_id`) без разрыва `DuplexStream` и TUN-интерфейса.
* Если сервер выдал новый туннельный IP и включён `abort_on_ip_change = true` (либо сервер отказал `AuthDenyError` / истёк `reconnect_timeout_secs`), транспорт корректно закрывает `DuplexStream`, передавая управление failover-ядру клиента.

### 2.2. Разделение AEAD nonce, >64 КБ фрейминг и `ReassemblyQueue`
* **Непересекающиеся пространства `sequence`:**
  * Uplink (клиент $\to$ сервер) всегда нумеруется от `CLIENT_SEQUENCE_START` (`2^63`, старший бит `1`).
  * Downlink (сервер $\to$ клиент) всегда нумеруется от `SERVER_SEQUENCE_START` (`0`, старший бит `0`).
  * При одном общем `shared_key` и `nonce_prefix` направления криптографически изолированы — коллизия `(key, nonce)` в ChaCha20-Poly1305 полностью исключена.
* **Общий кодек пакетов > 64 КБ:** оба конца используют `anet_common::transport::unwrap_packet_with_seq`, корректно распаковывающий пакеты с `LARGE_PACKET_LEN_SENTINEL`.
* **Выделенный sink Downlink и скользящее окно `ReassemblyQueue`:**
  * Клиентский `ReassemblyQueue` вынесен в отдельную фоновую задачу `run_downlink_sink`, освобождая HTTP-воркеры от мьютекса и точно отрабатывая таймер `gap_remaining()` $\to$ `flush_expired()` даже при полном прекращении входящего трафика (нет HoL-зависаний хвостовых пакетов).
  * Серверный `ReassemblyQueue` также сбрасывает просроченные дыры при получении пустых poll-запросов, а при смене `nonce_prefix` (после `resume`) сессия переинициализируется с новым `rx_router` и чистым ресемблером.

### 2.3. Механизмы минимизации задержек и защиты от таймаутов
1. **Мгновенный ответ сервера на тяжёлые Uplink-батчи ($\ge$ `heavy_uplink_threshold_bytes`, 8 КБ):** сервер проверяет очередь через `try_recv` (таймаут 1 мс) и сразу отдаёт `200 OK`, не задерживая слот `concurrency` при активной выгрузке.
2. **Self-Clocking при активном скачивании (`downlink_credits`):** при получении непустого ответа воркер клиента начисляет кредиты (`+3` при батче $\ge 1300$ байт или $\ge 2$ пакетах, `+1` при одиночном пакете) и мгновенно отправляет следующий запрос без ожидания `poll_timeout_ms`.
3. **Умное ожидание в покое:** при отсутствии трафика работает ограничение `max_idle_polls` (`1`), адаптивная пауза `idle_poll_interval_ms..idle_backoff_max_ms` (`25..500 мс`) и серверный `idle_poll_timeout_ms` (`1500 мс`).
4. **Таймауты и сборка мусора на сервере:** чтение заголовков и тела ограничено `read_timeout_ms` (`15000 мс`), запись ответа — `write_timeout_ms` (`15000 мс`), простаивающие keep-alive сокеты — `idle_keepalive_timeout_secs` (`75 с`, больше стандартных `60 с` в Nginx во избежание гонки закрытия сокета), а фоновый GC каждые `session_gc_interval_secs` (`15 с`) удаляет уже выселенные из `ClientRegistry` сессии.

---

## 3. Примеры настройки Nginx

Перед `anet-server` рекомендуется ставить Nginx, который терминирует TLS (HTTP/2) и проксирует запросы по HTTP/1.1 keep-alive к локальному сокету `ahttp_bind_to` (`127.0.0.1:8081`).

### 3.1. Полный конфиг Nginx с TLS и HTTP/2 (для работы напрямую и через Cloudflare / CDN)

Файл `/etc/nginx/sites-available/ahttp-node.conf`:

```nginx
# Пул постоянных HTTP/1.1 соединений от Nginx к локальному anet-server
upstream anet_ahttp_backend {
    server 127.0.0.1:8081;
    keepalive 64;
    keepalive_timeout 60s;
}

server {
    listen 80;
    listen [::]:80;
    server_name example.com;

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name example.com;

    # Сертификаты Let's Encrypt или Cloudflare Origin CA
    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # Разрешаем крупные батчи в теле POST-запросов (согласовано с max_body_bytes = 4m..16m)
    client_max_body_size 16m;
    tcp_nodelay on;

    # 1. Сайт-прикрытие (Decoy) на всех остальных путях
    location / {
        root /var/www/html;
        index index.html index.htm;
        try_files $uri $uri/ =404;
    }

    # 2. Маршрут AHTTP-транспорта (должен совпадать с ahttp_path в server.toml)
    location /api/v2/telemetry {
        proxy_pass http://anet_ahttp_backend;
        proxy_http_version 1.1;

        # Очищаем заголовок Connection для корректной работы upstream keepalive
        proxy_set_header Connection "";

        # Проброс реального IP клиента (включая CF-Connecting-IP / X-Forwarded-For)
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # КРИТИЧНО: полностью отключаем буферизацию запросов и ответов в Nginx
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_cache off;
        proxy_socket_keepalive on;

        # Таймауты удержания соединений
        proxy_connect_timeout 60s;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;

        # Запрет буферизации и трансформации тела для CDN / Cloudflare
        add_header X-Accel-Buffering "no" always;
        add_header Cache-Control "private, no-store, no-cache, max-age=0, must-revalidate, no-transform" always;
        add_header Pragma "no-cache" always;
    }
}
```

### 3.2. Конфиг Nginx без TLS (за Cloudflare Flexible / внешним фронтендом на порту :80)

```nginx
upstream anet_ahttp_backend {
    server 127.0.0.1:8081;
    keepalive 64;
    keepalive_timeout 60s;
}

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    client_max_body_size 16m;
    tcp_nodelay on;

    location / {
        root /var/www/html;
        index index.html;
    }

    location /api/v2/telemetry {
        proxy_pass http://anet_ahttp_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        proxy_buffering off;
        proxy_request_buffering off;
        proxy_cache off;

        proxy_connect_timeout 60s;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

---

## 4. Конфигурация `client.toml` и `server.toml`

### 4.1. Клиент (`client.toml`)

В `dsn` сервера поддерживаются необязательные query-параметры для точечной подстройки под маршрут:
* `?cdn=1` — включает профиль совместимости с CDNVideo (ограничивает Uplink-батч до `49152` байт и при `http2_adaptive_window = false` выставляет окна `49152` байт); для Cloudflare `?cdn=1` обычно **не нужен**;
* `?budget=65536` — явное переопределение лимита Uplink-батча в байтах для данного сервера;
* `?pool=2` — переопределение числа TCP/TLS соединений в пуле (`tcp_pool_size`);
* `?method=POST` — переопределение HTTP-метода отправки (`POST`, `PUT` и т.д.);
* `?fp=auto|chrome|firefox|safari|randomized` — переопределение профиля TLS ClientHello (BoringSSL) и HTTP-заголовков;
* `?verify=1|0` и `?pin=<SHA256>` — управление защитой от активного спуфинга ТСПУ (`tls_verify_peer = true` по умолчанию);
* `?tls_frag=1` (`?tls_frag=0`), `?tfrag=10..20`, `?tdelay=0` — L4 TCP-фрагментация первого TLS `ClientHello` (`tlshello`) для обхода DPI по открытому SNI.

```toml
[stealth]
tls_fingerprint = "auto"
tls_verify_peer = true
tls_frag_enabled = false
tls_frag_length = "10..20"
tls_frag_delay_ms = "0"

# Пример 1: Прямое подключение к серверу (без CDN)
[[servers]]
name = "Direct Node [AHTTP]"
dsn = "https://example.com/api/v2/telemetry"
timeout_secs = 10
server_pub_key = "<BASE64_ED25519_PUBLIC_KEY>"

# Пример 2: Подключение через Cloudflare Proxy (CF)
# [[servers]]
# name = "Cloudflare Node [AHTTP]"
# dsn = "https://cf.example.com/api/v2/telemetry?pool=2"
# timeout_secs = 15
# server_pub_key = "<BASE64_ED25519_PUBLIC_KEY>"

# Пример 3: Подключение через строгую CDN (CDNVideo)
# [[servers]]
# name = "CDNVideo Node [AHTTP]"
# dsn = "https://cdn.example.com/api/v2/telemetry?cdn=1"
# timeout_secs = 15
# server_pub_key = "<BASE64_ED25519_PUBLIC_KEY>"

[ahttp]
# --- Параметры параллельности и коалесценции пакетов ---
concurrency = 12
# concurrency = 8 # для CDN / Cloudflare

tcp_pool_size = 4
# tcp_pool_size = 2 # для CDN / Cloudflare

coalesce_budget_bytes = 131072
# coalesce_budget_bytes = 65536 # для CDN / Cloudflare

# Отдельный лимит размера Uplink POST-батча (для CDNVideo рекомендуется 49152)
# uplink_coalesce_budget_bytes = 49152

# Микро-коалесценция тяжелого uplink-трафика (длительность в мкс и порог активации в байтах)
micro_coalesce_us = 500
micro_coalesce_min_bytes = 256

# --- Управление фоновым опросом (защита от idle RPS-флуда на Cloudflare / CDN) ---
poll_timeout_ms = 10
max_idle_polls = 1
idle_poll_interval_ms = 25
idle_backoff_max_ms = 500

# --- Очереди и скользящее окно переупорядочивания ---
tx_queue_capacity = 256
downlink_queue_capacity = 512
reassembly_queue_max_size = 2048
# reassembly_queue_max_size = 1024 # для CDN
reassembly_gap_timeout_ms = 150

# --- Устойчивость к сбоям, rate-limit (429/503) и восстановление сессии ---
max_retries = 4
retry_base_ms = 100
retry_max_ms = 3000
max_consecutive_failures = 6
# reconnect_timeout_secs = 30
reconnect_retry_min_ms = 350
reconnect_retry_max_ms = 1500
abort_on_ip_change = true

# Передавать session_id в HTTP-заголовке вместо query-параметра (рекомендуется для Cloudflare)
send_session_in_header = false
# send_session_in_header = true
session_id_header = "X-Session-Id"
session_id_query_param = "session_id"

# --- Настройки HTTP/2 и пула сокетов ---
http2_adaptive_window = true
# http2_adaptive_window = false # для CDNVideo при жёстком окне edge-узла
# http2_initial_stream_window_size = 49152
# http2_initial_connection_window_size = 49152
http2_max_frame_size = 65536
http2_max_header_list_size = 65536
http2_keep_alive_interval_secs = 20
# http2_keep_alive_interval_secs = 15 # для CDN / Cloudflare
http2_keep_alive_timeout_secs = 10
http2_keep_alive_while_idle = true

pool_max_idle_per_host = 16
# pool_max_idle_per_host = 8 # для CDN / Cloudflare
pool_idle_timeout_secs = 90
# pool_idle_timeout_secs = 45 # для CDN / Cloudflare
tcp_nodelay = true
timeout_secs = 10
# timeout_secs = 15 # для CDN / Cloudflare (должно быть строго > серверного idle_poll_timeout_ms)

# Суффиксы эндпоинтов (прибавляются к базовому пути из dsn; должны совпадать с server.toml)
handshake_path = "/handshake"
auth_path = "/auth"
traffic_path = "/traffic"
```

### 4.2. Сервер (`server.toml`)

```toml
[server]
# Локальный адрес, на который Nginx проксирует запросы (или 0.0.0.0:8081 при прямом http://)
ahttp_bind_to = "127.0.0.1:8081"
# Базовый префикс маршрута (должен совпадать с location в Nginx и путём в dsn клиента)
ahttp_path = "/api/v2/telemetry"

[ahttp]
handshake_path = "/handshake"
auth_path = "/auth"
traffic_path = "/traffic"

max_header_bytes = 16384
# Максимум тела входящего запроса (для Content-Length и Transfer-Encoding: chunked)
max_body_bytes = 4194304

# Таймауты HTTP-транспорта: чтение/запись (мс) и ожидание idle keep-alive сокета (сек, >= Nginx keepalive_timeout)
read_timeout_ms = 15000
write_timeout_ms = 15000
idle_keepalive_timeout_secs = 75

# Фоновая очистка устаревших ServerSession (сек)
session_gc_interval_secs = 15

# Настраиваемый HTTP-заголовок и query-параметр URL, из которых сервер извлекает session_id
session_id_header = "X-Session-Id"
session_id_query_param = "session_id"

# Шаблон HTTP-заголовков ответа ({} автоматически заменяется на Content-Length пачки)
response_headers = """
HTTP/1.1 200 OK
Content-Type: video/mp4
Cache-Control: no-cache, no-transform, private, must-revalidate
Pragma: no-cache
X-Accel-Buffering: no
Content-Length: {}
Connection: keep-alive\n\n"""

# Скользящее окно ReassemblyQueue и таймаут дыры последовательности (мс)
reassembly_queue_max_size = 1024
reassembly_gap_timeout_ms = 150

# Бюджет коалесценции Downlink-ответа сервера и окно добора пачки (мс / мкс)
coalesce_budget_bytes = 131072
coalesce_max_wait_ms = 4
coalesce_gap_timeout_us = 1000

# Ожидание при мелком uplink (мс), длинный опрос в простое (мс) и порог мгновенного ответа на upload (байт)
poll_timeout_ms = 25
idle_poll_timeout_ms = 1500
heavy_uplink_threshold_bytes = 8192
```
