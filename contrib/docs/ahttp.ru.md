# Транспорт `ahttp` (`http://` / `https://`): архитектура, режимы работы и настройка

## 1. Назначение и два режима работы (Напрямую и через CDN)

Транспорт `ahttp` (`Asymmetric HTTP Stream` / Stateless Packet-Exchange) инкапсулирует шифрованный трафик ASTP в серию стандартных HTTP/1.1 и HTTP/2 запросов (`POST`, `GET`, `PUT`) без использования заголовков `Upgrade: websocket`. Для внешнего наблюдателя, корпоративного прокси или ТСПУ обмен выглядит как обычная отправка телеметрии или подгрузка медиа-фрагментов (`video/mp4`, `application/octet-stream`) современным браузером.

Хотя изначально `ahttp` создавался для прохождения через жёсткие HTTP-прокси и облачные **CDN (например, CDNVideo)**, не поддерживающие WebSocket или режущие длинные стримы, **транспорт штатно и на полной скорости работает в обоих режимах**:

### Режим 1: Напрямую до сервера (Direct Mode — без CDN)
```text
[клиент] --https:// (HTTP/2, TLS 1.3)--> [Nginx на VPN-сервере :443]
                                         --http:// (127.0.0.1:8081)--> [anet-server] --> [интернет]
```
*(либо напрямую `http://203.0.113.10:8081/api/v2/telemetry` без Nginx)*

В прямом режиме отсутствуют промежуточные буферы CDN-нод, поэтому:
* Включается автоматическое масштабирование окон HTTP/2 (`http2_adaptive_window = true`), позволяющее окну соединения расширяться под реальный Bandwidth-Delay Product (BDP) канала.
* Размер HTTP/2 DATA-фрейма поднимается до `65536` байт (64 КБ), а бюджет одного батча (`coalesce_budget_bytes`) составляет `65536`–`131072` байт (64–128 КБ).
* Снятие искусственных лимитов окна HTTP/2 позволяет развивать полную скорость канала как на скачивание (Downlink), так и на выгрузку (Uplink).

### Режим 2: Через CDN (CDN Mode — CDNVideo, Cloudflare и др.)
```text
[клиент] --https:// (HTTP/2)--> [Edge-нода CDN] --http(s):// (HTTP/1.1)--> [Nginx на сервере]
                                                                           --> [anet-server]
```
При работе через некоторые CDN (в частности, CDNVideo) на пограничных узлах действует стандартное стартовое окно потока HTTP/2 по RFC 7540 (`65535` байт) и специфичная буферизация крупных POST-тел при конвертации HTTP/2 $\to$ HTTP/1.1 к origin-серверу:
* Для работы через такую CDN достаточно добавить параметр `?cdn=1` в `dsn` сервера (например, `https://example.com/api/v2/telemetry?cdn=1`) либо задать `uplink_coalesce_budget_bytes = 49152` (48 КБ) в `client.toml`.
* Тогда каждый исходящий POST-батч клиента гарантированно укладывается в стартовое окно `65535` байт и уходит за один RTT без паузы на ожидание кадра `WINDOW_UPDATE` от CDN.

---

## 2. Архитектура конвейера данных (`AHTTP` Data Plane)

### 2.1. Фазы соединения
Весь обмен разделён на три HTTP-пути относительно базового префикса из `dsn` (например, `/api/v2/telemetry`):
1. **`POST .../handshake` (Phase I–II):** клиент отправляет `ClientHello`, сервер отвечает подписанным `ServerHello` и создаёт запись в `PendingHandshakes`.
2. **`POST .../auth` (Phase III–IV):** клиент отправляет зашифрованные учётные данные, сервер валидирует их, выделяет туннельный IP, создаёт сессию с уникальным `session_id` и возвращает параметры туннеля.
3. **`POST .../traffic?session_id=<HEX>` (Data Plane):** непрерывный двусторонний обмен батчами сетевых пакетов.

### 2.2. Формат бинарного батча и скользящее окно `ReassemblyQueue`
Так как клиент отправляет до `concurrency` (например, 8–12) параллельных HTTP-запросов одновременно, батчи разного размера могут приходить в `anet-server` (и обратно на клиент) не по порядку.
* Каждый зашифрованный пакет внутри тела HTTP-запроса/ответа снабжается 10-байтным заголовком:
  ```text
  [ Sequence Number: u64 BE (8 байт) ] [ Packet Length: u16 BE (2 байта) ] [ ASTP Encrypted Packet ]
  ```
* На сервере порядковые номера `seq` для каждого пакета присваиваются строго в момент формирования батча в порядке очереди, а на приёмной стороне (и на клиенте, и на сервере) работает буфер переупорядочивания **`ReassemblyQueue`**:
  * Пакеты, пришедшие с опережением (out-of-order), буферизуются в `BTreeMap` до прихода задержавшегося соседа.
  * Если пакет действительно потерян или задержан дольше `gap_timeout` (150 мс), скользящее окно `next_expected_seq` продвигается к первому доступному ключу в `BTreeMap`, **выдавая все накопленные пакеты в TUN без потерь** (предотвращая ложные TCP RTO Stall).

### 2.3. Механизмы минимизации задержек (Low-Latency Pipeline)
1. **Мгновенный ответ сервера на тяжёлые Uplink-батчи ($\ge 8\text{ КБ}$):**
   * Когда клиент выгружает данные (Uplink) и присылает крупный `POST` ($\ge 8192$ байт), сервер не удерживает запрос на `poll_timeout_ms` (25 мс) при пустой очереди Downlink, а отвечает `200 OK` мгновенно (`try_recv`). Это освобождает слот `concurrency` на клиенте и позволяет выгрузке идти на полной скорости канала.
2. **Self-Clocking при активном скачивании (`downlink_credits`):**
   * Если сервер вернул непустой ответ с данными (особенно $\ge 16\text{ КБ}$), воркер клиента взводит счётчик `downlink_credits` и отправляет следующий запрос немедленно без ожидания `poll_timeout_ms`.
3. **Микро-коалесценция мелких пакетов ($500\text{ мкс}$):**
   * При появлении одиночного мелкого пакета (например, TCP ACK при скачивании) клиент ждёт всего `500 мкс` (вместо полного `poll_timeout_ms`), собирая соседние ACK из канала, и сразу отправляет батч.
4. **Компактный прогретый пул TCP/TLS соединений (`tcp_pool_size`):**
   * Вместо создания десятков холодных TCP-сокетов клиент держит компактный Round-Robin пул из `tcp_pool_size` (по умолчанию **4**) постоянных HTTP/2 клиентов. Все соединения непрерывно прокачиваются трафиком, не остывают (TCP Congestion Window всегда остаётся открытым), а внутри каждого соединения запросы мультиплексируются по потокам HTTP/2.

---

## 3. Примеры настройки Nginx

Как и в случае с `wss://`, перед `anet-server` рекомендуется ставить Nginx, который терминирует TLS (HTTP/2) и проксирует запросы к локальному сокету `ahttp_bind_to` (`127.0.0.1:8081`).

### 3.1. Полный конфиг Nginx с TLS и HTTP/2 (для работы напрямую и через CDN)

Файл `/etc/nginx/sites-available/ahttp-node.conf`:

```nginx
# Пул постоянных HTTP/1.1 соединений от Nginx к локальному anet-server
upstream anet_ahttp_backend {
    server 127.0.0.1:8081;
    keepalive 64;
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

    # Сертификаты Let's Encrypt
    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # Разрешаем крупные батчи в теле POST-запросов
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

        # Проброс реального IP клиента и заголовков кодирования
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Transfer-Encoding $http_transfer_encoding;

        # КРИТИЧНО: полностью отключаем буферизацию запросов и ответов в Nginx
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_cache off;
        proxy_socket_keepalive on;

        # Таймауты удержания соединений
        proxy_connect_timeout 60s;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;

        # Запрет буферизации и трансформации тела для CDN (если трафик идёт через CDN)
        add_header X-Accel-Buffering "no" always;
        add_header Cache-Control "private, no-store, no-cache, max-age=0, must-revalidate, no-transform" always;
        add_header Pragma "no-cache" always;
    }
}
```

### 3.2. Конфиг Nginx без TLS (за внешним фронтендом / CDN на порту :80)

```nginx
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
        proxy_pass http://127.0.0.1:8081;
        proxy_http_version 1.1;
        proxy_set_header Connection "";

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Transfer-Encoding $http_transfer_encoding;

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

В `dsn` сервера поддерживаются необязательные query-параметры для быстрой подстройки под конкретный маршрут без изменения глобальной секции `[ahttp]`:
* `?cdn=1` — включает профиль совместимости с CDNVideo (ограничивает Uplink-батч до `49152` байт и при `http2_adaptive_window = false` выставляет окна `49152` байт);
* `?budget=65536` — явное переопределение лимита Uplink-батча в байтах для данного сервера;
* `?pool=4` — переопределение числа TCP/TLS соединений в пуле (`tcp_pool_size`);
* `?method=POST` — переопределение HTTP-метода отправки (`POST`, `PUT` и т.д.).

```toml
# Пример 1: Прямое подключение к серверу (без CDN)
[[servers]]
name = "Direct Node [AHTTP]"
dsn = "https://example.com/api/v2/telemetry"
timeout_secs = 10
server_pub_key = "<BASE64_ED25519_PUBLIC_KEY>"

# Пример 2: Подключение через CDNVideo
# [[servers]]
# name = "CDN Node [AHTTP]"
# dsn = "https://cdn.example.com/api/v2/telemetry?cdn=1"
# timeout_secs = 10
# server_pub_key = "<BASE64_ED25519_PUBLIC_KEY>"

[ahttp]
# Количество параллельных HTTP-запросов (потоков обмена батчами)
concurrency = 12

# Количество постоянных TCP/TLS соединений (HTTP/2 клиентов) в Round-Robin пуле
tcp_pool_size = 4

# Общий бюджет коалесценции пакетов в одну пачку (в байтах)
coalesce_budget_bytes = 65536

# Опциональный отдельный лимит размера Uplink POST-батча (от клиента к серверу).
# Для CDNVideo рекомендуется 49152 (48 КБ). Для прямого режима оставьте закомментированным.
# uplink_coalesce_budget_bytes = 49152

# Интервал фонового опроса сервера (в мс) при отсутствии исходящих пакетов
poll_timeout_ms = 5

# Размер скользящего окна переупорядочивания пакетов (ReassemblyQueue)
reassembly_queue_max_size = 1024

# Автоматическое масштабирование окна HTTP/2 (true — для прямого режима и большинства CDN)
http2_adaptive_window = true

# Ручные размеры окон HTTP/2 (применяются ТОЛЬКО если http2_adaptive_window = false)
# http2_initial_stream_window_size = 49152
# http2_initial_connection_window_size = 1048576

# Размер одного HTTP/2 DATA-фрейма (64 КБ позволяет отправлять пачку одним фреймом)
http2_max_frame_size = 65536
http2_max_header_list_size = 65536
http2_keep_alive_interval_secs = 20
http2_keep_alive_timeout_secs = 10
http2_keep_alive_while_idle = true

# Настройки пула сокетов и таймауты
pool_max_idle_per_host = 16
pool_idle_timeout_secs = 60
tcp_nodelay = true
timeout_secs = 10

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

# Шаблон HTTP-заголовков ответа ({} автоматически заменяется на Content-Length пачки)
response_headers = """
HTTP/1.1 200 OK
Content-Type: video/mp4
Cache-Control: no-cache, no-transform, private, must-revalidate
Pragma: no-cache
X-Accel-Buffering: no
Content-Length: {}
Connection: keep-alive\n\n"""

# Размер скользящего окна ReassemblyQueue на сервере
reassembly_queue_max_size = 1024

# Бюджет коалесценции Downlink-ответа сервера (65536 или 131072 байт)
coalesce_budget_bytes = 131072

# Время удержания пустого poll-запроса на сервере в ожидании Downlink-пакетов (в мс)
poll_timeout_ms = 25
```
