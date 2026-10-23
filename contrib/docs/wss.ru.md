# Транспорт `ws://` / `wss://` (WebSocket): топология, режимы работы и настройка

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

Для достижения высокой пропускной способности (как напрямую, так и через прокси) в транспорте реализованы следующие механизмы:

1. **Отсутствие двойного фреймирования (Zero Redundant Framing):**
   * Протокол WebSocket (RFC 6455) уже содержит собственную длину каждого бинарного фрейма (`Message::Binary`).
   * Поэтому между клиентом и сервером в каждом `Message::Binary` передаётся один или несколько склеенных пакетов с 2-байтовым префиксом длины `[len: u16 BE][encrypted_astp_packet]` без лишних внешних обёрток.
2. **Агрегация пакетов на отправке (Coalescing до 64 КБ):**
   * Если в очереди TUN-интерфейса накопилась пачка пакетов, воркер отправки вычитывает их через `try_recv()` до бюджета `65536` байт и отправляет **одним** WebSocket-фреймом за один системный вызов.
3. **Принудительный `TCP_NODELAY = true`:**
   * И на клиенте (`connect_async_with_config(..., true)`), и на сервере (`stream.set_nodelay(true)`) алгоритм Нейгла принудительно отключён, что исключает 40-миллисекундные задержки TCP ACK при обмене мелкими фреймами.
4. **Пул параллельных WebSocket-соединений (`?pool=N` / `?mux=N`):**
   * Клиент по умолчанию открывает пул из **4 параллельных WebSocket-соединений** в рамках одной ASTP-сессии (первое соединение выполняет полное рукопожатие, а дополнительные — быструю привязку `MUX_BIND` за 1 RTT).
   * Исходящие пакеты балансируются по пулу методом Round-Robin, а сервер распределяет входящий трафик по всем активным сокетам сессии. Это нивелирует Head-of-Line Blocking одного TCP-соединения и кратно повышает скорость на каналах с высоким RTT или шейпингом одиночных потоков.

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
[[servers]]
name = "Direct or CDN Node [WSS]"
# Схема wss:// (через Nginx/CDN с TLS) или ws:// (без TLS)
# Дополнительные query-параметры (опционально):
#   ?pool=4  — количество параллельных WebSocket-соединений в пуле (по умолчанию 4, макс. 8)
dsn = "wss://example.com/socket?pool=4"
timeout_secs = 10
server_pub_key = "<BASE64_ED25519_PUBLIC_KEY>"

# Интервал плановой ротации долгоживущих WebSocket-соединений (в секундах)
websocket_min_session_secs = 900
websocket_max_session_secs = 1800
```

*Примечание по проверке сертификата:* клиентский TLS-коннектор использует браузерный список ALPN (`["h2", "http/1.1"]`), но намеренно не требует привязки к системному CA (`AcceptAnyServerCert`), так как подлинность сервера криптографически верифицируется на этапе ASTP-рукопожатия ключом `server_pub_key` (Ed25519).

### 5.2. Сервер (`server.toml`)

```toml
[server]
# Локальный адрес, на который Nginx проксирует запросы (или 0.0.0.0:8080 при прямом ws://)
websocket_bind_to = "127.0.0.1:8080"
# Путь должен совпадать с location в Nginx и путём в dsn клиента
websocket_path = "/socket"
```
