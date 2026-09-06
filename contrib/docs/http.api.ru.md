Ниже представлена актуализированная и полная спецификация HTTP REST API для сервиса `anet-auth` с учетом всех новых модулей: **Node Pools**, **Route Maps**, **User Groups**, **eBPF-шейпера**, **Control Plane нод** и расширенной **статистики**.

---

# Спецификация HTTP API (`anet-auth`)

Актуально для версии протокола `ASTP v0.7+`.

Базовый путь для всех эндпоинтов: `/api/v1`.

### Зоны доступа и авторизация:
1. **Публичная зона** — не требует заголовков авторизации (скачивание клиентских конфигураций по UUID).
2. **Административная панель (WebUI / Admin)** — требует заголовок `Authorization: Bearer <JWT_ACCESS_TOKEN>`.
3. **Межсерверная зона VPN-нод (Data Plane / Auth)** — требует заголовок `X-Auth-Key: <AUTH_BACKEND_KEY>`.
4. **Управляющий протокол нод (Control Plane)** — требует индивидуальный заголовок `X-Node-Token: <NODE_TOKEN>`.

---

## 1. Авторизация Администратора (Admin Auth)

Время жизни JWT-токена в базе данных — 12 часов.

### `POST /login` — Вход в панель управления
* **Тип доступа**: Публичный
* **Тело запроса (JSON)**:
  ```json
  {
    "login": "admin",
    "password": "your_secure_password"
  }
  ```
* **Ответ (200 OK)**:
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
  ```

---

## 2. Управление нодами (Nodes / Servers)

Требует заголовок: `Authorization: Bearer <token>`.

### `GET /servers` — Список всех VPN-нод с runtime-статусом
* **Ответ (200 OK)**:
  ```json
  [
    {
      "id": "5ca3580d-8488-457b-85e6-7013239747c4",
      "name": "Germany Node 1",
      "address": "64.188.118.201",
      "public_key": "ecfNEF2kYJ8kjyUqlI8HgBZaAnPBmsZVequuoxjZppk=",
      "quic_port": 4519,
      "ssh_port": 822,
      "vnc_port": 56678,
      "websocket_url": "wss://tunnel.example.com/socket",
      "ahttp_url": "https://cdn.example.com/api/v2/telemetry",
      "ssh_user": "hanyuu",
      "is_active": true,
      "has_control_credential": true,
      "runtime": {
        "status": "online",
        "last_seen_at": "2026-09-04T12:00:00Z",
        "version": "0.7.2",
        "uptime_seconds": 86400,
        "active_connections": 14,
        "accepting_connections": true
      }
    }
  ]
  ```

### `POST /servers` — Регистрация новой ноды
* **Тело запроса (JSON)**:
  ```json
  {
    "name": "Netherlands Fast CDN",
    "address": "144.31.186.196",
    "public_key": "dWAvFBO08zuG708zUbOt9dsqEVNH40p7Y4kmO/bqVks=",
    "quic_port": 4519,
    "ssh_port": 822,
    "vnc_port": 56678,
    "websocket_url": "wss://144.31.186.196:8080/socket",
    "ahttp_url": "https://cdn.example.net/api/v2/telemetry",
    "ssh_user": "hanyuu",
    "is_active": true
  }
  ```
* **Ответ (200 OK)**: Объект созданного сервера `ServerDto`.

### `PATCH /servers/:id` — Обновление параметров и статуса ноды
* **Тело запроса (JSON)**: Все поля опциональны.

### `POST /servers/:id/credentials` — Выпустить токен для Control Plane
Генерирует секретный токен для исходящего взаимодействия ноды с панелью. Токен возвращается **только один раз** (в базе сохраняется SHA-256 хэш).
* **Ответ (200 OK)**:
  ```json
  {
    "node_id": "5ca3580d-8488-457b-85e6-7013239747c4",
    "token": "HaAMhcAAHT6EZdcK5TpXTp89t8UsP-ftOYp5SWAmlHM"
  }
  ```

### `POST /servers/:id/commands/admission` — Управление допуском подключений
Ставит в очередь ноды команду на открытие или временное закрытие приема новых клиентов (дрейн ноды).
* **Тело запроса (JSON)**:
  ```json
  {
    "accepting_connections": false
  }
  ```

---

## 3. Пулы балансировки (Node Pools)

Управляют автоматическим распределением клиентов между нодами (`weighted` или `least_connections`).
Требует заголовок: `Authorization: Bearer <token>`.

### `GET /pools` — Список всех пулов
* **Ответ (200 OK)**:
  ```json
  [
    {
      "id": "7b7d2a3f-f02f-4a61-add1-955401ea9554",
      "name": "Европа (Высокая скорость)",
      "strategy": "least_connections",
      "is_active": true,
      "members": [
        { "server_id": "5ca3580d-8488-457b-85e6-7013239747c4", "weight": 5 },
        { "server_id": "334f7bd6-1774-4b12-945b-4c46751d2be2", "weight": 10 }
      ]
    }
  ]
  ```

### `POST /pools` и `PATCH /pools/:id` — Создание / Редактирование пула
* **Тело запроса (JSON)**:
  ```json
  {
    "name": "Европа (Высокая скорость)",
    "strategy": "weighted",
    "is_active": true,
    "members": [
      { "server_id": "5ca3580d-8488-457b-85e6-7013239747c4", "weight": 1 }
    ]
  }
  ```

### `DELETE /pools/:id` — Удалить пул

---

## 4. Маршрутные карты (Route Maps / Split Tunneling)

Политики выборочной маршрутизации трафика на клиентах (CIDR подсети и исполняемые файлы Windows).
Требует заголовок: `Authorization: Bearer <token>`.

### `GET /route-maps` — Список маршрутных карт
* **Ответ (200 OK)**:
  ```json
  [
    {
      "id": "00000000-0000-4000-a000-000000000001",
      "name": "Full Tunnel",
      "description": "Весь трафик в VPN, локальные сети напрямую",
      "default_action": "tunnel",
      "is_active": true,
      "revision": 3,
      "rules": [
        { "id": "uuid", "position": 0, "match_type": "cidr", "match_value": "192.168.0.0/16", "action": "direct" },
        { "id": "uuid", "position": 1, "match_type": "application", "match_value": "steam.exe", "action": "direct" }
      ]
    }
  ]
  ```

### `POST /route-maps` и `PATCH /route-maps/:id` — Создание / Обновление карты
* **Тело запроса (JSON)**:
  ```json
  {
    "name": "Whitelist Only",
    "description": "Только заблокированные ресурсы",
    "default_action": "direct",
    "is_active": true,
    "rules": [
      { "position": 0, "match_type": "cidr", "match_value": "1.1.1.1/32", "action": "tunnel" }
    ]
  }
  ```

### `DELETE /route-maps/:id` — Удалить карту

---

## 5. Группы пользователей (User Groups / Лимиты)

Групповые профили с автоматическим ограничением ресурсов (трафик, скорость, сессии, срок действия).
Требует заголовок: `Authorization: Bearer <token>`.

### `GET /groups` — Список групп с количеством участников
* **Ответ (200 OK)**:
  ```json
  [
    {
      "id": "00000000-0000-4000-c000-000000000001",
      "name": "Standard Plan",
      "traffic_limit": 107374182400,
      "speed_limit": 51200,
      "sessions_limit": 2,
      "duration_days": 30,
      "user_count": 48,
      "created_at": "2026-08-30T10:00:00Z",
      "updated_at": "2026-09-01T12:00:00Z"
    }
  ]
  ```

### `POST /groups` и `PATCH /groups/:id` — Создание / Редактирование группы
Параметры: `traffic_limit` (байты, 0 — безлимит), `speed_limit` (кбит/с, 0 — безлимит), `sessions_limit` (0 — безлимит), `duration_days` (срок активации в днях, 0 — бессрочно).
* **Тело запроса (JSON)**:
  ```json
  {
    "name": "VIP Premium",
    "traffic_limit": 0,
    "speed_limit": 0,
    "sessions_limit": 5,
    "duration_days": 90
  }
  ```

### `GET /groups/:id/members` — Постраничный список участников группы
* **Параметры (Query)**: `from` (смещение), `limit` (лимит), `search` (фильтр по имени/UID).
* **Ответ (200 OK)**: `PaginatedUsers` (структура аналогична `/users`).

### `POST /groups/:id/members` — Привязать пользователя к группе
* **Тело запроса (JSON)**: `{"user_id": "uuid"}`

### `DELETE /groups/:id/members/:user_id` — Исключить пользователя из группы

---

## 6. Управление клиентами (VPN Users)

Требует заголовок: `Authorization: Bearer <token>`.

### `GET /users` — Список клиентов (с фильтрацией и сортировкой)
* **Параметры (Query)**:
  * `from`: Смещение (по умолчанию `0`)
  * `limit`: Лимит (по умолчанию `50`)
  * `search`: Поиск по UID или Fingerprint
  * `group_ids`: Фильтр по UUID групп через запятую
  * `sort_by`: Поле сортировки (`uid`, `id`, `is_active`, `created_at`)
  * `descending`: `true` или `false`
* **Ответ (200 OK)**:
  ```json
  {
    "items": [
      {
        "id": "612fff22-67f9-4040-9f7b-0686e9cc0215",
        "uid": "sup_2",
        "fingerprint": "xXXwHV0OQuEhDUWynlp0Xg==",
        "is_active": true,
        "created_at": "2026-08-30 13:26:08",
        "static_ip": "10.0.0.15",
        "server_ids": ["5ca3580d-8488-457b-85e6-7013239747c4"],
        "pool_ids": ["7b7d2a3f-f02f-4a61-add1-955401ea9554"],
        "route_map_id": "00000000-0000-4000-a000-000000000001",
        "group_id": "00000000-0000-4000-c000-000000000001",
        "rate": {
          "id": "e24f0041-5d00-4f33-8fd4-b58319ce9200",
          "sessions": 3,
          "date_end": "2026-09-29-13:26"
        }
      }
    ],
    "total": 1
  }
  ```

### `POST /add` — Создать нового клиента
Генерирует пару ключей Ed25519, шифрует их через ChaCha20Poly1305 и привязывает к группе/нодам.
* **Тело запроса (JSON)**:
  ```json
  {
    "uid": "alice_pc",
    "server_ids": ["5ca3580d-8488-457b-85e6-7013239747c4"],
    "pool_ids": [],
    "route_map_id": "00000000-0000-4000-a000-000000000001",
    "group_id": "00000000-0000-4000-c000-000000000001"
  }
  ```
* **Ответ (200 OK)**:
  ```json
  {
    "id": "b3254fc0-67bc-4889-a212-054fc3292410",
    "uid": "alice_pc",
    "fingerprint": "8hJfyOg3vG7n65ww2JiI6+A==",
    "private_key": "T3pMiMHMlo7wsFD0uipDHRbXZB7Jc+zZBrhTxXB3TJ0=",
    "public_key": "enfNE72kYJ8kjyUqlI8HgBZaAnPBmsZVequuoxjZppk=",
    "rate": null
  }
  ```

### `PATCH /user/:id` — Обновление профиля
Поддерживает назначение статического IP, изменение привязанных серверов, пулов, группы (`group_id` / `clear_group`) и маршрутной карты (`route_map_id` / `clear_route_map`).

### `POST /regenerate/:id` — Перевыпуск ключей клиента

---

## 7. Наблюдаемость и статистика (Observability)

Требует заголовок: `Authorization: Bearer <token>`.

### `GET /statistics/nodes` — Трафик по нодам
* **Ответ (200 OK)**: `[ { "node_id": "uuid", "name": "Node 1", "rx_bytes": 1048576, "tx_bytes": 2097152 } ]`

### `GET /statistics/users` — Трафик по пользователям
* **Ответ (200 OK)**: `[ { "user_id": "uuid", "uid": "sup_2", "fingerprint": "...", "rx_bytes": 100, "tx_bytes": 200 } ]`

### `GET /statistics/active-connections` — Сессии в реальном времени
Возвращает список клиентов, передававших трафик за последние 90 секунд.
* **Ответ (200 OK)**:
  ```json
  [
    {
      "user_id": "612fff22-67f9-4040-9f7b-0686e9cc0215",
      "username": "sup_2",
      "server_id": "5ca3580d-8488-457b-85e6-7013239747c4",
      "server_name": "Germany Node 1",
      "rx_bytes": 183536546,
      "tx_bytes": 916075957,
      "connection_count": 1,
      "protocol": "quic",
      "fingerprint": "xXXwHV0OQuEhDUWynlp0Xg=="
    }
  ]
  ```

### `POST /statistics/active-connections/disconnect` — Принудительный сброс сессии
Отправляет команду на ноду для немедленного разрыва соединения пользователя.
* **Тело запроса (JSON)**:
  ```json
  {
    "server_id": "5ca3580d-8488-457b-85e6-7013239747c4",
    "fingerprint": "xXXwHV0OQuEhDUWynlp0Xg=="
  }
  ```

### `GET /statistics/traffic/history` — История трафика (графики)
* **Параметры (Query)**:
  * `hours`: Глубина выборки в часах (по умолчанию 24, с шагом в 15 минут)
  * `server_id`, `user_id`, `fingerprint`, `protocol` (`quic`, `ssh`, `vnc`, `ws`, `ahttp`)

---

## 8. Control Plane взаимодействия с нодами

Эндпоинты опрашиваются самим демоном `anet-server` по защищенному каналу.
Требуют заголовок: `X-Node-Token: <NODE_CONTROL_TOKEN>`.

### `POST /control/nodes/heartbeat` — Периодический отчет состояния
* **Тело запроса (JSON)**:
  ```json
  {
    "node_id": "5ca3580d-8488-457b-85e6-7013239747c4",
    "version": "0.7.2",
    "uptime_seconds": 3600,
    "active_connections": 5,
    "accepting_connections": true
  }
  ```

### `GET /control/nodes/commands?node_id=<id>` — Забор команд из очереди
Нода забирает управляющие команды (`disconnect_user`, `set_accepting_connections`).

### `POST /control/nodes/commands/:id/result` — Подтверждение выполнения команды

### `POST /control/nodes/traffic` — Отчет накопительных счетчиков трафика
Нода периодически передает статистику. Панель автоматически проверяет лимиты по таблице `traffic_hourly` и при превышении лимита ставит команду `disconnect_user`.

---

## 9. Публичная раздача конфигураций (Provisioning)

Публичная зона (секретом выступает UUID пользователя). При неактивном или заблокированном статусе пользователя возвращает `404 Not Found`.

### `GET /config/:id` — Скачать скомпилированный `client.toml`
* **Поведение**: Расшифровывает приватный ключ, формирует список серверов и пулов с учетом балансировки (Rendezvous / Least connections), компилирует правила Route Map и отдает готовый файл клиенту.

### `GET /config/qr/:id` — Страница сопряжения с QR-кодом
* **Поведение**: Отдает готовую веб-страницу с динамическим QR-кодом для быстрого сканирования мобильным клиентом ANet.

---

## 10. Межсерверная аутентификация при Handshake

Используется `anet-server` при подключении клиентов.
Требует заголовок: `X-Auth-Key: <AUTH_BACKEND_KEY>`.

### `POST /check_access` — Валидация прав доступа и получение лимитов шейпера
* **Тело запроса (JSON)**:
  ```json
  {
    "fingerprint": "xXXwHV0OQuEhDUWynlp0Xg=="
  }
  ```
* **Ответ (200 OK — Доступ разрешен)**:
  ```json
  {
    "allowed": true,
    "message": "OK",
    "static_ip": "10.0.0.15",
    "user_id": "612fff22-67f9-4040-9f7b-0686e9cc0215",
    "speed_limit": 51200
  }
  ```
  *(Поле `speed_limit` возвращается в кбит/с и передается в eBPF-модуль ядра для ограничения полосы пропускания).*

### `POST /session/start` и `POST /session/stop` — Учет одновременных сессий
