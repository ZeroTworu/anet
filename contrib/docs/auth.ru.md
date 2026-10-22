# Техническое задание и Архитектура: Система авторизации, учёта сессий и обработки ошибок доступа (`anet-auth` / `anet-server` / `anet-client-core`)

Документ описывает архитектуру подсистемы аутентификации, биллинга, декларативной синхронизации активных сессий и обработки отказов в доступе в экосистеме **ANet** (`v0.7+`), а также содержит подробные технические пометки для ИИ-ассистентов и разработчиков о том, как и в каких модулях реализован каждый механизм.

---

## 1. Цели и назначение документа

Настоящее Техническое Задание (ТЗ) фиксирует требования и фактическую реализацию следующих контуров:
1. **Криптографическая аутентификация при установке туннеля (ASTP Handshake)** между клиентом (`anet-client-core`) и VPN-нодой (`anet-server`).
2. **Межсерверная авторизация и биллинг** между VPN-нодой (`anet-server`) и центральным сервером авторизации (`anet-auth`).
3. **Декларативный учёт одновременных сессий (`sessions_limit > 0`)** без «залипания» счётчиков при аварийных обрывах связи, рестартах нод или `anet-auth`, а также без двойного учёта при resume сессий (например, при ротации WebSocket-соединений).
4. **Корректная обработка отказов в авторизации (`AuthDenyNotification` / `AuthDenyError`)** на стороне клиента с разграничением фатальных ошибок учётной записи и транзиентных ошибок конкретной ноды (устранение бесконечного цикла реконнектов).

---

## 2. Общая архитектура компонентов

| Компонент | Крейт / Директория | Роль в контуре авторизации и сессий |
| :--- | :--- | :--- |
| **Общий протокол и DTO** | `anet-common` | Protobuf-сообщения хендшейка (`DhClientExchange`, `DhServerExchange`, `EncryptedAuthRequest`, `EncryptedAuthResponse`, `AuthRequest`, `AuthResponse`, `AuthDenyNotification`) и HTTP DTO (`CheckAccessRequest`, `CheckAccessResponse`, `NodeTrafficReport`, `NodeSessionCountItem`, `BillingType`). |
| **Сервер авторизации и Control Plane** | `anet-auth` | Хранение пользователей, групп (`groups`), персональных тарифов (`rates`), нод (`servers`), пулов (`node_pools`), маршрутных карт (`route_maps`), агрегированного трафика (`traffic_totals`, `traffic_hourly`) и активных сессий (`active_sessions`). Валидация прав в `/api/v1/check_access` и декларативная синхронизация живых сессий через `/api/v1/control/nodes/traffic` и `/api/v1/control/nodes/heartbeat`. |
| **VPN-нода (Data Plane)** | `anet-server` | Приём туннелей (QUIC, SSH, VNC, WebSocket, AHTTP, WebRTC), локальный реестр клиентов (`ClientRegistry`), очистка неактивных сессий по внутритуннельным зондам, обращение в `anet-auth` через `AuthProvider`, защита от гонок параллельных хендшейков, применение eBPF-шейпера скорости. |
| **Ядро клиента** | `anet-client-core` | Выполнение ASTP-хендшейка (`AuthHandler`), распознавание `Content::AuthError(AuthDenyNotification)` в типизированную ошибку `AuthDenyError`, управление каскадным failover-циклом (`AnetClient::start`) и немедленная остановка при фатальном отказе доступа. |
| **Веб-панель администратора** | `anet-webui` | Управление пользователями, группами, лимитами (`sessions_limit`, `traffic_limit`, `speed_limit`, `duration_days`), мониторинг живых сессий и принудительный сброс подключений (`disconnect_user`). |

---

## 3. Протокол рукопожатия (ASTP Handshake) и передача ошибок

### 3.1. Фазы рукопожатия
Все внешние пакеты рукопожатия обфусцируются симметричным шифром `ChaCha20-Poly1305` (`handshake_cipher`), ключ которого выводится из публичного ключа сервера (`crypto_utils::create_handshake_cipher(&server_pub_key_bytes)`), и выравниваются случайным паддингом до шага `padding_step`.

1. **Фаза I (`DhClientExchange`, Клиент $\rightarrow$ Нода)**:
   - Клиент генерирует эфемерную пару X25519 (`ephemeral_secret`, `public_key`).
   - Подписывает своим приватным ключом Ed25519 (`signing_key`) конкатенацию `public_key || resume_session_id` (если запрашивается resume).
   - Отправляет `DhClientExchange { public_key, client_public_key, client_signed_dh_key, resume_session_id }`.
2. **Фаза II (Проверка доступа и `DhServerExchange` / `AuthError`, Нода $\rightarrow$ Клиент)**:
   - Нода вычисляет `client_fingerprint = generate_key_fingerprint(&client_public_key)` (Base64 от первых 16 байт SHA-256 публичного ключа Ed25519).
   - Если `resume_session_id` валиден и принадлежит тому же `client_fingerprint` в пределах окна `RESUME_WINDOW` (45 секунд) — нода пропускает внешний запрос и разрешает продолжение хендшейка.
   - Иначе проверяет флаг допуска ноды (`registry.is_accepting_connections()`). Если нода в дрейне — возвращает `Content::AuthError(AuthDenyNotification { message: "Node is not accepting new connections" })`.
   - Перед проверкой лимита сессий нода принудительно очищает «мёртвые» сессии этого `client_fingerprint`, от которых не было пакетов/зондов более **10 секунд** (`cleanup_inactive_for_fingerprint(&client_fingerprint, 10)`), и подсчитывает фактическое число живых локальных сессий (`local_active`).
   - Нода вызывает `auth_provider.is_client_allowed(&client_fingerprint, Some(local_active))`.
   - При успехе нода проверяет Ed25519-подпись клиента, генерирует свой X25519-ключ, вычисляет общий секрет `shared_key`, сохраняет контекст во временную карту `temp_dh_map` и отправляет `Content::DhServerExchange`.
   - При отказе нода формирует пакет `Content::AuthError(AuthDenyNotification { message: reason })`, шифрует его `handshake_cipher` и отправляет клиенту.
3. **Фаза III (`EncryptedAuthRequest` $\rightarrow$ `EncryptedAuthResponse` / `AuthError`)**:
   - Клиент проверяет подпись сервера на `DhServerExchange`, вычисляет `shared_key` и отправляет `EncryptedAuthRequest` (внутри зашифрован `AuthRequest { client_id, resume_session_id }`).
   - Нода извлекает `TempDHInfo` из `temp_dh_map`, расшифровывает запрос и сверяет `client_id == temp_info.client_fingerprint` и `resume_session_id`.
   - Если это **не** resume сессии, нода выполняет повторную атомарную проверку локального лимита сессий (`if limit > 0 && local_active >= limit`) для защиты от гонки параллельных хендшейков (Фаза I двух устройств могла пройти одновременно). При превышении возвращается `Content::AuthError("Достигнут лимит одновременных подключений")`.
   - При успехе выделяется IP-адрес (статический или из `IpPool`), генерируется `session_id` и `nonce_prefix`, создаётся `ClientTransportInfo` и клиенту возвращается `EncryptedAuthResponse` с полными параметрами туннеля и телеметрией тарифа (`AuthResponse`).

---

## 4. Логика авторизации и приоритетов тарификации в `anet-auth`

### 4.1. Эндпоинт `POST /api/v1/check_access`
Защищён заголовком `X-Auth-Key: <AUTH_BACKEND_KEY>` (проверяется в `anet-auth/src/middleware.rs`).

Принимает `CheckAccessRequest`:
```json
{
  "fingerprint": "xXXwHV0OQuEhDUWynlp0Xg==",
  "node_id": "5ca3580d-8488-457b-85e6-7013239747c4",
  "node_active_sessions": 0
}
```

### 4.2. Лестница приоритетов биллинга (`BillingType`)
В `anet-auth/src/api/auth.rs` реализована строгая трёхуровневая иерархия ограничений:

1. **Приоритет 1 — Персональный тариф (`rates`)**:
   - Если у пользователя есть запись в таблице `rates`, применяются её параметры: `allowed_sessions = rate.sessions`, `max_traffic = rate.traffic_limit`, `speed_limit = rate.speed_limit`, `expiration_date = rate.date_end`.
   - Начало расчётного периода трафика: `cycle_start = rate.date_end - Duration::days(group.duration_days.unwrap_or(30))`.
   - Тип биллинга: `BillingType::GroupAndIndividual` (если пользователь также состоит в группе) или `BillingType::Individual`.
2. **Приоритет 2 — Групповой профиль (`groups`)**:
   - Если персонального тарифа нет, но задан `user.group_id`:
     - `allowed_sessions = group.sessions_limit`
     - `max_traffic = group.traffic_limit`
     - `speed_limit = group.speed_limit`
     - Если `group.duration_days > 0`: срок действия проверяется как `user.updated_at + Duration::days(group.duration_days)`.
     - Если `group.duration_days == 0`: подписка бессрочная, а трафик считается по календарному месяцу (`first_day_current_month .. first_day_next_month`).
   - Тип биллинга: `BillingType::Group`.
3. **Приоритет 3 — Без тарифа и без группы (`NoTariffNoGroup`)**:
   - Полный безлимит (`allowed_sessions = 0`, `max_traffic = 0`, `speed_limit = 0`, `check_expiration = false`).

> **Важное правило трактовки лимитов:**
> Для всех числовых лимитов (`allowed_sessions`, `traffic_limit`, `speed_limit`, `duration_days`) значение **`0` означает «без ограничений» (анлим)**, а условие активного лимита строго **`> 0`** (например, `allowed_sessions > 0 && current_sessions >= allowed_sessions`).

### 4.3. Проверки и причины отказа
Если учётная запись не проходит проверку, `/check_access` возвращает HTTP `200 OK` с `allowed: false` и человекочитаемой причиной в поле `message`:
- Пользователь отсутствует в БД: `"Not found"`
- Флаг `user.is_active == false`: `"Учетная запись заблокирована"`
- Текущее время UTC `> expiration_date`: `"Время действия подписки истекло"`
- Израсходованный трафик за расчётный период `total_bytes >= max_traffic` (при `max_traffic > 0`): `"Лимит трафика на этот период исчерпан"`
- Число активных сессий `current_sessions >= allowed_sessions` (при `allowed_sessions > 0`): `"Достигнут лимит одновременных подключений"`

---

## 5. Декларативная синхронизация активных сессий

### 5.1. Проблема классических инкрементов/декрементов
Использование отдельных событий `session/start` и `session/stop` как единственного источника истины приводит к рассинхронизации («залипанию» сессий в БД) при:
- падении процесса `anet-server` или перезагрузке VPS ноды;
- временной недоступности `anet-auth` в момент отключения клиента;
- обрыве мобильной сети клиента без закрытия сокета.

### 5.2. Реализованная гибридная декларативная модель
Единым источником истины о живых сессиях являются **сами VPN-ноды**:

1. **На стороне `anet-server` (`ClientRegistry`)**:
   - Сессия считается живой и активной только тогда, когда она финализирована и присутствует в таблице маршрутизации `quic_router` (`active_session_counts()` и `active_session_count_for_fingerprint()`).
   - Сессии, переведённые в `suspended_sessions` (например, на время бесшовной ротации WebSocket-соединения в пределах 45 секунд), **не увеличивают** счётчик активных сессий и не блокируют переподключение того же клиента.
   - Клиент каждые 2 секунды отправляет внутритуннельные ICMP-зонды; фоновый сторожевой таймер ноды и пре-хендшейк фильтр `cleanup_inactive_for_fingerprint(..., 10)` гарантируют удаление оборванных сессий не позднее чем через 10 секунд после потери связи.
   - При каждом добавлении или удалении клиента `ClientRegistry` будит `state_changed: Notify`, благодаря чему `control_plane::run_heartbeat` отправляет внеочередной отчёт в `anet-auth` с коалесценцией **100 мс** (не дожидаясь периодического таймера).

2. **На стороне `anet-auth` (`LIVE_NODE_SESSIONS` в `anet-auth/src/api/api.rs`)**:
   - В памяти `anet-auth` поддерживается потокобезопасный реестр `LIVE_NODE_SESSIONS: HashMap<Uuid, NodeLiveSnapshot>` с временем жизни снимка ноды `LIVE_NODE_TTL = 45 секунд`.
   - При каждом запросе `POST /api/v1/control/nodes/traffic` нода передаёт полный декларативный массив `active_session_counts: Vec<NodeSessionCountItem>`. `anet-auth` обновляет снимок этой ноды, автоматически отбрасывает ноды, молчащие дольше 45 секунд, и синхронизирует таблицу `active_sessions` в PostgreSQL через `sync_active_sessions_db()`.
   - Если на ноде `active_connections == 0` при `POST /api/v1/control/nodes/heartbeat`, снимок этой ноды немедленно очищается.
   - В момент `POST /api/v1/check_access` нода передаёт свой `node_id` и `node_active_sessions` (уже очищенный от мёртвых туннелей). `anet-auth` мгновенно обновляет локальный счётчик этой ноды (`set_live_node_session_for_fingerprint`), проверяет суммарный лимит по всем нодам, и при выдаче разрешения сразу резервирует `+1` слот (`next_node_cnt`), чтобы параллельный хендшейк со второго устройства увидел актуальное число сессий до прихода следующего heartbeat.

---

## 6. Обработка ошибок авторизации на клиенте (`anet-client-core`)

### 6.1. Проблема бесконечного реконнекта
Ранее при получении от сервера `Content::AuthError(AuthDenyNotification)` метод `AuthHandler::attempt_handshake` возвращал нетипизированную ошибку `anyhow::anyhow!("Server denied authentication: {}", deny.message)`.
Из-за этого:
1. На UDP/QUIC-транспортах `AuthHandler::authenticate()` повторял хендшейк до `MAX_RETRIES = 10` раз подряд на том же сокете, несмотря на явный криптографически достоверный отказ сервера.
2. Внешний цикл `AnetClient::start()` в `anet-client-core/src/client.rs` воспринимал ошибку как сетевой таймаут ноды (`Node error: ...`), переходил в статус `ClientState::Reconnecting`, ждал 2 секунды и бесконечно перебирал серверы по кругу.
3. В WebSocket-транспорте (`anet-client-core/src/transport/websocket.rs`) внутренний цикл плановой ротации сессии продолжал попытки переподключения при получении `AuthDenyError`.

### 6.2. Реализованное решение
1. **Типизированная ошибка `AuthDenyError` (`anet-client-core/src/auth.rs`)**:
   - Введена структура `pub struct AuthDenyError { pub message: String }`, реализующая `std::error::Error`.
   - Метод `AuthDenyError::is_node_transient(&self) -> bool` классифицирует отказ:
     - **Транзиентные ошибки конкретной ноды (`true`)**:
       - `"Node is not accepting new connections"` (нода выведена в дрейн администратором);
       - `"Все сервера авторизации недоступны"` (конкретная нода потеряла связь с `anet-auth`).
     - **Фатальные ошибки учётной записи (`false`)**:
       - `"Достигнут лимит одновременных подключений"`
       - `"Учетная запись заблокирована"`
       - `"Время действия подписки истекло"`
       - `"Лимит трафика на этот период исчерпан"`
       - `"Not found"` и любые другие отказы доступа.
2. **Немедленный выход из `AuthHandler::authenticate()`**:
   - В цикле `for attempt in 1..=MAX_RETRIES` при обнаружении `e.downcast_ref::<AuthDenyError>().is_some()` ретраи на текущем канале немедленно прекращаются и ошибка пробрасывается наверх с первой попытки.
3. **Умная остановка failover-цикла в `AnetClient::start()` (`anet-client-core/src/client.rs`)**:
   - Функция `should_abort_on_auth_deny(err: &anyhow::Error, server_count: usize) -> Option<&AuthDenyError>` проверяет цепочку ошибок (`err.chain()`).
   - Если ошибка является **фатальной ошибкой аккаунта** (`!auth_err.is_node_transient()`), клиент **всегда** немедленно прекращает цикл подключения независимо от числа серверов в конфиге.
   - Если ошибка является **транзиентной ошибкой ноды** (`auth_err.is_node_transient()`):
     - при `server_count > 1` клиент переключается на следующую ноду в списке failover;
     - при `server_count <= 1` (альтернативных нод нет) клиент также немедленно прекращает цикл подключения.
   - При остановке цикла клиент:
     - отправляет событие `err(auth_err.message.clone())` (`AnetEvent::Error`);
     - переводит состояние в `ClientState::Failed` с текстом `"Auth error: <причина>"`;
     - выставляет `self.stop_requested.store(true, Ordering::SeqCst)` и выходит из `loop`, сбрасывая `self.is_active` в `false`.
4. **Выход из ротации WebSocket (`anet-client-core/src/transport/websocket.rs`)**:
   - Если во время плановой ротации сессии WebSocket-транспорт получает `AuthDenyError`, он немедленно прерывает внутренний цикл и возвращает ошибку в `AnetClient`.

---

## 7. Пометки для ИИ (AI Implementation Notes)

> Данный раздел предназначен для ИИ-агентов и разработчиков при последующем анализе, рефакторинге или расширении кодовой базы.

### 7.1. Карта ключевых файлов и функций
- **`anet-common/proto/anet.proto`**:
  - `message AuthDenyNotification { string message = 1; }` включён в `Message.content` под тегом `8` (`AuthDenyNotification auth_error = 8;`).
  - `message AuthResponse` содержит поля телеметрии тарифа (`billing_type = 8`, `group_name = 9`, `traffic_limit = 10`, `traffic_consumed = 11`, `active_sessions = 12`, `allowed_sessions = 13`, `speed_limit_kbps = 14`, `expires_at = 15`).
  - **Инвариант для ИИ**: Не изменяйте номера тегов существующих полей в `anet.proto`, чтобы не нарушить бинарную совместимость между клиентами и нодами разных минорных версий.
- **`anet-auth/src/api/auth.rs`**:
  - Функция `check_access` (`POST /api/v1/check_access`).
  - **Инвариант для ИИ**: Проверка лимита сессий всегда должна иметь вид `if allowed_sessions > 0 && current_sessions >= allowed_sessions`. Никогда не заменяйте `allowed_sessions > 0` на `== 1` и не блокируйте пользователя при `allowed_sessions == 0` (0 — это безлимит).
  - При успешном прохождении `check_access` обязательно выполняется упреждающее резервирование слота (`set_live_node_session_for_fingerprint` + запись `reported_active = current_sessions + 1` в таблицу `active_sessions`), чтобы закрыть окно гонки до следующего отчёта `/control/nodes/traffic`.
- **`anet-auth/src/api/api.rs`**:
  - Функции `update_node_live_sessions`, `get_live_sessions_for_fingerprint`, `get_live_node_sessions_for_fingerprint`, `set_live_node_session_for_fingerprint`, `prune_stale_live_sessions`, `sync_active_sessions_db`.
  - **Инвариант для ИИ**: При холодном старте `anet-auth` (пока не все ноды прислали первый heartbeat/traffic отчёт в `LIVE_NODE_SESSIONS`) функция `sync_active_sessions_db` добирает данные по ещё не отчитавшимся нодам из таблицы `traffic_totals` со свежестью `<= 45` секунд. Не удаляйте этот fallback, иначе при рестарте `anet-auth` счётчики сессий кратковременно обнулятся.
- **`anet-server/src/auth_handler.rs`**:
  - `ServerAuthHandler::handle_dh_exchange` (Фаза I $\rightarrow$ II) и `ServerAuthHandler::handle_encrypted_auth` (Фаза III).
  - **Инвариант для ИИ**:
    1. В Фазе I перед вызовом `auth_provider.is_client_allowed` обязательно вызывается `self.registry.cleanup_inactive_for_fingerprint(&client_fingerprint, 10).await`, чтобы мгновенно освободить слот сессии, если клиент переподключается после обрыва сети.
    2. В Фазе III (если сессия не является resume) обязательно повторно проверяется локальное число активных сессий `local_active >= limit as u32`. При превышении возвращается `Ok((deny_msg, None))`, где `deny_msg` содержит `Content::AuthError(AuthDenyNotification)` и шифруется внешним `handshake_cipher` (так как клиент в `attempt_handshake` ожидает внешний пакет, зашифрованный `handshake_cipher`, и проверяет `Content::AuthError` до расшифровки `EncryptedAuthResponse`).
- **`anet-server/src/client_registry.rs`**:
  - **Инвариант для ИИ**:
    1. Метод `active_session_counts()` и `active_session_count_for_fingerprint()` считают уникальные `session_id` только среди клиентов, присутствующих в `quic_router` (то есть прошедших `finalize_client`).
    2. Метод `suspend_client` удаляет клиента из `quic_router` и переносит в `suspended_sessions` на 45 секунд, а также вызывает `self.state_changed.notify_waiters()`. Благодаря этому приостановленные сессии не раздувают счётчик активных сессий.
    3. При принудительном отключении (`disconnect_by_fingerprint` или `remove_client`) у QUIC-клиентов обязательно вызывается `conn.close(...)` на сохранённом `quic_conn` **до** удаления записи из `clients_by_addr`, чтобы фрейм `CONNECTION_CLOSE` успел уйти в UDP-сокет.
- **`anet-client-core/src/auth.rs` и `anet-client-core/src/client.rs`**:
  - `AuthDenyError` оборачивается в `anyhow::Error` при получении `Content::AuthError(deny)` в `AuthHandler::attempt_handshake`.
  - **Инвариант для ИИ**: Любые обёртки `.context(...)` поверх результата `authenticate()` / `authenticate_once()` в транспортах (`quic.rs`, `ssh.rs`, `vnc.rs`, `websocket.rs`, `ahttp.rs`, `wrtc.rs`) сохраняют `AuthDenyError` внутри цепочки `anyhow::Error`. Поэтому для извлечения `AuthDenyError` всегда используйте `err.chain().find_map(|cause| cause.downcast_ref::<AuthDenyError>())` (как реализовано в `should_abort_on_auth_deny`), а не только верхнеуровневый `err.downcast_ref`.

### 7.2. Покрытие тестами и команды верификации
При внесении изменений в контур авторизации и сессий необходимо прогонять следующие тесты:
```bash
# Модульные тесты ядра клиента (обработка AuthDenyError, классификация ошибок, обрыв цикла реконнектов)
cargo test --package anet-client-core

# Модульные тесты сервера (resume сессий, учёт активных/suspended сессий в ClientRegistry, admission control)
cargo test --package anet-server
```
Ключевые тесты:
- `anet-client-core/src/auth.rs`:
  - `authenticate_stops_immediately_on_auth_deny_without_retrying` — проверяет, что при получении `Content::AuthError` клиент делает ровно 1 попытку вместо `MAX_RETRIES`.
  - `auth_deny_error_classifies_account_vs_transient_node_errors` — проверяет разграничение ошибок аккаунта и транзиентных ошибок ноды.
- `anet-client-core/src/client.rs`:
  - `aborts_reconnect_loop_on_account_auth_deny_even_with_multiple_servers` — проверяет, что ошибки лимита сессий, бана, истечения подписки и трафика немедленно останавливают failover-цикл даже при наличии нескольких серверов.
  - `allows_failover_on_transient_node_auth_deny_when_multiple_servers_exist` — проверяет, что при дрейне ноды или недоступности `anet-auth` клиент переключается на следующую ноду, если `server_count > 1`, но останавливается при `server_count == 1`.
- `anet-server/src/auth_handler.rs`:
  - `resume_keeps_logical_session_and_ip` — проверяет сохранение `session_id` и IP при resume.
- `anet-server/src/client_registry.rs`:
  - `suspended_session_does_not_inflate_active_session_counts` — проверяет отсутствие двойного учёта при переводе сессии в suspended-состояние.
