# Динамический балансировщик, телеметрия узлов, E2E-криптография `Client <-> anet-auth` и отказоустойчивость control plane

> **Статус документа:** Архитектурная спецификация и план реализации (код на текущем этапе не изменялся).  
> **Сверено с веткой `master` на коммите:** `d88b0c3fddc67ddfba82adc4a5a5213c7b1f29ead` (`d88b0c3`, 2026-11-12 — *fix(server): convert wrtc_mtu_cap to i32 in ServerAuthHandler*).

---

## Оглавление

1. [Аудит текущей кодовой базы (`master` @ `d88b0c3`)](#1-аудит-текущей-кодовой-базы-master--d88b0c3)
2. [Телеметрия нод (CPU / RAM / LAN), WebSocket-канал и балансировка (п. 1.1)](#2-телеметрия-нод-cpu--ram--lan-websocket-канал-и-балансировка-п-11)
3. [Конфиги без серверов, Protobuf over HTTPS и DH до конфига (п. 2.2)](#3-конфиги-без-серверов-protobuf-over-https-и-dh-до-конфига-п-22)
4. [Рефакторинг DH / ASTP-криптографии в `anet-common` (п. 2.2.3)](#4-рефакторинг-dh--astp-криптографии-в-anet-common-п-223)
5. [Подводные камни: блокировка и падение `anet-auth` (п. 3.1 и 3.2)](#5-подводные-камни-блокировка-и-падение-anet-auth-п-31-и-32)
6. [Влияние на клиентские подсистемы и ответы по UI/Mobile/Server](#6-влияние-на-клиентские-подсистемы-и-ответы-по-uimobileserver)
7. [Поэтапный план реализации и `TODO` на следующие итерации](#7-поэтапный-план-реализации-и-todo-на-следующие-итерации)
8. [Финальные решения и ответы на вопросы ревью](#8-финальные-решения-и-ответы-на-вопросы-ревью)

---

## 1. Аудит текущей кодовой базы (`master` @ `d88b0c3`)

### 1.1. Что уже отправляет нода в `anet-auth`

Фактическое состояние в `anet-server/src/control_plane.rs` и `anet-common/src/dto.rs` (на коммите `d88b0c3`):

- Фоновая задача `control_plane::run_heartbeat` раз в `heartbeat_interval_seconds.max(5)` секунд (а также внеочередно с коалесценцией `100 мс` при срабатывании `registry.wait_state_changed()`) отправляет в `anet-auth` (с заголовком `X-Node-Token`):
  1. `POST /api/v1/control/nodes/heartbeat` (`NodeHeartbeatRequest`):
     - `node_id: String`
     - `version: String`
     - `uptime_seconds: u64` *(аптайм процесса `started_at.elapsed()`, не ОС)*
     - `active_connections: usize` *(живые клиенты в `ClientRegistry`)*
     - `accepting_connections: bool`
  2. `POST /api/v1/control/nodes/traffic` (`NodeTrafficReport`):
     - `samples: Vec<TrafficUsageSample>` (дельты `rx_bytes`/`tx_bytes` по `fingerprint`),
     - `active_session_counts: Vec<NodeSessionCountItem>` (`fingerprint`, `count`, `oldest_created_at`).
  3. Дополнительно при рукопожатии каждого клиента `anet-server/src/auth_provider.rs` вызывает `POST /api/v1/check_access` (`CheckAccessRequest { fingerprint, node_id, node_active_sessions }`) с заголовком `X-Auth-Key`.
- `anet-auth` сохраняет heartbeat в `node_runtime_states` (`anet-auth/src/entities/node_runtime_states.rs`), считает ноду `online` при `now - last_seen_at <= 45s`, а активные сессии по пользователям держит в `LIVE_NODE_SESSIONS` (TTL `45s`).
- **Чего сейчас нет:**
  - Никаких системных метрик железа и сети (**CPU %, LoadAvg, RAM, LAN RX/TX Mbps, ёмкость канала**) нода не собирает и не шлёт.
  - Нет постоянного real-time канала (`WebSocket`) между нодой и `anet-auth`: команды нодам (`GET /control/nodes/commands`) и телеметрия живут только на HTTP-поллинге/heartbeat.

> **`TODO` (унификация конфига ноды, не в этой задаче, но нужно вычистить позже):**  
> Сейчас в `contrib/config/server.toml` авторизация клиентов и control plane смотрят на один и тот же `anet-auth` через две разные секции:
> - `[authentication]`: `auth_servers = []`, `auth_server_token = ""`, `allowed_clients = []`
> - `[control_plane]`: `node_id = ""`, `url = ""`, `token = ""`, `heartbeat_interval_seconds = 15`
>
> Поскольку `anet-auth` стал единым control plane, в будущем нужно **убрать** устаревшие `auth_servers` / `auth_server_token` и ходить в `anet-auth` (включая `/check_access` / WS) через единую конфигурацию `[control_plane]` (`url`, `token`, `node_id`), а от ручного `allowed_clients` для переживания падений отказаться в пользу Redis-кэша на ноде (см. п. 5.3).

### 1.2. Как клиенты сейчас получают конфиг и работают с кэшем

1. **Desktop GUI (`anet-client-gui/src/app.rs`):**
   - При запуске `ANetApp::new()` сразу грузит локально зашифрованный `EncryptedServerConfigBundle` (через `DesktopSecureStore`) и параллельно вызывает `Updater::fetch_server_config(&url, etag)` (`If-None-Match` + `BrowserProfile::random()`).
   - Если `anet-auth` недоступен, GUI остаётся на кэше.
   - У `rules.abc` (`RuleCacheManager`, `anet-client-core/src/rule_updater.rs`) есть свой дисковый кэш и фоновое обновление раз в `600 сек`.
2. **Android (`https://github.com/ZeroTworu/anet-android` + `anet-mobile/src/lib.rs`):**
   - Мобильная обвязка существует **только под Android** (iOS/Swift-клиента нет).
   - **Архитектурный перекос на сейчас:** Rust-библиотека `anet-mobile/src/lib.rs` принимает готовый `config_toml: &str` снаружи, из Kotlin-части `anet-android`. То есть загрузка конфига и работа с кэшем оказались на стороне Kotlin вместо единого Rust-ядра (`anet-client-core` / `anet-common`). При внедрении нового протокола эта логика должна жить **внутри `anet-client-core` / `anet-common`** и прокидываться наружу через тонкий FFI в `anet-mobile`.
3. **CLI (`anet-client-cli/src/main.rs`):**
   - Инструмент исключительно для разработчиков и тестирования: читает локальный `-c ./client.toml`. Загрузка по URL и кэширование конфигов в CLI **не требуются**; достаточно сохранить совместимость `CoreConfig::sanitize()` для локальных файлов со статическими `[[servers]]`.

### 1.3. Зачистка мёртвого кода в `anet-auth`

- В `anet-auth/src/balancer.rs` и `resolve_client_servers()` (`anet-auth/src/api/api.rs:349`) сейчас лежит неиспользуемый черновой код (`weighted` / `least_connections`), который не подключён к `download_config` (`anet-auth/src/api/users.rs:751-1004`), не верифицировался и не отражает реальную модель нагрузки.
- **Решение:** при реализации новой системы старые `balancer.rs` и `resolve_client_servers()` **полностью удаляются/переписываются с нуля** без оглядки на них.

### 1.4. Терминология проекта

Чтобы не путать две разные сущности в БД и API, в рамках всего дизайна фиксируются два чётких термина:
- **«Группы пользователей»** (`groups` в БД) — тарифные планы и лимиты (`traffic_limit`, `speed_limit`, `sessions_limit`, `duration_days`) + привязка доступных пулов серверов (`group_node_pools`). Подробно описаны в `contrib/docs/billing_and_cabinet.ru.md`.
- **«Группы серверов»** (`node_pools` в БД) — локации / пулы узлов с протоколами и весами (`node_pool_members`), которые видит и выбирает пользователь в VPN-клиенте (в старом `client.toml` они передавались как `group_id` и `group_name` у каждой ноды).

### 1.5. Уязвимости текущего `GET /api/v1/config/:id`

1. `download_config` отдаёт по обычному HTTP открытый TOML-текст, в котором лежат **приватный ключ клиента (`[keys].private_key`)**, ключи серверов (`server_pub_key`), все адреса/порты нод и параметры транспортов.
2. При компрометации УЦ, корпоративном SSL-инспекте, MITM на ТСПУ или сбое проверки сертификата (а в старом `fetch_config_from_url()` в `updater.rs` даже был fallback на `verify_peer = false`) злоумышленник получает и ключ пользователя, и всю карту серверов сразу.

---

## 2. Телеметрия нод (CPU / RAM / LAN), WebSocket-канал и балансировка (п. 1.1)

### 2.1. Какие метрики собирает `anet-server`

Сбор без сканирования процессов (на Linux — напрямую из `/proc/stat`, `/proc/meminfo`, `/proc/loadavg`, `/proc/net/dev`, `/proc/uptime`; при необходимости кроссплатформенно — `sysinfo` только с CPU/Memory/Network):

| Поле | Источник | Зачем нужно |
|---|---|---|
| `cpu_usage_pct: f32` | Дельта `/proc/stat` (0..100%) | Главный маркер нагрузки на криптографию, VP8/WebRTC и QUIC |
| `cpu_cores: u16` | Число логических ядер | Нормировка `load_avg` для разнородных VPS |
| `load_avg_1m: f32` | `/proc/loadavg` | Показывает очередь ядра (iowait / softirq на сетевых пакетах) |
| `ram_used_bytes: u64`, `ram_total_bytes: u64` | `/proc/meminfo` (`MemTotal - MemAvailable`) | Защита от OOM при росте буферов и сессий |
| `net_rx_mbps: f32`, `net_tx_mbps: f32` | Дельта `/proc/net/dev` по внешнему NIC (НЕ по `tun*` и `lo`) | Реальная входящая/исходящая полоса ноды в мир |
| `net_capacity_mbps: Option<u32>` | `[control_plane].nic_capacity_mbps` или `/sys/class/net/<iface>/speed` (дефолт e.g. `1000`) | Позволяет считать % забитости канала `max(rx, tx) / capacity` |
| `active_connections: usize` | `ClientRegistry` | Фактическое число открытых клиентских туннелей |
| `max_connections: Option<u32>` | Конфиг ноды / поле в таблице `servers` | Защита от исчерпания пула TUN-IP (`IpPool`) или лимита ФС |
| `os_uptime_seconds: u64` | `/proc/uptime` | Отделение ребута машины от рестарта демона |

> **Замечание по LAN:** важно брать именно внешний сетевой интерфейс (интерфейс маршрута по умолчанию или явно заданный `wan_interface`), чтобы двойная инкапсуляция (например, CF WARP / WRTC / IMAP) не искажала замер. Мгновенные скачки за секунду перед отчётом сглаживаются экспоненциальным скользящим средним (**EMA**, $\alpha \approx 0.35$).

### 2.2. Двухканальная связь `anet-server <-> anet-auth`: WebSocket + HTTP Heartbeat

Отличная идея из ревью: добавить постоянный **WebSocket-канал поверх TLS**, который **инициирует сама нода** в сторону `anet-auth` (аналогично исходящему транспорту, **нода не открывает никаких новых входящих портов** и спокойно работает даже за NAT/фаерволом):

```
anet-server (Нода)                         anet-auth (Control Plane)
   |                                                |
   |== 1. Outbound WSS (X-Node-Token + BrowserProfile) ==>|  (постоянный live-канал)
   |   -> TelemetryPush (раз в 1-2с или по дельте)  |
   |   -> Immediate CheckAccess / SessionEvent      |
   |   <- LiveCommands (KickSession, Drain, Manifest)|
   |                                                |
   |-- 2. HTTP POST /control/nodes/heartbeat ------>|  ("железобетонный" watchdog раз в 15-30с)
```

#### Зачем это даёт качественный скачок:
1. **Мгновенный баланс в реальном времени:** вместо слепого окна в 5–15 секунд между HTTP heartbeat'ами, нода шлёт по WS лёгкие телеметрические кадры (раз в 1–2 с при активных изменениях или сразу при подключении/отключении клиента). Проблема эффекта «громового стада» (когда 50 клиентов успевают попасть на одну ноду до следующего heartbeat) уменьшается на порядок.
2. **Мгновенные управляющие команды от `anet-auth` к ноде:**
   - В `billing_and_cabinet.ru.md` (§ 6, `UserCabinetApi::disconnect_session`) уже заложена кнопка принудительного сброса активной сессии из Личного Кабинета. С WebSocket эта команда (а также отзыв заблокированного/просроченного `fingerprint` из кэша ноды или перевод ноды в drain-режим `accepting_connections = false`) доходит **за миллисекунды**, а не через polling-цикл `GET /commands`.
   - Живой push нового списка адресов `anet-auth` (`SignedAuthManifest`) на ноды при переезде панели.
3. **Зачем оставлять HTTP Heartbeat:**
   - WebSocket через CDN/прокси/ТСПУ может залипнуть или рваться на переключениях сети. Классический HTTP `POST /api/v1/control/nodes/heartbeat` остаётся как **«железобетонный» запасной канал и watchdog**: если WS жив, heartbeat подтверждает состояние (можно реже, например раз в 15–30 с); если WS упал — нода остаётся в статусе `online` по HTTP-пульсу и в фоне переподключает WS с backoff.
   - По желанию в WS можно проксировать и быстрые проверки `/check_access`, а при недоступности WS — сразу падать обратно на обычный HTTP `POST /check_access`.

### 2.3. Хранение метрик и дашборды в WebUI

1. `anet-common/src/dto.rs`: расширить `NodeHeartbeatRequest` (и общий `NodeTelemetrySnapshot` для WS и HTTP) полями из таблицы п. 2.1 с `#[serde(default)]` для совместимости на время rolling-обновления.
2. `anet-auth`:
   - Миграция SeaORM на `node_runtime_states`: добавить `cpu_usage_pct`, `cpu_cores`, `load_avg_1m`, `ram_used_bytes`, `ram_total_bytes`, `net_rx_mbps`, `net_tx_mbps`, `net_capacity_mbps`, `load_score`, `ws_connected`.
   - В оперативной памяти `anet-auth` держать `DashMap<Uuid, LiveNodeState>` с актуальным EMA-снимком и небольшим ring-buffer (15–30 минут) для графиков в админке, не долбя PostgreSQL каждую секунду при 1–2с пушах по WS (в БД сбрасывать состояние раз в 10–15 секунд или по смене статуса).
3. `anet-webui`: на страницах `Overview.vue` и `Servers.vue` вывести загрузку CPU %, RAM, LAN RX/TX Mbps, % канала, статус WS-линка (`LIVE` / `HTTP-ONLY`) и интегральный `load_score`.

### 2.4. Новая логика выбора ноды (`smart_load`)

Старый `balancer.rs` выпиливается. Новый движок выбора ноды в выбранной **группе серверов** (`node_pool`) работает так:

1. **Фильтрация доступности (Circuit Breaker):**
   Исключаем участников `node_pool_members`, если:
   - сервер неактивен (`!server.is_active`), закрыл приём (`!accepting_connections`) или не выходил на связь (`now - last_seen > 45s`);
   - достигнут `max_connections`;
   - сервер в `exclude_server_ids` (клиент только что не смог к нему подключиться);
   - перегруз: `cpu >= 92%` или `ram >= 94%` или `lan >= 95%` *(если перегружены вообще все ноды в группе — мягко ослабляем фильтр и выбираем наименее перегруженную, чтобы не отказывать пользователю при живой инфраструктуре)*.
2. **Расчёт интегральной нагрузки $L$:**
   $$L = 0.45 \cdot U_{\text{lan}} + 0.30 \cdot U_{\text{cpu}} + 0.15 \cdot U_{\text{ram}} + 0.10 \cdot U_{\text{conn}}$$
   где $U_{\text{lan}} = \frac{\max(\text{rx}, \text{tx})}{\text{capacity}}$, $U_{\text{cpu}} = \frac{\text{cpu\_pct}}{100}$, $U_{\text{ram}} = \frac{\text{ram\_used}}{\text{ram\_total}}$, $U_{\text{conn}}$ — нормированная доля подключений.
   При разных по мощности серверах в одной группе учитывается вес участника `member.weight` (`cost = (L + 0.02) / weight_factor + recent_assign_penalty`).
3. **Защита от гонок (`recent_assign_penalty`):**
   Даже с WS 1–2с возможны одновременные запросы от нескольких клиентов в одну секунду. Пока не пришёл свежий апдейт с ноды, каждое выданное назначение добавляет временный (на ~5–10 сек) микроштраф ноде в памяти `anet-auth`, размазывая всплеск подключений по свободным узлам.

---

## 3. Конфиги без серверов, Protobuf over HTTPS и DH до конфига (п. 2.2)

### 3.1. Связка с Личным Кабинетом (`billing_and_cabinet.ru.md`) и ревью 2 режимов DH

В `billing_and_cabinet.ru.md` зафиксировано, что у **каждого** пользователя в системе есть единый профиль в `users` и Личный Кабинет (Web на `public_domain` или Telegram Mini App), откуда пользователь берёт свой конфиг / ссылку / QR (`UserCabinetApi::get_client_config`). При этом реализация ЛК и нового балансировщика идут **параллельно**, поэтому протокол обмена клиента с `anet-auth` обязан аккуратно стыковаться с текущим и будущим ЛК.

Ниже — **ревью** предложенного 2-режимного рукопожатия с учётом криптографии и ЛК:

#### Почему нельзя делать просто «голый DH без ключей»?
1. Если клиент делает анонимный X25519 DH до скачивания конфига, не зная **публичного ключа `anet-auth`**, то активный MITM (DPI / прокси с подменённым сертификатом) подменит ключ DH на лету, перехватит `config_token`, скачает `private_key` пользователя и вскроет весь обмен.
2. При **самом первом** входе в приложение клиент ещё **не знает свой `private_key`** (в текущей модели из `users.rs` и `billing_and_cabinet.ru.md` ключ генерируется на стороне `anet-auth` при регистрации и выдаётся клиенту при скачивании конфига). Значит, на самом первом запросе клиент физически **не может** подписать DH своим ключом.

#### Как это решается чисто и безопасно (Ревью схемы из двух режимов):

1. **Трёхуровневая модель доверия к `auth_pub_key` (под любые сценарии раздачи):**
   У `anet-auth` появляется своя постоянная Ed25519-пара (`auth_signing_key` / `auth_pub_key`). Откуда клиент её берёт:
   - **Уровень 1 — Вшитый `auth_pub_key` (официальный клиент Google Play / релизный бинарник):**
     - Для сценария «скачал клиент -> нажал *Регистрация* без ввода email/ТГ -> сразу попал в встроенный ЛК внутри приложения» ключ твоего `anet-auth` зашит прямо в бинарник клиента. MITM исключён с нулевого байта.
   - **Уровень 2 — Ссылка / QR с `#pk=<base64url_auth_pub_key>` (почта, Telegram, ЛК, кастомный инстанс):**
     - Если ссылка пришла через третий канал или это сторонний `anet-auth`, клиент берёт ключ из фрагмента `#pk=...` (который по стандарту HTTP не уходит на сервер и не светится в прокси).
   - **Уровень 3 — «Дикий fallback» (обычная ссылка БЕЗ `#pk=`, в БД нет ни email, ни ТГ, ключ не вшит):**
     - В `anet-common/src/boring_tls.rs` (`http_help.rs`) для запросов к `anet-auth` включается режим **strict WebPKI-only**: проверка только по встроенным в исходники `webpki_root_certs` (**без** системных корневых УЦ ОС вроде Минцифры/Kaspersky и **без** `verify_peer = false`).
     - На первом обмене `anet-auth` отдаёт `auth_pub_key` внутри TLS-подтверждённого ответа, клиент сохраняет его по модели **TOFU (Trust On First Use)** в свой зашифрованный кэш — и начиная со 2-го запроса проверяет подписи жёстко по этому ключу независимо от TLS.

2. **Жёсткое разделение прав двух режимов рукопожатия с `anet-auth`:**

   - **Режим 0 — `Bootstrap` (первое получение конфига / смена устройства по ссылке из ЛК):**
     - **Кто подписывает:** **ТОЛЬКО `anet-auth`** подписывает ответ своим `auth_signing_key`. Клиент шлёт свой эфемерный X25519 ключ без клиентской подписи (`bootstrap_mode = true`).
     - **Что защищено:** клиент проверяет подпись `auth_pub_key` -> активный MITM **невозможен** даже при полностью скомпрометированном HTTPS/CA. Далее `config_token` уходит уже внутри `ChaCha20-Poly1305` на нейтральный URL (`POST /api/v1/client/exchange`, без передачи UUID пользователя в открытом HTTP URL!).
     - **Жёсткое ограничение прав в Режиме 0 (важно при ревью!):**
       - В `bootstrap_mode = true` `anet-auth` разрешает **ТОЛЬКО `ClientConfigRequest`** (получить базовый TOML, `[keys].private_key`, список доступных **групп серверов** и список зеркал `auth`).
       - **`AllocateNodeRequest` в `bootstrap_mode = true` СТРОГО ЗАПРЕЩЁН** (ошибка `403`): пока клиент не доказал владение `[keys].private_key` (или пока он не прошёл в Режим 1), адреса и `server_pub_key` нод ему не выдаются.
       - На эндпоинт в `bootstrap_mode` ставится строгий rate-limit по IP/токену.
       - *Стыковка с ЛК:* если ссылка/QR скомпрометированы, пользователь в ЛК нажимает кнопку перевыпуска ключа/ссылки, и старый `config_token` + `fingerprint` перестают приниматься. *(На будущее — см. `TODO` по генерации ключей прямо на клиенте).*

   - **Режим 1 — `Authenticated Session` (все штатные запросы: обновление конфига, групп, балансировка `AllocateNode`):**
     - У клиента уже в кэше есть свой `[keys].private_key` (полученный в Режиме 0 или из конфига).
     - Выполняется **полный взаимный DH (Mutual Ed25519 + X25519)**: клиент подписывает свой эфемерный X25519-ключ своим `private_key`, `anet-auth` подписывает свой — своим `auth_signing_key`.
     - Внутри полученной сессии (`session_id` + `shared_key` можно кэшировать в RAM на короткий TTL, например 15 минут, чтобы не тратить 2 RTT при каждом нажатии кнопки «Подключиться», и автоматически пересогласовывать при истечении) клиент запрашивает `AllocateNodeRequest` и обновления `ClientConfigRequest`.

3. **Общая проверка статуса подписки с ЛК (`billing_and_cabinet.ru.md`):**
   - И ЛК (`/api/v1/user/me`), и `ClientConfigResponse` / `AllocateNodeResponse` используют единую логику расчёта действующих лимитов из `billing_and_cabinet.ru.md`: `rates` (персональный тариф) > `groups` (группа пользователей) > default/block.
   - `ClientConfigResponse` сразу передаёт в клиент актуальные для UI поля: `expires_at_unix`, `traffic_limit_bytes`, `traffic_used_bytes`, `user_status`, чтобы десктоп/Android показывали статус подписки даже без открытия браузера.

### 3.2. Новый формат конфига клиента (без `[[servers]]`)

`anet-auth` перестаёт отдавать массив `[[servers]]`. Клиент получает только свои параметры, ключи и доступные ему **группы серверов**:

```toml
version = 2

[main]
# tun_name, manual_routing, route_for, exclude_route_for, dns_server_list, per_app...

[auth]
endpoints = ["https://auth.example.com/api/v1/client/exchange"]
auth_pub_key = "<base64 Ed25519 публичный ключ anet-auth>"
config_token = "<токен конфига пользователя>"
manifest_seq = 14

[keys]
private_key = "<base64 Ed25519 приватный ключ клиента>"
# server_pub_key здесь больше НЕ хранится: для каждой выбранной ноды
# его выдаёт anet-auth динамически внутри E2E-ответа AllocateNodeResponse!

[[groups]]
id = "<node_pool.id (группа серверов)>"
# Название свободно задаётся в админке:
#   "[WRTC: VIDEO]: Все локации", "[WRTC: VIDEO]: NL / FN", "Нидерланды · Auto"
name = "[WRTC: VIDEO]: NL / FN"
protocols = ["wrtc_video"]
# Уникальный список кодов локаций живых нод внутри группы серверов
# (агрегируется из нового поля servers.location в БД, например ["nl", "fn"])
locations = ["nl", "fn"]
strategy = "smart_load"
health = "online"          # online | degraded | offline
load_pct = 24              # 0..100 (сводная загрузка группы)
available_nodes = 4        # кол-во живых нод в группе (без раскрытия IP)

# Секции [stealth], [ahttp], [quic_transport], [wrtc], [imap], [routing],
# [connectivity], [[browser_profiles]] остаются общими настройками клиента.
```

> **Совместимость для разработчиков (`anet-client-cli`):** в `CoreConfig::sanitize()` локальный ручной конфиг считается валидным, если задано `!self.servers.is_empty()` **ИЛИ** (`!self.groups.is_empty() && !self.auth.endpoints.is_empty()`).

### 3.3. Схема в `anet-common/proto/protocol.proto` (п. 2.2.1)

Все HTTP-like запросы к `anet-auth` передаются по HTTPS с профилем `BrowserProfile` (`stealth.tls_fingerprint`), `Content-Type: application/octet-stream` на настраиваемый путь (по умолчанию нейтральный, например `/api/v1/client/exchange` или `/api/v1/telemetry`). `AuthDhInitRequest` при известном `auth_pub_key` дополнительно заворачивается через `create_handshake_cipher(&auth_pub_key)`, чтобы на проводе даже не было видно protobuf-структур.

```protobuf
// === Внешний конверт Client <-> anet-auth (HTTP POST body) ===

message AuthEnvelope {
  uint32 protocol_version = 1; // = 1
  oneof payload {
    AuthDhInitRequest dh_init_req = 10;
    AuthDhInitResponse dh_init_res = 11;
    AuthEncryptedFrame encrypted = 12;
  }
}

message AuthDhInitRequest {
  bytes client_ephemeral_pub = 1;     // 32 байта X25519
  bytes client_identity_pub = 2;      // 32 байта Ed25519 (пусто, если bootstrap_mode = true)
  bytes signature = 3;                // Подпись client_identity_sk (пусто, если bootstrap_mode = true)
  uint64 timestamp = 4;               // Unix secs
  bytes client_nonce = 5;             // 16 байт
  bool bootstrap_mode = 6;            // true ТОЛЬКО для первичного ClientConfigRequest
  bytes padding = 7;
}

message AuthDhInitResponse {
  bytes session_id = 1;               // 16 байт ID DH-сессии
  bytes server_ephemeral_pub = 2;     // 32 байта X25519
  bytes signature = 3;                // ОБЯЗАТЕЛЬНАЯ подпись auth_signing_key над каноническим транскриптом
  uint64 timestamp = 4;
  bytes server_nonce = 5;             // 16 байт
  uint32 session_ttl_secs = 6;        // TTL кэширования session_id + shared_key в памяти клиента
  bytes padding = 7;
}

message AuthEncryptedFrame {
  bytes session_id = 1;
  uint64 counter = 2;                 // Монотонный счётчик против replay
  bytes nonce = 3;                    // 12 байт ChaCha20-Poly1305
  bytes ciphertext = 4;               // Шифротекст AuthInnerPayload (AAD = session_id || counter)
}

message AuthInnerPayload {
  bytes padding = 1;
  oneof body {
    ClientConfigRequest config_req = 10;
    ClientConfigResponse config_res = 11;
    AllocateNodeRequest allocate_req = 12;
    AllocateNodeResponse allocate_res = 13;
    AuthError error = 14;
  }
}

// === Строгие перечисления (Enum в Protobuf, Rust и SeaORM/Postgres) ===

enum OsPlatform {
  OS_PLATFORM_UNSPECIFIED = 0;
  OS_PLATFORM_WINDOWS = 1;
  OS_PLATFORM_LINUX = 2;
  OS_PLATFORM_ANDROID = 3;
  OS_PLATFORM_MACOS = 4;
}

enum GroupHealth {
  GROUP_HEALTH_UNSPECIFIED = 0;
  GROUP_HEALTH_ONLINE = 1;
  GROUP_HEALTH_DEGRADED = 2;
  GROUP_HEALTH_OFFLINE = 3;
}

enum TransportProtocol {
  TRANSPORT_PROTOCOL_UNSPECIFIED = 0;
  TRANSPORT_PROTOCOL_QUIC = 1;
  TRANSPORT_PROTOCOL_SSH = 2;
  TRANSPORT_PROTOCOL_VNC = 3;
  TRANSPORT_PROTOCOL_WS = 4;
  TRANSPORT_PROTOCOL_AHTTP = 5;
  TRANSPORT_PROTOCOL_WRTC = 6;
  TRANSPORT_PROTOCOL_WRTC_WS = 7;
  TRANSPORT_PROTOCOL_WRTC_VIDEO = 8;
  TRANSPORT_PROTOCOL_WRTC_DC = 9;
  TRANSPORT_PROTOCOL_WRTC_P2P = 10;
  TRANSPORT_PROTOCOL_IMAP = 11;
}

enum WrtcMode {
  WRTC_MODE_UNSPECIFIED = 0;
  WRTC_MODE_MEDIA_VIDEO = 1;
  WRTC_MODE_DATACHANNEL = 2;
  WRTC_MODE_P2P_DIRECT = 3;
}

enum BalanceStrategy {
  BALANCE_STRATEGY_UNSPECIFIED = 0;
  BALANCE_STRATEGY_SMART_LOAD = 1;
}

enum AuthErrorCode {
  AUTH_ERROR_CODE_UNSPECIFIED = 0;
  AUTH_ERROR_CODE_UNAUTHORIZED = 1;
  AUTH_ERROR_CODE_EXPIRED = 2;
  AUTH_ERROR_CODE_QUOTA_EXCEEDED = 3;
  AUTH_ERROR_CODE_GROUP_NOT_FOUND = 4;
  AUTH_ERROR_CODE_NO_HEALTHY_NODES = 5;
  AUTH_ERROR_CODE_BOOTSTRAP_FORBIDDEN = 6;
  AUTH_ERROR_CODE_RATE_LIMITED = 7;
}

// === Бизнес-сообщения внутри AuthEncryptedFrame ===

message ClientConfigRequest {
  string config_token = 1;            // Передаётся ТОЛЬКО внутри шифроканала
  string etag = 2;
  string client_version = 3;
  OsPlatform os_platform = 4;
  uint64 known_manifest_seq = 5;
}

message ServerGroupSummary {
  string group_id = 1;                // node_pools.id (группа серверов)
  string name = 2;                    // Задаётся админом, напр. "[WRTC: VIDEO]: NL / FN"
  repeated TransportProtocol protocols = 3;
  repeated string locations = 4;      // Коды локаций активных нод пула, напр. ["nl", "fn"]
  BalanceStrategy strategy = 5;
  GroupHealth health = 6;
  uint32 load_pct = 7;                // Сводная загрузка пула 0..100%
  uint32 available_nodes = 8;         // Живых нод в пуле (без IP)
}

message AuthEndpointManifest {
  uint64 seq = 1;                     // Монотонная ревизия (защита от отката)
  uint64 issued_at = 2;
  uint64 expires_at = 3;
  repeated string endpoints = 4;      // Актуальные URL зеркал anet-auth
  repeated string doh_txt_records = 5;// (TODO на будущее) Домены TXT-записей
  repeated string dead_drop_urls = 6; // (TODO на будущее) Резервные площадки
  bytes active_auth_pub_key = 7;      // Для плановой ротации ключа без поломки клиентов
}

message SignedAuthManifest {
  bytes payload_bytes = 1;            // Сериализованный AuthEndpointManifest
  bytes auth_signature = 2;           // Подпись auth_signing_key
}

message ClientConfigResponse {
  bool not_modified = 1;
  string etag = 2;
  string config_toml = 3;             // Профили и [keys].private_key (БЕЗ [[servers]]!)
  repeated ServerGroupSummary groups = 4;
  SignedAuthManifest auth_manifest = 5;
  bytes auth_pub_key = 6;             // Для сохранения при TOFU ("дикий fallback")
  string user_status = 7;
  int64 traffic_limit_bytes = 8;
  int64 traffic_used_bytes = 9;
  uint64 expires_at_unix = 10;
}

message AllocateNodeRequest {
  string group_id = 1;                // Выбранная пользователем группа серверов (node_pool.id)
  repeated TransportProtocol preferred_protocols = 2;
  repeated string preferred_locations = 3; // Опционально: фильтр по локациям внутри группы
  repeated string exclude_server_ids = 4;  // Упавшие ноды для failover
  string client_version = 5;
  OsPlatform os_platform = 6;
  uint64 known_manifest_seq = 7;
}

message AllocatedServerEndpoint {
  string server_id = 1;
  string server_name = 2;
  string location = 3;                // Локация выбранной ноды ("nl", "fn", ...)
  TransportProtocol protocol = 4;
  string dsn = 5;
  string server_pub_key = 6;          // Base64 Ed25519 ключ ЭТОЙ ноды
  WrtcMode wrtc_mode = 7;
  string ssh_user = 8;
  string tls_pin_sha256 = 9;
  uint32 score_hint = 10;
}

message AllocateNodeResponse {
  AllocatedServerEndpoint primary = 1;
  repeated AllocatedServerEndpoint fallbacks = 2; // 1-2 резервные ноды на случай мгновенного отказа primary
  uint32 lease_ttl_secs = 3;
  SignedAuthManifest auth_manifest = 4;
}

message AuthError {
  AuthErrorCode code = 1;
  string message = 2;
}
```

> **Принцип строгих `Enum`:** все закрытые множества значений (`OsPlatform`, `GroupHealth`, `TransportProtocol`, `WrtcMode`, `BalanceStrategy`, `AuthErrorCode`) описываются строго как `Enum` — в `protocol.proto`, в Rust DTO и в PostgreSQL/SeaORM-миграциях (в т.ч. перевести `node_pools.strategy` и `servers.wrtc_mode` со строк на Postgres Enum). Коды локаций (`"nl"`, `"fn"`, ...) остаются короткими строками в `servers.location`, чтобы админ мог заводить новые страны без миграций БД.

---

## 4. Рефакторинг DH / ASTP-криптографии в `anet-common` (п. 2.2.3)

Сейчас 4-фазное DH-рукопожатие и упаковка ChaCha20-Poly1305 конвертов прибиты гвоздями к `anet-server/src/auth_handler.rs` (`TempDHInfo`, `ClientRegistry`, `SocketAddr`) и `anet-client-core/src/auth.rs` (`Transport`).

Чтобы не копипастить криптографию в `anet-auth`, выносим в `anet-common` (новый модуль `anet_common::dh_handshake` или расширение `crypto_utils.rs`) транспортно-независимое ядро:

1. **Единый транскрипт без сигнатур проекта в бинарнике:**
   `build_dh_transcript(context: DhContext, signer_pub: &[u8; 32], client_eph: &[u8; 32], server_eph: &[u8; 32], client_nonce: &[u8], server_nonce: &[u8], timestamp: u64)`  
   - **Никаких захардкоженных ASCII-строк вроде `"ANET-..."`!** Для изоляции подписей между нодой и `anet-auth` достаточно 1-байтового перечисления `#[repr(u8)] enum DhContext { Tunnel = 0x01, Control = 0x02 }` **+** включения публичного ключа самого подписанта (`signer_pub`) в подписываемый транскрипт. И в бинарнике нет лишних палевных сигнатур, и cross-protocol replay полностью невозможен.
   - Туда же выносится единая проверка окна `verify_timestamp_window(ts, max_skew_secs = 120)`.
2. **`ServerDhResponder` (общий для `anet-server` и `anet-auth`):**
   - Принимает `client_ephemeral_pub`, опциональную подпись/публичный ключ клиента (или флаг `allow_bootstrap`), проверяет окно времени и подпись клиента.
   - Генерирует эфемерную пару X25519 (`StaticSecret`), выводит `shared_key` через `derive_shared_key`, формирует и подписывает ответ своим `SigningKey`.
   - Возвращает `(shared_key, server_response_parts)` — дальше:
     - `anet-server` складывает это в `TempDHInfo` по `SocketAddr` и выдаёт IP из `IpPool`;
     - `anet-auth` складывает это в `DashMap<[u8; 16], AuthHttpSession>` с `counter` и TTL.
3. **`ClientDhInitiator` (общий для `anet-client-core/src/auth.rs` и `AuthApiClient`):**
   - `begin(client_signing_key: Option<&SigningKey>, ...)` -> `(PendingClientDh, client_hello_parts)`
   - `finish(pending, server_hello_parts, expected_server_pub: &VerifyingKey)` -> `Result<[u8; 32]>`
4. **Единый AEAD-конверт (`seal_envelope` / `open_envelope`):**
   - `ChaCha20-Poly1305` с `AAD`, 12-байтным nonce и padding (`PaddingUtils`).
   - В `anet-auth/Cargo.toml` подключаются уже имеющиеся в корневом `[workspace.dependencies]` пакеты `x25519-dalek`, `chacha20poly1305` и `prost`.

---

## 5. Подводные камни: блокировка и падение `anet-auth` (п. 3.1 и 3.2)

### Что реализуем СЕЙЧАС (в текущей итерации)

#### 5.1. Единый локальный кэш в `anet-client-core` (необходимая база для п. 5.3)

Зашифрованный бандл (`EncryptedServerConfigBundle`) переносится из `anet-client-gui` в `anet-client-core` (через трейт хранилища для Desktop и Android через `anet-mobile`). В кэше сохраняются:
- последний валидный `ClientConfigResponse` (профили, `[keys].private_key`, `auth_pub_key`, список **групп серверов**, `endpoints`);
- **кэш последних выданных нод по каждой группе серверов** (`last_allocated_by_group`: до 2–3 последних рабочих нод — `primary` + `fallbacks`, куда клиент реально успешно подключался).

#### 5.2 (База) Перебор зеркал `endpoints`

В `[auth].endpoints` сразу закладывается массив URL (основной + зеркала/прокси) через `http_help.rs` (`BrowserProfile` + **strict WebPKI-only**, без доверия системным УЦ ОС). При недоступности первого URL клиент перебирает список `endpoints`.

#### 5.3. Сценарий 3.2: `anet-auth` упал полностью (Redis grace-кэш на ноде + переезд панели)

**Главный фокус реализации в этой задаче:** клиенты и живые ноды должны спокойно переживать падение `anet-auth` **без ручного прописывания `allowed_clients` и рассылок в Telegram**.

```
Нормальная работа:
  Клиент -> Подключается к Ноде X -> Нода X спрашивает /check_access у anet-auth
  Если allowed = true  -> Нода X пишет в локальный Redis:
                          SET auth_grace:<fingerprint> "{limits, expires_at}" EX 86400 (12-24ч)
  Если allowed = false -> Нода X удаляет ключ: DEL auth_grace:<fingerprint>
  Если админ/ЛК кикнул или забанил юзера -> anet-auth по WS мгновенно шлёт ноде Revoke(fingerprint) -> DEL из Redis

Когда anet-auth упал:
  1. Клиент не достучался до anet-auth -> берёт из своего кэша последнюю ноду, куда он ходил (Нода X).
  2. Нода X стучится в /check_access -> anet-auth не отвечает (timeout / 5xx).
  3. Нода X проверяет свой локальный Redis по fingerprint клиента:
     - Запись есть И текущий момент < expires_at -> ПУСКАЕМ в grace-режиме с теми же лимитами скорости (eBPF)!
     - Записи нет или подписка уже истекла (expires_at < now) -> отказ.
```

- **Почему именно Redis на ноде (а не только RAM процесса `anet-server`):** кэш переживает рестарт/обновление `anet-server`, а несколько нод в одном ДЦ могут делить один локальный Redis. При недоступности Redis — мягкий fallback на `DashMap` в памяти.
- **Переезд `anet-auth` без лишних ключей:** `auth_signing_key` (32 байта Ed25519) переносится вместе с бэкапом панели, поэтому клиенты с уже известным/кэшированным `auth_pub_key` бесшовно примут новый сервер после обновления DNS `A`-записи или зеркала в `endpoints`.

### Отложенные механизмы устойчивости (`TODO` для человека и для AI — НЕ делать сейчас)

> ⚠️ **`TODO [AI/Human]` — вынесено за рамки текущей задачи, реализовать отдельным этапом:**
> 1. **In-Tunnel Sync (п. 3.1):** режим «сначала поднять туннель на кэшированной ноде -> затем синхронизировать `ClientConfig` / `AllocateNode` внутри туннеля» (потребует пересмотра логики bypass-маршрутов в `anet-client-core/src/client.rs:604-628`).
> 2. **Node Proxy Relay (`POST /api/v1/control/client_relay`):** проброс зашифрованного `AuthEnvelope` через любую живую VPN-ноду в `anet-auth`, если сам домен `anet-auth` заблокирован в стране клиента.
> 3. **Внеполосное обнаружение нового `SignedAuthManifest` при бане самого домена и падении всех зеркал:**
>    - Push свежего `SignedAuthManifest` от живых VPN-нод клиентам прямо внутри ASTP-сессии;
>    - Опрос резервных `DNS TXT` записей через DoH (`1.1.1.1` / `8.8.8.8`);
>    - Чтение подписанного блоба с публичных площадок («Dead Drops»: GitHub Raw/Gist, S3, Cloudflare Workers).

---

## 6. Влияние на клиентские подсистемы и ответы по UI/Mobile/Server

### 6.1. `NodeProbeMonitor` и `node_selector.rs` (Выбран Вариант 1)

По итогам обсуждения зафиксирован **Вариант 1** (без фонового пробирования и без отдельных маяков-приманок):

- **До подключения (в списке групп серверов в UI):** клиент показывает сводку от `anet-auth` (`ServerGroupSummary`):
  - индикатор статуса (`GroupHealth`: зелёный / жёлтый / красный),
  - количество живых нод в группе (`available_nodes`), локации (`locations`) и сводную загрузку (`load_pct`),
  - **последний / усреднённый реальный RTT (`~42 ms`) из локального кэша клиента**, который автоматически замеряется через внутритуннельный `icmp_probe` во время реальных подключений к этой группе (до первого коннекта для группы показывается `"—"`).
- **Преимущество:** ни один IP/порт ноды не раскрывается до подключения, а `NodeProbeMonitor` не создаёт лишнего фонового трафика на ноды (ниже заметность для DPI и расход батареи на Android).

### 6.2. Цикл переключения нод при обрыве (`AnetClient::start()`)

- Вместо статического перебора `cfg.servers` клиент вызывает `NodeAllocator`:
  1. Запрос `AllocateNodeRequest(group_id, exclude_server_ids)` в `anet-auth` -> получаем `primary` + 1–2 `fallbacks`.
  2. Подключаемся к `primary`. Если рукопожатие/транспорт не поднялись — **мгновенно** пробуем `fallbacks[0]` без лишнего ожидания `anet-auth`, одновременно занося `primary.server_id` в `exclude_server_ids` (с TTL 3 минуты).
  3. Если упали и `fallbacks` — делаем новый запрос `AllocateNodeRequest` с обновлённым `exclude_server_ids`.
  4. Если сам `anet-auth` не отвечает — берём кэшированную ноду этой группы из `last_allocated_by_group` (где у этой ноды в Redis с высокой вероятностью уже лежит grace-кэш на пользователя).

### 6.3. Мобильный клиент Android (`https://github.com/ZeroTworu/anet-android` и `anet-mobile`)

- Логика загрузки/обновления конфига по URL (`#pk=...`), DH-обмен с `anet-auth`, шифрованный кэш (`EncryptedServerConfigBundle` + `last_allocated_by_group`) и вызов `AllocateNode` должны жить **строго в Rust (`anet-client-core` / `anet-common`)**.
- В `anet-mobile/src/lib.rs` выставляется единый FFI-контракт для `anet-android`: Kotlin передаёт только ссылку/путь к приватному каталогу/ключу хранилища, список групп и параметры туннеля Kotlin получает уже готовыми из Rust-ядра.

### 6.4. CLI (`anet-client-cli`)

- Остаётся сугубо отладочным инструментом для разработчиков (`-c ./client.toml`), в него загрузчик конфигов и кэш не добавляются.

---

## 7. Поэтапный план реализации и `TODO` на следующие итерации

### Этап 1. Криптографическое ядро и Protobuf (`anet-common`, `anet-auth/Cargo.toml`)
1. В `anet-common/proto/protocol.proto` добавить `AuthEnvelope`, `AuthDhInitRequest/Response`, `AuthEncryptedFrame`, `AuthInnerPayload`, `ClientConfigRequest/Response`, `ServerGroupSummary`, `AllocateNodeRequest/Response`, `AllocatedServerEndpoint`, `AuthEndpointManifest`, `SignedAuthManifest` со строгими `enum` (`OsPlatform`, `GroupHealth`, `TransportProtocol`, `WrtcMode`, `BalanceStrategy`, `AuthErrorCode`).
2. Вынести в `anet-common` чистые `ClientDhInitiator`, `ServerDhResponder`, `AstpEnvelopeCipher`, `build_dh_transcript` (без ASCII-сигнатур проекта — с байтовым `DhContext` + `signer_pub`) и проверку timestamp; перевести на них `anet-server/src/auth_handler.rs` и `anet-client-core/src/auth.rs`.
3. В `anet-common/src/boring_tls.rs` добавить флаг режима **strict WebPKI-only** (отключение загрузки системных корневых сертификатов ОС для обращений к `anet-auth`).
4. Подключить к `anet-auth` зависимости из workspace (`x25519-dalek`, `chacha20poly1305`, `prost`).

### Этап 2. Телеметрия, WebSocket-линк, Redis и балансировщик (`anet-server`, `anet-auth`, `anet-webui`)
1. Выпилить старые AI-заглушки `anet-auth/src/balancer.rs` и `resolve_client_servers()` в `api.rs`.
2. На `anet-server`:
   - Реализовать сбор метрик CPU %, CPU cores, LoadAvg, RAM, LAN RX/TX Mbps на внешнем интерфейсе + `nic_capacity_mbps` с EMA-сглаживанием; расширить `NodeHeartbeatRequest`.
   - Добавить исходящий WebSocket-клиент до `anet-auth` (`/api/v1/control/nodes/ws`) для push-телеметрии (1–2с / по событию) и приёма живых команд (`KickSession`, `RevokeFingerprint`, `Drain`), оставив HTTP heartbeat как железобетонный fallback.
   - В `AuthProvider` (`anet-server/src/auth_provider.rs`) добавить **Redis grace-кэш** разрешённых `fingerprint` с TTL (и удалением при отказе/WS-отзыве) + fallback в `DashMap`, чтобы переживать падение `anet-auth` без ручного `allowed_clients`.
3. На `anet-auth`:
   - SeaORM-миграции: `servers.location`, перевод `node_pools.strategy` и `servers.wrtc_mode` на PostgreSQL `Enum`, расширение `node_runtime_states` (CPU/RAM/LAN/`load_score`/`ws_connected`).
   - Обработчики WS + обновлённый HTTP heartbeat.
   - Новый балансировщик `smart_load` (admission filter + композитная формула LAN/CPU/RAM/Conns + `pending_leases` + `exclude_server_ids` + агрегация `locations` пула).
4. На `anet-webui`: поле `location` у серверов, отображение CPU/RAM/LAN/% канала/статуса WS в `Overview.vue` и `Servers.vue`, выбор стратегии `smart_load` в `Pools.vue`.

### Этап 3. Защищённый протокол `Client <-> anet-auth` и ЛК (`anet-auth`)
1. Добавить `auth_signing_key` (Ed25519) в конфиг/инициализацию `anet-auth`.
2. Реализовать `POST /api/v1/client/exchange` с `BrowserProfile`-совместимым бинарным ответом и картой краткоживущих DH-сессий.
3. Реализовать внутри шифрованного канала:
   - `ClientConfigRequest` (допускается в `bootstrap_mode = true` и в Режиме 1, отдаёт конфиг без `[[servers]]`, `ServerGroupSummary[]` с `locations` и `Enum`-ами, статус подписки/лимитов как в `billing_and_cabinet.ru.md`, и `auth_pub_key` для TOFU);
   - `AllocateNodeRequest` (**только в Режиме 1 с подписью клиента!** Проверяет права и лимиты, выбирает ноду по `smart_load`, отдаёт `primary` + `fallbacks` + `server_pub_key` каждой ноды).
4. Обновить генерацию ссылок/QR (`#pk=<auth_pub_key>`), оставив старый `GET /api/v1/config/:id` в режиме legacy для команды.

### Этап 4. Клиентское ядро и интерфейсы (`anet-client-core`, `anet-client-gui`, `anet-mobile`)
1. Перенести и расширить `EncryptedServerConfigBundle` + `last_allocated_by_group` в `anet-client-core`.
2. Реализовать `AuthApiClient` (3 уровня доверия к `auth_pub_key`: вшитый ключ -> `#pk=` -> TOFU на строгом WebPKI-only; кэш DH-сессии; `BrowserProfile` HTTPS; перебор зеркал `endpoints`; откат на кэш `last_allocated_by_group` при падении `anet-auth`).
3. Обновить `CoreConfig::sanitize()` и `AnetClient` (`NodeAllocator` + локальный failover на `fallbacks`).
4. В `anet-client-gui`: перевести `node_selector.rs` для групповых конфигов на **Вариант 1** (`ServerGroupSummary` с локациями/нагрузкой + кэшированный реальный RTT по группе; индикатор кэш-режима при недоступности `anet-auth`).
5. В `anet-mobile`: вынести FFI-обвязку для `ZeroTworu/anet-android` (включая базу для встроенной регистрации без email/ТГ через вшитый `auth_pub_key`), убрав загрузку/кэширование конфигов из Kotlin внутрь Rust-ядра.

### Отложенные задачи (`TODO` для человека и для AI — НЕ делать в этой итерации)
- **`TODO #1` (Унификация `server.toml`):** удалить `[authentication].auth_servers` и `auth_server_token`, перевести `AuthProvider` полностью на секцию `[control_plane]` (`url`, `token`, `node_id`) + единый список зеркал.
- **`TODO #2` (Генерация клиентских ключей на устройстве):** перейти от выдачи `[keys].private_key` с сервера при `bootstrap_mode = true` к генерации Ed25519-ключей локально на устройстве клиента при первом входе и регистрации только `public_key` по одноразовому invite-токену из ЛК.
- **`TODO #3` (Сценарий 3.1 — обход блокировки живого `anet-auth`):** In-Tunnel Sync (сначала туннель по кэшу -> потом sync внутри туннеля в обход bypass-маршрутов `client.rs:604-628`) и проксирование `AuthEnvelope` через живую VPN-ноду (`POST /api/v1/control/client_relay`).
- **`TODO #4` (Резервное обнаружение `SignedAuthManifest` при смерти домена и всех зеркал):** доставка `SignedAuthManifest` через ASTP-тракт живых нод, опрос `DNS TXT` через DoH и чтение с публичных Dead Drops (GitHub Raw/Gist, S3, Cloudflare Workers).

---

## 8. Финальные решения и ответы на вопросы ревью

1. **Совместимость старого `GET /api/v1/config/:id` на переходный период:**  
   **Принято.** Старый `GET /api/v1/config/:id` остаётся работать без изменений для команды (5 человек на текущих клиентах), а новый протокол (конфиги без `[[servers]]` + DH + Protobuf) запускается параллельно для новых версий клиента и тестирования.
2. **Выдача `private_key` клиента в `bootstrap_mode = true` vs генерация на клиенте:**  
   **Принято.** В первой итерации сохраняем текущую схему БД: при `bootstrap_mode = true` клиент забирает свой `[keys].private_key` внутри DH-шифроканала (с запретом на `AllocateNode` в этом режиме). Генерация ключа на стороне клиента вынесена в `TODO #2`.
3. **«Sticky vs Dynamic» при переподключении клиента (ответ на замечание п. 8.3):**  
   *Пояснение, о чём шла речь:* имелось в виду, стоит ли специально привязывать клиента к одной и той же ноде при ручных переподключениях (чтобы не менялся выходной IP), или просто каждый раз брать самую свободную ноду.  
   **Принятое решение (без лишнего усложнения):** никакой искусственной «липкости» делать не нужно — при запросе подключения в группе серверов `anet-auth` просто отдаёт наименее загруженную ноду (и если это оказалась та же самая нода, значит она и сейчас самая свободная — отлично). Единственное исключение: клиент передаёт `exclude_server_ids`, только если попытка коннекта к какой-то ноде только что физически упала, чтобы не попасть на ту же мёртвую ноду по кругу.
4. **Отдельный оффлайн `master_key` для `SignedAuthManifest` (ответ на замечание п. 8.4):**  
   *Пояснение:* отдельный оффлайн root-ключ предлагался только на случай, если при потере ДЦ потерялся и сам `auth_signing_key` от `anet-auth` и при этом старый домен/IP мёртв. **Для реальной жизни это действительно оверинжиниринг.**  
   **Упрощённое решение:** никакого отдельного второго ключа заводить не нужно — достаточно хранить в бэкапе единственный `auth_signing_key` от `anet-auth`. При переезде `anet-auth` на новый сервер/домен новая панель подписывает `AuthEndpointManifest` этим же `auth_signing_key`, а клиенты проверяют его уже известным им `auth_pub_key`.
