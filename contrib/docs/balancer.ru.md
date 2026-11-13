# Динамический балансировщик, телеметрия узлов, E2E-криптография `Client <-> anet-auth` и отказоустойчивость control plane

> **Статус документа:** Архитектурная спецификация и план реализации (код на текущем этапе не изменялся).  
> **Базовая ветка аудита:** `master` (`d88b0c3`).

---

## Оглавление

1. [Аудит текущей кодовой базы (сверка предположений с `master`)](#1-аудит-текущей-кодовой-базы-сверка-предположений-с-master)
2. [Расширение телеметрии нод: CPU / RAM / LAN и интеллектуальная балансировка (п. 1.1)](#2-расширение-телеметрии-нод-cpu--ram--lan-и-интеллектуальная-балансировка-п-11)
3. [Групповые конфиги, E2E-обмен по Protobuf over HTTPS и DH до конфига (п. 2.2)](#3-групповые-конфиги-e2e-обмен-по-protobuf-over-https-и-dh-до-конфига-п-22)
4. [Рефакторинг DH / ASTP-криптографии в `anet-common` (п. 2.2.3)](#4-рефакторинг-dh--astp-криптографии-в-anet-common-п-223)
5. [Подводные камни: блокировка и падение `anet-auth` (п. 3.1 и 3.2)](#5-подводные-камни-блокировка-и-падение-anet-auth-п-31-и-32)
6. [Влияние на клиентские подсистемы (UI, Probe, Failover, CLI, Mobile)](#6-влияние-на-клиентские-подсистемы-ui-probe-failover-cli-mobile)
7. [Поэтапный план реализации](#7-поэтапный-план-реализации)
8. [Открытые вопросы и решения для согласования](#8-открытые-вопросы-и-решения-для-согласования)

---

## 1. Аудит текущей кодовой базы (сверка предположений с `master`)

Перед проектированием проведена полная сверка наброска с актуальным состоянием репозитория.

### 1.1. Что уже отправляет нода в `anet-auth`

**Предположение:** *«уже сейчас каждая нода шлёт частичные данные о своём состоянии (включая онлайн / кол-во сессий)»*.  
**Факт в коде — ПОДТВЕРЖДЕНО ЧАСТИЧНО:**

- Фоновая задача `control_plane::run_heartbeat` (`anet-server/src/control_plane.rs`) раз в `heartbeat_interval_seconds.max(5)` секунд (а также досрочно с коалесценцией `100 мс` при срабатывании `registry.wait_state_changed()`) отправляет в `anet-auth` (с заголовком `X-Node-Token`):
  1. `POST /api/v1/control/nodes/heartbeat` — структура `NodeHeartbeatRequest` (`anet-common/src/dto.rs`):
     - `node_id: String`
     - `version: String`
     - `uptime_seconds: u64` *(внимание: это аптайм процесса `started_at.elapsed()`, а не ОС)*
     - `active_connections: usize` *(реальное число активных клиентов в `ClientRegistry`)*
     - `accepting_connections: bool`
  2. `POST /api/v1/control/nodes/traffic` — структура `NodeTrafficReport`:
     - `samples: Vec<TrafficUsageSample>` (дельты `rx_bytes`/`tx_bytes` по fingerprint за интервал),
     - `active_session_counts: Vec<NodeSessionCountItem>` (`fingerprint`, `count`, `oldest_created_at`).
  3. Дополнительно при аутентификации каждого клиента `anet-server/src/auth_provider.rs` вызывает `POST /api/v1/check_access` (`CheckAccessRequest { fingerprint, node_id, node_active_sessions }`).
- `anet-auth` сохраняет heartbeat в таблице `node_runtime_states` (`anet-auth/src/entities/node_runtime_states.rs`) и считает узел `online`, если `now - last_seen_at <= 45s` (`anet-auth/src/api/api.rs`, `servers.rs`). Посессионные срезы живут в памяти в `LIVE_NODE_SESSIONS` с TTL `45s`.
- **Чего НЕТ сейчас:** никаких метрик железа и сети (**CPU %, RAM used/total, Load Average, скорость/утилизация сетевых интерфейсов LAN RX/TX Mbps, пропускная способность канала ноды, число пакетов/очередей/дропов**) нода не собирает и не передаёт.

### 1.2. Как клиент сейчас получает конфиг и работает с кэшем

**Предположение:** *«уже сейчас клиент вначале запрашивает у `anet-auth` конфиг при старте, и только если нету коннекта — юзает старый из кеша»*.  
**Факт в коде — ПОДТВЕРЖДЕНО С КРИТИЧЕСКИМИ ОГОВОРКАМИ ПО ПЛАТФОРМАМ:**

1. **Desktop GUI (`anet-client-gui/src/app.rs`):**
   - При старте `ANetApp::new()` **сразу** поднимает последний локально сохранённый конфиг `settings.get_active_config_with_overrides(&storage_key)` из зашифрованного локального бандла `EncryptedServerConfigBundle` (плюс локальные пользовательские overrides) и параллельно запускает асинхронный `fetch_and_apply_server_config(false)`.
   - `Updater::fetch_server_config(url, etag)` (`anet-client-core/src/updater.rs`) делает HTTPS GET с `If-None-Match` (`ETag`) и браузерным `BrowserProfile::random()`. Если `anet-auth` недоступен, GUI продолжает работать на зашифрованном кэше (или показывает уведомление, если кэша нет вовсе).
   - У правила маршрутизации `rules.abc` (`RuleCacheManager`, `anet-client-core/src/rule_updater.rs`) также есть дисковый кэш + фоновое обновление каждые `600 сек`.
2. **CLI (`anet-client-cli/src/main.rs`):**
   - **НЕ умеет** скачивать конфиг с `anet-auth` и **НЕ имеет** кэша конфигов — читает только локальный файл `-c ./client.toml` (`tokio::fs::read_to_string(&opt.cfg)`). Синхронизирует только `rules.abc`.
3. **Mobile (`anet-mobile/src/lib.rs`):**
   - Библиотека на Rust принимает готовый `config_toml: &str` от нативной Kotlin/Swift-оболочки; обновление/кэширование `config.toml` сейчас живёт в платформенном слое, а не в едином ядре `anet-client-core`.

### 1.3. Критическая находка: балансировщик в `anet-auth` уже написан, но не используется в `download_config`

- В `anet-auth/src/balancer.rs` **уже реализованы** стратегии `weighted` (Weighted Rendezvous Hashing) и `least_connections` на структуре `BalanceCandidate { server_id, weight, active_connections }`.
- Функция `resolve_client_servers()` (`anet-auth/src/api/api.rs:349`) вызывает этот балансировщик, фильтруя только активные и живые (`last_seen_at <= 45s`, `accepting_connections == true`) узлы.
- **НО** реальный endpoint выдачи клиентского конфига `download_config` (`GET /api/v1/config/:id` в `anet-auth/src/api/users.rs:751-1004`) **вообще не вызывает `resolve_client_servers()`!** Вместо этого он выгружает в `client.toml` **все** активные записи `[[servers]]` из всех активных пулов пользователя, отсортированные только по статическому `member.weight`, прописывая в каждой секции `group_name` и `group_id`.
- На клиенте (`anet-client-gui/src/app.rs:715-793`, `anet-mobile/src/lib.rs:1160-1213`) выбор пользователя в UI выбирает `group_id`, фильтрует массив `cfg.servers` по этому `group_id`, а `AnetClient::start()` просто крутит их по кругу в том порядке, в котором они пришли в `client.toml`.

### 1.4. Терминологическая коллизия: `groups` vs `node_pools`

В текущей базе и коде термин «группа» означает две разные сущности:
- **`groups`** (`anet-auth/src/entities/groups.rs`) — **тарифная группа пользователя** (лимит трафика, скорости, сессий, срок подписки, набор доступных пулов `group_node_pools`).
- **`node_pools`** (`anet-auth/src/entities/node_pools.rs`) — **пул серверов / локация / транспортный профиль** (например, *«Нидерланды (WRTC)»*, *«Германия (Auto)»*), который в `[[servers]]` попадает как `group_id = pool.id` и `group_name = pool.name`, и именно его пользователь выбирает в клиенте.

В рамках этого документа под **«группой выбора клиента»** далее понимается **`node_pool` (пул нод)**, доступный пользователю по его тарифу (`groups`) или персональной привязке (`user_node_pools`). В новом протоколе рекомендуется явно называть идентификатор в protobuf `pool_id` (или `group_id` с чёткой привязкой к `node_pools.id`, чтобы не сломать существующий UI).

### 1.5. Текущие проблемы безопасности `GET /api/v1/config/:id`

1. `download_config` отдаёт по HTTP **в открытом TOML-тексте** приватный Ed25519-ключ клиента (`[keys].private_key`), ключи всех нод (`server_pub_key`), внутренние DSN/IP/порты и токены/креды транспортов (`wrtc`, `imap`, `ssh`).
2. При компрометации УЦ (или подмене корпоративного/государственного прокси-сертификата, либо при срабатывании fallback на `verify_peer = false` как в `fetch_config_from_url()`) атакующий (MITM / ТСПУ) получает:
   - приватный ключ клиента (полный имперсонаж),
   - полный список всех VPN-нод и их портов (моментальный бан всей инфраструктуры по одному утекшему конфигу).

---

## 2. Расширение телеметрии нод: CPU / RAM / LAN и интеллектуальная балансировка (п. 1.1)

### 2.1. Какие метрики собирать на `anet-server`

Использование `sysinfo` (или прямого чтения `/proc/stat`, `/proc/meminfo`, `/proc/loadavg`, `/proc/net/dev` на Linux с минимальными накладными расходами, т.к. `anet-server` работает преимущественно на Linux-нодах; для кроссплатформенного fallback можно использовать crate `sysinfo` с точечным `RefreshKind` без сканирования процессов):

| Метрика | Источник (Linux) | Тип в DTO / БД | Зачем нужна |
|---|---|---|---|
| `cpu_usage_pct` | Δ `/proc/stat` за интервал heartbeat (0..100%) | `f32` (`REAL`) | Главный индикатор перегрузки шифрованием/VP8/WebRTC |
| `load_avg_1m` | `/proc/loadavg` (нормированный по числу ядер `cpu_cores`) | `f32`, `u16` (`cpu_cores`) | Показывает очередь процессов / прерываний (iowait, softirq) |
| `ram_used_bytes` / `ram_total_bytes` | `/proc/meminfo` (`MemTotal - MemAvailable`) | `u64` / `i64` | Контроль OOM и давления памяти от буферов WebRTC/QUIC |
| `net_rx_mbps` / `net_tx_mbps` | Δ `/proc/net/dev` по основному внешнему интерфейсу (исключая `lo` и `tun*`) | `f32` | Реальная текущая полоса (Мбит/с) в мир |
| `net_capacity_mbps` | Из конфига ноды `[control_plane].nic_capacity_mbps` или ethtool/sysfs (`/sys/class/net/<iface>/speed`) | `u32` (опционально, по умолчанию e.g. `1000`) | Позволяет считать % утилизации канала: `max(rx, tx) / capacity` |
| `active_connections` | `ClientRegistry` (уже есть) | `usize` / `i32` | Кол-во активных клиентских сессий |
| `max_connections` | Опциональный лимит в конфиге ноды или таблице `servers` (`0` = без жёсткого лимита) | `Option<u32>` | Защита от переполнения IP-пула TUN (`IpPool`) или сокетов |
| `os_uptime_seconds` | `/proc/uptime` (плюс оставить `process_uptime_seconds`) | `u64` | Отличие рестарта демона от перезагрузки сервера |

> **Важный нюанс по LAN-метрике:** Считать нужно именно **внешний физический/виртуальный NIC** (например, автодетект интерфейса маршрута по умолчанию через netlink/route-таблицу или явный `control_plane.wan_interface`), **а не** TUN-интерфейс, иначе при двойной инкапсуляции (особенно в WRTC/TURN/CF WARP/IMAP) реальная утилизация канала будет занижена или искажена. Также необходимо сглаживать мгновенные пики через **EMA (экспоненциальное скользящее среднее)** на ноде или в `anet-auth` (например, $\alpha = 0.35$), чтобы микробёрст на 1 секунду перед heartbeat не ронял рейтинг ноды.

### 2.2. Расширение контрактов и БД

1. **`anet-common/src/dto.rs` — `NodeHeartbeatRequest`:**
   Добавить поля с `#[serde(default)]` для полной обратной совместимости со старыми нодами во время rolling-обновления:
   ```rust
   pub struct NodeSystemMetrics {
       pub cpu_usage_pct: f32,        // 0.0 .. 100.0
       pub cpu_cores: u16,
       pub load_avg_1m: f32,
       pub ram_used_bytes: u64,
       pub ram_total_bytes: u64,
       pub net_rx_mbps: f32,
       pub net_tx_mbps: f32,
       pub net_capacity_mbps: Option<u32>,
   }
   ```
2. **Миграция `anet-auth` для `node_runtime_states`:**
   Добавить колонки (`cpu_usage_pct`, `cpu_cores`, `load_avg_1m`, `ram_used_bytes`, `ram_total_bytes`, `net_rx_mbps`, `net_tx_mbps`, `net_capacity_mbps`, `load_score`).
   В оперативной памяти `anet-auth` также стоит держать лёгкий `DashMap<Uuid, NodeRuntimeSnapshot>` с EMA-сглаживанием и короткой историей (или ring-buffer на 15–30 минут), чтобы:
   - не нагружать SQLite/Postgres постоянными тяжёлыми выборками при каждом запросе клиента на подключение;
   - отдавать графики/спарклайны в WebUI.
3. **WebUI (`anet-webui`):**
   - `Servers.vue` и `Overview.vue`: добавить прогресс-бары **CPU %**, **RAM (GiB / %)**, **LAN (RX/TX Mbps + % канала)**, интегральный **Load Score** и цветовые бейджи деградации (`OK` / `HIGH LOAD` / `SATURATED`).

### 2.3. Алгоритм балансировки с учётом ресурсов (`anet-auth/src/balancer.rs`)

Текущая стратегия `least_connections` не учитывает, что 10 качающих торренты/4K-видео пользователей нагружают CPU/LAN сильнее, чем 80 пользователей в мессенджерах. Новая стратегия (например, `smart_load` / обновлённая `least_load`) должна работать в два этапа:

#### Этап A. Жёсткая фильтрация (Admission & Circuit Breaker)
Нода **исключается** из выдачи, если выполняется любое условие:
- `!server.is_active` или `!runtime.accepting_connections`;
- `now - runtime.last_seen_at > 45s` (stale/offline);
- `max_connections > 0 && active_connections >= max_connections`;
- `cpu_usage_pct >= 92.0` или `ram_pct >= 94.0` или `lan_pct >= 95.0` *(пороги настраиваемы на уровне пула/сервера; если ВСЕ ноды в пуле перегреты — переходим в режим мягкой деградации и берём наименее перегруженную, чтобы не отказать клиенту полностью)*.

#### Этап B. Взвешенный интегральный индекс нагрузки (`load_score`)
Для каждого допущенного кандидата в пуле вычисляем нормированную загрузку $L \in [0.0, 1.0+]$:

$$
L = w_{\text{lan}} \cdot U_{\text{lan}} + w_{\text{cpu}} \cdot U_{\text{cpu}} + w_{\text{ram}} \cdot U_{\text{ram}} + w_{\text{conn}} \cdot U_{\text{conn}}
$$

где:
- $U_{\text{lan}} = \frac{\max(\text{net\_rx\_mbps}, \text{net\_tx\_mbps})}{\text{capacity\_mbps}}$ (если `capacity == 0`, берётся дефолт 1000 Мбит/с или настраиваемый параметр пула);
- $U_{\text{cpu}} = \frac{\text{cpu\_usage\_pct}}{100.0}$;
- $U_{\text{ram}} = \frac{\text{ram\_used\_bytes}}{\text{ram\_total\_bytes}}$;
- $U_{\text{conn}} = \frac{\text{active\_connections}}{\text{ref\_connections}}$ (или относительная доля от `max_connections`).
- Рекомендуемые дефолтные веса: $w_{\text{lan}} = 0.45$, $w_{\text{cpu}} = 0.30$, $w_{\text{ram}} = 0.15$, $w_{\text{conn}} = 0.10$ *(LAN важнее всего, т.к. узкое место VPN — обычно сетевой интерфейс и CPU на шифровании/WRTC)*.

Итоговый ранг с учётом веса участника `member.weight` (где больший `weight` означает большую желаемую долю трафика, например мощный 10G-сервер имеет `weight = 100`, а слабый `weight = 25`):

$$
\text{effective\_cost} = \frac{L + \epsilon}{(\text{weight})^{\alpha}} + \text{recent\_assign\_penalty}
$$

#### Этап C. Защита от эффекта «громового стада» (Thundering Herd)
Heartbeat ноды ходит раз в 5–15 секунд. Если 50 клиентов подключатся в течение 2 секунд после рестарта пула, все 50 получат одну и ту же «самую пустую» ноду до прихода следующего heartbeat:
1. В `anet-auth` ведётся счётчик **недавно выданных назначений (`pending_leases`)** за последние ~15 секунд (по `node_id`), который добавляет небольшой штраф `recent_assign_penalty` к `effective_cost` при каждой выдаче ноды до тех пор, пока от неё не придёт свежий `heartbeat` или `check_access`.
2. Выбор ведётся не строго `min`, а **Power-of-Two / Weighted Top-K Random** среди топ-2/топ-3 лучших нод (или детерминированный jitter), если разница их `effective_cost` меньше 5%.
3. Поле `exclude_server_ids` в запросе клиента гарантирует, что при ретрае/переподключении клиент не попадёт повторно на ту же проблемную ноду.

---

## 3. Групповые конфиги, E2E-обмен по Protobuf over HTTPS и DH до конфига (п. 2.2)

### 3.1. Главная криптографическая проблема п. 2.2.2 («DH до получения конфига») и её решение

В требовании п. 2.2.2 заложена **критически важная деталь**, которую легко упустить при наивной реализации:

1. **Проблема неаутентифицированного DH (Active MITM):**  
   Если клиент делает обычный анонимный Diffie-Hellman (X25519) с `anet-auth` **до** скачивания конфига, не имея никаких ключей сервера заранее, то активный MITM (например, ТСПУ с подменённым TLS или злой прокси) проведёт два отдельных DH (Клиент↔MITM и MITM↔Auth) и всё равно расшифрует трафик. HTTPS сам по себе при недоверии к CA не даёт корня доверия для DH.
2. **Проблема ключа клиента при первичном подключении (Chicken-and-Egg):**  
   В текущей системе (`anet-auth/src/api/users.rs:992`) пользователь не генерирует Ed25519-ключ сам — `anet-auth` хранит зашифрованный ключ пользователя в БД и **выдаёт `private_key` клиенту при первом скачивании `config/:id`**. При этом в ASTP (`anet-server/src/auth_handler.rs`) клиент должен подписать свой DH-ключ своим `private_key`. На этапе **самого первого** скачивания конфига у клиента **ещё нет ни своего `private_key`, ни `server_pub_key`**!

#### Как решить обе проблемы чисто и криптографически строго:

1. **Закреплённый публичный ключ `anet-auth` (`auth_pub_key`, Ed25519):**
   - `anet-auth` заводит собственную постоянную пару ключей Ed25519 (`auth_signing_key` / `auth_pub_key`, аналогично `server_signing_key` у нод).
   - **Корень доверия попадает к клиенту ДО первого HTTP-запроса двумя путями:**
     - **Способ А (рекомендуемый для подписок/ссылок):** добавление публичного ключа (или его SHA-256 пина) во **fragment** или query ссылки конфига (причём `#pk=...` во фрагменте URL браузерами и HTTP-прокси вообще **не отправляется на сервер в HTTP-запросе**):  
       `https://auth.example.com/api/v1/config/<token_or_uuid>#pk=<base64url_auth_pub_key>`  
       или deep-link: `anet://connect?u=...&pk=...`
     - **Способ Б (fallback / встроенный root key):** в бинарники клиентов (`anet-client-gui`, `anet-client-cli`, `anet-mobile`) вшивается root/master Ed25519 public key проекта (или список доверенных `auth_pub_key` для официальных инстансов). Если `#pk=` в URL нет (старая ссылка), клиент проверяет подпись `anet-auth` вшитым root-ключом (либо требует явного подтверждения TOFU только в dev-режиме).
2. **Разделение этапов рукопожатия с `anet-auth` на два режима:**
   - **Режим 0 — Bootstrap (первое получение конфига, ключа клиента ещё нет):**
     - Клиент шлёт эфемерный `dh_pub_key`, **без** подписи клиентом (`client_pub_key` пуст, вместо него передаётся `bootstrap_id` / одноразовый `config_token` уже внутри шифроконверта или в ослеплённом виде).
     - `anet-auth` отвечает своим эфемерным `dh_pub_key`, **подписанным `auth_signing_key` (`Ed25519`)** над транскриптом `(client_dh_pub || server_dh_pub || timestamp || nonce)`.
     - Клиент проверяет подпись `auth_pub_key` -> **MITM исключён даже при полностью скомпрометированном HTTPS/CA!**
     - Далее внутри `ChaCha20-Poly1305` (и дополнительного E2E-конверта поверх HTTPS) клиент запрашивает `ClientConfig` и **забирает свой `[keys].private_key`** (или же в перспективе сам генерирует ключ и регистрирует `public_key` по одноразовому invite-токену).
     - Важно: `config_id` из URL при этом передаётся уже **внутри зашифрованного DH-канала** (в HTTP POST идёт на нейтральный эндпоинт, например `POST /api/v1/telemetry/report` или `/api/v1/client/exchange`, а не `GET /api/v1/config/<uuid>` в открытом URL, который светит UUID пользователя в логах прокси/DPI!).
   - **Режим 1 — Authenticated Session (последующие обновления конфига, запрос ноды `AllocateNode`):**
     - У клиента уже есть свой Ed25519 `private_key` (из кэша) и `auth_pub_key`.
     - Выполняется **полный взаимно аутентифицированный DH (Mutual Ed25519 + X25519)**: клиент подписывает свой DH-ключ своим ключом, `anet-auth` подписывает свой DH-ключ своим `auth_signing_key`.
     - Внутри полученной сессии (или с кэшированной сессией на короткий TTL / 1-RTT с `session_ticket`, чтобы при нажатии «Подключиться» не тратить лишний RTT на DH при каждом клике!) клиент шлёт `AllocateNodeRequest`.

> **Оптимизация задержки (0-RTT / 1-RTT при кнопке «Подключиться»):**  
> При запуске приложения или в фоне клиент держит актуальный DH-обмен или делает 2-шаговый HTTPS POST (`/dh` -> `/rpc`, ~1-2 RTT). Чтобы не добавлять задержку при каждом клике пользователя, в `AllocateNode` можно передавать **краткоживущий `auth_session_token` + `session_key` (срок жизни например 15–30 минут, или до перезапуска)** либо делать 1-RTT ECIES-подобный конверт (эфемерный X25519 клиента + долгосрочный X25519/Ed25519 ключ `anet-auth` из `auth_pub_key`), с дополнительным DH для Forward Secrecy. С точки зрения архитектуры проще и чище **явная 2-шаговая DH-сессия** (как в ASTP) с кэшированием `AuthSessionId + shared_key` в памяти на `N` минут и авто-пересогласованием при `401 / SESSION_EXPIRED`.

### 3.2. Новый формат клиентского конфига (без `[[servers]]`)

`anet-auth` **перестаёт отдавать `[[servers]]`** в `ClientConfigResponse` / экспортируемом `client.toml`. Вместо этого в конфиге появляются:

```toml
version = 2

[main]
# ... текущие поля tun_name, manual_routing, route_for, exclude_route_for, dns_server_list, per_app ...

[auth]
# Основной и резервные адреса anet-auth (поддерживают mirror failover)
endpoints = ["https://auth.example.com/api/v1/client"]
auth_pub_key = "<base64 Ed25519 public key of anet-auth>"
master_pub_key = "<base64 Ed25519 root key for signed announcements>"
config_token = "<user subscription/config uuid or token>"
# Последняя ревизия манифеста адресов auth (защита от rollback)
manifest_seq = 14

[keys]
private_key = "<base64 Ed25519 client private key>"
# server_pub_key здесь больше НЕ хранится глобально — его выдаёт anet-auth
# динамически для каждой выделенной ноды в AllocateNodeResponse!

[[groups]]
id = "<node_pool uuid>"
name = "Нидерланды · Auto"
protocols = ["wrtc", "ahttp", "ws", "quic"]
strategy = "smart_load"
# Агрегированная оценка доступности/нагрузки со стороны auth (без раскрытия IP нод)
health = "online"          # online | degraded | offline
load_pct = 24              # 0..100
estimated_rtt_hint = 45    # опционально, если сервер знает регион/тег

# Секции [stealth], [ahttp], [quic_transport], [wrtc], [imap], [routing], [connectivity], [[browser_profiles]]
# сохраняются как общие транспортные профили клиента.
```

> **Обратная совместимость со статическими/ручными конфигами:**  
> Для локальной разработки, self-hosted без `anet-auth` и `anet-client-cli` ручное указание `[[servers]]` в локальном `.toml` должно **остаться валидным**! В `CoreConfig::sanitize()` нужно проверять: конфиг валиден, если **либо** `!self.servers.is_empty()`, **либо** `!self.groups.is_empty() && !self.auth.endpoints.is_empty()`.

### 3.3. Расширение `anet-common/proto/protocol.proto` (п. 2.2.1)

Поскольку клиент и `anet-auth` общаются по HTTPS (`Content-Type: application/x-protobuf` или замаскированный под бинарную телеметрию `application/octet-stream`), в `anet-common/proto/protocol.proto` добавляется блок сообщений для control plane `Client <-> anet-auth`.

Чтобы избежать путаницы с туннельными сообщениями `Message` и одновременно переиспользовать общий DH-механизм, предлагаем следующую схему в `protocol.proto`:

```protobuf
// === Запрос/ответ обёртки Client <-> anet-auth (передаётся в теле HTTPS POST) ===

message AuthEnvelope {
  uint32 protocol_version = 1; // = 1
  oneof payload {
    AuthDhInitRequest dh_init_req = 10;
    AuthDhInitResponse dh_init_res = 11;
    AuthEncryptedFrame encrypted = 12;
  }
}

// Фаза 1: Клиент -> anet-auth (маскируется как в ASTP либо передаётся открыто под TLS + подпись)
message AuthDhInitRequest {
  bytes client_ephemeral_pub = 1;     // 32 байта X25519
  bytes client_identity_pub = 2;      // 32 байта Ed25519 (пусто в режиме Bootstrap)
  bytes signature = 3;                // Подпись client_identity_sk(client_ephemeral_pub || timestamp || client_nonce)
  uint64 timestamp = 4;               // Unix secs (защита от replay)
  bytes client_nonce = 5;             // 16 байт
  bool bootstrap_mode = 6;            // true при самом первом получении конфига по config_token
  bytes padding = 7;                  // Рандомизация размера запроса против DPI по длине
}

// Фаза 2: anet-auth -> Клиент
message AuthDhInitResponse {
  bytes session_id = 1;               // 16 байт ID эфемерной/кэшируемой сессии на anet-auth
  bytes server_ephemeral_pub = 2;     // 32 байта X25519
  bytes signature = 3;                // ОБЯЗАТЕЛЬНАЯ подпись auth_signing_key над транскриптом:
                                      // (client_ephemeral_pub || server_ephemeral_pub || session_id || client_nonce || server_nonce || timestamp)
  uint64 timestamp = 4;
  bytes server_nonce = 5;             // 16 байт
  uint32 session_ttl_secs = 6;        // Сколько секунд можно переиспользовать session_id + shared_key
  bytes padding = 7;
}

// Фаза 3: Любой зашифрованный запрос/ответ внутри уже установленного shared_key
message AuthEncryptedFrame {
  bytes session_id = 1;               // Привязка к DH-сессии
  uint64 counter = 2;                 // Монотонный счётчик / защита от replay внутри сессии
  bytes nonce = 3;                    // 12 байт ChaCha20-Poly1305
  bytes ciphertext = 4;               // Зашифрованный AuthInnerPayload (AEAD AAD = session_id || counter)
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
```

#### Внутренние бизнес-сообщения `AuthInnerPayload`:

```protobuf
message ClientConfigRequest {
  string config_token = 1;            // UUID/токен подписки (передаётся ТОЛЬКО в шифрованном виде!)
  string etag = 2;                    // Если не изменился -> not_modified = true
  string client_version = 3;
  string os_platform = 4;             // "windows" | "linux" | "android" | "macos"
  uint64 known_manifest_seq = 5;      // Версия последнего AuthEndpointManifest у клиента
}

message GroupSummary {
  string group_id = 1;                // node_pools.id
  string name = 2;
  repeated string protocols = 3;      // Доступные транспорты в пуле (["wrtc", "ahttp", ...])
  string strategy = 4;
  string health = 5;                  // "online" | "degraded" | "offline"
  uint32 load_pct = 6;                // Агрегированная нагрузка по пулу (0..100)
  uint32 available_nodes = 7;         // Кол-во живых нод в пуле (без IP!)
}

message ClientConfigResponse {
  bool not_modified = 1;
  string etag = 2;
  string config_toml = 3;             // Базовый конфиг БЕЗ [[servers]] (включая [keys].private_key при bootstrap/обновлении)
  repeated GroupSummary groups = 4;   // Список доступных групп/пулов для UI
  SignedAuthManifest auth_manifest = 5; // Подписанный список актуальных зеркал/доменов auth
  string user_status = 6;             // Остаток трафика, expires_at, статус подписки
  int64 traffic_limit_bytes = 7;
  int64 traffic_used_bytes = 8;
  uint64 expires_at_unix = 9;
}

message AllocateNodeRequest {
  string group_id = 1;                // Выбранная пользователем группа (node_pool.id)
  repeated string preferred_protocols = 2; // Опционально: фильтр протокола со стороны клиента
  repeated string exclude_server_ids = 3;  // Ноды, которые только что упали при попытке коннекта (failover!)
  string client_version = 4;
  string os_platform = 5;
  bool include_backup_node = 6;       // Можно запросить 1 резервную ноду на случай отказа первой
  uint64 known_manifest_seq = 7;
}

message AllocatedServerEndpoint {
  string server_id = 1;               // UUID ноды (для exclude_server_ids при отказе и кэша)
  string server_name = 2;             // Читаемое имя ноды для логов/статуса
  string protocol = 3;                // "quic" | "ssh" | "vnc" | "ws" | "ahttp" | "wrtc" | "imap"
  string dsn = 4;                     // Адрес подключения: host:port / https://... / wss://... / imap://...
  string server_pub_key = 5;          // Base64 Ed25519 ключ ЭТОЙ ноды (доставляется по E2E!)
  string wrtc_mode = 6;               // "media_video" | "datachannel" | "p2p_direct"
  string ssh_user = 7;                // Для ssh-транспорта
  string tls_pin_sha256 = 8;          // Опциональный SHA-256 пин TLS-сертификата ноды
  uint32 score_hint = 9;              // Текущий load_score на момент выдачи
}

message AllocateNodeResponse {
  AllocatedServerEndpoint primary = 1;
  repeated AllocatedServerEndpoint fallbacks = 2; // 0..2 резервные ноды того же пула (для мгновенного локального failover)
  uint32 lease_ttl_secs = 3;          // Рекомендуемое время жизни кэша этого назначения на случай падения auth
  SignedAuthManifest auth_manifest = 4; // Опционально обновлённый манифест адресов auth
}

message AuthError {
  uint32 code = 1;                    // 401 UNAUTHORIZED, 403 EXPIRED/QUOTA, 404 GROUP_NOT_FOUND, 503 NO_HEALTHY_NODES
  string message = 2;
}
```

> **Замечание о маскировке HTTPS-обёртки:**  
> Запрос `POST /api/v1/client/exchange` стоит отправлять с теми же `BrowserProfile` TLS/HTTP2-настройками (`stealth.tls_fingerprint`), которые уже есть в `anet-common::http_help` / `boring_tls`. Путь эндпоинта целесообразно сделать конфигурируемым (например, `/api/v1/telemetry` или `/api/v1/sync` как в `[ahttp].auth_path`), а `AuthDhInitRequest` (при `bootstrap_mode = false` или при известном `auth_pub_key`) можно дополнительно заворачивать в `create_handshake_cipher(&auth_pub_key)` — тогда в wire-формате DPI не увидит даже структуры полей protobuf, только случайный бинарный блоб.

### 3.4. Поток взаимодействия (Sequence Diagram)

```
Клиент                             anet-auth                          anet-server (Ноды)
  |                                    |                                     |
  |                                    |<--- Heartbeat (CPU/RAM/LAN/Conns) --| (каждые 5-15с)
  |                                    |                                     |
  |-- 1. POST (AuthDhInitRequest) ---->| (проверяет подпись клиента или      |
  |   [X25519 eph_pub, ts, sig/boot]   |  bootstrap_mode; генерит session)   |
  |<-- 2. AuthDhInitResponse ----------|                                     |
  |   [session_id, auth_eph_pub,       |                                     |
  |    Ed25519_sig(auth_signing_key)]  |                                     |
  |   (Клиент проверяет подпись        |                                     |
  |    по auth_pub_key -> MITM нет!)   |                                     |
  |                                    |                                     |
  |-- 3. AuthEncryptedFrame ---------->|                                     |
  |   (ClientConfigRequest + token)    |                                     |
  |<-- 4. ClientConfigResponse --------| (TOML БЕЗ [[servers]] +             |
  |   (кэшируется в EncryptedBundle)   |  GroupSummary[] + AuthManifest)     |
  |                                    |                                     |
  |  [Пользователь выбирает Группу X   |                                     |
  |   и нажимает "Подключиться"]       |                                     |
  |                                    |                                     |
  |-- 5. AuthEncryptedFrame ---------->|                                     |
  |   (AllocateNodeRequest: group_id,  |-- Расчёт smart_load в balancer.rs  |
  |    exclude_server_ids)             |-- Резерв pending_lease              |
  |<-- 6. AllocateNodeResponse --------|                                     |
  |   (primary ServerConfig +          |                                     |
  |    server_pub_key + fallbacks[])   |                                     |
  |                                    |                                     |
  |-- 7. ASTP Handshake + VPN Tunnel --------------------------------------->|
      (использует выданный DSN и server_pub_key)
```

---

## 4. Рефакторинг DH / ASTP-криптографии в `anet-common` (п. 2.2.3)

Сейчас логика 4-фазного DH-рукопожатия и шифрования/дешифрования ASTP-кадров дублируется и жёстко привязана к типам:
- В `anet-server/src/auth_handler.rs`: `ServerAuthHandler` завязан на `ClientRegistry`, `DashMap<SocketAddr, TempDHInfo>`, `AuthProvider` и `ServerNetworkConfig`.
- В `anet-client-core/src/auth.rs`: `AuthClient` завязан на `Transport` и клиентские ключи.
- В `anet-common/src/crypto_utils.rs`: лежат только примитивы (`create_handshake_cipher`, `derive_shared_key`, `sign_data`, `verify_signature`, `generate_key_fingerprint`).

### План декомпозиции (без копипасты)

Вынести в `anet-common` чистый, независимый от транспорта (UDP / HTTP / WS / WRTC) крипто-модуль `anet_common::dh_handshake` (или расширить `crypto_utils.rs` + отдельный `astp_crypto.rs`):

1. **`DhTranscript` и верификация/подпись:**
   - Единая функция формирования канонического транскрипта:  
     `build_dh_transcript(domain_tag: &[u8], client_eph: &[u8; 32], server_eph: &[u8; 32], client_nonce: &[u8], server_nonce: &[u8], timestamp: u64)`  
     *(использование `domain_tag`, например `b"ANET-ASTP-V1"` vs `b"ANET-AUTH-HTTP-V1"`, исключает cross-protocol replay-атаки между нодой и `anet-auth`!)*.
   - Единые функции `verify_timestamp_window(ts, max_skew_secs)` (в `anet-server` используется `120s`, сейчас это захардкожено внутри `auth_handler.rs`).
2. **`ServerDhResponder` (чистая state-machine без `ClientRegistry`):**
   - `process_client_dh_hello(req, server_signing_key, allow_anonymous_bootstrap) -> Result<(DhSessionKeys, DhServerHelloPayload)>`
   - Генерирует эфемерный `StaticSecret`, считает X25519 `shared_secret`, прогоняет через `derive_shared_key`, подписывает ответ через `server_signing_key`, возвращает `shared_key: [u8; 32]` и сериализованный/подписанный ответ.
   - После этого:
     - `anet-server` оборачивает `ServerDhResponder` своими `TempDHInfo`, `IpPool` и `ClientRegistry`.
     - `anet-auth` оборачивает **тот же самый** `ServerDhResponder` своей картой HTTPS-сессий (`DashMap<[u8; 16], AuthHttpSession>` с TTL и счётчиком `counter` против replay).
3. **`ClientDhInitiator` (чистая state-machine без `Transport`):**
   - `begin_dh(client_signing_key: Option<&SigningKey>, ...)` -> создаёт `(PendingDhState, DhClientHelloPayload)`.
   - `finish_dh(state, server_hello, expected_server_pub: &VerifyingKey) -> Result<[u8; 32]>` -> проверяет подпись `expected_server_pub`, вычисляет `shared_key`.
   - Используется одинаково и в `anet-client-core/src/auth.rs` (для подключения к ноде), и в новом `AuthApiClient` (для общения с `anet-auth`).
4. **Единый AEAD-конверт (`seal_envelope` / `open_envelope`):**
   - Упаковка и распаковка `ChaCha20-Poly1305` с произвольным `AAD`, `nonce` (`NONCE_LEN = 12`) и рандомизированным padding (`PaddingUtils`).
   - В `anet-common` для `anet-auth` достаточно включить уже присутствующие в workspace-корне зависимости `x25519-dalek`, `chacha20poly1305`, `prost` в `anet-auth/Cargo.toml` (все они уже есть в корневом `[workspace.dependencies]`).

---

## 5. Подводные камни: блокировка и падение `anet-auth` (п. 3.1 и 3.2)

Это самая сложная часть архитектуры: если клиент больше не хранит список всех нод в `client.toml`, то при недоступности `anet-auth` наивная реализация полностью сломает VPN даже тогда, когда сами VPN-ноды живы.

Необходимо чётко разделять два сценария и комбинировать несколько слоёв защиты.

### 5.1. Локальный кэш (обязательная база для 3.1 и 3.2)

В `EncryptedServerConfigBundle` (переносится из `anet-client-gui` в `anet-client-core`, чтобы работало в **GUI, CLI и Mobile** одинаково) сохраняются:
1. Последний успешный `ClientConfigResponse` (профили транспортов, `[keys].private_key`, список `groups`, `auth_manifest` с монотонной версией `manifest_seq`).
2. **Кэш последних выданных нод по группам (`last_allocated_by_group: HashMap<GroupId, Vec<CachedAllocation>>`)**:
   - Для каждой группы клиент хранит до 2–3 последних рабочих нод (primary + fallbacks, выданных при прошлых подключениях), зашифрованных на устройстве тем же `storage_key`.
   - Если `anet-auth` недоступен при нажатии «Подключиться», клиент **не падает с ошибкой**, а автоматически переходит в **Cached / Emergency Mode**: подключается к последней кэшированной ноде выбранной группы (с предупреждением в UI/логах, что балансировка временно работает по кэшу).

> **Проблема первого запуска («холодный старт» при бане `anet-auth`):**  
> Если пользователь только скачал приложение и `anet-auth` *уже* забанен в его стране, локального кэша ещё нет. Это решается встроенным/доставленным в ссылке набором **Bootstrap / Emergency зеркал** (см. п. 5.2 и 5.3).

### 5.2. Сценарий 3.1: `anet-auth` жив, но заблокирован в стране (по IP, домену/SNI или DNS)

Замена `A`-записи в DNS помогает только от блокировки по IP, но **не спасает** от блокировки по домену/SNI (ТСПУ) или DNS-спуфинга. Нужен эшелонированный пробив:

1. **Multi-Endpoint + Mirror Failover в `AuthManifest`:**
   - У `anet-auth` в конфиге/манифесте есть список равнозначных URL:
     - основной домен (`https://api.domain-a.tld/...`),
     - альтернативные домены/поддомены-зеркала (`https://cdn-sync.domain-b.tld/...`),
     - обратный прокси за дружественным CDN / Cloudflare / отечественным или нейтральным прокси-релеем (с тем же E2E DH поверх HTTPS — сам CDN/прокси **не видит** содержимого `AuthInnerPayload`!).
   - Запрос к `anet-auth` использует `BrowserProfile` (JA3/JA4 мимикрия + ECH GREASE), а если основной URL дал timeout / TLS RST / DNS error — клиент перебирает зеркала из `auth_manifest`.
2. **DNS-over-HTTPS (DoH) для резолва `anet-auth`:**
   - В `anet-client-core` уже есть DoH (`dev/doh` / `dns_server_list`, `http_help`). При DNS-блокировке домена `anet-auth` клиент должен резолвить домен `anet-auth` не только системным DNS, но и через DoH, а также кэшировать известные IP из `AuthEndpointManifest`.
3. **Стратегия «Сначала туннель — потом Auth» (In-Tunnel Sync):**
   - **Очень важно проверить маршрутизацию!** Сейчас в `anet-client-core/src/client.rs:604-628` адрес сервера правил (`rules_url`) принудительно добавляется в `bypass` (идёт в обход VPN-туннеля).
   - Для `anet-auth` поведение должно быть **умным (Fallback-to-Tunnel)**:
     - При **выключенном VPN**: клиент пробует дотянуться до `anet-auth` напрямую по всем зеркалам. Если все зеркала заблокированы (3.1), но в кэше есть нода (или вшитая/переданная в ссылке bootstrap-нода), клиент **сначала поднимает VPN-туннель на кэшированной ноде**, а затем повторяет `ClientConfigRequest` / `AllocateNodeRequest` **уже через поднятый VPN-туннель** (используя `1.1.1.1` / туннельный DNS)!
     - Если внутри туннеля `anet-auth` выдал **более оптимальную/разгруженную ноду**, клиент может либо остаться на текущей (если она ок и пользователь уже сидит в сети), либо бесшовно переключиться.
     - Когда VPN **уже включён**, запросы к `anet-auth` по умолчанию идут **внутри туннеля**, с fallback в direct только если туннель ещё не готов.
4. **Опционально (уровень Pro): Релей `AllocateNode` / `Config` через любую живую VPN-ноду:**
   - Каждая VPN-нода (`anet-server`) *уже* имеет доверенный канал до `anet-auth` (`auth_servers` + `auth_server_token`).
   - В экстренном случае клиент может передать зашифрованный для `anet-auth` блоб (`AuthEnvelope`) прямо по ASTP-рукопожатию на кэшированную ноду, а нода перешлёт его в `anet-auth` (`POST /api/v1/control/client_relay`) и вернёт зашифрованный ответ назад. Поскольку всё шифровано ключами `Client <-> anet-auth` (DH + `auth_pub_key`), сама нода даже при компрометации не сможет прочитать или подменить `ClientConfigResponse`.

### 5.3. Сценарий 3.2: `anet-auth` упал полностью (DDoS, техработы, потеря ДЦ, смена домена/инфраструктуры)

Если старый `anet-auth` «лёг» физически, а вместе с ним недоступны и все его старые URL:

1. **Работа без `anet-auth` (Graceful Degradation):**
   - За счёт локального кэша (п. 5.1) существующие клиенты продолжают подключаться к последним известным нодам своей группы.
   - На стороне `anet-server` (`anet-server/src/auth_provider.rs`) уже стоит продумать **fail-soft кэш допуска** (или короткий grace-period): сейчас при `check_access` если `auth_servers` недоступны, как ведёт себя `auth_provider.rs`? *(Необходимо явно задокументировать и при необходимости добавить в `anet-server` кэш недавно разрешённых `fingerprint` с коротким TTL, например 12–24 часа, чтобы при падении `anet-auth` живые ноды не отбрасывали легитимных пользователей!)*
2. **Механизм анонса нового адреса `anet-auth` (`SignedAuthManifest`):**
   Чтобы злоумышленник не подсунул фальшивый адрес `anet-auth` (и не украл `config_token` или не отследил клиентов), новый адрес обязан распространяться как **криптографически подписанный манифест**:
   ```rust
   struct AuthEndpointManifest {
       seq: u64,                     // Строго возрастающий номер версии (защита от отката на старый манифест!)
       issued_at: u64,
       expires_at: u64,              // Срок годности манифеста
       endpoints: Vec<String>,       // Новые HTTPS-зеркала anet-auth
       doh_txt_records: Vec<String>, // Резервные домены для опроса TXT-записей (см. ниже)
       dead_drop_urls: Vec<String>,  // Публичные стабильные площадки с зашифрованным/подписанным манифестом
       active_auth_pub_key: [u8; 32],// Позволяет даже сменить auth_signing_key при потере ДЦ!
   }
   struct SignedAuthManifest {
       payload_bytes: Vec<u8>,       // Protobuf-сериализация AuthEndpointManifest
       master_signature: [u8; 64],   // Подпись ХОЛОДНЫМ Master/Root Ed25519 ключом (НЕ лежит на сервере anet-auth!)
   }
   ```
   **Почему подпись именно холодным `master_pub_key`?** Если ДЦ со старым `anet-auth` полностью сгорел или скомпрометирован, администратор с оффлайн-ключа подписывает `AuthEndpointManifest` (с `seq = prev + 1` и новым `active_auth_pub_key`), и все клиенты безоговорочно примут переезд без пересборки приложения.

3. **Каналы доставки нового `SignedAuthManifest`, когда старый `anet-auth` мёртв:**
   Клиент проверяет каналы по приоритету, если все известные `endpoints` недоступны более 2 попыток:
   - **Канал 1 — Push через живые VPN-ноды (самый надёжный!):**  
     Когда админ поднимает новый `anet-auth`, VPN-нодам обновляют `auth_servers` (или ноды сами забирают новый `SignedAuthManifest`). При следующем подключении клиента (в `EncryptedAuthResponse` ASTP-рукопожатия или отдельным управляющим фреймом в туннеле) **нода сама передаёт клиенту свежий `SignedAuthManifest`**. Поскольку манифест подписан холодным `master_key`, клиент проверяет подпись локально и переключается на новый `anet-auth`.
   - **Канал 2 — DNS TXT (через DoH):**  
     Хранение base64-кодированного (или сжатого zstd + base64) `SignedAuthManifest` в `TXT`-записи контрольного домена (или списка резервных доменов), опрашиваемой через DoH (`1.1.1.1`, `8.8.8.8`, `dns.quad9.net`). Работает, если сам DNS-домен не забанен/не разделён.
   - **Канал 3 — Независимые публичные площадки («Dead Drops»):**  
     Статические JSON/бинарные файлы `SignedAuthManifest` (подписанного `master_key`, можно дополнительно шифрованного общим симметричным ключом проекта, чтобы площадки не парсили содержимое) на сторонних трудно-блокируемых платформах (например, GitHub Releases/Raw/Gist, S3-совместимые бакеты, Cloudflare Workers/Pages, Telegraph и т.п.). Клиент проверяет `master_signature` и `manifest.seq > local_manifest_seq` перед применением.

---

## 6. Влияние на клиентские подсистемы (UI, Probe, Failover, CLI, Mobile)

Удаление `[[servers]]` из `ClientConfig` напрямую затрагивает 4 существующих модуля клиента — это нужно учесть в плане заранее:

### 6.1. `NodeProbeMonitor` и `node_selector.rs` (статус и пинг групп в GUI)

- **Сейчас (`anet-common/src/probe_nodes.rs`, `anet-client-core/src/connectivity_monitor.rs`, `anet-client-gui/src/ui/node_selector.rs`):**  
  Клиент раз в несколько секунд запускает `NodeProbeMonitor`, который **напрямую пробирует каждый `[[servers]]`** (QUIC/SSH/VNC/WS/AHTTP/WRTC/IMAP) и рисует зелёный/жёлтый/красный индикатор и RTT (`45 / 22 ms`) на карточке группы в UI.
- **Проблема:** Если в конфиге клиента больше нет `[[servers]]` (ни IP, ни портов, ни `server_pub_key`), клиент не сможет пробировать конкретные ноды до нажатия «Подключиться».
- **Варианты решения:**
  1. **Вариант 1 (рекомендуемый, максимальная скрытность топологии):**  
     До подключения UI показывает **серверную сводку из `GroupSummary`** (зелёный/жёлтый/красный статус `health`, загрузку пула `load_pct`, количество доступных нод без их IP). А реальный сетевой RTT замеряется **после выбора ноды / внутри туннеля** (через `ConnectivityMonitor` и существующий `icmp_probe`) + кэшируется последний известный RTT для данной группы.
  2. **Вариант 2 (опционально — региональный probe-маяк):**  
     Если критично показывать *клиентский* пинг до локаций в списке ещё до коннекта — `GroupSummary` может отдавать 1 обезличенный lightweight echo/TLS-probe endpoint на регион (не являющийся самой VPN-нодой или без выдачи `server_pub_key`/DSN), либо отдавать зашифрованный/обезличенный пинг-целевой хост, но это частично раскрывает IP инфраструктуры и требует осторожности с блокировками. **Оптимально выбрать Вариант 1.**

### 6.2. Цикл переключения нод при обрыве (`AnetClient::start()` в `anet-client-core/src/client.rs`)

- **Сейчас:** `AnetClient::start()` имеет встроенный бесконечный/многошаговый цикл round-robin по `config_clone.servers`. Если нода не отвечает или падает watchdog, цикл просто инкрементирует индекс `idx = (idx + 1) % servers.len()`.
- **Как должно стать:**
  1. `AnetClient` при старте (и при переподключении после обрыва) вызывает **колбэк / провайдер `NodeAllocator`**:
     - Первый шаг: запрос `AllocateNodeRequest(group_id, exclude_server_ids = failed_recently)` к `anet-auth`.
     - Если получены `primary` + `fallbacks`: пытаемся подключиться к `primary`. Если рукопожатие провалилось -> сразу пробуем `fallbacks[0]` (мгновенный локальный failover без ожидания сетевого таймаута auth!), параллельно добавляя упавшую ноду в `exclude_server_ids` (с TTL ~2–5 минут).
     - Если и `fallbacks` провалились -> новый запрос `AllocateNodeRequest` с расширенным `exclude_server_ids`.
     - Если `anet-auth` недоступен -> работа с локальным кэшем `CachedAllocation` + параллельная попытка синхронизации с `anet-auth` уже через поднятый туннель (п. 5.2).

### 6.3. Выравнивание `anet-client-cli` и `anet-mobile`

- В `anet-client-core` стоит вынести единый менеджер `ClientBootstrapService` (или `ConfigSyncManager`):
  - загрузка по `config_url` (`#pk=...`),
  - хранение зашифрованного кэша (`ConfigCacheStore`, абстрагированного трейтом над `DesktopSecureStore` для GUI, файлом/keyring для CLI и SharedPreferences/Keystore для Mobile),
  - DH-сессия с `anet-auth` + `AllocateNode`.
- Тогда `anet-client-cli` получит флаг `--config-url <url>` (и команду `--select-group <name_or_id>`), а `anet-mobile` избавится от дублирования логики загрузки/парсинга TOML на стороне Kotlin/Swift.

### 6.4. Кэш доступа на `anet-server` при падении `anet-auth`

- В `anet-server/src/auth_provider.rs`: проверить и гарантировать, что если `anet-auth` временно недоступен по HTTP (`5xx` / timeout), `anet-server` не отклоняет **уже известных/недавно валидированных** клиентов (кэш `fingerprint -> CachedAccessDecision` с настраиваемым grace-TTL, например 6–24 часа с учётом `expires_at` из последнего ответа `check_access`).

---

## 7. Поэтапный план реализации

### Этап 1. Криптографическое ядро и Protobuf (`anet-common`)
1. В `anet-common/proto/protocol.proto`:
   - Добавить `AuthEnvelope`, `AuthDhInitRequest`, `AuthDhInitResponse`, `AuthEncryptedFrame`, `AuthInnerPayload`, `ClientConfigRequest/Response`, `GroupSummary`, `AllocateNodeRequest/Response`, `AllocatedServerEndpoint`, `AuthEndpointManifest`, `SignedAuthManifest`.
2. Рефакторинг DH / ASTP в `anet-common`:
   - Вынести чистую state-machine `ClientDhInitiator`, `ServerDhResponder`, `AstpEnvelopeCipher`, `build_dh_transcript` (с `domain_tag`) и проверки временного окна.
   - Перевести `anet-server/src/auth_handler.rs` и `anet-client-core/src/auth.rs` на общие примитивы из `anet-common` (проверить, что существующие VPN-подключения работают без изменений протокола).
3. Подключить в `anet-auth/Cargo.toml` зависимости из workspace: `x25519-dalek`, `chacha20poly1305`, `prost` (и `anet-common` с нужными фичами).

### Этап 2. Расширенная телеметрия нод и умный балансировщик (`anet-server`, `anet-auth`, `anet-webui`)
1. На `anet-server`:
   - Реализовать сборщик метрик (`cpu_usage_pct`, `cpu_cores`, `load_avg_1m`, `ram_used/total`, `net_rx/tx_mbps`, `net_capacity_mbps`, `os_uptime_seconds`) с EMA-сглаживанием и чтением `nic_capacity_mbps` / `wan_interface` из конфига.
   - Расширить `NodeHeartbeatRequest` в `anet-common/src/dto.rs`.
   - Добавить в `AuthProvider` локальный grace-кэш на случай кратковременного падения `anet-auth`.
2. На `anet-auth`:
   - Добавить SeaORM-миграцию для `node_runtime_states` (новые поля CPU/RAM/LAN/`load_score`).
   - Обновить `/api/v1/control/nodes/heartbeat` для сохранения и EMA-сглаживания метрик в памяти и БД.
   - Обновить `anet-auth/src/balancer.rs`: добавить стратегию `smart_load` (admission filter + композитная формула LAN/CPU/RAM/Conns + `pending_leases` + учёт `exclude_server_ids`).
3. На `anet-webui`:
   - Отобразить CPU %, RAM, LAN RX/TX Mbps и `load_score` в `Overview.vue`, `Servers.vue`, и выбор стратегии `smart_load` в `Pools.vue` / `PoolModal.vue`.

### Этап 3. Новый защищённый протокол `anet-auth` (`Client <-> anet-auth`)
1. Добавить генерацию/хранение конфигурации `auth_signing_key` (Ed25519) в `anet-auth` (и поддержку `master_pub_key` + загрузку/выдачу подписанного `SignedAuthManifest` через админку/конфиг).
2. Реализовать HTTPS-эндпоинт `POST /api/v1/client/exchange` (и алиасы, маскируемые под телеметрию) с хранением короткоживущих DH-сессий (`DashMap<[u8; 16], AuthHttpSession>`).
3. Реализовать внутри защищённого канала обработчики:
   - `ClientConfigRequest` -> выдаёт шаблон конфига **без `[[servers]]`**, список `GroupSummary[]`, `SignedAuthManifest`, статус подписки/лимитов.
   - `AllocateNodeRequest` -> проверяет доступность пользователя (активен, не истёк, не исчерпан трафик), проверяет права пользователя на выбранную `group_id` (`node_pool`), вызывает `balancer::select_nodes(...)` с учётом `exclude_server_ids`, резервирует `pending_lease`, возвращает `primary` + `fallbacks` с `server_pub_key` каждой ноды.
4. Реализовать формат ссылки конфига с `#pk=<auth_pub_key>` (и поддержку генерации таких ссылок в WebUI `Users.vue`).
5. *(Опционально / Phase 3.5)*: добавить proxy-relay метод `POST /api/v1/control/client_relay` для проброса `AuthEnvelope` через живую VPN-ноду.

### Этап 4. Клиентское ядро, кэширование и отказоустойчивость (`anet-client-core`, `gui`, `cli`, `mobile`)
1. В `anet-client-core`:
   - Реализовать `AuthApiClient` (DH-инициализация по `auth_pub_key`, кэширование `session_id`, Protobuf over HTTPS через `BrowserProfile`, failover по зеркалам из `AuthEndpointManifest` и DoH-резолв).
   - Перенести и расширить `EncryptedConfigBundle` в `anet-client-core`: хранить базовый конфиг, список групп, `SignedAuthManifest` и `last_allocated_by_group`.
   - Обновить `CoreConfig::sanitize()` для поддержки групповых конфигов без `[[servers]]`.
   - Обновить `AnetClient` для работы через `NodeAllocator` (динамический запрос ноды перед подключением, мгновенный локальный failover на `fallbacks`, повторный запрос с `exclude_server_ids`, откат на кэш при недоступности `anet-auth`, возможность синхронизации `AuthApiClient` и проверки `dead_drop_urls` / DNS TXT поверх поднятого туннеля).
   - Поддержать доставку `SignedAuthManifest` внутри ASTP-сессии от ноды (Push-канал при переезде `anet-auth`).
2. В `anet-client-gui`:
   - Перевести `node_selector.rs` для групповых конфигов на отображение `GroupSummary` (онлайн-статус, нагрузка пула, доступность) и последнего замеренного RTT внутри туннеля, без прямого пробирования скрытых IP всех нод.
   - Показывать понятный индикатор режима работы при отказе `anet-auth` (например, *«Автономный режим: подключение по кэшу»*).
3. В `anet-client-cli` и `anet-mobile`:
   - Добавить CLI-аргументы `--config-url` и `--group` с использованием общего `ClientBootstrapService` и локального зашифрованного кэша.
   - Обновить FFI в `anet-mobile/src/lib.rs` для работы с групповым конфигом и динамической аллокацией ноды.

---

## 8. Открытые вопросы и решения для согласования

1. **Переключаемость и обратная совместимость старых конфигов:**  
   Оставляем ли старый `GET /api/v1/config/:id` на переходный период (пока не обновятся все мобильные и десктопные клиенты), или добавляем версию протокола `v2` / query-параметр, а `client_template.toml` без `[[servers]]` отдаём только новым клиентам через новый DH+Protobuf канал?  
   *Рекомендация:* оставить старый `GET /api/v1/config/:id` как legacy (с возможностью отключить флагом в настройках безопасности панели, когда парк клиентов обновится), а новым клиентам выдавать ссылки для DH+Protobuf обмена.
2. **Анонимность `config_token` vs регистрация ключей на клиенте:**  
   В перспективе для полной защиты от утечки клиентского `private_key` даже при компрометации БД `anet-auth`, стоит рассмотреть генерацию `Ed25519`-пары прямо на устройстве клиента при первом вводе invite-токена (чтобы `private_key` вообще никогда не передавался по сети и не хранился в БД панели). Для первой итерации в данном плане сохранена текущая модель (ключ выдаётся при `bootstrap_mode = true` внутри DH-защищённого канала), чтобы не ломать существующую БД пользователей и миграции.
3. **Политика «прилипания» сессий (Sticky vs Dynamic):**  
   Если пользователь переподключается вручную в той же группе через 10 секунд, должен ли балансировщик пересаживать его на другую ноду или стараться удерживать на той же (если она не перегружена) до смены группы/отказа?  
   *Рекомендация:* использовать `least_load` без жёсткого sticky при каждом новом старте VPN, но при кратком сетевом реконнекте внутри активного туннеля (`watchdog` в `AnetClient`) пробовать текущую ноду 1 раз, и только при неудаче запрашивать новую через `AllocateNode` с `exclude_server_ids`.
4. **Master/Root ключ для `SignedAuthManifest`:**  
   Готов ли процесс генерации отдельного оффлайн-ключа (`anet-keygen` уже есть в workspace!) и вшивание его публичной части в клиентские сборки, чтобы переезд `anet-auth` работал даже при полной потере сервера панели?
