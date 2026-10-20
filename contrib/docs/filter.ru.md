# Техническое задание: Smart DNS, Geo-Routing и AdBlock для ANet VPN

Документация актуальна для ветки `dev/filter` (ANet v0.7.0+).  
Статус: **Реализовано (Implemented & Verified in `dev/filter`)**.

---

## 1. Обзор (Overview)

### 1.1. Цель
Внедрение в экосистему ANet высокопроизводительной системы раздельного туннелирования (**Split Tunneling**) по доменным именам (**GeoSite**) и IP-адресам/сетям (**GeoIP**), а также фильтрации нежелательного трафика и рекламы (**AdBlock**) на уровне DNS.

### 1.2. Ограничения и граничные условия
1. **Экстремально низкое потребление ОЗУ и CPU на клиентах**:
   - Клиентская кодовая база работает на широком спектре устройств: от мощных десктопов до слабых Android TV приставок и бюджетных смартфонов с ограниченными ресурсами (512 МБ – 1 ГБ ОЗУ).
   - Недопустимо хранить миллионы текстовых строк в оперативной памяти или выполнять регулярные выражения (regex) на каждый пакет.
2. **Отсутствие SSL/TLS MITM**:
   - Никакой подмены сертификатов и расшифровки TLS-трафика.
   - Инспекция трафика и принятие решений осуществляются строго на уровнях **L3/L4** (IP, TCP/UDP) и **L7 DNS** (порт 53).
3. **Мгновенный старт клиента (Zero Cold Start Delay)**:
   - Старт туннеля не должен блокироваться на парсинг многомегабайтных текстовых файлов со списками доменов и CIDR.
   - Клиент должен быть готов к маршрутизации трафика за единицы миллисекунд после запуска.

### 1.3. Архитектурный подход: Offloaded Heavy Lifting & Zero-Copy
Вся «тяжелая» работа выносится на управляющий бэкенд (`anet-auth`):
- Скачивание сырых списков правил (MetaCubeX, Anti-AD, custom community lists).
- Валидация, дедупликация, нормализация доменов и IP-подсетей с сохранением нормализованных элементов в таблицу кэша `rule_provider_items` для аудита и инспекции через WebUI.
- Включение правил провайдеров (с глобальным действием или переопределением внутри маршрутной карты `route_rules`) и администраторских списков исключений (`custom_block`, `custom_direct`, `custom_proxy`).
- Защита системных доменов проверки связности (`CAPTIVE_PORTAL_DOMAINS`) и блокировка публичных DoH-резолверов (`DEFAULT_DOH_DOMAINS`).
- Построение эффективных структур поиска: **инвертированного префиксного дерева (Domain Trie)** и **Radix Trie (LPM)**.
- Компиляция и бинарная упаковка в специализированный формат `.abc` (**ANet Binary Cache**) с использованием Zero-copy фреймворка `rkyv`.

Клиент (`anet-client-core`):
- Скачивает бинарный слепок `.abc` по HTTP (`GET /api/v1/routing/compiled`) с поддержкой `ETag` / `If-None-Match`.
- Отображает файл в память через системный вызов `mmap` (`memmap2`).
- Применяет локальные пользовательские исключения (Client Overrides) с наивысшим приоритетом.
- Выполняет поиск соответствий напрямую по отображенной памяти без единой аллокации строк или векторов в куче.

---

## 2. Сквозная архитектурная схема

```text
+----------------------------------------------------------------------------------------------------+
|                                    БЭКЕНД УПРАВЛЕНИЯ (anet-auth)                                   |
|                                                                                                    |
|  [ Внешние провайдеры ]      [ Web UI: Администратор ]                                             |
|  (MetaCubeX, Anti-AD)        - Провайдеры (Action: Block/Direct/Proxy + инспекция кэша в БД)       |
|           |                  - Маршрутные карты (привязка провайдеров и доменных правил)           |
|           |                  - Пользовательские правила (custom_block / custom_direct / proxy)     |
|           |                          |                                                             |
|           +----------> [ Background Fetcher & Compiler ] <-----------------------------------------+
|                                      |                                                             |
|                       1. Парсинг, дедупликация, нормализация -> БД (rule_provider_items)           |
|                       2. Базовые правила DoH + защита Captive Portal                               |
|                       3. Наложение правил RouteMap и Custom Overrides администратора               |
|                       4. Построение Domain Trie & Radix LPM                                        |
|                       5. rkyv-сериализация -> rules.abc (глобальный и по route_map_id)             |
|                       6. Генерация ETag (SHA-256)                                                  |
|                                      |                                                             |
|                                      v                                                             |
|                            [ Local Storage / Memory ]                                              |
|                                      |                                                             |
|                                      v                                                             |
|              REST API: GET /api/v1/routing/compiled[?route_map_id=...] (ETag)                      |
+--------------------------------------|-------------------------------------------------------------+
                                       | HTTP (mmap update)
                                       v
+----------------------------------------------------------------------------------------------------+
|                                      КЛИЕНТ (anet-client-core)                                     |
|                                                                                                    |
|  [ Rule Updater ] ---- (ETag check) ----> [ rules.abc на диске ]                                    |
|                                                    | (mmap)                                        |
|                                                    v                                               |
|  [ client.toml: Local Overrides ] ----> [ Decision Engine ] <--- [ CompiledRoutingCache (.abc) ]   |
|  (Приоритет: Local > Admin > Default)              |                                               |
|                                                    +---------------------------+                   |
|                                                    |                           |                   |
|  [ ОС TUN / WinDivert ]                            v (Domain Lookup)           v (IP LPM Lookup)   |
|           |                             [ DnsInterceptor ]             [ PacketRouter ]            |
|           |                                    |                               |                   |
|           +--- (UDP :53 DNS Query) ----------->|                               |                   |
|           |                                    |-- Canary --> NXDOMAIN         |                   |
|           |                                    |              (use-app-dns)    |                   |
|           |                                    |-- Block  --> Синтетич. ответ  |                   |
|           |                                    |              (0.0.0.0 / ::)   |                   |
|           |                                    |              + L3/L4 Checksum |                   |
|           |                                    |-- Direct --> Прямой резолв    |                   |
|           |                                    |              + DirectIpCache -+                   |
|           |                                    |-- Proxy  --> Туннельный DNS   |                   |
|           |                                                                    |                   |
|           +--- (TCP/UDP Data Packet) ----------------------------------------->|                   |
|                                                                                |-- Direct -> Bypass|
|                                                                                |-- Proxy  -> VPN   |
|                                                                                |-- Block  -> Drop  |
+----------------------------------------------------------------------------------------------------+
```

---

## 3. Бэкенд (`anet-auth`) — Компилятор правил и управление

Модуль отвечает за сбор текстовых списков, кэширование разобранных элементов в БД для прозрачного аудита, обработку администраторских исключений, слияние в соответствии с политиками маршрутизации и компиляцию бинарных артефактов `.abc`.

### 3.1. Схема базы данных (SeaORM)

#### Сущность `RuleProvider` (`rule_providers`)
Хранит источники правил (внешние URL), действие по умолчанию для данного списка и опциональную привязку к маршрутной карте:
```rust
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "rule_providers")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub provider_type: ProviderType, // DomainList | IpList
    pub format: ProviderFormat,      // PlainText | V2RayDomain | CidrList
    pub action: ProviderAction,      // Block | Direct | Proxy
    pub route_map_id: Option<Uuid>,  // None = глобально для всех профилей
    pub url: String,
    pub update_interval_hours: i32,
    pub last_fetched_at: Option<DateTime>,
    pub last_etag: Option<String>,
    pub item_count: i64,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum ProviderType {
    #[sea_orm(string_value = "domain")]
    DomainList,
    #[sea_orm(string_value = "ip")]
    IpList,
}

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum ProviderFormat {
    #[sea_orm(string_value = "plain")]
    PlainText,
    #[sea_orm(string_value = "v2ray")]
    V2RayDomain,
    #[sea_orm(string_value = "cidr")]
    CidrList,
}

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum ProviderAction {
    #[sea_orm(string_value = "block")]
    Block,
    #[sea_orm(string_value = "direct")]
    Direct,
    #[sea_orm(string_value = "proxy")]
    Proxy,
}
```

#### Сущность кэша элементов провайдера `RuleProviderItem` (`rule_provider_items`)
Хранит распарсенные и нормализованные правила каждого провайдера в базе данных. Это позволяет администратору в WebUI просматривать, какие именно домены и подсети были загружены при принудительном или фоновом обновлении провайдера, а также пересобирать `.abc` без повторного обращения к внешним URL:
```rust
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "rule_provider_items")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub provider_id: Uuid,
    pub position: i32,
    pub raw_value: String,
    pub normalized_value: String,
    pub item_type: String, // "domain_exact", "domain_suffix", "ip_cidr"
    pub match_subdomains: bool,
    pub created_at: DateTime,
}
```

#### Расширение сущностей маршрутизации (`route_rules` и `admin_custom_overrides`)
В таблицу `route_rules` добавлена поддержка привязки к `rule_provider_id` и типам правил `rule_provider` / `domain` с действиями `direct`, `tunnel`/`proxy` и `block`, а также создана сущность администраторских ручных исключений `admin_custom_overrides`:

```rust
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "route_rules")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub route_map_id: Uuid,
    pub position: i32,
    pub match_type: String, // "cidr", "application", "rule_provider", "domain"
    pub match_value: String, // Значение или UUID rule_provider
    pub rule_provider_id: Option<Uuid>,
    pub action: String,     // "direct", "tunnel" / "proxy", "block"
}

/// Администраторские исключения в БД
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "admin_custom_overrides")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub route_map_id: Option<Uuid>, // None = глобально для всех
    pub rule_type: OverrideType,    // Domain | SubdomainWildcard | IpNet
    pub pattern: String,            // например, "corp.internal", "192.168.0.0/16"
    pub category: OverrideCategory, // custom_block | custom_direct | custom_proxy
    pub comment: String,
    pub is_active: bool,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum OverrideType {
    #[sea_orm(string_value = "domain")]
    Domain,
    #[sea_orm(string_value = "wildcard")]
    SubdomainWildcard,
    #[sea_orm(string_value = "cidr")]
    IpNet,
}

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum OverrideCategory {
    #[sea_orm(string_value = "block")]
    CustomBlock,
    #[sea_orm(string_value = "direct")]
    CustomDirect,
    #[sea_orm(string_value = "proxy")]
    CustomProxy,
}
```

### 3.2. Административные возможности в WebUI (`anet-webui`)
В панели управления администратор получает полный цикл управления фильтрацией и маршрутизацией:
- **Управление провайдерами списков (вкладка `Rule Providers`)**:
  - Добавление и редактирование внешнего списка с указанием **действия (`Action`: `Block / AdBlock`, `Direct / Bypass`, `Proxy / VPN`)** и **области применения (`Scope`: глобально или для конкретной `Route Map`)**.
  - Принудительное обновление кэша кнопкой **Fetch Now** (`POST /api/v1/rule-providers/:id/fetch`), при котором список скачивается, парсится, сохраняется в таблицу `rule_provider_items` и немедленно перекомпилирует бинарный кэш `.abc`.
  - **Инспектор закешированных данных (`View Cached Items`)**: модальное окно с пагинацией и поиском (`GET /api/v1/rule-providers/:id/items`), отображающее точное количество правил, исходную строку (`raw_value`), нормализованное значение (`normalized_value`), тип (`domain_exact`, `domain_suffix`, `ip_cidr`) и область совпадения (`*.subdomains` или `exact`).
- **Интеграция провайдеров и доменов в Маршрутные карты (`Route Maps` / `RouteMapModal`)**:
  - Внутри любой маршрутной карты администратор может добавлять правила типов `CIDR`, `Application`, **`Rule Provider`** (выбор из списка провайдеров) и **`Domain`** с индивидуальным действием для этой карты (`Direct`, `Tunnel / Proxy`, `Block / AdBlock`).
- **Интерактивные Custom Overrides (вкладка `Custom Overrides`)**:
  - Быстрое добавление единичных доменов, wildcard-масок или подсетей в категории `custom_block`, `custom_direct`, `custom_proxy` (глобально или для выбранной маршрутной карты).
- Администраторские исключения имеют наивысший приоритет среди серверных правил: при компиляции они накладываются поверх списков провайдеров и правил маршрутной карты, переопределяя конфликтующие узлы дерева.

### 3.3. Фоновый воркер (`RuleCompilerService`)
Фоновая служба `RuleCompilerService` запускается внутри процесса `anet-auth`:
1. **Планировщик скачивания и кэширования в БД**:
   - Регулярно опрашивает `rule_providers`, у которых истек `update_interval_hours` (или по сигналу `POST /rule-providers/:id/fetch`).
   - Выполняет HTTP GET с поддержкой заголовка `If-None-Match`.
   - В случае `304 Not Modified` (при наличии уже сохраненных записей в `rule_provider_items`) обновляет `last_fetched_at`.
   - При получении нового списка парсит правила, нормализует их и сохраняет батчами по 500 записей в таблицу `rule_provider_items` внутри транзакции.
2. **Стриминговый парсинг и нормализация**:
   - Построчное чтение с отсечением комментариев (`#`, `//`, `;`) и поддержкой форматов `hosts` (`0.0.0.0 domain`, `127.0.0.1 domain`), AdGuard (`||domain^`) и Clash/V2Ray (`+.`, `*.`, `domain:`, `full:`, `DOMAIN-SUFFIX,`, `DOMAIN,`, `IP-CIDR,`).
   - Для доменов: приведение к нижнему регистру (ASCII), разделение на *точное совпадение* (`domain_exact`) или *по всем поддоменам* (`domain_suffix`).
   - Для IP-адресов: парсинг одиночных адресов `/32` (IPv4), `/128` (IPv6) и подсетей CIDR (`ipnet::IpNet`).
3. **Наложение правил и построение структур**:
   - В базовый слой включаются известные DoH-резолверы (`DEFAULT_DOH_DOMAINS` $\to$ `Block`).
   - Накладываются элементы из `rule_provider_items` с действием провайдера (`provider.action`).
   - Накладываются правила конкретной маршрутной карты из `route_rules` (включая переопределение действия для подключенных `rule_provider` и правил `domain`/`cidr`).
   - Накладываются записи из `admin_custom_overrides` (наложение с заменой терминального действия).
   - Применяется защита системных доменов проверки доступности интернета (`CAPTIVE_PORTAL_DOMAINS`), гарантирующая, что они никогда не блокируются AdBlock-списками.
4. **Компиляция и кэширование**:
   - При любом изменении провайдеров, `route_rules` или `admin_custom_overrides` перекомпилируется глобальный артефакт `rules.abc` и индивидуальные слепки для активных маршрутных карт.
   - Генерируется хэш SHA-256 содержимого бинарного файла, служащий `ETag`.

### 3.4. REST API для клиентов
Эндпоинт является публичным (аутентификация не требуется), что позволяет клиентам скачивать и обновлять правила автономно, а также кэшировать их на уровне CDN/Edge прокси.

- **Маршрут**: `GET /api/v1/routing/compiled` (или с параметром профиля: `GET /api/v1/routing/compiled?route_map_id=<UUID>`)
- **Аутентификация**: Отсутствует (публичный доступ в `ApiKeyMiddleware`).
- **Заголовки запроса**:
  - `If-None-Match: "<ETag>"`
- **Поведение сервера**:
  - Если переданный `ETag` совпадает с текущим: `304 Not Modified`.
  - Если правила изменились или это первичный запрос: `200 OK`, `Content-Type: application/octet-stream`, `ETag: "<SHA256>"`, тело ответа — бинарные байты `.abc`.

---

## 4. Пользовательские исключения (Custom Overrides): Двухуровневая модель

Система поддерживает разделение ответственности между администратором сети и конечным пользователем.

### 4.1. Иерархия приоритетов правил
При проверке любого домена или IP-адреса клиент применяет строгий каскад приоритетов (от высшего к низшему):

```text
+-----------------------------------------------------------------------+
|  1. Canary Domains (Вшитые служебные правила: use-application-dns.net)|
+-----------------------------------------------------------------------+
                                   | не совпало
                                   v
+-----------------------------------------------------------------------+
|  2. Локальные исключения пользователя (client.toml / Local UI)        |
|     [routing.overrides] block / direct / proxy                        |
+-----------------------------------------------------------------------+
                                   | не совпало
                                   v
+-----------------------------------------------------------------------+
|  3. Администраторские исключения сервера (Запечены в rules.abc)       |
|     admin_custom_overrides (custom_block, custom_direct, custom_proxy)|
+-----------------------------------------------------------------------+
                                   | не совпало
                                   v
+-----------------------------------------------------------------------+
|  4. Внешние списки провайдеров (Запечены в rules.abc)                 |
|     MetaCubeX, Anti-AD, GeoSite, GeoIP                                |
+-----------------------------------------------------------------------+
                                   | не совпало
                                   v
+-----------------------------------------------------------------------+
|  5. Действие по умолчанию (default_action: Proxy или Direct)          |
+-----------------------------------------------------------------------+
```

### 4.2. Локальная конфигурация конечного пользователя (`client.toml`)
Конечный пользователь может переопределить любое решение без обращения к администратору:
```toml
# Секция локальных исключений пользователя в client.toml
[routing.overrides]
# Домены и CIDR, которые блокируются локально (заглушка 0.0.0.0)
block = [
    "metrics.local-telemetry.com",
    "adservice.internal",
    "198.51.100.0/24"
]

# Домены и CIDR, которые идут строго мимо VPN (Direct Split-Tunneling)
direct = [
    "*.home.arpa",
    "router.lan",
    "workstation.local",
    "192.168.1.0/24",
    "10.0.0.0/8"
]

# Домены и CIDR, которые принудительно направляются в VPN-туннель (Proxy)
proxy = [
    "blocked-developer-portal.dev",
    "specific-restricted-api.io"
]
```

#### Реализация на клиенте:
- При запуске клиента `client.rs` компилирует эти списки в легковесную in-memory структуру `LocalOverrides` (на базе `ahash::HashSet<String>` для точных доменов, небольшого суффиксного дерева для wildcard-доменов и массива `ipnet::IpNet`).
- Проверка в `LocalOverrides` выполняется **до** обращения к `mmap`-кэшу `rules.abc`.

---

## 5. Канареечные домены (Canary Domains) и обход DoH

### 5.1. Проблема браузерного DoH (DNS-over-HTTPS)
Современные браузеры (Firefox, Google Chrome, Microsoft Edge) по умолчанию включают DoH (Secure DNS) через Cloudflare или Google. При включенном DoH:
- Запросы браузера уходят по протоколу HTTPS (порт 443 TCP), минуя системный порт UDP 53.
- Внутренний DNS-перехватчик ANet теряет возможность анализировать запрашиваемые домены.
- Как следствие, для этих доменов перестает работать AdBlock и динамическое добавление IP в `DirectIpCache` для Split Tunneling.

### 5.2. Обработка DoH Canary Domains
`DnsInterceptor` перехватывает специальные канареечные домены и возвращает ожидаемые кодовые ответы для принудительного возврата браузера на классический системный DNS:

1. **Mozilla Firefox Canary (`use-application-dns.net`)**:
   - Согласно спецификации Mozilla DoH, перед включением DoH браузер делает регулярный DNS-запрос на порт 53 к `use-application-dns.net`.
   - Если DNS-сервер возвращает **NXDOMAIN** (или SERVFAIL), Firefox считает, что локальная сеть использует специфические политики родительского контроля/фильтрации, и **автоматически отключает DoH**, возвращаясь к обычному DNS (UDP:53).
   - **Реализация в ANet**: перехватчик жестко перехватывает `use-application-dns.net` и мгновенно возвращает DNS-ответ с флагом `RCODE = 3 (NXDOMAIN)`.

2. **Блокировка прямых DoH резолверов**:
   - В списки блокировки по умолчанию (`rules.abc`) включаются известные DoH-эндпоинты:
     * `cloudflare-dns.com`
     * `dns.google`
     * `dns.quad9.net`
     * `doh.opendns.com`
   - При попытке браузера разрешить имя DoH-сервера через системный DNS он получает `0.0.0.0`, что заставляет сетевой стек браузера откатиться на стандартный локальный резолвер.

### 5.3. Служебные домены проверки доступности (Captive Portal & Probes)
Некоторые системные домены требуют деликатной обработки, чтобы ОС не выдавала ложное уведомление «Подключение к интернету ограничено»:
- `connectivitycheck.gstatic.com` (Android/ChromeOS)
- `msftconnecttest.com` (Windows)
- `captive.apple.com` (iOS / macOS)
- `detectportal.firefox.com` (Firefox)

Для этих доменов перехватчик гарантирует:
- При наличии активного туннеля — резолвятся штатно через режим `Proxy` (или `Direct` при авторизации в публичном Wi-Fi).
- Блокировка AdBlock на них **никогда не применяется**.

---

## 6. Спецификация бинарного формата `.abc` (ANet Binary Cache)

Формат `.abc` спроектирован для мгновенной валидации и прямого отображения через `mmap` без промежуточных аллокаций.

### 6.1. Модель данных (rkyv)

```rust
use rkyv::{Archive, Deserialize, Serialize};

/// Корневой контейнер скомпилированных правил (.abc)
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)]
pub struct CompiledRoutingCache {
    /// Магическое число 'ABC1' (0x31434241)
    pub magic: u32,
    /// Версия формата схемы (1)
    pub schema_version: u32,
    /// Временная метка сборки (Unix Timestamp Seconds)
    pub created_at: u64,
    /// Дефолтное действие для не совпавших запросов
    pub default_action: RuleAction,
    /// Дерево поиска доменных имен (Reversed Domain Trie)
    pub domain_trie: DomainTrie,
    /// Таблица подсетей (Radix Tree Longest Prefix Match)
    pub ip_table: IpRoutingTable,
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[archive(check_bytes)]
#[repr(u8)]
pub enum RuleAction {
    Proxy = 0,
    Direct = 1,
    Block = 2,
}

/// Инвертированное дерево меток домена
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq, Default)]
#[archive(check_bytes)]
pub struct DomainTrie {
    pub root_nodes: rkyv::vec::ArchivedVec<TrieNode>,
}

#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)]
pub struct TrieNode {
    /// Метка уровня домена (например, "com", "google", "analytics")
    pub label: rkyv::string::ArchivedString,
    /// Действие для данного узла (если узел терминальный)
    pub terminal_action: Option<RuleAction>,
    /// Распространяется ли действие на все поддомены данного уровня
    pub match_subdomains: bool,
    /// Дочерние узлы (следующие метки домена справа-налево)
    pub children: rkyv::vec::ArchivedVec<TrieNode>,
}

/// Таблица префиксов IP-сетей
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq, Default)]
#[archive(check_bytes)]
pub struct IpRoutingTable {
    pub ipv4_nodes: rkyv::vec::ArchivedVec<RadixNodeV4>,
    pub ipv6_nodes: rkyv::vec::ArchivedVec<RadixNodeV6>,
}

#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)]
pub struct RadixNodeV4 {
    pub prefix: u32,
    pub prefix_len: u8,
    pub action: RuleAction,
}

#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)]
pub struct RadixNodeV6 {
    pub prefix: [u8; 16],
    pub prefix_len: u8,
    pub action: RuleAction,
}
```

### 6.2. Свойства и гарантии формата
1. **Magic Header**: первые 4 байта строго `0x41, 0x42, 0x43, 0x31` (`ABC1`).
2. **Zero Allocations**: После `mmap` клиент вызывает `rkyv::archived_root::<CompiledRoutingCache>(&mapped_bytes)`. Указатель напрямую смотрит на страницы памяти ОС.
3. **Безопасность памяти**: Метод `check_archived_root` проверяет корректность границ, выравнивания (alignment) и отсутствие некорректных указателей за один быстрый линейный проход.
4. **Кэш-локальность**: Узлы упорядочены по вероятности совпадения (популярные TLD в начале списков `children`).

---

## 7. Пересчет контрольных сумм в TUN (Checksums Calculation)

При генерации синтетических DNS-ответов (`Block` $\to$ `0.0.0.0` / `Canary` $\to$ `NXDOMAIN`) инжектор пакетов формирует ответный IP/UDP пакет прямо в пространстве пользователя. 

Сетевые стеки операционных систем (в особенности Windows WFP/NDIS, Linux conntrack и BSD/macOS) немедленно отбрасывают входящие в TUN/TAP пакеты, если нарушена хотя бы одна контрольная сумма заголовка или полезной нагрузки.

```text
+-------------------------------------------------------------------------+
|                  Структура синтетического пакета DNS                    |
|                                                                         |
|  [ IPv4 Header (20 байт) ]      -> Пересчет IPv4 Header Checksum        |
|  [ UDP Header (8 байт) ]        -> Пересчет UDP Checksum (Псевдозаголовок)|
|  [ DNS Payload (Ответ) ]        -> Включается в расчет UDP Checksum     |
+-------------------------------------------------------------------------+
```

### 7.1. Контрольная сумма заголовка IPv4 (RFC 791, RFC 1071)
Заголовок IPv4 защищен 16-битным сложением с дополнением до единицы (Internet Checksum):
1. Поле `header_checksum` (смещение +10 в заголовке IPv4) обнуляется: `pkt[10..12] = [0, 0]`.
2. Все 16-битные слова 20-байтного заголовка суммируются в 32-битный аккумулятор:
   $$\text{Sum} = \sum_{i=0}^{9} \text{Word}_{i}$$
3. Старшие 16 бит складываются с младшими до тех пор, пока сумма не уместится в 16 бит (folding):
   $$\text{Sum} = (\text{Sum} \gg 16) + (\text{Sum} \& 0xFFFF)$$
4. Берется побитовая инверсия:
   $$\text{Checksum} = \sim \text{Sum}$$
5. Полученное значение записывается в сетевом порядке байт (Big-Endian).

### 7.2. Контрольная сумма UDP для IPv4 (RFC 768)
В отличие от TCP, в IPv4 контрольная сумма UDP может быть `0x0000` (выключена). Однако многие ОС (включая Windows NDIS-драйверы и Android kernel netfilter) отбрасывают локальные DNS-ответы с нулевой чексуммой. ANet производит обязательный честный расчет контрольной суммы UDP.

Алгоритм расчета включает виртуальный **IPv4 Pseudo-Header** (12 байт):
```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source IPv4 Address                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination IPv4 Address                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Zero     |    Protocol   |           UDP Length          |
|      0x00     |    17 (0x11)  |      (Заголовок + Payload)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

1. Складываются 16-битные слова псевдозаголовка.
2. Складываются 16-битные слова заголовка UDP (при этом в самом поле `udp_checksum` временно выставляется `0x0000`).
3. Складываются все слова данных DNS Payload. Если длина данных нечетная, последний байт дополняется нулем в младшем разряде (`byte << 8`).
4. Сумма складывается (fold) до 16 бит и инвертируется.
5. **Важнейшее правило RFC 768**: если вычисленная контрольная сумма получилась равной `0x0000`, она должна быть записана как `0xFFFF` (все единицы), так как значение `0x0000` зарезервировано для обозначения "контрольная сумма не передана".

### 7.3. Обязательная контрольная сумма UDP для IPv6 (RFC 8200)
В IPv6 поле контрольной суммы в заголовке самого IP отсутствует, поэтому контрольная сумма UDP в IPv6 является **строго обязательной** и не может быть отключена:
- Псевдозаголовок IPv6 занимает 40 байт:
  - 16 байт Source IPv6 Address
  - 16 байт Destination IPv6 Address
  - 4 байта UDP Length
  - 3 байта Zero + 1 байт Next Header (17 = UDP)
- Если итоговая сумма равна `0x0000`, она также преобразуется в `0xFFFF`.

### 7.4. Реализация в кодовой базе (Zero-alloc модуль `checksum.rs`)
```rust
/// Вычисление IPv4 Header Checksum
pub fn compute_ipv4_checksum(header: &mut [u8]) {
    header[10] = 0;
    header[11] = 0;
    let mut sum: u32 = 0;
    for i in (0..header.len()).step_by(2) {
        let word = u16::from_be_bytes([header[i], header[i + 1]]);
        sum += word as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    let bytes = checksum.to_be_bytes();
    header[10] = bytes[0];
    header[11] = bytes[1];
}

/// Вычисление UDP Checksum для IPv4
pub fn compute_udp_v4_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], udp_packet: &mut [u8]) {
    udp_packet[6] = 0;
    udp_packet[7] = 0;
    let udp_len = udp_packet.len() as u16;

    let mut sum: u32 = 0;
    // Псевдозаголовок
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += 17u32; // Protocol UDP
    sum += udp_len as u32;

    // UDP заголовок + тело
    let mut i = 0;
    while i + 1 < udp_packet.len() {
        let word = u16::from_be_bytes([udp_packet[i], udp_packet[i + 1]]);
        sum += word as u32;
        i += 2;
    }
    if i < udp_packet.len() {
        sum += (udp_packet[i] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let mut checksum = !(sum as u16);
    if checksum == 0 {
        checksum = 0xFFFF;
    }
    let bytes = checksum.to_be_bytes();
    udp_packet[6] = bytes[0];
    udp_packet[7] = bytes[1];
}
```

---

## 8. Клиент (`anet-client-core`) — Архитектура и цикл обработки

### 8.1. Менеджер обновлений (`RuleUpdater`)
- **Неблокирующая инициализация**:
  - При вызове `AnetClient::start()` немедленно загружается локальный файл `cache/rules.abc` (если существует).
  - В фоновом `tokio`-таске инициируется сетевой запрос к `anet-auth`.
  - При получении `304 Not Modified` фоновый таск завершается.
  - При получении `200 OK`:
    1. Ответ сохраняется во временный файл `rules.abc.tmp`.
    2. Выполняется валидация целостности (`rkyv::check_archived_root`).
    3. Атомарное переименование `rules.abc.tmp` $\to$ `rules.abc`.
    4. Атомарное обновление указателя `Arc<ArcSwap<MmapRuleCache>>` в рантайме без перезапуска VPN-сессии.

### 8.2. Внутренний DNS-перехватчик (`DnsInterceptor`)
Интегрируется напрямую в цикл чтения пакетов из интерфейса (`tun_rx` / `WinDivert`):

```text
               Входящий IP-пакет из TUN (rx_from_tun)
                                 |
                                 v
                     [ Проверка IPv4/IPv6 ]
                                 |
                  +--------------+--------------+
                  |                             |
             [ Не UDP ]                  [ UDP пакет ]
                  |                             |
                  |                +------------+------------+
                  |                |                         |
                  |         [ Dst Port != 53 ]        [ Dst Port == 53 ]
                  |                |                         |
                  v                v                         v
        +----------------------------+             [ DNS Interceptor ]
        |   Обычная обработка L3/L4  |                       |
        |   (Packet Router Engine)   |             1. Парсинг заголовка и QNAME
        +----------------------------+             2. Проверка Local Overrides
                                                   3. Поиск в Domain Trie (.abc)
                                                             |
                 +-------------------+-----------------------+--------------------+
                 |                   |                       |                    |
                 v                   v                       v                    v
          [ Canary Domain ]    [ Rule: Block ]        [ Rule: Direct ]     [ Rule: Proxy ]
                 |                   |                       |                    |
            NXDOMAIN          Синтетический DNS       Прямой DNS-запрос    Форвардинг в туннель
          (use-app-dns)       ответ (0.0.0.0 / ::)    через прямой сокет   на серверный DNS
                 |                   |                       |                    |
                 |            + L3/L4 Checksum        +-> Внести A/AAAA           v
                 |                   |                    в DirectIpCache  Отправка в VPN-транспорт
                 +---------+---------+                       |             (QUIC / WebRTC)
                           |                                 v
                           v                        Отправка ответа в TUN
                    Отправка в TUN                       (tx_to_tun)
                     (tx_to_tun)
```

#### Обработка сценариев DNS:

#### A. Действие `RuleAction::Block` (Блокировка рекламы и трекеров)
1. Пакет перехватывается, запрос в туннель **не уходит**.
2. Извлекаются `DNS Transaction ID` и флаги запроса.
3. Формируется валидный DNS Response:
   - Флаги: `QR = 1`, `RD = 1`, `RA = 1`, `RCODE = 0 (NoError)`.
   - Если запрашивался тип `A`: Answer Resource Record возвращает `0.0.0.0`, TTL = 3600 сек.
   - Если запрашивался тип `AAAA`: Answer Resource Record возвращает `::`, TTL = 3600 сек.
4. Пакет упаковывается в обратный IPv4/UDP-пакет (своп адресов источника и назначения, портов).
5. **Выполняется пересчет контрольных сумм** по алгоритмам из Раздела 7.
6. Пакет инжектируется напрямую в `tx_to_tun`.
7. Клиентское приложение мгновенно получает ответ, не ожидая сетевого таймаута.

#### B. Действие `RuleAction::Direct` (В обход VPN — Split Tunneling по доменам и Wildcard)
1. **Отсечение не-IPv4 типов запросов (`NODATA`)**: если входящий запрос для `Direct`-домена имеет `qtype != 1` (например, `AAAA` (`28`) или `HTTPS/SVCB` (`65`)), `DnsInterceptor` мгновенно возвращает синтетический пустой ответ `NoError (NODATA, ANCOUNT = 0)`. Это гарантирует, что браузер не попытается использовать IPv6 или взять `ipv4hint` из `HTTPS`-записи раньше установки маршрута обхода, а использует стандартную `A`-запись (`qtype = 1`).
2. **Прямой резолв**: для `A`-запроса (`qtype = 1`) клиент выполняет UDP DNS-запрос к выделенным публичным резолверам (`1.1.1.1:53`, `8.8.8.8:53`), чьи `/32` маршруты заранее добавлены в обход туннеля (запрос идет через физический интерфейс и возвращает корректные региональные CDN IP).
3. Из полученного DNS-ответа извлекаются все IP-адреса из секции Answers и их минимальный `TTL`.
4. Извлеченные IP-адреса регистрируются в памяти (`DirectIpCache`) и передаются в `RouteManager::add_bypass_routes`:
   ```rust
   self.direct_cache.insert_batch(&resolved_ips, RuleAction::Direct, Duration::from_secs(min_ttl as u64));
   rm_c.add_bypass_routes(&routes).await;
   ```
5. **Синхронное применение маршрута ДО возврата DNS-ответа**: только после того, как `RouteManager::add_bypass_routes` завершит установку маршрутов обхода в ОС (или горячее обновление `VpnService` на Android), собранный DNS-ответ отправляется обратно приложению через `tx_to_tun`.
6. Приложение начинает устанавливать TCP/UDP-соединение с полученными IP-адресами напрямую через физический сетевой интерфейс.

#### C. Действие `RuleAction::Proxy` (Принудительно через VPN)
1. DNS-запрос транслируется на внутритуннельный защищенный DNS-сервер ANet (или инкапсулируется в туннельный транспорт).
2. Ответ возвращается клиенту через туннель.

---

## 9. Обработка L3/L4 трафика: Движок маршрутизации (`PacketRouter`)

Когда приложение отправляет целевой сетевой трафик (TCP, UDP, ICMP), каждый пакет, пришедший из сетевого стека, проходит проверку назначения:

```text
                           Входящий пакет данных из TUN
                                        |
                                        v
                            Извлечение Destination IP
                                        |
                                        v
                   [ 0. Проверка в Local Overrides (client.toml) ]
                                        |
                         +--------------+--------------+
                         | Совпало                     | Не найдено
                         v                             v
                 [ Local Action ]        [ 1. Динамический DirectIpCache ]
                         |                             |
                         |              +--------------+--------------+
                         |              | Совпало                     | Не найдено
                         |              v                             v
                         |       [ Action: Direct ]      [ 2. Статический LPM Radix ]
                         |              |                [      из rules.abc        ]
                         |              |                             |
                         |              |              +--------------+--------------+
                         |              |              | Найдено                     | Не найдено
                         |              |              v                             v
                         |              |      [ Действие из Trie ]         [ default_action ]
                         |              |              |                             |
                         +--------------+-------+------+-----------------------------+
                                                |
                               +----------------+----------------+
                               |                                 |
                               v                                 v
                  [ Action == Block / Direct ]          [ Action == Proxy ]
                               |                                 |
                    Не пересылать в туннель:               Инкапсуляция:
                    Block — дроп пакета;                   Пакет шифруется и уходит
                    Direct — защита от утечки              в активный VPN-транспорт
                    в туннель (идет мимо TUN)
```

### 9.1. Структура `DirectIpCache`
Кэш хранит маппинг динамически разрешенных IP-адресов на действия:
```rust
use std::net::IpAddr;
use std::time::Instant;
use dashmap::DashMap;

pub struct DirectIpCache {
    entries: DashMap<IpAddr, CacheEntry>,
}

pub struct CacheEntry {
    pub action: RuleAction,
    pub expires_at: Instant,
}

impl DirectIpCache {
    pub fn check(&self, ip: &IpAddr) -> Option<RuleAction> {
        if let Some(entry) = self.entries.get(ip) {
            if Instant::now() < entry.expires_at {
                return Some(entry.action);
            } else {
                drop(entry);
                self.entries.remove(ip);
            }
        }
        None
    }
}
```

### 9.2. Платформенная реализация Split-Tunneling Bypass

Для трафика с действием `Direct` (включая динамические поддомены по правилам `*.domain`) необходимо исключить петли маршрутизации и гарантировать отправку пакетов мимо VPN-туннеля:

1. **Android (`anet-mobile` + `ANetVpnService`)**:
   Так как на Android нет прав `root` для прямого вызова `ip route add`, а `VpnService` управляет маршрутами только через `VpnService.Builder`, реализована двухфазная архитектура с **горячей переконфигурацией TUN (Hot-Swap / Seamless Handover)**:
   - **Инициализация кэша (`connectVpn`)**: при старте JNI автоматически запрашивает у Android-контекста `getCacheDir().getAbsolutePath()` и выставляет `ANET_RULES_CACHE_PATH=<cache_dir>/rules.abc`. `RuleCacheManager` мапит `rules.abc` в память (Zero-Copy `rkyv` с выравниванием страниц) и проверяет `ETag` на сервере.
   - **Быстрый старт (`create_tun`)**: до поднятия `tun0` в `AndroidRouteManager` записываются обязательные `/32` исключения (IP VPN-сервера, IP сервера правил, прямые DNS `1.1.1.1`/`8.8.8.8`, статические CIDR из `rules.abc` и локальные `overrides` из `client.toml`). Дерево доменов на старте не перебирается — туннель поднимается мгновенно.
   - **Подавление системного DoT (порт 853)**: если список `dns_server_list` пуст, в `VpnService.Builder.addDnsServer` передается виртуальный шлюз туннеля (`auth.gateway`, например `10.8.0.1`), чтобы Android не пытался делать 5-секундные попытки подключения по DoT (TCP:853) и сразу отправлял все DNS-запросы в `tun0` по UDP:53.
   - **Коалесцирование и Hot-Swap TUN в рантайме (`ActiveTunSession::rebind_tun`)**:
     1. Когда приложение обращается к домену или любому поддомену wildcard-правила (например, `2ip.io` и `static.2ip.io` по правилу `*.2ip.io -> Direct`), `DnsInterceptor` резолвит их `A`-записи через прямой DNS и вызывает `AndroidRouteManager::add_bypass_routes`.
     2. `add_bypass_routes` ждет окно коалесцирования **15 мс**, объединяя параллельные DNS-ответы со страницы в один пакет маршрутов.
     3. Координатор `spawn_tun_io_worker` получает `TunSwapRequest`, останавливает чтение/запись со старого `AsyncDevice` и освобождает `epoll`-регистрацию старого `fd`, **не закрывая** каналы `mpsc` между ядром VPN и TUN (шифрованная сессия с сервером не прерывается).
     4. Через JNI вызывается `ANetVpnService.configureTun(...)` с дополненным списком `excludeRoutes` (на Android 13+ через нативный `builder.excludeRoute(IpPrefix)`, на более старых версиях — через пересчет `fallbackRoutes`).
     5. В `ANetVpnService.kt` вызывается `builder.establish()`, и только **после** создания нового интерфейса закрывается старый `ParcelFileDescriptor` (**Seamless Handover** в Android: `netd` атомарно обновляет таблицу маршрутизации без разрыва VPN и без коллизии номеров `fd`).
     6. Новый `fd` оборачивается в `AsyncDevice` и передается обратно в `spawn_tun_io_worker`. После паузы **25 мс** (на применение правил в `netd`) DNS-ответ возвращается браузеру в `tun0`.
   - **Защита на уровне пакетов (`should_forward_to_tunnel`)**: если пакет на IP из `DirectIpCache` все же попал в `tun0` в момент переключения маршрутов, `should_forward_to_tunnel` возвращает `false`, не давая соединению уйти в VPN-туннель.

2. **Linux / Windows / macOS (`SystemRouteManager`)**:
   - При старте туннеля и при каждом срабатывании `DnsInterceptor` на `RuleAction::Direct` метод `RouteManager::add_bypass_routes` динамически добавляет `/32` маршруты через физический шлюз по умолчанию (`default_gateway`) в системную таблицу маршрутизации ОС (Netlink на Linux, IP Helper API / `route` на Windows, `route` на macOS) до возврата DNS-ответа приложению.
   - На Windows в режиме `per-app` дополнительно используется `anet-appfilter` (WinDivert).

---

## 10. Жизненный цикл, отказоустойчивость и безопасность

1. **Cold Start при отсутствии интернета**:
   - Клиент обязан запуститься с последней сохраненной версией `rules.abc`.
   - Если файл отсутствует или поврежден, клиент откатывается к режиму `default_action = Proxy` и логирует предупреждение.
2. **Атомарность обновлений**:
   - Запись файла правил всегда ведется в `.tmp` с последующим системным `rename`.
   - Замена ссылки на отображенную память (`mmap`) в работающих тасках происходит атомарно (RCU / ArcSwap).
3. **Предотвращение DNS Leaks**:
   - Все DNS-запросы перехватываются жестко на уровне L3/L4 драйвера (TUN/WinDivert), а оппортунистические DoH/DoT-пакеты к публичным резолверам блокируются (`is_encrypted_dns_packet`).
   - Ни один запрос к внутренним доменам корпоративной сети или заблокированным ресурсам не попадает в открытую сеть без явного правила `Direct`.
4. **Защита от переполнения кэша (DoS)**:
   - `DirectIpCache` имеет верхнюю границу размера (например, 50 000 записей).
   - При достижении лимита выполняется вытеснение по алгоритму LRU / TTL-expired.

---

## 11. План поэтапной реализации (Roadmap)

### Этап 1: Базовый крейт `anet-filter-core`
- [x] Определение структур данных `DomainTrie`, `IpRoutingTable`, `CompiledRoutingCache` с атрибутами `rkyv` (магическое число `ABC1`).
- [x] Алгоритм построения инвертированного Domain Trie с поддержкой администраторских оверрайдов, защитой `CAPTIVE_PORTAL_DOMAINS` и блокировкой `DEFAULT_DOH_DOMAINS`.
- [x] Алгоритм построения Radix Trie (LPM).
- [x] Реализация модуля `checksum.rs` (RFC 791, RFC 768, RFC 8200) с тестами.
- [x] Модульные тесты на проверку сопоставления доменов (точные совпадения, поддомены, wildcard) и сетей (IPv4/IPv6).

### Этап 2: Бэкенд-компилятор в `anet-auth`
- [x] Миграции SeaORM для таблиц `rule_providers`, `rule_provider_items` и `admin_custom_overrides`, модификация `route_rules`.
- [x] Фоновый воркер `RuleCompilerService` (скачивание списков MetaCubeX/AdBlock, нормализация, сохранение элементов в `rule_provider_items`, наложение правил маршрутных карт и оверрайдов, компиляция в `.abc`).
- [x] REST API эндпоинт `GET /api/v1/routing/compiled` (с поддержкой `route_map_id` и валидацией `ETag`) и `GET /api/v1/rule-providers/:id/items` (инспекция кэша).
- [x] Интеграция в `anet-webui`: управление провайдерами с выбором действия (`Block`/`Direct`/`Proxy`), просмотр закешированных элементов провайдера с поиском и пагинацией, подключение провайдеров и доменов в `Route Maps`, добавление `custom_block`, `custom_direct`, `custom_proxy`.

### Этап 3: Клиентский движок в `anet-client-core`
- [x] Поддержка `[routing.overrides]` в `client.toml` для локальных пользовательских правил.
- [x] Менеджер `RuleUpdater` с загрузкой `.abc` и выровненным маппингом через `memmap2` / `AlignedVec`.
- [x] Внутритуннельный парсер и перехватчик `DnsInterceptor` (включая фильтрацию `NODATA` для `AAAA`/`HTTPS` на `Direct`-доменах).
- [x] Обработка Canary Domains (`use-application-dns.net` $\to$ NXDOMAIN).
- [x] Генератор синтетических ответов DNS для `RuleAction::Block` с пересчетом L3/L4 контрольных сумм.
- [x] Модуль `DirectIpCache` для динамического отслеживания ответов резолвера и прямой UDP-резолв `RuleAction::Direct`.
- [x] Маршрутизация исходящих пакетов в цикле туннеля (`client.rs` / `acquire_packet_source`).

### Этап 4: Платформенная интеграция и оптимизация
- [x] Интеграция с `anet-appfilter` (Windows WinDivert direct bypass) и таблицей маршрутизации ОС.
- [x] Интеграция с Android JNI (`ANET_RULES_CACHE_PATH`, `AndroidRouteManager` с коалесцированием и горячим переключением `VpnService` TUN `rebind_tun` без разрыва сессии).
- [x] Интеграция с Linux / macOS / Windows `SystemRouteManager`.
- [ ] Нагрузочное тестирование на реальном трафике (пропускная способность 1+ Gbps, задержка DNS < 0.5 мс, проверка в Wireshark).
