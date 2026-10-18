# Техническое задание: Smart DNS, Geo-Routing и AdBlock для ANet VPN

Документация актуальна для ветки `dev/filter` (ANet v0.7.0+).  
Статус: **Архитектурная спецификация (Approved Implementation Spec)**.

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
- Валидация, дедупликация, нормализация доменов и IP-подсетей.
- Включение администраторских списков исключений (`custom_drop`/`custom_block`, `custom_direct`, `custom_proxy`).
- Построение эффективных структур поиска: **инвертированного префиксного дерева (Domain Trie)** и **Radix Trie (LPM)**.
- Компиляция и бинарная упаковка в специализированный формат `.abc` (**ANet Binary Cache**) с использованием Zero-copy фреймворка `rkyv`.

Клиент (`anet-client-core`):
- Скачивает бинарный слепок `.abc` по HTTP с поддержкой `ETag` / `If-None-Match`.
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
|  (MetaCubeX, Anti-AD)        - Пользовательские правила (custom_block / custom_direct / proxy)     |
|           |                          |                                                             |
|           +----------> [ Background Fetcher & Compiler ] <-----------------------------------------+
|                                      |                                                             |
|                       1. Парсинг, дедупликация и нормализация                                      |
|                       2. Наложение Custom Overrides администратора                                 |
|                       3. Построение Domain Trie & Radix LPM                                        |
|                       4. rkyv-сериализация -> rules.abc                                            |
|                       5. Генерация ETag (SHA-256)                                                  |
|                                      |                                                             |
|                                      v                                                             |
|                            [ Local Storage / CDN ]                                                 |
|                                      |                                                             |
|                                      v                                                             |
|              REST API: GET /api/v1/routing/compiled-rules (ETag)                                   |
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

Модуль отвечает за сбор текстовых списков, обработку администраторских исключений, слияние в соответствии с политиками маршрутизации и компиляцию бинарных артефактов `.abc`.

### 3.1. Схема базы данных (SeaORM)

#### Сущность `RuleProvider` (`rule_providers`)
Хранит источники правил (внешние URL или локальные наборы):
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
    pub format: ProviderFormat,       // PlainText | V2RayDomain | CidrList
    pub url: String,
    pub update_interval_hours: i32,
    pub last_fetched_at: Option<DateTime>,
    pub last_etag: Option<String>,
    pub item_count: i64,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(None)")]
pub enum ProviderType {
    #[sea_orm(string_value = "domain")]
    DomainList,
    #[sea_orm(string_value = "ip")]
    IpList,
}

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(None)")]
pub enum ProviderFormat {
    #[sea_orm(string_value = "plain")]
    PlainText,
    #[sea_orm(string_value = "v2ray")]
    V2RayDomain,
    #[sea_orm(string_value = "cidr")]
    CidrList,
}
```

#### Расширение сущностей маршрутизации (`route_rules` и `custom_overrides`)
В существующую таблицу `route_rules` добавляется поддержка привязки к `rule_provider_id`, а также создается сущность администраторских ручных исключений `CustomOverride`:

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
    pub action: String,     // "direct", "proxy", "block"
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
#[sea_orm(rs_type = "String", db_type = "String(None)")]
pub enum OverrideType {
    #[sea_orm(string_value = "domain")]
    Domain,
    #[sea_orm(string_value = "wildcard")]
    SubdomainWildcard,
    #[sea_orm(string_value = "cidr")]
    IpNet,
}

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(None)")]
pub enum OverrideCategory {
    #[sea_orm(string_value = "block")]
    CustomBlock,
    #[sea_orm(string_value = "direct")]
    CustomDirect,
    #[sea_orm(string_value = "proxy")]
    CustomProxy,
}
```

### 3.2. Административные исключения в WebUI
В панели управления `anet-webui` администратор получает интерфейс:
- **Управление провайдерами списков**: добавление URL (например, `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/...`), настройка периода автообновления, просмотр количества правил и даты последней загрузки.
- **Интерактивные Custom Overrides**:
  - Быстрое добавление единичных доменов или списков в категории:
    * `custom_block` (или `custom_drop`): принудительная блокировка нежелательных ресурсов без ожидания обновления внешних фильтров.
    * `custom_direct`: принудительный вывод из VPN критичных сервисов (банковские шлюзы, локальные корпоративные домены, стриминги).
    * `custom_proxy`: принудительное направление в VPN ресурсов, ошибочно попавших в списки исключений.
- Администраторские исключения имеют наивысший приоритет среди серверных правил: при компиляции они накладываются поверх списков провайдеров, переопределяя конфликтующие узлы дерева.

### 3.3. Фоновый воркер (Fetcher & Compiler)
Фоновая служба `RuleCompilerService` запускается внутри процесса `anet-auth`:
1. **Планировщик скачивания**:
   - Регулярно опрашивает `rule_providers`, у которых истек `update_interval_hours`.
   - Выполняет HTTP GET с поддержкой заголовков `If-None-Match` и `If-Modified-Since`.
   - В случае `304 Not Modified` обновляет `last_fetched_at` без перекомпиляции.
2. **Стриминговый парсинг и нормализация**:
   - Построчное чтение с отсечением комментариев (`#`, `//`, `;`).
   - Для доменов:
     - Приведение к нижнему регистру (lowercase ASCII).
     - Преобразование IDN (Punycode).
     - Удаление префиксов `+.`, `full:`, `domain:` (форматы v2ray/clash).
     - Разделение на тип соответствия: *точное совпадение* (Exact) или *по всем поддоменам* (Subdomain suffix).
   - Для IP-адресов:
     - Парсинг одиночных адресов `/32` (IPv4) и `/128` (IPv6).
     - Парсинг подсетей формата CIDR (`ipnet::IpNet`).
     - Нормализация и слияние смежных и перекрывающихся подсетей (CIDR aggregation).
3. **Наложение правил и построение структур**:
   - Сначала строятся базовые деревья из провайдеров.
   - Затем узлы дерева модифицируются записями из `admin_custom_overrides` (наложение с заменой терминального действия).
   - Домены организуются в **Reversed Domain Trie** (дерево меток, разобранных с конца: `com` $\to$ `example` $\to$ `ads`).
   - Сети укладываются в бинарный **Radix Tree (LPM)** с битовой глубиной до 32 (IPv4) и 128 (IPv6).
4. **Компиляция и кэширование**:
   - При изменении любого из провайдеров, таблицы `route_rules` или таблицы `admin_custom_overrides` перекомпилируется артефакт `rules.abc`.
   - Генерируется хэш SHA-256 содержимого бинарного файла, служащий `ETag`.

### 3.4. REST API для клиентов
Эндпоинт является публичным (аутентификация не требуется), что позволяет клиентам скачивать и обновлять правила автономно, а также кэшировать их на уровне CDN/Edge прокси.

- **Маршрут**: `GET /api/v1/routing/compiled-rules` (или индивидуально по профилю: `/api/v1/routing/compiled-rules/:route_map_id`)
- **Аутентификация**: Отсутствует (публичный доступ, rate-limited при необходимости).
- **Заголовки запроса**:
  - `If-None-Match: "<ETag>"`
- **Поведение сервера**:
  - Если переданный `ETag` совпадает с текущим: `304 Not Modified`.
  - Если правила изменились или это первичный запрос: `200 OK`, `Content-Type: application/octet-stream`, `ETag: "<SHA256>"`, `Cache-Control: public, no-cache`, тело ответа — бинарные байты `.abc`.

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

#### B. Действие `RuleAction::Direct` (В обход VPN — Split Tunneling по доменам)
1. Клиент выполняет DNS-запрос к публичному резолверу (например, `1.1.1.1` или системный DNS провайдера) через **защищенный сокет в обход туннеля**.
2. Из полученного DNS-ответа извлекаются все IP-адреса из секции Answers (`A` и `AAAA`) и их минимальный `TTL`.
3. Извлеченные IP-адреса регистрируются в памяти:
   ```rust
   direct_ip_cache.insert_batch(resolved_ips, Duration::from_secs(ttl));
   ```
4. Исходный DNS-ответ отправляется обратно приложению через `tx_to_tun`.
5. Приложение начинает устанавливать TCP/UDP-соединение с полученными IP-адресами.

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
                       [ Action == Direct ]              [ Action == Proxy ]
                               |                                 |
                       Байпас туннеля:                    Инкапсуляция:
                       Пакет уходит напрямую              Пакет шифруется и уходит
                       в сетевой интерфейс ОС             в активный VPN-транспорт
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
Для трафика с действием `Direct` необходимо исключить петли маршрутизации и предотвратить отправку пакета в VPN-сервер:

1. **Android**:
   - Вызов `android.net.VpnService.protect(socket)` для сокетов, через которые резолвится прямой DNS и отправляются прямые пакеты.
   - Использование исключающих маршрутов `VpnService.Builder.addDisallowedApplication`.
2. **Windows**:
   - Использование архитектуры `anet-appfilter` (WinDivert):
     - Пакеты с действием `Direct` отправляются обратно в системный стек вызовом `WinDivertSend` без перенаправления в канал `tx_to_transport`.
3. **Linux**:
   - Маркировка трафика (`SO_MARK`, fwmark).
   - Правила политики маршрутизации `ip rule add fwmark 0x1000 lookup main` для направления прямых пакетов через физический шлюз по умолчанию.
4. **macOS**:
   - Привязка исходящих прямых сокетов к физическому сетевому интерфейсу через `IP_BOUND_IF` / `SO_BINDTODEVICE`.

---

## 10. Жизненный цикл, отказоустойчивость и безопасность

1. **Cold Start при отсутствии интернета**:
   - Клиент обязан запуститься с последней сохраненной версией `rules.abc`.
   - Если файл отсутствует или поврежден, клиент откатывается к режиму `default_action = Proxy` и логирует предупреждение.
2. **Атомарность обновлений**:
   - Запись файла правил всегда ведется в `.tmp` с последующим системным `rename`.
   - Замена ссылки на отображенную память (`mmap`) в работающих тасках происходит атомарно (RCU / ArcSwap).
3. **Предотвращение DNS Leaks**:
   - Все DNS-запросы перехватываются жестко на уровне L3/L4 драйвера (TUN/WinDivert).
   - Ни один запрос к внутренним доменам корпоративной сети или заблокированным ресурсам не попадает в открытую сеть без явного правила `Direct`.
4. **Защита от переполнения кэша (DoS)**:
   - `DirectIpCache` имеет верхнюю границу размера (например, 50 000 записей).
   - При достижении лимита выполняется вытеснение по алгоритму LRU / TTL-expired.

---

## 11. План поэтапной реализации (Roadmap)

### Этап 1: Базовый крейт `anet-filter-core`
- [ ] Определение структур данных `DomainTrie`, `IpRoutingTable`, `CompiledRoutingCache` с атрибутами `rkyv` (магическое число `ABC1`).
- [ ] Алгоритм построения инвертированного Domain Trie с поддержкой администраторских оверрайдов.
- [ ] Алгоритм построения Radix Trie (LPM).
- [ ] Реализация модуля `checksum.rs` (RFC 791, RFC 768, RFC 8200) с тестами.
- [ ] Модульные тесты на проверку сопоставления доменов (точные совпадения, поддомены, wildcard) и сетей (IPv4/IPv6).

### Этап 2: Бэкенд-компилятор в `anet-auth`
- [ ] Миграции SeaORM для таблиц `rule_providers` и `admin_custom_overrides`, модификация `route_rules`.
- [ ] Фоновый воркер `RuleCompilerService` (скачивание списков MetaCubeX/AdBlock, нормализация, наложение оверрайдов, компиляция в `.abc`).
- [ ] REST API эндпоинт `GET /api/v1/routing/compiled-rules` с валидацией `ETag`.
- [ ] Интеграция в `anet-webui`: управление провайдерами, добавление `custom_block`, `custom_direct`, `custom_proxy` и просмотр статуса кэша.

### Этап 3: Клиентский движок в `anet-client-core`
- [ ] Поддержка `[routing.overrides]` в `client.toml` для локальных пользовательских правил.
- [ ] Менеджер `RuleUpdater` с загрузкой `.abc` и маппингом через `memmap2`.
- [ ] Внутритуннельный парсер и перехватчик `DnsInterceptor`.
- [ ] Обработка Canary Domains (`use-application-dns.net` $\to$ NXDOMAIN).
- [ ] Генератор синтетических ответов DNS для `RuleAction::Block` с пересчетом L3/L4 контрольных сумм.
- [ ] Модуль `DirectIpCache` для динамического отслеживания ответов резолвера.
- [ ] Маршрутизация исходящих пакетов в цикле туннеля (`client.rs` / `acquire_packet_source`).

### Этап 4: Платформенная интеграция и оптимизация
- [ ] Интеграция с `anet-appfilter` (Windows WinDivert direct bypass).
- [ ] Интеграция с Android JNI / `protect_socket`.
- [ ] Интеграция с Linux `ip rule` / fwmark.
- [ ] Нагрузочное тестирование (пропускная способность 1+ Gbps, задержка DNS < 0.5 мс, корректность контрольных сумм в Wireshark).
