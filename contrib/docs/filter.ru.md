# Техническое задание: Smart DNS, Geo-Routing и AdBlock для ANet VPN

Документация актуальна для ветки `dev/filter` (ANet v0.7.0+).  
Статус: **Архитектурная спецификация (Approved Implementation Spec)**.

---

## 1. Обзор (Overview)

### 1.1. Цель
Внедрение в экосистему ANet высокопроизводительной системы раздельного туннелирования (**Split Tunneling**) по доменным именам (**GeoSite**) и IP-адресам/сетям (**GeoIP**), а также фильтрации нежелательного трафика и рекламы (**AdBlock**) на уровне DNS.

### 1.2. Ограничения и граничные условия
1. **Экстремально низкое потребление ОЗУ и CPU на клиентах**:
   - Клиентская кодовая база работает на широком спектре устройств: от мощных десктопов до слабых Android TV приставок и бюджетных смартфонов с ограниченными ресурсами.
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
- Построение эффективных структур поиска: **инвертированного префиксного дерева (Domain Trie)** и **Radix Trie (LPM)**.
- Компиляция и бинарная упаковка в специализированный формат `.abk` (**ANet Binary Kache**) с использованием Zero-copy фреймворка `rkyv`.

Клиент (`anet-client-core`):
- Скачивает бинарный слепок `.abk` по HTTP с поддержкой `ETag` / `If-None-Match`.
- Отображает файл в память через системный вызов `mmap` (`memmap2`).
- Выполняет поиск соответствий напрямую по отображенной памяти без единой аллокации строк или векторов в куче.

---

## 2. Сквозная архитектурная схема

```text
+----------------------------------------------------------------------------------------------------+
|                                    БЭКЕНД УПРАВЛЕНИЯ (anet-auth)                                   |
|                                                                                                    |
|  [ Внешние провайдеры ]      [ Web UI / Админ ]                                                    |
|  (MetaCubeX, Anti-AD)                |                                                             |
|           |                          v                                                             |
|           +----------> [ Background Fetcher & Compiler ]                                           |
|                                      |                                                             |
|                       1. Парсинг и нормализация                                                    |
|                       2. Построение Domain Trie & Radix LPM                                        |
|                       3. rkyv-сериализация -> rules.abk                                            |
|                       4. Генерация ETag (SHA-256)                                                  |
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
|  [ Rule Updater ] ---- (ETag check) ----> [ rules.abk на диске ]                                    |
|                                                    | (mmap)                                        |
|                                                    v                                               |
|                                    [ CompiledRoutingCache (Zero-copy) ]                            |
|                                                    |                                               |
|                                                    +---------------------------+                   |
|                                                    |                           |                   |
|  [ ОС TUN / WinDivert ]                            v (Domain Lookup)           v (IP LPM Lookup)   |
|           |                             [ DnsInterceptor ]             [ PacketRouter ]            |
|           |                                    |                               |                   |
|           +--- (UDP :53 DNS Query) ----------->|                               |                   |
|           |                                    |-- Block  --> Синтетич. ответ  |                   |
|           |                                    |              (0.0.0.0 / ::)   |                   |
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

## 3. Бэкенд (`anet-auth`) — Компилятор правил

Модуль отвечает за сбор текстовых списков, их слияние в соответствии с политиками маршрутизации и компиляцию бинарных артефактов.

### 3.1. Схема базы данных (SeaORM)

#### Сущность `RuleProvider` (`rule_providers`)
Хранит источники правил (внешние URL или локальные списки):
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

#### Расширение сущности `RouteRule` (`route_rules`)
В существующую таблицу `route_rules` добавляется поддержка привязки к `rule_provider_id` и расширяется перечень допустимых действий:
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
```

### 3.2. Фоновый воркер (Fetcher & Compiler)
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
3. **Построение оптимизированных структур**:
   - Домены организуются в **Reversed Domain Trie** (дерево меток, разобранных с конца: `com` $\to$ `example` $\to$ `ads`).
   - Сети укладываются в бинарный **Radix Tree (LPM)** с битовой глубиной до 32 (IPv4) и 128 (IPv6).
4. **Компиляция и кэширование**:
   - При изменении любого из провайдеров или таблицы `route_rules` перекомпилируется артефакт `rules.abk`.
   - Генерируется хэш SHA-256 содержимого бинарного файла, служащий `ETag`.

### 3.3. REST API для клиентов
- **Маршрут**: `GET /api/v1/routing/compiled-rules` (или индивидуально по профилю: `/api/v1/routing/compiled-rules/:route_map_id`)
- **Заголовки запроса**:
  - `Authorization: Bearer <session_token>`
  - `If-None-Match: "<ETag>"`
- **Поведение сервера**:
  - Если переданный `ETag` совпадает с текущим: `304 Not Modified`.
  - Если правила изменились: `200 OK`, `Content-Type: application/octet-stream`, `ETag: "<SHA256>"`, тело ответа — бинарные байты `.abk`.

---

## 4. Спецификация бинарного формата `.abk` (ANet Binary Kache)

Формат спроектирован для мгновенной валидации и прямого отображения через `mmap` без промежуточных аллокаций.

### 4.1. Модель данных (rkyv)

```rust
use rkyv::{Archive, Deserialize, Serialize};

/// Корневой контейнер скомпилированных правил
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)]
pub struct CompiledRoutingCache {
    /// Магическое число 'ABK1' (0x314B4241)
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

### 4.2. Свойства и гарантии формата
1. **Zero Allocations**: После `mmap` клиент вызывает `rkyv::archived_root::<CompiledRoutingCache>(&mapped_bytes)`. Указатель напрямую смотрит на страницы памяти ОС.
2. **Безопасность памяти**: Метод `check_archived_root` проверяет корректность границ, выравнивания (alignment) и отсутствие некорректных указателей за один быстрый линейный проход.
3. **Кэш-локальность**: Узлы упорядочены по вероятности совпадения (популярные TLD в начале списков `children`).

---

## 5. Клиент (`anet-client-core`) — Архитектура и обработка трафика

### 5.1. Менеджер обновлений (`RuleUpdater`)
- **Неблокирующая инициализация**:
  - При вызове `AnetClient::start()` немедленно загружается локальный файл `cache/rules.abk` (если существует).
  - В фоновом `tokio`-таске инициируется сетевой запрос к `anet-auth`.
  - При получении `304 Not Modified` фоновый таск завершается.
  - При получении `200 OK`:
    1. Ответ сохраняется во временный файл `rules.abk.tmp`.
    2. Выполняется валидация целостности (`rkyv::check_archived_root`).
    3. Атомарное переименование `rules.abk.tmp` $\to$ `rules.abk`.
    4. Атомарное обновление указателя `Arc<ArcSwap<MmapRuleCache>>` в рантайме без перезапуска VPN-сессии.

### 5.2. Внутренний DNS-перехватчик (`DnsInterceptor`)
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
        +----------------------------+             2. Поиск в Domain Trie
                                                             |
                           +------------------+--------------+------------------+
                           |                  |                                 |
                           v                  v                                 v
                     [ Rule: Block ]   [ Rule: Direct ]                  [ Rule: Proxy ]
                           |                  |                                 |
                 Синтетический DNS      Прямой DNS-запрос                Форвардинг в туннель
                 ответ (0.0.0.0 / ::)   через прямой сокет               на серверный DNS
                           |                  |                                 |
                           v                  +-> Добавить A/AAAA в             v
                    Отправка в TUN                DirectIpCache (TTL)    Отправка в VPN-транспорт
                     (tx_to_tun)              |                          (QUIC / WebRTC)
                                              v
                                       Отправка ответа в TUN
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
5. Контрольные суммы пересчитываются, и пакет инжектируется напрямую в `tx_to_tun`.
6. Клиентское приложение мгновенно получает ответ, не ожидая сетевого таймаута.

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

## 6. Обработка L3/L4 трафика: Движок маршрутизации (`PacketRouter`)

Когда приложение отправляет целевой сетевой трафик (TCP, UDP, ICMP), каждый пакет, пришедший из сетевого стека, проходит проверку назначения:

```text
                           Входящий пакет данных из TUN
                                        |
                                        v
                            Извлечение Destination IP
                                        |
                                        v
                    [ 1. Проверка в динамическом DirectIpCache ]
                                        |
                         +--------------+--------------+
                         | Совпало                     | Не найдено
                         v                             v
                  [ Action: Direct ]       [ 2. Поиск в статическом ]
                         |                 [   Radix Trie (LPM)     ]
                         |                             |
                         |              +--------------+--------------+
                         |              | Найдено                     | Не найдено
                         |              v                             v
                         |      [ Действие из Trie ]         [ default_action ]
                         |              |                             |
                         +-------+------+-----------------------------+
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

### 6.1. Структура `DirectIpCache`
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

### 6.2. Платформенная реализация Split-Tunneling Bypass
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

## 7. Жизненный цикл, отказоустойчивость и безопасность

1. **Cold Start при отсутствии интернета**:
   - Клиент обязан запуститься с последней сохраненной версией `rules.abk`.
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

## 8. План поэтапной реализации (Roadmap)

### Этап 1: Базовый крейт `anet-filter-core`
- [ ] Определение структур данных `DomainTrie`, `IpRoutingTable`, `CompiledRoutingCache` с атрибутами `rkyv`.
- [ ] Алгоритм построения инвертированного Domain Trie.
- [ ] Алгоритм построения Radix Trie (LPM).
- [ ] Модульные тесты на проверку сопоставления доменов (точные совпадения, поддомены, wildcard) и сетей (IPv4/IPv6).

### Этап 2: Бэкенд-компилятор в `anet-auth`
- [ ] Миграции SeaORM для таблиц `rule_providers` и модификация `route_rules`.
- [ ] Фоновый воркер `RuleCompilerService` (скачивание списков MetaCubeX/AdBlock, нормализация, компиляция в `.abk`).
- [ ] REST API эндпоинт `GET /api/v1/routing/compiled-rules` с валидацией `ETag`.
- [ ] Интеграция в `anet-webui`: управление провайдерами и просмотр статуса кэша.

### Этап 3: Клиентский движок в `anet-client-core`
- [ ] Менеджер `RuleUpdater` с загрузкой `.abk` и маппингом через `memmap2`.
- [ ] Внутритуннельный парсер и перехватчик `DnsInterceptor`.
- [ ] Генератор синтетических ответов DNS для `RuleAction::Block`.
- [ ] Модуль `DirectIpCache` для динамического отслеживания ответов резолвера.
- [ ] Маршрутизация исходящих пакетов в цикле туннеля (`client.rs` / `acquire_packet_source`).

### Этап 4: Платформенная интеграция и оптимизация
- [ ] Интеграция с `anet-appfilter` (Windows WinDivert direct bypass).
- [ ] Интеграция с Android JNI / `protect_socket`.
- [ ] Интеграция с Linux `ip rule` / fwmark.
- [ ] Нагрузочное тестирование (пропускная способность 1+ Gbps, задержка DNS < 0.5 мс).
