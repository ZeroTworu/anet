# Архитектура коммерческого модуля (Личный Кабинет, Биллинг, Лимиты)

Документация актуальна для ветки `master` (коммит `530c40a`) и синхронизирована с текущим состоянием кода `anet-auth` и `anet-webui`.

---

## 1. Концептуальная модель: Единый Пользователь

Архитектура строится на принципе **«Один пользователь = Один криптографический ключ = Один профиль доступа»**. В системе нет привязки к оборудованию (HWID).

Сущность `User` (таблица `users`, `anet-auth/src/entities/users.rs`) объединяет в себе:
1. **Сетевую идентичность:** Криптографические ключи (ASTP, зашифрованы в БД через `DbEncryptor`), `fingerprint`, выделенный статический IP (`static_ip`).
2. **Пользовательскую идентичность:** `email`, `password_hash`, `telegram_id`, `balance`.
3. **Статус подписки:** `group_id` (текущая группа доступа), `activated_at` (момент первой сетевой активности), `expires_at` (момент окончания платного периода).

Пользователь использует один и тот же конфигурационный файл (`client.toml` или QR-код) на всех своих устройствах (ноутбук, смартфон, роутер). Ограничение потребления ресурсов строится **исключительно на количестве одновременных сессий, лимите скорости и лимите трафика**.

Публичный домен сервиса задаётся через переменную окружения `PUBLIC_DOMAIN` (fallback `ANET_PUBLIC_URL`, например: `https://service.example.com`) и используется при генерации ссылок подтверждения Email и URL QR-кода.  
*(Внутренняя панель управления администратора `anet-webui` развёртывается отдельно и защищена административным JWT `AdminToken` с проверкой активной сессии в таблице `sessions`)*.

---

### 1.1. Иерархия лимитов: Группы (`groups`) vs Индивидуальные тарифы (`rates`)

В кодовой базе заложено четкое разделение между базовыми групповыми планами и индивидуальными переопределениями:

```
                  ┌────────────────────────────────────────────────────────┐
                  │                 UserModel (users)                      │
                  │   - id, fingerprint, email, telegram_id, balance       │
                  │   - group_id: Option<Uuid>                             │
                  │   - activated_at: Option<DateTimeUtc>                  │
                  │   - expires_at: Option<DateTimeUtc>                    │
                  └───────────────────────────┬────────────────────────────┘
                                              │
                    ┌─────────────────────────┴────────────────────────┐
                    ▼                                                  ▼
      ┌───────────────────────────┐                      ┌───────────────────────────┐
      │       groups (План)       │                      │   rates (Кастом/Оверрайд) │
      ├───────────────────────────┤                      ├───────────────────────────┤
      │ Predefined в админке      │                      │ Персональная запись       │
      │ - is_default: bool        │                      │ (POST /addrate,           │
      │ - duration_days: i32      │                      │  PATCH/DELETE /rate/:id)  │
      │ - sessions_limit: i32     │                      │ - sessions: i32           │
      │ - traffic_limit: i64      │                      │ - speed_limit: i32        │
      │ - speed_limit: i32        │                      │ - traffic_limit: i64      │
      │ - Node Pools (привязка)   │                      │ - date_end: NaiveDateTime │
      └───────────────────────────┘                      └───────────────────────────┘
                    ▲                                                  ▲
                    │                                                  │
             Базовые лимиты                                     OVERRIDE ПРИОРИТЕТ
       (по умолчанию из группы)                                (полное переопределение)
```

1. **Группы (`groups` — Предопределенные тарифные планы):**
   * Создаются и настраиваются администратором в `anet-webui` (`/groups`, `/groups/:id`).
   * Содержат в себе предустановленные параметры:
     * `is_default: bool` — флаг группы по умолчанию. Назначается новому пользователю при регистрации (Email или Telegram TMA), а также активируется, когда у пользователя истекает оплаченный период (`expires_at < now`). При установке `is_default = true` в `POST /api/v1/groups` или `PATCH /api/v1/groups/:id` флаг автоматически снимается с остальных групп.
     * `duration_days: i32` — срок действия подписки (дельта в днях при активации; `0` = бессрочный доступ).
     * `sessions_limit: i32` — количество одновременных сессий (`0` = без лимита).
     * `traffic_limit: i64` — лимит трафика в байтах (`0` = безлимит).
     * `speed_limit: i32` — ограничение скорости в kbps (`0` = максимальная скорость; в `anet-webui` ввод/вывод пересчитывается в Мбит/с).
     * Привязка к пулам серверов (`group_node_pools`).
   * В каталоге товаров (`products`) базовый тариф оформляется как `ProductType::GroupSubscription`, где `target_id = Some(group_id)`. Все лимиты и длительность наследуются напрямую из связанной группы `groups`.

2. **Индивидуальные тарифы (`rates` — Оверрайд лимитов / Кастом):**
   * Запись в `rates` привязана к `user_id` (1-к-1), создаётся через `POST /api/v1/addrate`, обновляется через `PATCH /api/v1/rate/:id` и удаляется через `DELETE /api/v1/rate/:id` (в том числе из карточки пользователя в `anet-webui`).
   * В биллинге `rates` также зарезервирован для **динамического конструктора тарифов** (Backlog / Phase 2).
   * **Правило приоритета (Лестница приоритетов в `anet-auth/src/api/auth.rs` и `anet-auth/src/api/user_cabinet.rs`):**
     При авторизации клиента (`check_access`) и при запросе профиля ЛК (`/api/v1/user/me`), если у пользователя существует активная запись в `rates` (`date_end > now`), её лимиты **полностью переопределяют (override)** любые групповые лимиты из `groups`.

---

### 1.2. Проблема коллизии сессий: Реконнект vs Вытеснение (The libastral Paradox)

В системе действует фундаментальный принцип приватности: **никаких `device_id`, HWID или аппаратных идентификаторов нет и не будет**. Пользователь идентифицируется исключительно своим криптографическим ключом (`fingerprint`).

В режиме передачи данных (`data pass`) клиент передает зашифрованный туннельный трафик. Инспекция заголовков каждого IP-пакета ради команд управления **недопустима** (убийство скорости и батареи). Сервер может разорвать соединение только одним способом — физически закрыв сокет (`kill tx/rx`).

#### Суть проблемы: Неотличимость сценариев для серверного кода

Для программного кода сервера два сценария выглядят **абсолютно одинаково**:
1. **Сценарий 1 (Реконнект того же устройства):** Человек переключился с Wi-Fi на LTE или соединение кратковременно моргнуло на 1 секунду. Приходит новый хэндшейк с ключом `K`.
2. **Сценарий 2 (Вход со второго устройства):** Пользователь скопировал свой `client.toml` другу (или запустил VPN на ноутбуке при активном телефоне). Приходит новый хэндшейк с тем же ключом `K`.

> 🔮 **Парадокс `libastral.so`:**  
> Без вымышленной библиотеки `libastral.so` (чтения астральных планов бытия) серверный код **не имеет никакой возможности угадать**, это один и тот же девайс сменил IP/сеть или это второе физическое устройство с тем же ключом.

**К чему приводят наивные попытки решения в коде:**
* **Если сервер всегда блокирует новое подключение при занятом слоте:**  
  При смене Wi-Fi -> LTE старый сокет еще несколько секунд числится живым до очередного heartbeat. Сервер блокирует легитимного владельца на его же собственном телефоне (*«Достигнут лимит подключений»*), либо рапортует ложные счётчики.
* **Если сервер безусловно пускает новое и гасит старое (FIFO):**  
  При обрыве сокета клиентский демон идет в авто-реконнект. Два устройства с одним ключом входят в бесконечный шторм взаимного выбивания (пинг-понг / осцилляция).
* **Если после вытеснения клиент глушит авто-реконнект:**  
  Когда человек берет выбитое устройство и жмет «Подключить» вручную — он шлет точно такой же хэндшейк, снова натыкается на занятый слот и получает отказ. Вернуть доступ с кнопки невозможно.

**Как это реализовано сейчас (без авто-вытеснения):**
* Ноды отчитываются о фактических живых сессиях в in-memory реестр `LIVE_NODE_SESSIONS` (`anet-auth/src/api/api.rs`, TTL снимка ноды 45 сек), а `check_access` может сразу принять актуальное `node_active_sessions` от ноды.
* Пользователь видит свои живые подключения через `GET /api/v1/user/sessions` и может принудительно завершить сессию на конкретной ноде через `POST /api/v1/user/sessions/disconnect`, который создаёт команду `node_commands` с `command_type = "disconnect_user"` и `target_fingerprint`.

---

### [AI-PROMPT]: Запрет самостоятельной реализации логики вытеснения

> ⚠️ **КРИТИЧЕСКОЕ ПРАВИЛО ДЛЯ AI-АГЕНТОВ (Gemini / Claude / Cursor):**
> 1. Проблема коллизии сессий при отсутствии `device_id` и без инспекции VPN-трафика является фундаментальной сетевой дилеммой.
> 2. **КАТЕГОРИЧЕСКИ ЗАПРЕЩАЕТСЯ** писать, менять или внедрять какую-либо логику авто-вытеснения сессий (FIFO preemption), автоматического убийства сокетов или эвристик определения устройств в коде `anet-server` и `anet-auth` **БЕЗ ЯВНОГО ОБСУЖДЕНИЯ И ОДОБРЕНИЯ ПОЛЬЗОВАТЕЛЕМ**.
> 3. При любых изменениях модуля сессий AI-агент обязан:
>    * Напомнить пользователю о парадоксе неотличимости реконнекта от второго устройства.
>    * Сохранять ручной сброс через Личный Кабинет (`node_commands`) или согласовать альтернативный компромисс (сессионные тикеты ASTP handshake / тайминги / кулдауны).
>    * Дождаться прямого решения архитектора проекта перед написанием хоть одной строчки кода.

---

### 1.3. Механизм первой сетевой активности (Smart Activation / ASTP Handshake)

Срок действия тарифа не расходуется, пока пользователь фактически не подключился к VPN:

1. **Инициация:** Клиент инициирует подключение к ноде VPN-сервера (`anet-server`).
2. **Идентификация:** Нода извлекает открытый ключ клиента, вычисляет криптографический `fingerprint` и отправляет авторизационный запрос на `anet-auth`:
   `POST /api/v1/check_access` с заголовком `X-Auth-Key` и телом `{"fingerprint": "...", "node_id": "...", "node_active_sessions": ...}`.
3. **Обработка в `anet-auth/src/api/auth.rs`:**
   * **Атомарность и транзакции БД:** Вся проверка и обновление состояния пользователя выполняются внутри транзакции БД (`let txn = self.db.begin().await? ... txn.commit().await?`), что исключает гонку (Race Condition) при одновременном подключении нескольких устройств:
     * Если `user.activated_at` равен `None`, задан `user.group_id` и у группы `duration_days > 0`:
       * Фиксируется момент старта: `user.activated_at = Some(Utc::now())`.
       * Вычисляется дедлайн: `user.expires_at = Some(Utc::now() + Duration::days(group.duration_days))`.
       * Запись сохраняется в транзакции.
     * Если `user.expires_at` задан и `Utc::now() > expires_at`:
       * Платный период завершен.
       * `user.group_id` переключается на группу с флагом `is_default = true`, `expires_at` сбрасывается в `None`.
       * Если в дефолтной группе доступ заблокирован (`sessions_limit == 0`), возвращается `{ allowed: false, message: "Время действия подписки истекло. Продлите тариф в Личном Кабинете" }`.
     * Если нода передала `node_id` и `node_active_sessions`, обновляется `LIVE_NODE_SESSIONS` (`set_live_node_session_for_fingerprint`).
     * Проверяются персональные оверрайды: активная запись `rates` (`date_end > now_naive`) переопределяет параметры группы.
   * Транзакция фиксируется (`txn.commit().await?`).
4. **Ответ и шейпинг:** `anet-auth` возвращает `CheckAccessResponse`. Нода применяет выданные ограничения (`speed_limit_kbps`, `allowed_sessions`, `traffic_limit`) и завершает хэндшейк.

---

## 2. Модель монетизации, Товары (Products) и Статус этапов

Архитектура биллинга строится вокруг сущности **Product (Товар)** (`products`), связанной с заказами (`orders`), транзакциями (`transactions`) и ваучерами (`vouchers`).

### 2.1. Текущее состояние реализации (коммит `530c40a`)

* **Реализовано в `anet-auth` (Backend) и `anet-webui` (Admin Panel):**
  1. Конфигурация коммерческого модуля через переменные окружения (`.env.example.auth`, `--env-file` / `ANET_ENV_FILE`, `src/config.rs`).
  2. Полная схема БД и SeaORM-миграции (`000034`, `000035`) + сущности (`products`, `orders`, `transactions`, `vouchers`, `verification_tokens`, поля в `users` и `groups.is_default`).
  3. Регистрация и вход пользователей (`/api/v1/user/auth/*`): одноразовые ссылки на Email через `EMAIL_WEBHOOK_URL`, установка пароля (`bcrypt`), вход по Email+паролю, привязка Email (`link-email`) и вход/авторегистрация через Telegram Mini App (`HMAC-SHA256`).
  4. Полноценное API Личного Кабинета (`/api/v1/user/*`): профиль и действующие лимиты (`/user/me`), витрина продуктов (`/user/products`), создание и история заказов (`/user/orders`), реальные активные сессии (`/user/sessions`, `/user/sessions/disconnect`), графики трафика из `traffic_hourly` (`/user/traffic-history`), генерация `client.toml` и QR URL (`/user/config`).
  5. Интеграция FreeKassa (`src/api/freekassa.rs`): SCI, API v1 `orders/create`, вебхук `/billing/freekassa/notify`, атомарный `fulfill_order` (включая генерацию ваучера `ANET-GIFT-...` при `is_gift = true`), фоновый воркер сверки `cron_sync_freekassa`.
  6. Административное API биллинга (`/api/v1/admin/products`, `/api/v1/admin/orders`, `/api/v1/admin/transactions`) + расширенные админ-эндпоинты `users`, `groups`, `rate`.
  7. Admin WebUI (`anet-webui`): управление пользователями (Email/пароль/группа), расширенное управление `Rate` (трафик, скорость, удаление), поддержка `groups.is_default`, а также раздел **Billing** (`Products`, `Orders`, `Transactions`).
  8. Набор HTTP/unit-тестов API с `sea_orm::MockDatabase` (`anet-auth/src/api/tests/*`).

* **Остаётся в Backlog (Phase 2 — дальнейшее развитие):**
  1. Публичный фронтенд Личного Кабинета пользователя (User WebUI) и интерфейс Telegram Mini App поверх уже готового API `/api/v1/user/*`.
  2. Активация подарочных ваучеров пользователем (API погашения кода `ANET-GIFT-...` + UI в ЛК) и реестр `Vouchers` в `anet-webui`.
  3. Интерактивный калькулятор/конструктор тарифов (`ProductType::RateExtension`, `fulfill_order` пока содержит заглушку с логированием).
  4. Поддержка платёжных шлюзов Telegram Stars / Aaio / YooMoney (enum в БД уже подготовлены) и алертов мониторинга.

---

## 3. Схема Базы Данных (SeaORM Entities & Migrations)

### [AI-PROMPT]: Обязательное создание SeaORM миграций параллельно с сущностями

> ⚠️ **КРИТИЧЕСКОЕ ПРАВИЛО ДЛЯ AI-АГЕНТОВ (Gemini / Claude / Cursor):**
> 1. При создании или модификации любой структуры в `anet-auth/src/entities/` **ОБЯЗАТЕЛЬНО ПАРАЛЛЕЛЬНО** создавайте файл миграции в `anet-auth/src/migration/` (формат имени: `mYYYYMMDD_HHMMSS_<описание>.rs`).
> 2. Созданная миграция **ДОЛЖНА БЫТЬ СРАЗУ ЗАРЕГИСТРИРОВАНА** в векторе `Migrator::migrations()` внутри `anet-auth/src/migration/mod.rs`.
> 3. Миграции описываются строго через SeaQuery DSL (`Table::create()`, `Table::alter()`) либо через типизированный DDL. Никогда не оставляйте сущности без миграций!

**Актуальные миграции коммерческого модуля (`anet-auth/src/migration/`):**
* `m20261112_000034_create_billing_and_user_cabinet.rs` — PostgreSQL ENUM (`currency`, `payment_system`, `order_status`, `product_type`, `voucher_status`), колонка `groups.is_default`, поля `users` (`email`, `password_hash`, `telegram_id`, `balance`, `activated_at`, `expires_at`), таблицы `products`, `orders`, `transactions`, `vouchers`.
* `m20261113_000035_create_verification_tokens.rs` — таблица `verification_tokens` для одноразовых ссылок подтверждения Email.

### Код сущностей в `anet-auth/src/entities/`

```rust
// ============================================================================
// anet-auth/src/entities/billing_enums.rs
// ============================================================================

use poem_openapi::Enum;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Поддерживаемые валюты системы
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize, Enum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "currency")]
pub enum Currency {
    /// Российский рубль
    #[sea_orm(string_value = "RUB")]
    Rub,
    /// Доллар США
    #[sea_orm(string_value = "USD")]
    Usd,
    /// Евро
    #[sea_orm(string_value = "EUR")]
    Eur,
    /// Звезды Telegram Stars
    #[sea_orm(string_value = "STARS")]
    Stars,
}

impl Currency {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Rub => "RUB",
            Self::Usd => "USD",
            Self::Eur => "EUR",
            Self::Stars => "STARS",
        }
    }
}

/// Поддерживаемые платежные шлюзы
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize, Enum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "payment_system")]
pub enum PaymentSystem {
    /// Платежный агрегатор FreeKassa
    #[sea_orm(string_value = "freekassa")]
    FreeKassa,
    /// Платежный шлюз Aaio
    #[sea_orm(string_value = "aaio")]
    Aaio,
    /// Сервис ЮKassa / YooMoney
    #[sea_orm(string_value = "yoomoney")]
    YooMoney,
    /// Встроенные платежи Telegram Stars
    #[sea_orm(string_value = "telegram_stars")]
    TelegramStars,
}

/// Жизненный цикл заказа
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize, Enum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "order_status")]
pub enum OrderStatus {
    /// Заказ создан, ожидает оплаты пользователем
    #[sea_orm(string_value = "pending")]
    Pending,
    /// Заказ успешно оплачен, услуга начислена
    #[sea_orm(string_value = "paid")]
    Paid,
    /// Ошибка проведения платежа на стороне шлюза
    #[sea_orm(string_value = "failed")]
    Failed,
    /// Заказ отменен пользователем или истек таймаут ожидания
    #[sea_orm(string_value = "cancelled")]
    Cancelled,
    /// Чарджбэк или возврат средств клиенту
    #[sea_orm(string_value = "refunded")]
    Refunded,
}

/// Тип продаваемого продукта
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize, Enum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "product_type")]
pub enum ProductType {
    /// Подписка на готовую группу (лимиты и duration_days берутся из таблицы groups)
    #[sea_orm(string_value = "group_subscription")]
    GroupSubscription,
    /// Кастомный тариф / расширение лимитов (параметры сохраняются в rates)
    #[sea_orm(string_value = "rate_extension")]
    RateExtension,
    /// Дополнительный модуль или фича (например, статический выделенный IP)
    #[sea_orm(string_value = "feature")]
    Feature,
}

/// Статус подарочного ваучера
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize, Enum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "voucher_status")]
pub enum VoucherStatus {
    /// Ваучер создан и доступен для активации
    #[sea_orm(string_value = "created")]
    Created,
    /// Ваучер уже успешно активирован пользователем
    #[sea_orm(string_value = "claimed")]
    Claimed,
    /// Ваучер отозван администратором
    #[sea_orm(string_value = "revoked")]
    Revoked,
}

/// Источник действующих ограничений пользователя
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Enum)]
pub enum LimitSource {
    /// Персональный тариф из таблицы rates
    #[oai(rename = "rates")]
    Rates,
    /// Базовый тариф из привязанной группы groups
    #[oai(rename = "groups")]
    Groups,
    /// Дефолтные ограничения системы
    #[oai(rename = "default")]
    Default,
    /// Безлимитный доступ
    #[oai(rename = "unlimited")]
    Unlimited,
}
```

> 📌 **Важно про сериализацию enum в OpenAPI / JSON:**  
> У `Currency`, `PaymentSystem`, `OrderStatus` и `ProductType` нет `#[oai(rename_all = ...)]`, поэтому в REST JSON (и в `anet-webui`) они сериализуются в PascalCase:
> * `Currency`: `"Rub" | "Usd" | "Eur" | "Stars"`
> * `ProductType`: `"GroupSubscription" | "RateExtension" | "Feature"`
> * `OrderStatus`: `"Pending" | "Paid" | "Failed" | "Cancelled" | "Refunded"`
> * `PaymentSystem`: `"FreeKassa" | "Aaio" | "YooMoney" | "TelegramStars"`

```rust
// ============================================================================
// anet-auth/src/entities/users.rs (коммерческие поля) и groups.rs
// ============================================================================

// В anet-auth/src/entities/users.rs:
    #[sea_orm(unique, nullable)]
    pub email: Option<String>,
    #[sea_orm(nullable)]
    pub password_hash: Option<String>,
    #[sea_orm(unique, nullable)]
    pub telegram_id: Option<i64>,
    pub balance: f64,
    pub activated_at: Option<DateTimeUtc>,
    pub expires_at: Option<DateTimeUtc>,

// В anet-auth/src/entities/groups.rs:
    pub is_default: bool,        // Группа по умолчанию при регистрации и истечении подписки
    pub traffic_limit: i64,      // Лимит трафика в байтах (0 - безлимит)
    pub speed_limit: i32,        // Лимит скорости в kbps (0 - безлимит)
    pub sessions_limit: i32,     // Максимум сессий
    pub duration_days: i32,      // Дельта подписки в днях при активации

// ============================================================================
// anet-auth/src/entities/products.rs
// ============================================================================

use super::billing_enums::{Currency, ProductType};
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "products")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub price: f64,
    pub currency: Currency,
    pub product_type: ProductType,
    pub target_id: Option<Uuid>,
    pub sort_order: i32,
    pub badge: Option<String>,
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub metadata: Option<serde_json::Value>,
    pub is_active: bool,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::groups::Entity",
        from = "Column::TargetId",
        to = "super::groups::Column::Id"
    )]
    Group,
}

impl Related<super::groups::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Group.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

// ============================================================================
// anet-auth/src/entities/orders.rs
// ============================================================================

use super::billing_enums::{Currency, OrderStatus};
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "orders")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub user_id: Uuid,
    pub product_id: Uuid,
    pub amount: f64,
    pub currency: Currency,
    pub status: OrderStatus,
    pub is_gift: bool,
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::users::Entity",
        from = "Column::UserId",
        to = "super::users::Column::Id"
    )]
    User,
    #[sea_orm(
        belongs_to = "super::products::Entity",
        from = "Column::ProductId",
        to = "super::products::Column::Id"
    )]
    Product,
}

impl Related<super::users::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl Related<super::products::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Product.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

// ============================================================================
// anet-auth/src/entities/transactions.rs
// ============================================================================

use super::billing_enums::PaymentSystem;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "transactions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub order_id: Option<Uuid>,
    pub payment_system: PaymentSystem,
    pub external_tx_id: String,
    pub amount_received: f64,
    #[sea_orm(column_type = "JsonBinary")]
    pub raw_request: serde_json::Value,
    pub created_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::orders::Entity",
        from = "Column::OrderId",
        to = "super::orders::Column::Id"
    )]
    Order,
}

impl Related<super::orders::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Order.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

// ============================================================================
// anet-auth/src/entities/vouchers.rs
// ============================================================================

use super::billing_enums::VoucherStatus;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "vouchers")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(unique)]
    pub code: String,
    pub product_id: Uuid,
    pub buyer_user_id: Option<Uuid>,
    pub claimed_by_user_id: Option<Uuid>,
    pub status: VoucherStatus,
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub metadata: Option<serde_json::Value>,
    pub claimed_at: Option<DateTimeUtc>,
    pub created_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::products::Entity",
        from = "Column::ProductId",
        to = "super::products::Column::Id"
    )]
    Product,
    #[sea_orm(
        belongs_to = "super::users::Entity",
        from = "Column::BuyerUserId",
        to = "super::users::Column::Id"
    )]
    Buyer,
}

impl Related<super::products::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Product.def()
    }
}

impl Related<super::users::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Buyer.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

// ============================================================================
// anet-auth/src/entities/verification_tokens.rs
// ============================================================================

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "verification_tokens")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    #[sea_orm(column_type = "Text")]
    pub email: String,
    #[sea_orm(unique, column_type = "Text")]
    pub token_hash: String,
    pub expires_at: DateTimeUtc,
    pub used_at: Option<DateTimeUtc>,
    pub created_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::users::Entity",
        from = "Column::UserId",
        to = "super::users::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    User,
}

impl Related<super::users::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
```

---

## 4. Конфигурация, Регистрация и Авторизация

### 4.1. Переменные окружения (`anet-auth/src/config.rs`, `.env.example.auth`)

Вместо `server.toml` вся конфигурация коммерческого модуля читается строго из переменных окружения (`.env`, опция `--env-file` / `ANET_ENV_FILE`, либо `environment` в `contrib/docker/docker-compose.auth.preset.billing.yaml`) и инициализируется через `config::init_config()`:

```dotenv
DATABASE_URL=postgres://user:password@localhost:5432/anet_auth_db
AUTH_BACKEND_KEY=super_secret_vpn_key_2025
BIND_TO=127.0.0.1:3000
DB_ENCRYPTION_KEY=test_test
CLIENT_TEMPLATE_PATH=/opt/anet/client_template.toml

# --- Личный Кабинет и JWT ([cabinet.web]) ---
APP_ENV=production
JWT_SECRET=change_me_to_long_random_secret
USER_JWT_TTL_HOURS=168
PUBLIC_DOMAIN=https://service.example.com
VERIFICATION_TOKEN_TTL_MINS=15
MIN_PASSWORD_LENGTH=5
EMAIL_WEBHOOK_URL=
EMAIL_WEBHOOK_TOKEN=

# --- Telegram Bot / Mini App ([cabinet.telegram]) ---
TELEGRAM_BOT_TOKEN=
TELEGRAM_WEB_APP_DATA_KEY=WebAppData

# --- Платежный шлюз FreeKassa ([billing.freekassa]) ---
FK_SHOP_ID=
FK_SECRET1=
FK_SECRET2=
FK_API_KEY=
FK_PAY_URL=https://pay.freekassa.ru/
FK_API_URL=https://api.fk.life/v1
FK_SYNC_INTERVAL_SECS=900
FK_PENDING_THRESHOLD_MINS=15
```

### 4.2. Авторизация по Email (`anet-auth/src/api/user_auth.rs`)

Все маршруты `UserAuthApi` смонтированы в `OpenApiService` под префиксом `/api/v1`:

1. **`POST /api/v1/user/auth/request-link`** (`RequestEmailLinkRequest { email }`):
   * Нормализует email (lowercase/trim), проверяет базовый формат (`400 Bad Request`).
   * Если пользователь с таким Email существует и заблокирован (`is_active == false`) — возвращает `403 Forbidden`.
   * Генерирует 32-байтовый криптослучайный токен (`URL_SAFE_NO_PAD`), сохраняет в `verification_tokens` его `SHA-256` хэш (`token_hash`) со сроком `VERIFICATION_TOKEN_TTL_MINS`.
   * Формирует ссылку `{PUBLIC_DOMAIN}/auth/verify?token={raw_token}`.
   * Если задан `EMAIL_WEBHOOK_URL`, отправляет HTTP `POST` JSON `{ to, subject, verify_url, expires_in_mins, text }` (с заголовком `Authorization: Bearer <EMAIL_WEBHOOK_TOKEN>`, если токен задан).
   * Если `EMAIL_WEBHOOK_URL` не задан: логирует ссылку; при `APP_ENV=development` дополнительно возвращает её в поле `dev_verify_url`.
2. **`POST /api/v1/user/auth/verify`** (`VerifyEmailRequest { token, password }`):
   * Проверяет `password.len() >= MIN_PASSWORD_LENGTH` (`400 Bad Request`).
   * В транзакции ищет запись в `verification_tokens` по `SHA-256(token)`, проверяет `used_at.is_none()` (`400`) и `expires_at > now` (`400`), помечает `used_at = Some(now)`.
   * Хэширует пароль через `bcrypt`.
   * Если в токене есть `user_id` — привязывает `email` + `password_hash` к существующему аккаунту (проверяя конфликт Email `409 Conflict`). Иначе обновляет существующего пользователя с этим Email или создаёт нового (`create_new_user_with_default_group`), генерирует ASTP-ключи (`DbEncryptor`) и привязывает группу с `is_default = true` (`activated_at = None`, `expires_at = None`).
   * Выпускает JWT (`UserAuthTokenResponse`).
3. **`POST /api/v1/user/auth/login`** (`UserLoginRequest { email, password }`):
   * Проверяет `is_active` (`403`) и `bcrypt::verify`, возвращает JWT (`UserAuthTokenResponse`).

### 4.3. Связка аккаунтов (Telegram TMA -> Web-кабинет)

1. **`POST /api/v1/user/auth/telegram`** (`TelegramAuthRequest { init_data }`):
   * Проверяет подпись `init_data` по спецификации Telegram Mini App: `HMAC-SHA256(key = HMAC-SHA256(web_app_data_key, bot_token), data_check_string)` с `constant_time_eq` и проверкой `auth_date` (не старше 86 400 секунд).
   * По `telegram_id` находит существующего пользователя или создаёт нового без пароля с группой по умолчанию (`is_default = true`) и `uid = tg_<username|id>`, возвращает JWT.
2. **`POST /api/v1/user/auth/link-email`** (`UserAuth` + `RequestEmailLinkRequest { email }`):
   * Проверяет, что Email не занят другим пользователем (`409 Conflict`), и создаёт запись в `verification_tokens` с `user_id = Some(claims.user_id)`.
   * После перехода по ссылке и вызова `POST /api/v1/user/auth/verify` к профилю добавляются `email` и `password_hash`, что даёт единый вход как через TMA, так и через веб-форму.

---

## 5. Спецификация платёжного шлюза FreeKassa (`anet-auth/src/api/freekassa.rs`)

Криптография (`md5_hex` по RFC 1321 и `hmac_sha256_hex` по RFC 2104 поверх `sha2`) реализована непосредственно в `anet-auth/src/api/freekassa.rs` без добавления внешних крейтов.

### 5.1. Алгоритмы формирования и проверки подписей

1. **Создание заказа через SCI Form URL (`build_sci_payment_url`):**
   * Вызывается из `POST /api/v1/user/orders`, если `payment_system_id` не передан.
   * URL: `{FK_PAY_URL}/?m={shop_id}&oa={amount:.2}&currency={currency}&o={order_id}&s={sign}`
   * Строка подписи: `shop_id:amount_str:secret1:cur_str:order_id` -> `md5_hex`.
2. **Создание заказа через FreeKassa API v1 (`create_fk_api_order`):**
   * Вызывается из `POST /api/v1/user/orders`, если передан `payment_system_id`.
   * Эндпоинт: `POST {FK_API_URL}/orders/create`.
   * Ключи `amount`, `currency`, `email`, `i`, `ip`, `nonce`, `paymentId`, `shopId` сортируются по алфавиту, значения склеиваются через `|`, подписываются `HMAC-SHA256(FK_API_KEY)`.
3. **Входящий вебхук уведомления (`POST /billing/freekassa/notify`):**
   * Смонтирован вне `/api/v1` в `main.rs` (`poem::post(freekassa_notify_handler).data(db)`), проходит через `ApiKeyMiddleware` (который требует `X-Auth-Key` только для `/check_access` и `/session/*`).
   * **Извлечение и проверка IP:** Если peer — доверенный локальный или Docker-прокси (`is_trusted_proxy_peer`), реальный IP извлекается из `X-Real-IP` / `X-Forwarded-For` и проверяется по `FK_TRUSTED_IPS`: `168.119.157.136`, `168.119.60.227`, `138.201.88.124`, `178.154.197.79` (в `APP_ENV=development` проверка IP отключается).
   * **Проверка `MERCHANT_ID` и MD5-подписи:**
     Строка подписи: `MERCHANT_ID:AMOUNT:secret2:MERCHANT_ORDER_ID`.  
     **КРИТИЧЕСКИ ВАЖНО:** Поле `form.amount` подставляется в строку подписи **строго как исходная сырая строка из тела POST-запроса**.
   * **Атомарное начисление (`fulfill_order`):**
     1. Внутри транзакции БД проверяется статус заказа — если уже `OrderStatus::Paid`, выполняется идемпотентный выход `Ok(())`.
     2. Проверяется сумма: `(received_amount - order.amount).abs() <= 0.01`.
     3. Записывается аудит в `transactions` (включая `raw_request`).
     4. Статус заказа обновляется на `OrderStatus::Paid`.
     5. Если `order.is_gift == true` — создаётся ваучер `ANET-GIFT-XXXXXXXX` (`VoucherStatus::Created`). Иначе для `ProductType::GroupSubscription`:
        * Если у пользователя уже активна та же `group_id` и задан `expires_at` — `expires_at` продлевается на `group.duration_days`.
        * Если выбран новый тариф — назначается `group_id`, а `activated_at` и `expires_at` сбрасываются в `None` (ожидание Smart Activation).
   * Ответ шлюзу при успехе: `200 OK`, тело `"YES"`.

### 5.2. Фоновый воркер сверки `cron_sync_freekassa`

```rust
pub async fn cron_sync_freekassa(db: DatabaseConnection) {
    let fk = &crate::config::get().billing.freekassa;
    let shop_id = fk.shop_id.trim().to_string();
    let api_key = fk.api_key.trim().to_string();
    let sync_interval_secs = fk.sync_interval_secs.max(30);
    let pending_threshold_mins = fk.pending_threshold_mins.max(1);

    if shop_id.is_empty() || api_key.is_empty() {
        log::warn!("[FreeKassa Sync] [billing.freekassa] shop_id или api_key не заданы, воркер отключен");
        return;
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let orders_endpoint = format!("{}/orders", fk.api_url.trim_end_matches('/'));

    loop {
        sleep(Duration::from_secs(sync_interval_secs)).await;
        let threshold = Utc::now() - ChronoDuration::minutes(pending_threshold_mins);

        let pending_orders = match orders::Entity::find()
            .filter(orders::Column::Status.eq(OrderStatus::Pending))
            .filter(orders::Column::CreatedAt.lt(threshold))
            .all(&db)
            .await
        {
            Ok(orders) => orders,
            Err(e) => {
                log::error!("[FreeKassa Sync] DB error querying pending orders: {:?}", e);
                continue;
            }
        };

        for order in pending_orders {
            let nonce = Utc::now().timestamp_millis();
            let order_id_str = order.id.to_string();
            let sign_data = format!("{}|{}|{}", nonce, order_id_str, shop_id);
            let signature = hmac_sha256_hex(api_key.as_bytes(), sign_data.as_bytes());
            // POST {FK_API_URL}/orders -> при status == 1 вызывает fulfill_order(..., "fk_sync_{id}", ...)
            // при status == 8 || status == 9 переводит заказ в OrderStatus::Cancelled
            ...
        }
    }
}
```

---

## 6. Реализация API Личного Кабинета (`anet-auth/src/api/user_cabinet.rs`)

Все маршруты защищены `UserAuth` (проверка пользовательского JWT, активности `users.is_active` и валидности субъекта в `ensure_user`) и смонтированы под `/api/v1`:

### Основные DTO

```rust
#[derive(Object, Debug, Serialize, Deserialize)]
pub struct UserProfileResponse {
    pub id: Uuid,
    pub email: Option<String>,
    pub telegram_id: Option<i64>,
    pub fingerprint: String,
    pub balance: f64,
    pub is_active: bool,
    pub group_name: Option<String>,
    pub activated_at: Option<String>,
    pub expires_at: Option<String>,
    pub is_smart_activation_pending: bool,
    pub active_sessions_count: i32,
    pub traffic_used_bytes: i64,
    pub effective_limits: EffectiveLimitsDto,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct EffectiveLimitsDto {
    pub source: LimitSource,
    pub sessions_limit: i32,
    pub speed_limit_kbps: i32,
    pub traffic_limit_bytes: i64,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct ActiveSessionDto {
    pub session_id: String,
    pub server_id: Uuid,
    pub server_name: String,
    pub client_ip: String,
    pub protocol: ProtocolType,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
    pub connection_count: i32,
    pub connected_at: String,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct DisconnectSessionRequest {
    pub server_id: Uuid,
    pub session_id: String,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct CabinetTrafficHistoryPointDto {
    pub timestamp: String,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct ClientConfigResponse {
    pub client_toml: String,
    pub qr_code_url: String,
}
```

### Реализованные эндпоинты `UserCabinetApi`

1. **`GET /api/v1/user/me`** — возвращает `UserProfileResponse`:
   * Действующие лимиты (`EffectiveLimitsDto`) по лестнице приоритетов (`rates` -> `groups` -> `Unlimited`).
   * Число активных сессий `active_sessions_count` (из `LIVE_NODE_SESSIONS` с fallback на `active_sessions`).
   * Использованный трафик `traffic_used_bytes` за текущий расчётный цикл (сумма `rx_bytes + tx_bytes` из `traffic_hourly`).
2. **`GET /api/v1/user/products`** — список активных продуктов (`is_active == true`, сортировка по `sort_order`).
3. **`GET /api/v1/user/orders`** — последние 50 заказов текущего пользователя (`UserOrderDto`).
4. **`POST /api/v1/user/orders`** (`CreateOrderRequest { product_id, is_gift, payment_system_id }`) — создаёт заказ в статусе `Pending` и возвращает `CreateOrderResponse { order_id, amount, currency, payment_url }` (FreeKassa API v1 или SCI).
5. **`GET /api/v1/user/sessions`** — агрегирует реальные активные сессии пользователя с нод из `LIVE_NODE_SESSIONS` с добавлением статистики `rx_bytes`, `tx_bytes` и `protocol` из `traffic_totals`.
6. **`POST /api/v1/user/sessions/disconnect`** — проверяет наличие ноды (`servers`) и вставляет запись в `node_commands` (`command_type = "disconnect_user"`, `target_fingerprint = Some(claims.fingerprint)`, `status = "pending"`).
7. **`GET /api/v1/user/traffic-history?hours=24&bucket_hours=1`** — агрегирует почасовую/посуточную историю `rx_bytes` и `tx_bytes` из `traffic_hourly` за период от 1 часа до 90 суток (`clamp(1, 24 * 90)`).
8. **`GET /api/v1/user/config`** — собирает и расшифровывает полноценный `client.toml` через `build_client_toml_for_user` (с учётом серверов привязанных пулов, fallback на `Host`/`X-Forwarded-*` и `PUBLIC_DOMAIN`) + возвращает `qr_code_url`.

---

## 7. API Администратора (`anet-auth/src/api/admin_billing.rs`, `users.rs`, `groups.rs`)

Все административные эндпоинты защищены схемой безопасности `AdminToken` (`Bearer`) с проверкой активной сессии в таблице `sessions` через `validate_admin_session`.

### 7.1. Биллинг-контроллер `AdminBillingApi` (`anet-auth/src/api/admin_billing.rs`)

```rust
#[derive(Object, Debug, Serialize, Deserialize)]
pub struct AdminProductDto {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub price: f64,
    pub currency: Currency,
    pub product_type: ProductType,
    pub target_id: Option<Uuid>,
    pub sort_order: i32,
    pub badge: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct CreateProductRequest {
    pub name: String,
    pub description: String,
    pub price: f64,
    pub currency: Currency,
    pub product_type: ProductType,
    pub target_id: Option<Uuid>,
    pub sort_order: Option<i32>,
    pub badge: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub is_active: bool,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct UpdateProductRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub price: Option<f64>,
    pub currency: Option<Currency>,
    pub product_type: Option<ProductType>,
    pub target_id: Option<Option<Uuid>>,
    pub sort_order: Option<i32>,
    pub badge: Option<Option<String>>,
    pub metadata: Option<Option<serde_json::Value>>,
    pub is_active: Option<bool>,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct PaginatedOrdersResponse {
    pub items: Vec<AdminOrderDto>,
    pub total: u64,
    pub page: u64,
    pub page_size: u64,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct PaginatedTransactionsResponse {
    pub items: Vec<AdminTransactionDto>,
    pub total: u64,
    pub page: u64,
    pub page_size: u64,
}
```

**Маршруты `AdminBillingApi`:**
* `GET /api/v1/admin/products` — список всех продуктов (`order_by_asc(SortOrder)`).
* `POST /api/v1/admin/products` — создание продукта.
* `PATCH /api/v1/admin/products/:id` — частичное обновление (передача `null` в `target_id`, `badge`, `metadata` явно сбрасывает поле в `None`).
* `DELETE /api/v1/admin/products/:id` — удаление продукта (`Json<bool>`).
* `GET /api/v1/admin/orders?page=1&page_size=20&status=<OrderStatus>` — журнал заказов с пагинацией и фильтром по статусу.
* `GET /api/v1/admin/transactions?page=1&page_size=20` — аудит платёжных транзакций с пагинацией и `raw_request`.

### 7.2. Расширения в `users.rs`, `groups.rs` и `dto.rs`

* **Пользователи:** `AdminUserDto` содержит `email`, `has_password`, `telegram_id`, `balance`, `activated_at`, `expires_at`, `group_id`. `UpdateUserRequest` (`PATCH /api/v1/user/:id`) поддерживает `email`, `clear_email`, `password`, `clear_password`, `group_id`, `clear_group`.
* **Индивидуальные тарифы (`rates`):** `POST /api/v1/addrate` и `PATCH /api/v1/rate/:id` принимают `traffic_limit`, `speed_limit`, `sessions`, `date_end`; добавлен `DELETE /api/v1/rate/:id`.
* **Группы:** `CreateGroupRequest`, `UpdateGroupRequest` и `GroupDto` включают `is_default: bool`.

### 7.3. Покрытие тестами (`anet-auth/src/api/tests/`)

Реализованы 6 тестовых модулей на базе `sea_orm::MockDatabase` и `poem::Endpoint::call`:
* `mod.rs` — сборщик тестового `Route` (OpenAPI + `/billing/freekassa/notify`), генераторы мок-моделей и JWT.
* `user_auth_tests.rs` — Email-ссылки, верификация, `login`, `link-email`, проверка `HMAC-SHA256` Telegram TMA.
* `user_cabinet_tests.rs` — `/user/me`, `/user/products`, `/user/orders`, `/user/sessions`, `/user/sessions/disconnect`, `/user/traffic-history`, `/user/config`.
* `admin_billing_tests.rs` — CRUD `/admin/products`, пагинация `/admin/orders` и `/admin/transactions`, проверка `401` для неадминского JWT.
* `freekassa_tests.rs` — RFC-векторы MD5/HMAC-SHA256, проверка IP whitelist и подписи вебхука, идемпотентность и проверка суммы, создание ваучера при `is_gift`.
* `users_groups_auth_tests.rs` — админ-управление пользователями/тарифами/группами (`is_default`) и Smart Activation в `check_access`.

---

## 8. Пользовательский интерфейс (`User WebUI` & `Admin WebUI`)

### 8.1. Личный кабинет пользователя (`User WebUI`) — в Backlog (бэкенд готов)

Бэкенд `/api/v1/user/*` полностью готов для интеграции фронтенда Личного Кабинета:
* Авторизация по Email-ссылке / паролю и Telegram Mini App (`initData`).
* Карточка тарифа и состояния Smart Activation (`is_smart_activation_pending`, `activated_at`, `expires_at`).
* Получение `client.toml` и QR-кода (`/api/v1/user/config`).
* График потребления трафика (`/api/v1/user/traffic-history`) и активные сессии с кнопкой разрыва (`/api/v1/user/sessions*`).
* Витрина тарифов и переход на оплату FreeKassa (`/api/v1/user/products`, `/api/v1/user/orders`).

### 8.2. Панель управления администратора (`anet-webui`) — Реализовано

В `anet-webui` (Vue 3 + Vuetify 3 + TypeScript) реализованы и проверены (`oxlint`, `eslint`, `vue-tsc --build`, `vite build`):

1. **Актуализация пользователей, тарифов и групп:**
   * Удалены устаревшие поля `server_ids`, `pool_ids`, `route_map_id` / `clear_route_map` (`src/models/user.ts`, `src/composables/useUser.ts`, `src/components/UserForm.vue`, `src/components/CreateUserModal.vue`).
   * В `src/ui/Users.vue`, `src/components/UserModal.vue` и `src/components/UserForm.vue` добавлены:
     * привязка/изменение/очистка `email` (`clear_email`);
     * установка/смена/удаление пароля ЛК (`password`, `clear_password`, индикатор `has_password`);
     * передача `group_id` и `clear_group`;
     * просмотр `telegram_id`, `balance`, `activated_at`, `expires_at`;
     * столбец Email с индикаторами пароля и Telegram и расширенный поиск по UID / Email / Fingerprint.
   * В `src/models/rate.ts`, `src/api/rate.ts`, `src/composables/useRate.ts`, `src/components/RateCreateForm.vue`, `src/components/RateEditForm.vue` добавлены `traffic_limit` (ГБ -> байты), `speed_limit` (Мбит/с -> kbps), удаление индивидуального `Rate` (`DELETE /api/v1/rate/:id`) и преобразование `date_end` между `datetime-local` и форматом `YYYY-MM-DD-HH:mm`.
   * В `src/models/group.ts`, `src/components/GroupModal.vue`, `src/ui/Groups.vue` и `src/ui/GroupDetail.vue` добавлены переключатель и бейдж группы по умолчанию (`is_default`).
2. **Раздел Billing в боковом меню (`src/components/Navigation.vue`, `src/router/index.ts`, `src/models/billing.ts`, `src/api/billing.ts`):**
   * **Products (`/products` -> `src/ui/Products.vue`, `src/components/ProductModal.vue`):** CRUD каталога продуктов, выбор группы при `GroupSubscription`, цена, валюта (`Rub`, `Usd`, `Eur`, `Stars`), порядок сортировки `sort_order`, бейдж, JSON `metadata`, флаг `is_active`, явный сброс очищенных опциональных полей в `null`.
   * **Orders (`/orders` -> `src/ui/Orders.vue`):** серверная пагинация (`v-data-table-server`), фильтр по `OrderStatus`, подстановка названия продукта, пометка `Подарок` / `Себе` (`is_gift`), копирование UUID и диалог просмотра JSON `metadata`.
   * **Transactions (`/transactions` -> `src/ui/Transactions.vue`):** серверная пагинация аудит-лога платёжных шлюзов (`FreeKassa`, `Aaio`, `YooMoney`, `TelegramStars`), копирование `external_tx_id` и `order_id`, просмотр и копирование сырого `raw_request` JSON.

---

## 9. Функционал Phase 2 (Backlog / Дальнейшее развитие)

Следующие возможности заложены на уровне моделей базы данных и энумов, но вынесены в следующий этап:
1. **Фронтенд Личного Кабинета (User WebUI) и Telegram Mini App** поверх готового API `/api/v1/user/*`.
2. **Активация подарочных ваучеров и админ-реестр `Vouchers`:** API активации сгенерированного `ANET-GIFT-...`, интерфейс погашения в ЛК и раздел управления ваучерами в `anet-webui`.
3. **Индивидуальный конструктор тарифов (Subway sandwich):** ползунки количества сессий, трафика и скорости с динамическим расчётом цены и записью в `rates`.
4. **Дополнительные платёжные шлюзы:** интеграция Telegram Stars, Aaio и YooMoney.
