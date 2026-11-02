# Архитектура коммерческого модуля (Личный Кабинет, Биллинг, Лимиты)

Документация актуальна для ветки `master`.

---

## 1. Концептуальная модель: Единый Пользователь

Архитектура строится на принципе **«Один пользователь = Один криптографический ключ = Один профиль доступа»**. В системе нет привязки к оборудованию (HWID).

Сущность `User` (таблица `users`) объединяет в себе:
1. **Сетевую идентичность:** Криптографические ключи (ASTP), Fingerprint, выделенный статический IP (если назначен).
2. **Пользовательскую идентичность:** Email, Пароль, Telegram ID, Баланс.
3. **Статус подписки:** `group_id` (текущая группа доступа), `activated_at` (момент первой сетевой активности), `expires_at` (момент окончания платного периода).

Пользователь использует один и тот же конфигурационный файл (`client.toml` или QR-код) на всех своих устройствах (ноутбук, смартфон, роутер). Ограничение потребления ресурсов строится **исключительно на количестве одновременных сессий, лимите скорости и лимите трафика**.

Публичный Личный Кабинет пользователей обслуживается на домене сервиса (задается в конфигурации `server.toml` как `public_domain`, например: `https://service.example.com`).
*(Внутренняя панель управления администратора доступна на отдельном поддомене `cp.example.com` и закрыта от обычных пользователей)*.

---

### 1.1. Иерархия лимитов: Группы (`groups`) vs Индивидуальные тарифы (`rates`)

В кодовой базе заложено четкое разделение между базовыми групповыми планами и индивидуальными переопределениями:

```
                  ┌────────────────────────────────────────────────────────┐
                  │                 UserModel (users)                      │
                  │   - id, fingerprint, email, balance, group_id          │
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
      │ - is_default: bool        │                      │ (может быть создана/      │
      │ - duration_days: i32      │                      │  обновлена под user_id)   │
      │ - sessions_limit: i32     │                      │ - sessions: i32           │
      │ - traffic_limit: i64      │                      │ - speed_limit: i32        │
      │ - speed_limit: i32        │                      │ - traffic_limit: i64      │
      │ - Node Pools (привязка)   │                      │ - date_end: DateTime      │
      └───────────────────────────┘                      └───────────────────────────┘
                    ▲                                                  ▲
                    │                                                  │
             Базовые лимиты                                     OVERRIDE ПРИОРИТЕТ
       (по умолчанию из группы)                                (полное переопределение)
```

1. **Группы (`groups` — Предопределенные тарифные планы):**
   * Создаются и настраиваются администратором в Admin WebUI (например: тариф *«Бояре»*, *«Базовый»*, *«Гость»*).
   * Содержат в себе предустановленные параметры:
     * `is_default: bool` — флаг группы по умолчанию. Назначается новому пользователю при регистрации, а также активируется, когда у пользователя истекает оплаченный период (`expires_at < now`).
     * `duration_days: i32` — срок действия подписки (дельта в днях при активации).
     * `sessions_limit: i32` — количество одновременных сессий (0 = без лимита).
     * `traffic_limit: i64` — лимит трафика в байтах (0 = безлимит).
     * `speed_limit: i32` — ограничение скорости в kbps / Мбит/с (0 = максимальная скорость).
     * Привязка к пулам серверов (`group_node_pools`).
   * В каталоге товаров (`ProductModel`) базовый тариф оформляется как `ProductType::GroupSubscription`, где `target_id = Some(group_id)`. Все лимиты и длительность наследуются напрямую из связанной группы `groups`.

2. **Индивидуальные тарифы (`rates` — «Сэндвич в Subway» / Конструктор лимитов):**
   * Запись в `rates` привязана к `user_id` (1-к-1) и **может быть создана или обновлена** через API (`POST /addrate`, `PATCH /rate/:id`).
   * В биллинге `rates` используется для **динамического конструктора тарифов**: когда пользователь на витрине сам собирает себе индивидуальный пакет (выбирает желаемое число одновременных сессий, скорость, лимит гигабайт и срок действия).
   * В каталоге товаров конструктор оформляется как `ProductType::RateExtension`, где `target_id = None`. Все выбранные пользователем кастомные параметры сохраняются в `OrderModel.metadata` (JSONB).
   * После подтверждения оплаты бэкенд создает или обновляет запись в `rates` для данного `user_id`.
   * **Правило приоритета (Лестница приоритетов в `anet-auth/src/api/auth.rs`):**
     При авторизации клиента (`check_access`), если у пользователя существует активная запись в `rates` (`date_end > now()`), ее лимиты **полностью переопределяют (override)** любые групповые лимиты из `groups`!

---

### 1.2. Механизм вытеснения сессий (FIFO Disconnect)

Если пользователь имеет лимит в $N$ одновременных сессий, и сервер фиксирует попытку установки $(N+1)$-й сессии:
1. Новое входящее подключение **всегда одобряется** (приоритет новому подключению).
2. Сервер (через `ClientRegistry` ноды или координатор `anet-auth`) находит самую старую активную сессию данного `fingerprint` (сортировка по `created_at` ASC).
3. Сервер принудительно разрывает старую сессию, отправляя в транспорт (QUIC/TCP/WS/ASTP) команду закрытия со специфичной причиной:
   `"Session limit reached. Disconnected by newer connection."`.
4. **Реакция клиентских приложений (`anet-client-core`):**
   * Клиент **не выполняет автоматический reconnect** (чтобы предотвратить осцилляцию и циклическую войну двух устройств).
   * **В CLI:** Выводится сообщение `ERROR: Сессия завершена. Выполнен вход с другого устройства.` и процесс корректно завершается.
   * **В GUI / Android:** Туннель мгновенно останавливается, статус переходит в `Disconnected`, на экран выводится уведомление с пояснением.

---

### 1.3. Механизм первой сетевой активности (Smart Activation / ASTP Handshake)

В системе реализован принцип: **«Оплаченный срок не сгорает, пока пользователь фактически не подключился к VPN»**.

Техническая последовательность шагов:

```
[Клиент (GUI/CLI)]               [VPN Нода (anet-server)]           [Auth-сервер (anet-auth)]
        │                                  │                                  │
   1.   │─── ASTP / Noise Handshake ──────>│                                  │
        │    (передача открытого ключа)    │                                  │
   2.   │                                  │─── POST /check_access ──────────>│
        │                                  │    {fingerprint, node_id, ...}   │
   3.   │                                  │                                  │
        │                                  │   [Проверка User по fingerprint] │
        │                                  │   a) user.activated_at == None?  │
        │                                  │      -> now = Utc::now()         │
        │                                  │      -> activated_at = Some(now) │
        │                                  │      -> expires_at =             │
        │                                  │         now + group.duration_days│
        │                                  │      -> сохраняем в БД (users)   │
        │                                  │   b) now > user.expires_at?      │
        │                                  │      -> сброс group_id на        │
        │                                  │         default_group (Free/Блок)│
        │                                  │   c) проверка rates (оверрайд)   │
   4.   │                                  │<── CheckAccessResponse ──────────│
        │                                  │    {allowed: true, limits, ...}  │
   5.   │                                  │                                  │
        │                                  │─── Наложение eBPF шейпинга       │
   6.   │<── ASTP Handshake Complete ──────│                                  │
        │    (VPN Туннель поднят)          │                                  │
```

1. **Инициация:** Клиент инициирует ASTP/QUIC/WebRTC хэндшейк с нодой VPN-сервера (`anet-server`).
2. **Идентификация:** Нода извлекает открытый ключ клиента, вычисляет его криптографический `fingerprint` и отправляет авторизационный запрос на Auth-сервер:
   `POST /check_access` с телом `{"fingerprint": "...", "node_id": "...", "node_active_sessions": ...}`.
3. **Обработка в `anet-auth/src/api/auth.rs`:**
   * По `fingerprint` находится запись пользователя в `users`.
   * **Атомарность и защита от Race Condition:** Все операции проверки и изменения статуса пользователя выполняются в транзакции базы данных (`let txn = self.db.begin().await? ... txn.commit().await?`, аналог `transaction.atomic()`). Это защищает от ситуации, когда пользователь одновременно нажал «Подключиться» на двух устройствах и обе ноды прислали параллельные запросы:
     * Если `user.activated_at` равен `None` (первое подключение после оплаты):
       * Фиксируется момент старта: `user.activated_at = Some(Utc::now())`.
       * Вычисляется дедлайн: `user.expires_at = Some(Utc::now() + Duration::days(group.duration_days))`.
       * Запись сохраняется в транзакции: `user_active.update(&txn).await?`.
     * Если `user.expires_at` задан и `Utc::now() > expires_at`:
       * Платный период завершен.
       * `user.group_id` автоматически переключается на группу с флагом `is_default = true`.
       * Если в дефолтной группе доступ заблокирован (`sessions_limit == 0`), возвращается `{ allowed: false, message: "Подписка истекла" }`.
     * Проверяются персональные оверрайды: если у пользователя есть активная запись `rates` (`date_end > Utc::now()`), её параметры переопределяют групповые.
   * Транзакция фиксируется (`txn.commit().await?`).
4. **Ответ и шейпинг:** Auth-сервер возвращает структуру `CheckAccessResponse`. Нода применяет выданные параметры скорости через eBPF-шейпер на TUN-интерфейсе и успешно завершает сетевой хэндшейк.

---

## 2. Модель монетизации и Товары (Products)

Архитектура биллинга строится вокруг сущности **Product (Товар)** — витринного агрегатора платных услуг.

### 2.1. Отказ от избыточной сущности `subscriptions`

В ранних набросках биллинга предлагалась промежуточная таблица `subscriptions`. Однако в контексте архитектуры `anet` отдельная таблица подписок является **избыточным дублированием (overengineering)** по следующим причинам:
1. Ядро сети (`anet-server` и `anet-auth`) уже управляет доступом через `users.group_id`, `users.activated_at`, `users.expires_at` и `rates`.
2. Вся история платежей и покупок надежно хранится в `orders` (заказы) и `transactions` (сырой аудит шлюзов).
3. Продление существующего тарифа выполняется элементарной операцией сдвига даты:  
   `user.expires_at = user.expires_at + Duration::days(group.duration_days)`.
4. Для передачи тарифа в подарок другому лицу используется отдельная легковесная сущность `vouchers` (промокоды `ANET-GIFT-XXXX-XXXX`), которая после активации просто переключает `group_id` аккаунта получателя.

### 2.2. Типы продуктов (`ProductType`)

1. **`GroupSubscription` (Подписка на группу):**
   * Ссылается на существующую группу: `target_id = Some(group_id)`.
   * Срок действия (`duration_days`), число сессий, трафик, скорость и ноды наследуются напрямую из `groups`.
2. **`RateExtension` (Кастомный тариф / Сэндвич в Subway):**
   * `target_id = None`.
   * Параметры формируются динамически через калькулятор цен и сохраняются в `OrderModel.metadata`. После оплаты запись создается/обновляется в таблице `rates`.
3. **`Feature` (Дополнительные услуги):**
   * Выделенный статический IP-адрес, доступ к премиальным маршрутам и т.д.

---

## 3. Схема Базы Данных (SeaORM Entities)

### [AI-PROMPT]: Обязательное создание SeaORM миграций параллельно с сущностями

> ⚠️ **КРИТИЧЕСКОЕ ПРАВИЛО ДЛЯ AI-АГЕНТОВ (Gemini / Claude / Cursor):**
> 1. При создании или модификации любой структуры в `anet-auth/src/entities/` **ОБЯЗАТЕЛЬНО ПАРАЛЛЕЛЬНО** создавайте файл миграции в `anet-auth/src/migration/` (формат имени: `mYYYYMMDD_HHMMSS_<описание>.rs`).
> 2. Созданная миграция **ДОЛЖНА БЫТЬ СРАЗУ ЗАРЕГИСТРИРОВАНА** в векторе `Migrator::migrations()` внутри `anet-auth/src/migration/mod.rs`.
> 3. Миграции описываются строго через SeaQuery DSL (`Table::create()`, `Table::alter()`) либо через типизированный DDL. Никогда не оставляйте сущности без миграций, иначе при старте база данных упадет с ошибкой отсутствия колонок/таблиц!

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
    #[sea_orm(string_value = "RUB")]
    Rub,
    #[sea_orm(string_value = "USD")]
    Usd,
    #[sea_orm(string_value = "EUR")]
    Eur,
    #[sea_orm(string_value = "STARS")]
    Stars,
}

/// Поддерживаемые платежные шлюзы
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize, Enum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "payment_system")]
pub enum PaymentSystem {
    #[sea_orm(string_value = "freekassa")]
    FreeKassa,
    #[sea_orm(string_value = "aaio")]
    Aaio,
    #[sea_orm(string_value = "yoomoney")]
    YooMoney,
    #[sea_orm(string_value = "telegram_stars")]
    TelegramStars,
}

/// Жизненный цикл заказа
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize, Enum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "order_status")]
pub enum OrderStatus {
    #[sea_orm(string_value = "pending")]
    Pending,     /// Ожидает оплаты пользователем
    #[sea_orm(string_value = "paid")]
    Paid,        /// Успешно оплачен и услуга начислена
    #[sea_orm(string_value = "failed")]
    Failed,      /// Ошибка платежного шлюза
    #[sea_orm(string_value = "cancelled")]
    Cancelled,   /// Отменен пользователем или истек таймаут
    #[sea_orm(string_value = "refunded")]
    Refunded,    /// Чарджбэк / возврат средств
}

/// Тип продаваемого продукта
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize, Enum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "product_type")]
pub enum ProductType {
    /// Подписка на готовую группу (лимиты и duration_days берутся из groups)
    #[sea_orm(string_value = "group_subscription")]
    GroupSubscription,
    /// Кастомный тариф / доп. пакет (параметры из metadata пишутся в rates)
    #[sea_orm(string_value = "rate_extension")]
    RateExtension,
    /// Дополнительный модуль или фича (статический IP и т.д.)
    #[sea_orm(string_value = "feature")]
    Feature,
}

/// Статус подарочного ваучера
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize, Enum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "voucher_status")]
pub enum VoucherStatus {
    #[sea_orm(string_value = "created")]
    Created,
    #[sea_orm(string_value = "claimed")]
    Claimed,
    #[sea_orm(string_value = "revoked")]
    Revoked,
}

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
    /// Витринное наименование (например: "Тариф Бояре - 30 дней")
    pub name: String,
    /// Описание тарифа для карточки в ЛК
    pub description: String,
    /// Стоимость
    pub price: f64,
    /// Валюта (RUB, USD, STARS)
    pub currency: Currency,
    /// Тип продукта
    pub product_type: ProductType,
    /// Для GroupSubscription: Some(group_id), где лимиты и duration_days берутся из groups!
    /// Для RateExtension (кастомный конструктор): None, параметры хранятся в OrderModel.metadata
    pub target_id: Option<Uuid>,
    /// Порядок вывода на витрине
    pub sort_order: i32,
    /// Маркетинговый бейдж (например: "Хит", "Выгодно -20%", "VIP")
    pub badge: Option<String>,
    /// Дополнительные параметры в формате JSONB
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub metadata: Option<serde_json::Value>,
    /// Доступен ли товар к покупке
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
    /// Зафиксированная сумма к оплате
    pub amount: f64,
    pub currency: Currency,
    pub status: OrderStatus,
    /// Флаг подарка (true -> генерация Voucher, false -> активация на свой профиль)
    pub is_gift: bool,
    /// Для кастомных тарифов (Subway sandwich): {"sessions": 3, "speed": 100, "traffic_gb": 500, "days": 30}
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
    /// Ссылка на заказ (может быть Null, если шлюз прислал некорректный ID, но аудит пишется всегда)
    pub order_id: Option<Uuid>,
    pub payment_system: PaymentSystem,
    /// Внешний ID транзакции со стороны шлюза (например, intid во FreeKassa)
    pub external_tx_id: String,
    pub amount_received: f64,
    /// Полный сырой дамп тела запроса / формы для аудита и дебага
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
    /// Уникальный промокод (например: "ANET-GIFT-A8F2-99C1")
    #[sea_orm(unique)]
    pub code: String,
    pub product_id: Uuid,
    /// Пользователь, купивший подарок
    pub buyer_user_id: Option<Uuid>,
    /// Пользователь, активировавший ваучер
    pub claimed_by_user_id: Option<Uuid>,
    pub status: VoucherStatus,
    /// Резервное поле для будущих кастомных тарифов (RateExtension в подарок)
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
}

impl Related<super::products::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Product.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
```

---

## 4. Регистрация и Авторизация (WebUI & Telegram TMA)

### 4.1. Авторизация по Email (Пароли и ссылки)

1. **Запрос ссылки:** Пользователь указывает Email на странице входа Личного Кабинета.
2. **Токен подтверждения:** Бэкенд генерирует одноразовый токен (TTL = 15 минут), сохраняет его в таблице `verification_tokens` и отправляет письмо со ссылкой на публичный сервис:
   `https://service.example.com/auth/verify?token=XYZ`
3. **Установка пароля:** Пользователь вводит пароль (валидируется только длина $\ge 5$ символов).
4. **Создание профиля:**
   * Создается `UserModel`.
   * Генерируется ключевая пара ASTP и `fingerprint`.
   * Пользователю привязывается группа по умолчанию (`is_default = true`).
   * Поля `activated_at` и `expires_at` устанавливаются в `None` (ждет первого входа).
   * Возвращается сессионный JWT.

### 4.2. Бесшовная авторизация в Telegram Web App (TMA `initData`)

Параметр ключа `web_app_data_key` выносится в конфигурационный файл сервера `server.toml` (секция `[telegram]`):

```toml
# contrib/config/server.toml
[telegram]
bot_token = "123456789:ABCdefGHIjklMNOpqrsTUVwxyz"
web_app_data_key = "WebAppData" # Ключ для вычисления промежуточного HMAC по спецификации Telegram API
```

Функция криптографической проверки `initData`:

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::BTreeMap;

type HmacSha256 = Hmac<Sha256>;

/// Валидация подписи initData из Telegram WebApp
pub fn verify_telegram_init_data(
    init_data: &str,
    bot_token: &str,
    web_app_data_key: &[u8],
) -> Result<serde_json::Value, &'static str> {
    let mut params = BTreeMap::new();
    let mut received_hash = String::new();

    for part in init_data.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            let decoded_val = urlencoding::decode(v).map_err(|_| "Invalid urlencoding")?;
            if k == "hash" {
                received_hash = decoded_val.into_owned();
            } else {
                params.insert(k, decoded_val.into_owned());
            }
        }
    }

    if received_hash.is_empty() {
        return Err("Missing hash");
    }

    // 1. Формируем data_check_string (сортировка ключей по алфавиту)
    let data_check_string = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("\n");

    // 2. Секретный ключ: HMAC-SHA256(web_app_data_key из конфига, bot_token)
    let mut mac_secret = HmacSha256::new_from_slice(web_app_data_key).map_err(|_| "HMAC error")?;
    mac_secret.update(bot_token.as_bytes());
    let secret_key = mac_secret.finalize().into_bytes();

    // 3. Вычисление итогового хеша HMAC-SHA256(secret_key, data_check_string)
    let mut mac_data = HmacSha256::new_from_slice(&secret_key).map_err(|_| "HMAC error")?;
    mac_data.update(data_check_string.as_bytes());
    let expected_hash = hex::encode(mac_data.finalize().into_bytes());

    if expected_hash != received_hash {
        return Err("Invalid initData signature");
    }

    // 4. Извлекаем проверенные данные пользователя
    let user_str = params.get("user").ok_or("User field missing")?;
    let user_json: serde_json::Value = serde_json::from_str(user_str).map_err(|_| "Invalid user JSON")?;
    Ok(user_json)
}
```

### 4.3. Связка аккаунтов (Telegram TMA $\to$ Web-кабинет)

Если пользователь изначально зарегистрировался через Telegram-бота или Telegram Mini App (TMA):
1. Профиль создается мгновенно с `telegram_id: Some(id)`, а поля `email` и `password_hash` остаются `None` (пользователю не нужно придумывать пароль в Telegram).
2. Если в дальнейшем пользователь захочет войти в Личный Кабинет через браузер на компьютере:
   * В интерфейсе TMA (или по запросу боту) пользователь указывает свой рабочий Email.
   * Бэкенд генерирует токен верификации и отправляет на указанную почту ссылку для установки пароля:  
     `https://service.example.com/auth/verify?token=XYZ`
   * Пользователь переходит по ссылке и задает постоянный пароль.
   * Бэкенд сохраняет `email` и `password_hash` в существующую запись `users`.
   * Теперь учетная запись едина: пользователь может входить как через Telegram TMA в один клик, так и в браузере по логину и паролю.

---

## 5. Спецификация платежного шлюза FreeKassa (API v1 & Webhook)

### 5.1. Алгоритмы формирования и проверки подписей

1. **Генерация ссылки на оплату (SCI Form URL):**
   * URL: `https://pay.freekassa.ru/`
   * Строка подписи: `merchant_id:amount:secret1:currency:order_id`
   * Хэш: `md5(sign_string)` в нижнем регистре.
2. **Входящий вебхук уведомления (`/billing/freekassa/notify`):**
   * Строка подписи: `merchant_id:amount:secret2:order_id`
   * Хэш: `md5(sign_string)` в нижнем регистре.
   * **КРИТИЧЕСКИ ВАЖНО (Форматирование суммы в MD5):** Поле `form.amount` подставляется в строку подписи **СТРОГО как исходная сырая строка из тела POST-запроса от FreeKassa** (например, `"100.00"` или `"100"`). Ни в коем случае нельзя конвертировать сумму во `f64` или переформатировать перед генерацией хэша, иначе подпись не сойдется.
   * **Сверка суммы с заказом:** Для защиты от недоплаты сумма парсится во `f64` с допуском погрешности округления:
     ```rust
     let received_amount: f64 = form.amount.parse().unwrap_or(0.0);
     if (received_amount - order.amount).abs() > 0.01 {
         return Err(poem::Error::from_string("Amount mismatch", poem::http::StatusCode::BAD_REQUEST));
     }
     ```
   * **Атомарность (Database Transactions):** Обработка вебхука обязательно оборачивается в транзакцию БД (`let txn = self.db.begin().await? ... txn.commit().await?`). В рамках одной неделимой транзакции:
     1. Записывается аудит в таблицу `transactions` (включая `raw_request: JsonBinary`).
     2. Статус заказа в `orders` меняется на `Paid`.
     3. Начисляется услуга (назначается `user.group_id` с `activated_at = None`, либо обновляется запись `rates`).
     Если любая из операций завершилась с ошибкой, транзакция целиком откатывается, защищая БД от рассинхронизации.
   * Белый список IP-адресов FreeKassa: `168.119.157.136`, `168.119.60.227`, `138.201.88.124`, `178.154.197.79`.
   * Ответ шлюзу при успехе: строго строка `YES` с HTTP статусом 200.
3. **Фоновая проверка заказов через FreeKassa API v1 (`https://api.fk.life/v1/orders`):**
   * Согласно спецификации FreeKassa API (`getOrders`), подпись формируется по алгоритму **HMAC-SHA256**:
     1. Все поля запроса (кроме `signature`) сортируются в алфавитном порядке по ключам.
     2. Значения полей склеиваются через символ пайпа `|` (например: `nonce|orderId|shopId`).
     3. От полученной строки вычисляется `HMAC-SHA256` с использованием секретного `apiKey` (API-ключ из настроек ЛК FreeKassa).

### 5.2. Реализация фонового воркера FreeKassa

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sea_orm::{DatabaseConnection, EntityTrait, QueryFilter, ColumnTrait, ActiveModelTrait, Set};
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

pub async fn cron_sync_freekassa(db: DatabaseConnection) {
    let shop_id = std::env::var("FK_SHOP_ID").unwrap_or_default();
    let api_key = std::env::var("FK_API_KEY").unwrap_or_default();

    if shop_id.is_empty() || api_key.is_empty() {
        return;
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    loop {
        tokio::time::sleep(Duration::from_secs(900)).await;

        let threshold = chrono::Utc::now() - chrono::Duration::minutes(15);
        
        let pending_orders = match crate::entities::orders::Entity::find()
            .filter(crate::entities::orders::Column::Status.eq(crate::entities::billing_enums::OrderStatus::Pending))
            .filter(crate::entities::orders::Column::CreatedAt.lt(threshold))
            .all(&db)
            .await 
        {
            Ok(orders) => orders,
            Err(_) => continue,
        };

        for order in pending_orders {
            let nonce = chrono::Utc::now().timestamp_millis();
            let order_id_str = order.id.to_string();

            // Сортировка по ключам: nonce, orderId, shopId -> значения через "|"
            let sign_data = format!("{}|{}|{}", nonce, order_id_str, shop_id);
            
            let mut mac = match HmacSha256::new_from_slice(api_key.as_bytes()) {
                Ok(m) => m,
                Err(_) => continue,
            };
            mac.update(sign_data.as_bytes());
            let signature = hex::encode(mac.finalize().into_bytes());

            let request_body = serde_json::json!({
                "shopId": shop_id.parse::<i64>().unwrap_or(0),
                "nonce": nonce,
                "orderId": order_id_str,
                "signature": signature
            });

            let resp = client.post("https://api.fk.life/v1/orders")
                .json(&request_body)
                .send()
                .await;

            if let Ok(res) = resp {
                if let Ok(json) = res.json::<serde_json::Value>().await {
                    if json["type"].as_str() == Some("success") {
                        if let Some(status_num) = json["orders"][0]["status"].as_i64() {
                            if status_num == 1 {
                                // Оплачен -> начисляем услугу
                                let _ = fulfill_order(&db, order.id, "CRON_SYNC", json).await;
                            } else if status_num == 8 || status_num == 9 {
                                let mut active: crate::entities::orders::ActiveModel = order.into();
                                active.status = Set(crate::entities::billing_enums::OrderStatus::Cancelled);
                                let _ = active.update(&db).await;
                            }
                        }
                    }
                }
            }
        }
    }
}
```

---

## 6. Прототипы API Личного Кабинета (`anet-auth/src/api/user_cabinet.rs`)

```rust
// ============================================================================
// anet-auth/src/api/user_cabinet.rs
// ============================================================================

use poem_openapi::{
    auth::Bearer,
    payload::Json,
    ApiResponse, Object, OpenApi, SecurityScheme,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait,
    QueryFilter, QueryOrder, Set, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::{
    billing_enums::{Currency, OrderStatus, PaymentSystem, ProductType, VoucherStatus},
    groups, orders, products, rates, transactions, users, vouchers,
};

#[derive(SecurityScheme)]
#[oai(
    type = "bearer",
    key_name = "Authorization",
    in = "header",
    checker = "user_auth_checker"
)]
pub struct UserAuth(pub UserClaims);

#[derive(Clone, Debug)]
pub struct UserClaims {
    pub user_id: Uuid,
    pub fingerprint: String,
}

async fn user_auth_checker(_req: &poem::Request, bearer: Bearer) -> Option<UserClaims> {
    let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "secret".into());
    let mut validation = jsonwebtoken::Validation::default();
    validation.validate_exp = true;

    let token_data = jsonwebtoken::decode::<serde_json::Value>(
        &bearer.token,
        &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    ).ok()?;

    let sub = token_data.claims.get("sub")?.as_str()?;
    let fp = token_data.claims.get("fp").and_then(|v| v.as_str()).unwrap_or_default();

    Some(UserClaims {
        user_id: Uuid::parse_str(sub).ok()?,
        fingerprint: fp.to_string(),
    })
}

// ----------------------------------------------------------------------------
// DTOs
// ----------------------------------------------------------------------------

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct UserProfileResponse {
    pub id: Uuid,
    pub email: Option<String>,
    pub fingerprint: String,
    pub balance: f64,
    pub is_active: bool,
    pub group_name: Option<String>,
    pub activated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub is_smart_activation_pending: bool,
    pub effective_limits: EffectiveLimitsDto,
    pub gift_vouchers: Vec<VoucherDto>,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct EffectiveLimitsDto {
    pub source: String, // "rates" (индивидуальный) или "groups" (группа)
    pub sessions_limit: i32,
    pub speed_limit_kbps: i32,
    pub traffic_limit_bytes: i64,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct VoucherDto {
    pub id: Uuid,
    pub code: String,
    pub product_name: String,
    pub status: VoucherStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct ActiveSessionDto {
    pub session_id: String,
    pub server_id: Uuid,
    pub server_name: String,
    pub client_ip: String,
    pub transport: String,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
    pub connected_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct DisconnectSessionRequest {
    pub server_id: Uuid,
    pub session_id: String,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct ClaimVoucherRequest {
    pub code: String,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct CalculateRateRequest {
    pub sessions: i32,
    pub speed_mbps: i32,
    pub traffic_gb: i64,
    pub duration_days: i32,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct CalculateRateResponse {
    pub calculated_price: f64,
    pub currency: Currency,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct ClientConfigResponse {
    pub client_toml: String,
    pub qr_code_url: String,
}

// ----------------------------------------------------------------------------
// API Controller
// ----------------------------------------------------------------------------

pub struct UserCabinetApi {
    pub db: DatabaseConnection,
}

#[OpenApi]
impl UserCabinetApi {
    /// Получение профиля, баланса и действующих лимитов пользователя
    #[oai(path = "/api/v1/user/me", method = "get")]
    async fn get_me(&self, auth: UserAuth) -> poem::Result<Json<UserProfileResponse>> {
        let user = users::Entity::find_by_id(auth.0.user_id)
            .one(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or_else(|| poem::Error::from_string("User not found", poem::http::StatusCode::NOT_FOUND))?;

        // 1. Проверяем наличие индивидуального тарифа rates
        let user_rate = rates::Entity::find()
            .filter(rates::Column::UserId.eq(user.id))
            .one(&self.db)
            .await
            .unwrap_or(None);

        let now = chrono::Utc::now().naive_utc();
        let (effective_limits, group_name) = if let Some(rate) = user_rate.filter(|r| r.date_end > now) {
            (
                EffectiveLimitsDto {
                    source: "rates".into(),
                    sessions_limit: rate.sessions,
                    speed_limit_kbps: rate.speed_limit,
                    traffic_limit_bytes: rate.traffic_limit,
                },
                Some("Индивидуальный тариф".into()),
            )
        } else if let Some(group_id) = user.group_id {
            let group = groups::Entity::find_by_id(group_id).one(&self.db).await.unwrap_or(None);
            if let Some(g) = group {
                (
                    EffectiveLimitsDto {
                        source: "groups".into(),
                        sessions_limit: g.sessions_limit,
                        speed_limit_kbps: g.speed_limit,
                        traffic_limit_bytes: g.traffic_limit,
                    },
                    Some(g.name),
                )
            } else {
                (
                    EffectiveLimitsDto {
                        source: "default".into(),
                        sessions_limit: 1,
                        speed_limit_kbps: 0,
                        traffic_limit_bytes: 0,
                    },
                    None,
                )
            }
        } else {
            (
                EffectiveLimitsDto {
                    source: "unlimited".into(),
                    sessions_limit: 0,
                    speed_limit_kbps: 0,
                    traffic_limit_bytes: 0,
                },
                None,
            )
        };

        // 2. Подарочные ваучеры пользователя
        let vouchers = vouchers::Entity::find()
            .filter(vouchers::Column::BuyerUserId.eq(Some(user.id)))
            .filter(vouchers::Column::Status.eq(VoucherStatus::Created))
            .find_also_related(products::Entity)
            .all(&self.db)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|(v, p)| VoucherDto {
                id: v.id,
                code: v.code,
                product_name: p.map(|x| x.name).unwrap_or_else(|| "Подарок".into()),
                status: v.status,
                created_at: v.created_at,
            })
            .collect();

        let is_pending = user.activated_at.is_none() && user.group_id.is_some();

        Ok(Json(UserProfileResponse {
            id: user.id,
            email: user.email,
            fingerprint: user.fingerprint,
            balance: user.balance,
            is_active: user.is_active,
            group_name,
            activated_at: user.activated_at,
            expires_at: user.expires_at,
            is_smart_activation_pending: is_pending,
            effective_limits,
            gift_vouchers: vouchers,
        }))
    }

    /// Активные сессии пользователя со всех серверов
    #[oai(path = "/api/v1/user/sessions", method = "get")]
    async fn get_active_sessions(&self, auth: UserAuth) -> poem::Result<Json<Vec<ActiveSessionDto>>> {
        // [AI-PROMPT]: Возвращает активные сессии пользователя по его fingerprint
        Ok(Json(vec![]))
    }

    /// Принудительный сброс конкретной сессии
    #[oai(path = "/api/v1/user/sessions/disconnect", method = "post")]
    async fn disconnect_session(
        &self,
        auth: UserAuth,
        req: Json<DisconnectSessionRequest>,
    ) -> poem::Result<Json<bool>> {
        // [AI-PROMPT]: Отправка DisconnectCommand на ноду
        Ok(Json(true))
    }

    /// Активация подарочного ваучера
    #[oai(path = "/api/v1/user/vouchers/claim", method = "post")]
    async fn claim_voucher(
        &self,
        auth: UserAuth,
        req: Json<ClaimVoucherRequest>,
    ) -> poem::Result<Json<bool>> {
        let txn = self.db.begin().await
            .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?;

        let voucher = vouchers::Entity::find()
            .filter(vouchers::Column::Code.eq(req.code.trim().to_uppercase()))
            .filter(vouchers::Column::Status.eq(VoucherStatus::Created))
            .one(&txn)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or_else(|| poem::Error::from_string("Неверный промокод или уже активирован", poem::http::StatusCode::BAD_REQUEST))?;

        let product = products::Entity::find_by_id(voucher.product_id)
            .one(&txn)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or_else(|| poem::Error::from_string("Товар не найден", poem::http::StatusCode::NOT_FOUND))?;

        let user = users::Entity::find_by_id(auth.0.user_id)
            .one(&txn)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or_else(|| poem::Error::from_string("User not found", poem::http::StatusCode::NOT_FOUND))?;

        // Применяем купленный продукт к пользователю
        if let Some(target_group_id) = product.target_id {
            let mut u_active: users::ActiveModel = user.into();
            u_active.group_id = Set(Some(target_group_id));
            u_active.activated_at = Set(None); // Сброс даты: активируется при первом коннекте!
            u_active.expires_at = Set(None);
            u_active.update(&txn).await
                .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?;
        }

        // Помечаем ваучер активированным
        let mut v_active: vouchers::ActiveModel = voucher.into();
        v_active.status = Set(VoucherStatus::Claimed);
        v_active.claimed_by_user_id = Set(Some(auth.0.user_id));
        v_active.claimed_at = Set(Some(chrono::Utc::now()));
        v_active.update(&txn).await
            .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?;

        txn.commit().await
            .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?;

        Ok(Json(true))
    }

    /// Динамический калькулятор тарифа «Сэндвич в Subway» (настройки берутся из БД)
    #[oai(path = "/api/v1/user/rate/calculate", method = "post")]
    async fn calculate_custom_rate(
        &self,
        _auth: UserAuth,
        req: Json<CalculateRateRequest>,
    ) -> poem::Result<Json<CalculateRateResponse>> {
        // [AI-PROMPT]: Тарифная сетка запрашивается из системной таблицы настроек (settings / pricing_matrix):
        // base_day_cost, session_day_cost, gb_cost, speed_factor. Никакого хардкода в методе!
        let base_per_day = 3.0;
        let session_cost_per_day = (req.sessions.max(1) - 1) as f64 * 1.5;
        let traffic_cost = (req.traffic_gb as f64 / 10.0) * 2.0;
        let total = (base_per_day + session_cost_per_day) * (req.duration_days.max(1) as f64) + traffic_cost;

        Ok(Json(CalculateRateResponse {
            calculated_price: (total * 100.0).round() / 100.0,
            currency: Currency::Rub,
        }))
    }

    /// Получение client.toml и ссылки на QR-код
    #[oai(path = "/api/v1/user/config", method = "get")]
    async fn get_client_config(&self, auth: UserAuth) -> poem::Result<Json<ClientConfigResponse>> {
        let user = users::Entity::find_by_id(auth.0.user_id)
            .one(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or_else(|| poem::Error::from_string("User not found", poem::http::StatusCode::NOT_FOUND))?;

        let auth_host = std::env::var("PUBLIC_DOMAIN").unwrap_or_else(|_| "https://service.example.com".into());
        let toml_content = format!(
            "# Anet Client Config\nfingerprint = \"{}\"\nauth_server = \"{}\"\n",
            user.fingerprint, auth_host
        );

        Ok(Json(ClientConfigResponse {
            client_toml: toml_content,
            qr_code_url: format!("{}/api/v1/config/qr/{}", auth_host, user.fingerprint),
        }))
    }
}
```

---

## 7. Прототипы API Администратора (`anet-auth/src/api/admin_billing.rs`)

Все эндпоинты защищены административным JWT (`AdminAuth`).

```rust
// ============================================================================
// anet-auth/src/api/admin_billing.rs
// ============================================================================

use poem_openapi::{
    auth::Bearer,
    param::Query,
    payload::Json,
    ApiResponse, Object, OpenApi, SecurityScheme,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait,
    QueryFilter, QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::{
    billing_enums::{Currency, OrderStatus, PaymentSystem, ProductType},
    orders, products, transactions, vouchers,
};

#[derive(SecurityScheme)]
#[oai(
    type = "bearer",
    key_name = "Authorization",
    in = "header",
    checker = "admin_auth_checker"
)]
pub struct AdminAuth(pub Uuid);

async fn admin_auth_checker(_req: &poem::Request, bearer: Bearer) -> Option<Uuid> {
    let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "secret".into());
    let token_data = jsonwebtoken::decode::<serde_json::Value>(
        &bearer.token,
        &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
        &jsonwebtoken::Validation::default(),
    ).ok()?;

    let sub = token_data.claims.get("sub")?.as_str()?;
    Uuid::parse_str(sub).ok()
}

// ----------------------------------------------------------------------------
// DTOs
// ----------------------------------------------------------------------------

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
pub struct AdminOrderDto {
    pub id: Uuid,
    pub user_id: Uuid,
    pub product_id: Uuid,
    pub amount: f64,
    pub currency: Currency,
    pub status: OrderStatus,
    pub is_gift: bool,
    pub metadata: Option<serde_json::Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct PaginatedResponse<T: poem_openapi::types::Type + Send + Sync + 'static> {
    pub items: Vec<T>,
    pub total: u64,
    pub page: u64,
    pub page_size: u64,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct AdminTransactionDto {
    pub id: Uuid,
    pub order_id: Option<Uuid>,
    pub payment_system: PaymentSystem,
    pub external_tx_id: String,
    pub amount_received: f64,
    pub raw_request: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// ----------------------------------------------------------------------------
// API Controller
// ----------------------------------------------------------------------------

pub struct AdminBillingApi {
    pub db: DatabaseConnection,
}

#[OpenApi]
impl AdminBillingApi {
    // ------------------------------------------------------------------------
    // CRUD: Products
    // ------------------------------------------------------------------------

    #[oai(path = "/api/v1/admin/products", method = "get")]
    async fn list_products(&self, _auth: AdminAuth) -> poem::Result<Json<Vec<products::Model>>> {
        let items = products::Entity::find()
            .order_by_asc(products::Column::SortOrder)
            .all(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?;
        Ok(Json(items))
    }

    #[oai(path = "/api/v1/admin/products", method = "post")]
    async fn create_product(
        &self,
        _auth: AdminAuth,
        req: Json<CreateProductRequest>,
    ) -> poem::Result<Json<products::Model>> {
        let now = chrono::Utc::now();
        let new_prod = products::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(req.name.clone()),
            description: Set(req.description.clone()),
            price: Set(req.price),
            currency: Set(req.currency),
            product_type: Set(req.product_type),
            target_id: Set(req.target_id),
            sort_order: Set(req.sort_order.unwrap_or(0)),
            badge: Set(req.badge.clone()),
            metadata: Set(req.metadata.clone()),
            is_active: Set(req.is_active),
            created_at: Set(now),
            updated_at: Set(now),
        };

        let inserted = new_prod.insert(&self.db).await
            .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?;
        Ok(Json(inserted))
    }

    #[oai(path = "/api/v1/admin/products/:id", method = "patch")]
    async fn update_product(
        &self,
        _auth: AdminAuth,
        id: poem_openapi::param::Path<Uuid>,
        req: Json<UpdateProductRequest>,
    ) -> poem::Result<Json<products::Model>> {
        let prod = products::Entity::find_by_id(id.0)
            .one(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or_else(|| poem::Error::from_string("Product not found", poem::http::StatusCode::NOT_FOUND))?;

        let mut active: products::ActiveModel = prod.into();
        if let Some(v) = &req.name { active.name = Set(v.clone()); }
        if let Some(v) = &req.description { active.description = Set(v.clone()); }
        if let Some(v) = req.price { active.price = Set(v); }
        if let Some(v) = req.currency { active.currency = Set(v); }
        if let Some(v) = req.product_type { active.product_type = Set(v); }
        if let Some(v) = req.target_id { active.target_id = Set(v); }
        if let Some(v) = req.sort_order { active.sort_order = Set(v); }
        if let Some(v) = &req.badge { active.badge = Set(v.clone()); }
        if let Some(v) = &req.metadata { active.metadata = Set(v.clone()); }
        if let Some(v) = req.is_active { active.is_active = Set(v); }
        active.updated_at = Set(chrono::Utc::now());

        let updated = active.update(&self.db).await
            .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?;
        Ok(Json(updated))
    }

    #[oai(path = "/api/v1/admin/products/:id", method = "delete")]
    async fn delete_product(
        &self,
        _auth: AdminAuth,
        id: poem_openapi::param::Path<Uuid>,
    ) -> poem::Result<Json<bool>> {
        products::Entity::delete_by_id(id.0).exec(&self.db).await
            .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?;
        Ok(Json(true))
    }

    // ------------------------------------------------------------------------
    // Журнал Заказов (Orders)
    // ------------------------------------------------------------------------

    #[oai(path = "/api/v1/admin/orders", method = "get")]
    async fn list_orders(
        &self,
        _auth: AdminAuth,
        page: Query<Option<u64>>,
        page_size: Query<Option<u64>>,
        status: Query<Option<OrderStatus>>,
    ) -> poem::Result<Json<PaginatedResponse<AdminOrderDto>>> {
        let page = page.0.unwrap_or(1);
        let page_size = page_size.0.unwrap_or(20);

        let mut query = orders::Entity::find();
        if let Some(st) = status.0 {
            query = query.filter(orders::Column::Status.eq(st));
        }

        let paginator = query.order_by_desc(orders::Column::CreatedAt).paginate(&self.db, page_size);
        let total = paginator.num_items().await.unwrap_or(0);
        let items = paginator.fetch_page(page.saturating_sub(1)).await
            .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?
            .into_iter()
            .map(|o| AdminOrderDto {
                id: o.id,
                user_id: o.user_id,
                product_id: o.product_id,
                amount: o.amount,
                currency: o.currency,
                status: o.status,
                is_gift: o.is_gift,
                metadata: o.metadata,
                created_at: o.created_at,
                updated_at: o.updated_at,
            })
            .collect();

        Ok(Json(PaginatedResponse { items, total, page, page_size }))
    }

    // ------------------------------------------------------------------------
    // Журнал Транзакций и Аудита (Transactions)
    // ------------------------------------------------------------------------

    #[oai(path = "/api/v1/admin/transactions", method = "get")]
    async fn list_transactions(
        &self,
        _auth: AdminAuth,
        page: Query<Option<u64>>,
        page_size: Query<Option<u64>>,
    ) -> poem::Result<Json<PaginatedResponse<AdminTransactionDto>>> {
        let page = page.0.unwrap_or(1);
        let page_size = page_size.0.unwrap_or(20);

        let paginator = transactions::Entity::find()
            .order_by_desc(transactions::Column::CreatedAt)
            .paginate(&self.db, page_size);

        let total = paginator.num_items().await.unwrap_or(0);
        let items = paginator.fetch_page(page.saturating_sub(1)).await
            .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?
            .into_iter()
            .map(|t| AdminTransactionDto {
                id: t.id,
                order_id: t.order_id,
                payment_system: t.payment_system,
                external_tx_id: t.external_tx_id,
                amount_received: t.amount_received,
                raw_request: t.raw_request,
                created_at: t.created_at,
            })
            .collect();

        Ok(Json(PaginatedResponse { items, total, page, page_size }))
    }

    // ------------------------------------------------------------------------
    // Реестр Ваучеров (Vouchers)
    // ------------------------------------------------------------------------

    #[oai(path = "/api/v1/admin/vouchers", method = "get")]
    async fn list_vouchers(
        &self,
        _auth: AdminAuth,
        page: Query<Option<u64>>,
        page_size: Query<Option<u64>>,
    ) -> poem::Result<Json<PaginatedResponse<vouchers::Model>>> {
        let page = page.0.unwrap_or(1);
        let page_size = page_size.0.unwrap_or(20);

        let paginator = vouchers::Entity::find()
            .order_by_desc(vouchers::Column::CreatedAt)
            .paginate(&self.db, page_size);

        let total = paginator.num_items().await.unwrap_or(0);
        let items = paginator.fetch_page(page.saturating_sub(1)).await
            .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?;

        Ok(Json(PaginatedResponse { items, total, page, page_size }))
    }
}
```

---

## 8. Telegram Bot & TMA (Phase 2)

Разработка Telegram-бота начинается после стабилизации WebUI и API биллинга. Бот выступает интерфейсной надстройкой, вызывающей WebUI внутри **Telegram Web Apps (TMA)**:
1. Пользователь нажимает `/start` или кнопку меню «Личный кабинет».
2. Открывается защищенный webview с адресом `https://service.example.com/tma`.
3. Фронтенд автоматически передает `window.Telegram.WebApp.initData` на бэкенд `/api/v1/auth/telegram_tma`.
4. Бэкенд верифицирует криптографическую подпись через `verify_telegram_init_data`, связывает `telegram_id` с пользователем и выдает сессионный JWT.
5. Пользователь получает полный доступ к ЛК: скачивание конфига, завершение сессий, конструктор тарифов и оплата (включая Telegram Stars).

---

## 9. Пользовательский интерфейс (User WebUI & Admin Panel)

### 9.1. Личный кабинет пользователя (User Dashboard)
* **Витрина тарифов:** Переключение между готовыми тарифами (группами) и интерактивным калькулятором лимитов (Subway sandwich). Переключатель «Купить себе» / «Купить в подарок».
* **Инвентарь подарков:** Список неактивированных подарочных промокодов с кнопкой «Скопировать».
* **Управление сессиями:** Таблица устройств с информацией о подключении, типе транспорта (QUIC, WS, WRTC) и кнопкой принудительного разрыва «Завершить сессию».
* **Конфигурация:** Кнопка «Скачать client.toml» и генератор QR-кода для мобильных клиентов.

### 9.2. Панель управления администратора (Admin WebUI)
* **Вкладка Products:** Каталог платных услуг с возможностью привязки к `target_id` (группам), настройкой сортировки, цен и бейджей.
* **Вкладка Orders:** Мониторинг воронки оплат, ручная смена статусов, фильтрация по датам и пользователям.
* **Вкладка Transactions:** Аудит-лог платежей со всплывающим окном полного дампа входящего вебхука (`raw_request`) для быстрого разрешения спорных транзакций.
* **Вкладка Vouchers:** Реестр подарочных промокодов с информацией о покупателях и активировавших пользователях.