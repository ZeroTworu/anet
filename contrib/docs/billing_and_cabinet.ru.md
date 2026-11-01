# Архитектура коммерческого модуля (Личный Кабинет, Биллинг, Лимиты)

Документация актуальна для ветки `master`.

---

## 1. Концептуальная модель: Единый Пользователь

Архитектура строится на принципе **«Один пользователь = Один криптографический ключ = Одна подписка»**. В системе нет привязки к оборудованию (HWID).

Сущность `User` (таблица `users`) объединяет в себе:
1. **Сетевую идентичность:** Криптографические ключи (ASTP), Fingerprint, выделенный статический IP (если назначен).
2. **Пользовательскую идентичность:** Email, Password, Telegram ID, Баланс.

Пользователь использует один и тот же конфигурационный файл (`client.toml` или QR-код) на всех своих устройствах (ноутбук, смартфон, роутер). Ограничение потребления ресурсов строится **исключительно на количестве одновременных сессий, лимите скорости и лимите трафика**.

---

### 1.1. Иерархия лимитов: Группы (`groups`) vs Индивидуальные тарифы (`rates`)

В кодовой базе исторически заложено разделение между базовыми тарифными планами и гибкими пользовательскими оверрайдами:

```
                  ┌────────────────────────────────────────────────────────┐
                  │                 UserModel (users)                      │
                  │   - id, fingerprint, email, balance, group_id          │
                  └───────────────────────────┬────────────────────────────┘
                                              │
                    ┌─────────────────────────┴────────────────────────┐
                    ▼                                                  ▼
      ┌───────────────────────────┐                      ┌───────────────────────────┐
      │       groups (План)       │                      │   rates (Кастом/Сэндвич)  │
      ├───────────────────────────┤                      ├───────────────────────────┤
      │ Predefined в админке      │                      │ Dynamic (создается на лету│
      │ - duration_days: i32      │                      │   под user_id)            │
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
   * Создаются и настраиваются администратором в Admin WebUI (например: тариф *«Бояре»*, *«Базовый»*, *«Корпоративный»*).
   * Содержат в себе предустановленные параметры:
     * `duration_days: i32` — срок действия подписки (в днях).
     * `sessions_limit: i32` — количество одновременных сессий (0 = без лимита).
     * `traffic_limit: i64` — лимит трафика в байтах/ГБ (0 = безлимит).
     * `speed_limit: i32` — ограничение скорости в Мбит/с (0 = максимальная скорость).
     * Привязка к пулам серверов (`node_pools`).
   * В каталоге товаров (`ProductModel`) базовый тариф оформляется как `ProductType::GroupSubscription`, где `target_id = Some(group_id)`. Поля лимитов и срока действия берутся напрямую из связанной группы (`groups`), не дублируясь в продукте.

2. **Индивидуальные тарифы (`rates` — «Сэндвич в Subway» / Конструктор лимитов):**
   * Изначально сущность `rates` создавалась как персональная запись ограничений конкретного пользователя (`user_id`).
   * В биллинге `rates` используется для **динамического конструктора тарифов**: пользователь на витрине может сам собрать себе индивидуальный пакет (выбрать нужное количество одновременных сессий, скорость, лимит гигабайт и срок действия).
   * В каталоге товаров конструктор или докупка пакета оформляется как `ProductType::RateExtension`, где `target_id = None`. Все выбранные пользователем кастомные параметры сохраняются в `OrderModel.metadata` (JSONB).
   * После оплаты система не трогает таблицу `groups`, а создает или обновляет запись в `rates` для данного `user_id`.
   * **Правило приоритета (Auth Provider):** При авторизации сетевого подключения в `anet-server/src/auth_provider.rs`, если у пользователя существует активная запись в `rates` (`date_end > now()`), ее лимиты **полностью переопределяют (override)** любые групповые лимиты из `groups`.

---

### 1.2. Механизм вытеснения сессий (FIFO Disconnect)

Если пользователь имеет лимит в $N$ одновременных сессий, и сервер фиксирует попытку установки $(N+1)$-й сессии:
1. Новое входящее подключение **всегда одобряется** (приоритет новому подключению).
2. Сервер (через `ClientRegistry` ноды или координатор `anet-auth`) находит самую старую активную сессию данного `fingerprint` (сортировка по `created_at` ASC).
3. Сервер принудительно разрывает старую сессию, отправляя в транспорт (QUIC/TCP/WS/ASTP) команду закрытия со специфичной причиной:
   `"Session limit reached. Disconnected by newer connection."`.
4. **Реакция клиентских приложений (`anet-client-core`):**
   * При получении этой причины разрыва клиент **ни в коем случае не пытается делать автоматический reconnect** (чтобы предотвратить осцилляцию и циклическую войну двух устройств).
   * **В CLI:** Выводится сообщение `ERROR: Сессия завершена. Выполнен вход с другого устройства.` и процесс корректно завершается с кодом 0.
   * **В GUI / Android:** Туннель мгновенно останавливается, статус переходит в `Disconnected`, на экран выводится модальное уведомление с пояснением.

---

## 2. Модель монетизации и Товары (Products)

Архитектура биллинга строится вокруг универсальной сущности **Product (Товар)** — витринного агрегатора платных услуг.

### 2.1. Типы продуктов (`ProductType`)

1. **`GroupSubscription` (Подписка на группу):**
   * Ссылается на существующую группу: `target_id = Some(group_id)`.
   * Все параметры (длительность в днях, число сессий, трафик, скорость, доступные ноды) наследуются из `groups`.
2. **`RateExtension` (Кастомный тариф / Дополнительный пакет):**
   * `target_id = None`.
   * Параметры формируются динамически через калькулятор цен (Subway sandwich builder) и сохраняются в `OrderModel.metadata`. После оплаты обновляется таблица `rates`.
3. **`Feature` (Дополнительные услуги):**
   * Выделенный статический IP-адрес, доступ к премиальным маршрутам, BGP-маршрутизация и т.д.

### 2.2. Подарки и Ваучеры (`is_gift`)

* **Покупка для себя (`is_gift = false`):**
  После подтверждения оплаты заказ сразу генерирует запись `SubscriptionModel` со статусом `pending` в инвентаре пользователя.
* **Покупка в подарок (`is_gift = true`):**
  После оплаты генерируется запись `VoucherModel` с уникальным кодом формата `ANET-GIFT-XXXX-XXXX`. Покупатель видит ваучер в ЛК и может скопировать ссылку/код для передачи другу. При активации ваучера другим пользователем создается подписка на аккаунте активировавшего.

### 2.3. Отложенная активация (Smart Activation)

Срок действия купленной подписки отсчитывается **не с момента оплаты, а с момента первой фактической активности (первого сетевого подключения)**:
1. После оплаты подписка получает статус `pending`, а в поле `duration_days` фиксируется срок действия (из группы или заказа).
2. При первом успешном ASTP-хэндшейке на VPN-сервере сервис авторизации переводит подписку в статус `active`, проставляя:
   * `activated_at = Utc::now()`
   * `expires_at = Utc::now() + Duration::days(duration_days)`

---

## 3. Схема Базы Данных (SeaORM Entities)

### [AI-PROMPT]: Обязательное создание SeaORM миграций параллельно с сущностями

> ⚠️ **КРИТИЧЕСКОЕ ПРАВИЛО ДЛЯ AI-АГЕНТОВ (Gemini / Claude / Cursor):**
> 1. При создании или модификации любой структуры в `anet-auth/src/entities/` **ОБЯЗАТЕЛЬНО ПАРАЛЛЕЛЬНО** создавайте файл миграции в `anet-auth/src/migration/` (формат имени: `mYYYYMMDD_HHMMSS_<описание>.rs`).
> 2. Созданная миграция **ДОЛЖНА БЫТЬ СРАЗУ ЗАРЕГИСТРИРОВАНА** в векторе `Migrator::migrations()` внутри `anet-auth/src/migration/mod.rs`.
> 3. Миграции описываются строго через SeaQuery DSL (`Table::create()`) либо через типизированный DDL. Никогда не оставляйте сущности без соответствующих миграций, иначе при развертывании база данных упадет с ошибкой отсутствия таблиц!

```rust
// ============================================================================
// anet-auth/src/entities/billing_enums.rs
// ============================================================================

use poem_openapi::Enum;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

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

// ============================================================================
// anet-auth/src/entities/products.rs
// ============================================================================

use super::billing_enums::ProductType;
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
    pub currency: String,
    /// Тип продукта
    pub product_type: ProductType,
    /// Для GroupSubscription: Some(group_id), где лимиты и duration_days берутся из groups!
    /// Для RateExtension (кастомный конструктор): None, лимиты хранятся в OrderModel.metadata
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

use super::billing_enums::OrderStatus;
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
    pub currency: String,
    pub status: OrderStatus,
    /// Флаг подарка (true -> генерация Voucher, false -> Pending Subscription)
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
// anet-auth/src/entities/subscriptions.rs
// ============================================================================

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "subscriptions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub user_id: Uuid,
    pub product_id: Uuid,
    /// Статус: "pending" (куплена, ждет 1-го входа), "active", "expired", "cancelled"
    pub status: String,
    /// Зафиксированный срок действия в днях (до момента активации)
    pub duration_days: Option<i32>,
    /// Момент первой сетевой активности (ASTP Handshake)
    pub activated_at: Option<DateTimeUtc>,
    /// Момент истечения (activated_at + duration_days)
    pub expires_at: Option<DateTimeUtc>,
    pub created_at: DateTimeUtc,
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
// anet-auth/src/entities/vouchers.rs
// ============================================================================

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
    /// "created", "claimed", "revoked"
    pub status: String,
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

### 4.1. Авторизация по Email (OTP / Passwordless Link)

Для доставки писем в РФ используется крейт `lettre` через корпоративные SMTP-серверы (VK WorkMail, Yandex 360, Beget) без зависимости от блокируемых зарубежных провайдеров.

1. **Запрос ссылки:** Пользователь указывает Email на странице входа.
2. **Токен подтверждения:** Бэкенд генерирует криптостойкий одноразовый токен (TTL = 15 минут), сохраняет его в таблице `verification_tokens` и отправляет ссылку `https://cp.anet-project.org/auth/verify?token=XYZ`.
3. **Установка пароля:** Пользователь задает пароль (валидируется только длина $\ge 5$ знаков).
4. **Создание профиля:** Бэкенд создает `UserModel`, генерирует пару ключей ASTP, присваивает `fingerprint` и отдает сессионный JWT.

### 4.2. Бесшовная авторизация в Telegram Web App (TMA `initData`)

Для пользователей Telegram Mini App вход происходит прозрачно без ввода логина и пароля через валидацию подписи Telegram WebApp:

```rust
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

type HmacSha256 = Hmac<Sha256>;

/// Валидация подписи initData из Telegram WebApp согласно спецификации Telegram Bot API
pub fn verify_telegram_init_data(init_data: &str, bot_token: &str) -> Result<serde_json::Value, &'static str> {
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

    // 1. Формируем data_check_string (сортировка по ключам в алфавитном порядке)
    let data_check_string = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("\n");

    // 2. Секретный ключ: HMAC-SHA256("WebAppData", bot_token)
    let mut mac_secret = HmacSha256::new_from_slice(b"WebAppData").map_err(|_| "HMAC error")?;
    mac_secret.update(bot_token.as_bytes());
    let secret_key = mac_secret.finalize().into_bytes();

    // 3. Вычисление итогового хеша HMAC-SHA256(secret_key, data_check_string)
    let mut mac_data = HmacSha256::new_from_slice(&secret_key).map_err(|_| "HMAC error")?;
    mac_data.update(data_check_string.as_bytes());
    let expected_hash = hex::encode(mac_data.finalize().into_bytes());

    if expected_hash != received_hash {
        return Err("Invalid initData signature");
    }

    // 4. Извлекаем объект user из проверенных параметров
    let user_str = params.get("user").ok_or("User field missing")?;
    let user_json: serde_json::Value = serde_json::from_str(user_str).map_err(|_| "Invalid user JSON")?;
    Ok(user_json)
}
```

---

## 5. Спецификация платежного шлюза FreeKassa (API v1 & Webhook)

Интеграция реализует строгий принцип: **Сначала сохранение аудита (`transactions`), затем выполнение бизнес-логики (`orders` $\to$ начисление)**.

### 5.1. Алгоритмы формирования и проверки подписей FreeKassa

1. **Генерация ссылки на оплату (SCI Form URL):**
   * URL: `https://pay.freekassa.ru/`
   * Строка подписи: `merchant_id:amount:secret1:currency:order_id`
   * Хэш: `md5(sign_string)` в нижнем регистре.
2. **Входящий вебхук уведомления (`/billing/freekassa/notify`):**
   * Строка подписи: `merchant_id:amount:secret2:order_id`
   * Хэш: `md5(sign_string)` в нижнем регистре.
   * Обязательная проверка соответствия суммы: `form.amount == order.amount`.
   * Белый список IP-адресов FreeKassa: `168.119.157.136`, `168.119.60.227`, `138.201.88.124`, `178.154.197.79`.
   * Ответ шлюзу при успехе: строго строка `YES` с HTTP статусом 200.
3. **Фоновая проверка заказов через FreeKassa API v1 (`https://api.fk.life/v1/orders`):**
   * Согласно официальной документации FreeKassa API (`getOrders`), подпись запроса формируется по алгоритму **HMAC-SHA256**:
     1. Все поля запроса (кроме `signature`) сортируются в алфавитном порядке по ключу.
     2. Значения полей склеиваются через символ пайпа `|` (например: `shopId|nonce|orderId`).
     3. От полученной строки вычисляется `HMAC-SHA256` с использованием секретного `apiKey` (API-ключ из настроек магазина, не путать с secret1/secret2).

### 5.2. Реализация фонового Cron-синхронизатора FreeKassa

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sea_orm::{DatabaseConnection, EntityTrait, QueryFilter, ColumnTrait, ActiveModelTrait, Set};
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

/// Фоновый воркер синхронизации забытых / подвисших платежей
pub async fn cron_sync_freekassa(db: DatabaseConnection) {
    let shop_id = std::env::var("FK_SHOP_ID").unwrap_or_default();
    let api_key = std::env::var("FK_API_KEY").unwrap_or_default();

    if shop_id.is_empty() || api_key.is_empty() {
        tracing::warn!("FreeKassa API credentials not configured, cron sync disabled");
        return;
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    loop {
        // Опрос каждые 15 минут
        tokio::time::sleep(Duration::from_secs(900)).await;

        let threshold = chrono::Utc::now() - chrono::Duration::minutes(15);
        
        // 1. Ищем незавершенные заказы старше 15 минут
        let pending_orders = match crate::entities::orders::Entity::find()
            .filter(crate::entities::orders::Column::Status.eq(crate::entities::billing_enums::OrderStatus::Pending))
            .filter(crate::entities::orders::Column::CreatedAt.lt(threshold))
            .all(&db)
            .await 
        {
            Ok(orders) => orders,
            Err(e) => {
                tracing::error!("Failed to fetch pending orders for sync: {:?}", e);
                continue;
            }
        };

        for order in pending_orders {
            let nonce = chrono::Utc::now().timestamp_millis();
            let order_id_str = order.id.to_string();

            // Сортировка ключей по алфавиту: nonce, orderId, shopId
            // Склеивание значений через "|":
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

            // 2. Запрос статуса в API FreeKassa v1
            let resp = client.post("https://api.fk.life/v1/orders")
                .json(&request_body)
                .send()
                .await;

            if let Ok(res) = resp {
                if let Ok(json) = res.json::<serde_json::Value>().await {
                    // status == 1 (Оплачен)
                    if json["type"].as_str() == Some("success") {
                        if let Some(status_num) = json["orders"][0]["status"].as_i64() {
                            if status_num == 1 {
                                tracing::info!("Order {} confirmed via FreeKassa getOrders sync!", order.id);
                                // Вызываем начисление услуги
                                let _ = fulfill_order(&db, order.id, "CRON_SYNC", json).await;
                            } else if status_num == 8 || status_num == 9 {
                                // 8 - ошибка, 9 - отменен
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

Все методы требуют Bearer JWT аутентификацию пользователя.

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
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, ModelTrait,
    QueryFilter, QueryOrder, Set, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::{
    billing_enums::{OrderStatus, PaymentSystem, ProductType},
    groups, orders, products, rates, subscriptions, transactions, users, vouchers,
};

/// JWT Bearer авторизация для пользователя
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

async fn user_auth_checker(
    _req: &poem::Request,
    bearer: Bearer,
) -> Option<UserClaims> {
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
    /// Действующие лимиты (с учетом оверрайда rates над groups)
    pub effective_limits: EffectiveLimitsDto,
    /// Активная подписка
    pub active_subscription: Option<SubscriptionDto>,
    /// Подписки в статусе pending (активируются при первом входе)
    pub pending_subscriptions: Vec<SubscriptionDto>,
    /// Приобретенные неактивированные ваучеры (подарки)
    pub gift_vouchers: Vec<VoucherDto>,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct EffectiveLimitsDto {
    pub source: String, // "rates" (кастомный оверрайд) или "groups" (тариф)
    pub sessions_limit: i32,
    pub speed_limit_mbps: i32,
    pub traffic_limit_bytes: i64,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct SubscriptionDto {
    pub id: Uuid,
    pub product_id: Uuid,
    pub product_name: String,
    pub status: String,
    pub duration_days: Option<i32>,
    pub activated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct VoucherDto {
    pub id: Uuid,
    pub code: String,
    pub product_name: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct ActiveSessionDto {
    pub session_id: String,
    pub server_id: Uuid,
    pub server_name: String,
    pub client_ip: String,
    pub transport: String, // "quic", "ssh", "wrtc", "ws"
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
    pub currency: String,
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
    /// Получение профиля, баланса и сводки подписок пользователя
    #[oai(path = "/api/v1/user/me", method = "get")]
    async fn get_me(&self, auth: UserAuth) -> poem::Result<Json<UserProfileResponse>> {
        let user = users::Entity::find_by_id(auth.0.user_id)
            .one(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or_else(|| poem::Error::from_string("User not found", poem::http::StatusCode::NOT_FOUND))?;

        // 1. Проверяем индивидуальный оверрайд rates
        let user_rate = rates::Entity::find()
            .filter(rates::Column::UserId.eq(user.id))
            .one(&self.db)
            .await
            .unwrap_or(None);

        let now = chrono::Utc::now().naive_utc();
        let effective_limits = if let Some(rate) = user_rate.filter(|r| r.date_end > now) {
            EffectiveLimitsDto {
                source: "rates".into(),
                sessions_limit: rate.sessions,
                speed_limit_mbps: rate.speed_limit,
                traffic_limit_bytes: rate.traffic_limit,
                expires_at: Some(chrono::DateTime::from_naive_utc_and_offset(rate.date_end, chrono::Utc)),
            }
        } else if let Some(group_id) = user.group_id {
            let group = groups::Entity::find_by_id(group_id).one(&self.db).await.unwrap_or(None);
            if let Some(g) = group {
                EffectiveLimitsDto {
                    source: "groups".into(),
                    sessions_limit: g.sessions_limit,
                    speed_limit_mbps: g.speed_limit,
                    traffic_limit_bytes: g.traffic_limit,
                    expires_at: None,
                }
            } else {
                EffectiveLimitsDto {
                    source: "default".into(),
                    sessions_limit: 1,
                    speed_limit_mbps: 0,
                    traffic_limit_bytes: 0,
                    expires_at: None,
                }
            }
        } else {
            EffectiveLimitsDto {
                source: "default".into(),
                sessions_limit: 1,
                speed_limit_mbps: 0,
                traffic_limit_bytes: 0,
                expires_at: None,
            }
        };

        // 2. Получаем подписки
        let all_subs = subscriptions::Entity::find()
            .filter(subscriptions::Column::UserId.eq(user.id))
            .find_also_related(products::Entity)
            .all(&self.db)
            .await
            .unwrap_or_default();

        let mut active_sub = None;
        let mut pending_subs = Vec::new();

        for (sub, prod_opt) in all_subs {
            let p_name = prod_opt.map(|p| p.name).unwrap_or_else(|| "Тариф".into());
            let dto = SubscriptionDto {
                id: sub.id,
                product_id: sub.product_id,
                product_name: p_name,
                status: sub.status.clone(),
                duration_days: sub.duration_days,
                activated_at: sub.activated_at,
                expires_at: sub.expires_at,
            };
            if sub.status == "active" {
                active_sub = Some(dto);
            } else if sub.status == "pending" {
                pending_subs.push(dto);
            }
        }

        // 3. Купленные подарочные ваучеры
        let vouchers = vouchers::Entity::find()
            .filter(vouchers::Column::BuyerUserId.eq(Some(user.id)))
            .filter(vouchers::Column::Status.eq("created"))
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

        Ok(Json(UserProfileResponse {
            id: user.id,
            email: user.email,
            fingerprint: user.fingerprint,
            balance: user.balance,
            is_active: user.is_active,
            effective_limits,
            active_subscription: active_sub,
            pending_subscriptions: pending_subs,
            gift_vouchers: vouchers,
        }))
    }

    /// Список активных сессий пользователя со всех серверов
    #[oai(path = "/api/v1/user/sessions", method = "get")]
    async fn get_active_sessions(&self, auth: UserAuth) -> poem::Result<Json<Vec<ActiveSessionDto>>> {
        // Опрос нод кластера или ClientRegistry по fingerprint
        // [AI-PROMPT]: Возвращает текущие активные сессии из кэша соединений anet-auth/нод
        Ok(Json(vec![]))
    }

    /// Принудительный разрыв выбранной сессии
    #[oai(path = "/api/v1/user/sessions/disconnect", method = "post")]
    async fn disconnect_session(
        &self,
        auth: UserAuth,
        req: Json<DisconnectSessionRequest>,
    ) -> poem::Result<Json<bool>> {
        // [AI-PROMPT]: Отправка DisconnectCommand на соответствующую ноду
        tracing::info!("Disconnecting session {} on node {}", req.session_id, req.server_id);
        Ok(Json(true))
    }

    /// Активация подарочного ваучера
    #[oai(path = "/api/v1/user/vouchers/claim", method = "post")]
    async fn claim_voucher(
        &self,
        auth: UserAuth,
        req: Json<ClaimVoucherRequest>,
    ) -> poem::Result<Json<SubscriptionDto>> {
        let txn = self.db.begin().await
            .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?;

        let voucher = vouchers::Entity::find()
            .filter(vouchers::Column::Code.eq(req.code.trim().to_uppercase()))
            .filter(vouchers::Column::Status.eq("created"))
            .one(&txn)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or_else(|| poem::Error::from_string("Invalid or already claimed voucher", poem::http::StatusCode::BAD_REQUEST))?;

        let product = products::Entity::find_by_id(voucher.product_id)
            .one(&txn)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or_else(|| poem::Error::from_string("Product not found", poem::http::StatusCode::NOT_FOUND))?;

        // Вычисляем срок подписки из группы или метаданных
        let duration = if let Some(gid) = product.target_id {
            groups::Entity::find_by_id(gid).one(&txn).await.ok().flatten().map(|g| g.duration_days)
        } else {
            product.metadata.as_ref().and_then(|m| m.get("duration_days")?.as_i64().map(|d| d as i32))
        };

        // Создаем Pending Subscription
        let new_sub = subscriptions::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(auth.0.user_id),
            product_id: Set(product.id),
            status: Set("pending".into()),
            duration_days: Set(duration),
            activated_at: Set(None),
            expires_at: Set(None),
            created_at: Set(chrono::Utc::now()),
        };
        let inserted = new_sub.insert(&txn).await
            .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?;

        // Помечаем ваучер как активированный
        let mut v_active: vouchers::ActiveModel = voucher.into();
        v_active.status = Set("claimed".into());
        v_active.claimed_by_user_id = Set(Some(auth.0.user_id));
        v_active.claimed_at = Set(Some(chrono::Utc::now()));
        v_active.update(&txn).await
            .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?;

        txn.commit().await
            .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?;

        Ok(Json(SubscriptionDto {
            id: inserted.id,
            product_id: inserted.product_id,
            product_name: product.name,
            status: inserted.status,
            duration_days: inserted.duration_days,
            activated_at: None,
            expires_at: None,
        }))
    }

    /// Калькулятор тарифа «Сэндвич в Subway» (динамический расчет стоимости)
    #[oai(path = "/api/v1/user/rate/calculate", method = "post")]
    async fn calculate_custom_rate(
        &self,
        _auth: UserAuth,
        req: Json<CalculateRateRequest>,
    ) -> poem::Result<Json<CalculateRateResponse>> {
        // Формула расчета: базовый сбор + сессии + скорость + гигабайты, умноженное на срок
        let base_per_day = 3.0; // руб/день
        let session_cost_per_day = (req.sessions.max(1) - 1) as f64 * 1.5;
        let traffic_cost = (req.traffic_gb as f64 / 10.0) * 2.0; // 2 руб за каждые 10 ГБ
        let speed_multiplier = if req.speed_mbps > 100 { 1.3 } else { 1.0 };

        let total = ((base_per_day + session_cost_per_day) * (req.duration_days.max(1) as f64) + traffic_cost) * speed_multiplier;

        Ok(Json(CalculateRateResponse {
            calculated_price: (total * 100.0).round() / 100.0,
            currency: "RUB".into(),
        }))
    }

    /// Получение client.toml конфигурации и QR-ссылки
    #[oai(path = "/api/v1/user/config", method = "get")]
    async fn get_client_config(&self, auth: UserAuth) -> poem::Result<Json<ClientConfigResponse>> {
        let user = users::Entity::find_by_id(auth.0.user_id)
            .one(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), poem::http::StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or_else(|| poem::Error::from_string("User not found", poem::http::StatusCode::NOT_FOUND))?;

        let toml_content = format!(
            "# Anet Client Config\nfingerprint = \"{}\"\nauth_server = \"https://cp.anet-project.org\"\n",
            user.fingerprint
        );

        Ok(Json(ClientConfigResponse {
            client_toml: toml_content,
            qr_code_url: format!("https://cp.anet-project.org/api/v1/config/qr/{}", user.fingerprint),
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
    billing_enums::{OrderStatus, PaymentSystem, ProductType},
    orders, products, transactions, vouchers,
};

/// JWT Bearer авторизация администратора
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
    pub currency: String,
    pub product_type: ProductType,
    /// Для GroupSubscription: Some(group_id), для кастомного: None
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
    pub currency: Option<String>,
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
    pub currency: String,
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
            currency: Set(req.currency.clone()),
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
        if let Some(v) = &req.currency { active.currency = Set(v.clone()); }
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
2. Открывается защищенный webview с адресом `https://cp.anet-project.org/tma`.
3. Фронтенд автоматически передает `window.Telegram.WebApp.initData` на бэкенд `/api/v1/auth/telegram_tma`.
4. Бэкенд верифицирует криптографическую подпись через `verify_telegram_init_data`, связывает `telegram_id` с пользователем и выдает сессионный JWT.
5. Пользователь получает полный доступ к ЛК: скачивание конфига, завершение сессий, конструктор тарифов и оплата (включая Telegram Stars через `payment_system = TelegramStars`).

---

## 9. Пользовательский интерфейс (User WebUI & Admin Panel)

### 9.1. Личный кабинет пользователя (User Dashboard)
* **Витрина тарифов:** Переключение между фиксированными пакетами (группами) и интерактивным калькулятором лимитов (Subway sandwich). Переключатель «Купить себе» / «Купить в подарок».
* **Инвентарь:** Список неактивированных подписок (`Pending`) с индикатором «Активируется при первом подключении» и промокоды купленных ваучеров с кнопкой «Скопировать».
* **Управление сессиями:** Таблица устройств с информацией о подключении, типе транспорта (QUIC, WS, WRTC) и кнопкой принудительного разрыва «Завершить сессию».
* **Конфигурация:** Кнопка «Скачать client.toml» и генератор QR-кода для мобильных клиентов.

### 9.2. Панель управления администратора (Admin WebUI)
* **Вкладка Products:** Каталог платных услуг с возможностью привязки к `target_id` (группам), настройкой сортировки, цен и бейджей.
* **Вкладка Orders:** Мониторинг воронки оплат, ручная смена статусов, фильтрация по датам и пользователям.
* **Вкладка Transactions:** Аудит-лог платежей со всплывающим окном полного дампа входящего вебхука (`raw_request`) для быстрого разрешения спорных транзакций.
* **Вкладка Vouchers:** Реестр подарочных промокодов с информацией о покупателях и активировавших пользователях.