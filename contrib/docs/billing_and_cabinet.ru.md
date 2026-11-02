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

2. **Индивидуальные тарифы (`rates` — Оверрайд лимитов / Кастом):**
   * Запись в `rates` привязана к `user_id` (1-к-1) и **может быть создана или обновлена** через API (`POST /addrate`, `PATCH /rate/:id`).
   * В биллинге `rates` используется для **динамического конструктора тарифов** (Phase 2): когда пользователь на витрине сам собирает себе индивидуальный пакет.
   * **Правило приоритета (Лестница приоритетов в `anet-auth/src/api/auth.rs`):**
     При авторизации клиента (`check_access`), если у пользователя существует активная запись в `rates` (`date_end > now()`), ее лимиты **полностью переопределяют (override)** любые групповые лимиты из `groups`!

---

### 1.2. Проблема коллизии сессий: Реконнект vs Вытеснение (The libastral Paradox)

В системе действует фундаментальный принцип приватности: **никаких `device_id`, HWID или аппаратных идентификаторов нет и не будет**. Пользователь идентифицируется исключительно своим криптографическим ключом (`fingerprint`).

В режиме передачи данных (`data pass`) клиент передает зашифрованный туннельный трафик. Инспекция заголовков каждого IP-пакета ради команд управления **недопустима** (убийство скорости и батареи). Сервер может разорвать соединение только одним способом — физически закрыв сокет (`kill tx/rx`).

---

#### Суть проблемы: Неотличимость сценариев для серверного кода

Для программного кода сервера два сценария выглядят **абсолютно одинаково**:
1. **Сценарий 1 (Реконнект того же устройства):** Человек переключился с Wi-Fi на LTE или соединение кратковременно моргнуло на 1 секунду. Приходит новый хэндшейк с ключом `K`.
2. **Сценарий 2 (Вход со второго устройства):** Пользователь скопировал свой `client.toml` другу (или запустил VPN на ноутбуке при активном телефоне). Приходит новый хэндшейк с тем же ключом `K`.

> 🔮 **Парадокс `libastral.so`:**  
> Без вымышленной библиотеки `libastral.so` (чтения астральных планов бытия) серверный код **не имеет никакой возможности угадать**, это один и тот же девайс сменил IP/сеть или это второе физическое устройство с тем же ключом.

**К чему приводят наивные попытки решения в коде:**
* **Если сервер всегда блокирует новое подключение при занятом слоте:**  
  При смене Wi-Fi -> LTE старый сокет еще 10 секунд числится живым в `ClientRegistry`. Сервер блокирует легитимного владельца на его же собственном телефоне (*«Достигнут лимит подключений»*), либо рапортует ложные `Сессии: 2 / Безлимит`.
* **Если сервер безусловно пускает новое и гасит старое (FIFO):**  
  При обрыве сокета клиентский демон идет в авто-реконнект. Два устройства с одним ключом входят в бесконечный шторм взаимного выбивания (пинг-понг / осцилляция).
* **Если после вытеснения клиент глушит авто-реконнект:**  
  Когда человек берет выбитое устройство и жмет «Подключить» вручную — он шлет точно такой же хэндшейк, снова натыкается на занятый слот и получает отказ. Вернуть доступ с кнопки невозможно.

---

### [AI-PROMPT]: Запрет самостоятельной реализации логики вытеснения

> ⚠️ **КРИТИЧЕСКОЕ ПРАВИЛО ДЛЯ AI-АГЕНТОВ (Gemini / Claude / Cursor):**
> 1. Проблема коллизии сессий при отсутствии `device_id` и без инспекции VPN-трафика является фундаментальной сетевой дилеммой.
> 2. **КАТЕГОРИЧЕСКИ ЗАПРЕЩАЕТСЯ** писать, менять или внедрять какую-либо логику вытеснения сессий (FIFO preemption), убийства сокетов или эвристик определения устройств в коде `anet-server` и `anet-auth` **БЕЗ ЯВНОГО ОБСУЖДЕНИЯ И ОДОБРЕНИЯ ПОЛЬЗОВАТЕЛЕМ**.
> 3. Во время реализации модуля сессий AI-агент обязан:
>    * Напомнить пользователю о парадоксе неотличимости реконнекта от второго устройства.
>    * Предложить варианты компромиссов (например: строгая блокировка с ручным сбросом сессий через Личный Кабинет; либо привязка к сессионным тикетам ASTP handshake; либо тайминги/кулдауны).
>    * Дождаться прямого решения архитектора проекта перед написанием хоть одной строчки кода.

---

### 1.3. Механизм первой сетевой активности (Smart Activation / ASTP Handshake)

Срок действия тарифа не расходуется, пока пользователь фактически не подключился к VPN:

1. **Инициация:** Клиент инициирует ASTP/QUIC/WebRTC хэндшейк с нодой VPN-сервера (`anet-server`).
2. **Идентификация:** Нода извлекает открытый ключ клиента, вычисляет его криптографический `fingerprint` и отправляет авторизационный запрос на Auth-сервер:
   `POST /check_access` с телом `{"fingerprint": "...", "node_id": "...", "node_active_sessions": ...}`.
3. **Обработка в `anet-auth/src/api/auth.rs`:**
   * По `fingerprint` находится запись пользователя в `users`.
   * **Атомарность и транзакции БД:** Все операции проверки и изменения статуса пользователя обязательно оборачиваются в транзакцию БД (`let txn = self.db.begin().await? ... txn.commit().await?`). Это исключает гонку (Race Condition) при одновременном включении VPN на телефоне и ноутбуке:
     * Если `user.activated_at` равен `None` (первое подключение после оплаты):
       * Фиксируется момент старта: `user.activated_at = Some(Utc::now())`.
       * Вычисляется дедлайн: `user.expires_at = Some(Utc::now() + Duration::days(group.duration_days))`.
       * Запись сохраняется в транзакции: `user_active.update(&txn).await?`.
     * Если `user.expires_at` задан и `Utc::now() > expires_at`:
       * Платный период завершен.
       * `user.group_id` переключается на группу с флагом `is_default = true`.
       * Если в дефолтной группе доступ заблокирован (`sessions_limit == 0`), возвращается `{ allowed: false, message: "Подписка истекла" }`.
     * Проверяются персональные оверрайды: если у пользователя есть активная запись `rates` (`date_end > Utc::now()`), её параметры переопределяют групповые.
   * Транзакция фиксируется (`txn.commit().await?`).
4. **Ответ и шейпинг:** Auth-сервер возвращает структуру `CheckAccessResponse`. Нода применяет выданные параметры скорости через eBPF-шейпер на TUN-интерфейсе и успешно завершает сетевой хэндшейк.

---

## 2. Модель монетизации и Товары (Products)

Архитектура биллинга строится вокруг сущности **Product (Товар)**.

### 2.1. Этапы внедрения (Roadmap)

* **Phase 1 (MVP — Текущий фокус):**
  1. Пользователь может зарегистрироваться в Web (Email + ссылка подтверждения / пароль).
  2. Пользователь может выбрать и купить себе готовую «группу» (тариф) через FreeKassa.
  3. Полноценное API FreeKassa (создание платежа, защищенный вебхук, фоновая сверка).
  4. Личный кабинет пользователя (User Dashboard):
     - Карточка тарифа (группы), срок действия, статус.
     - Скачивание `client.toml` и QR-код для мобильных клиентов.
     - Цифры статистики (активные сессии, использованный трафик, скорость).
     - Интерактивные графики потребления трафика (Rx / Tx по часам и дням).
     - Список активных сессий с кнопкой принудительного разрыва.
* **Phase 2 (Backlog — Расширение):**
  * Интерактивный калькулятор лимитов (Subway sandwich).
  * Покупка в подарок (`is_gift = true`) и интерфейс ваучеров в ЛК.
  * Реестр ваучеров в панели администратора.
  * Telegram-бот и TMA.

---

## 3. Схема Базы Данных (SeaORM Entities)

### [AI-PROMPT]: Обязательное создание SeaORM миграций параллельно с сущностями

> ⚠️ **КРИТИЧЕСКОЕ ПРАВИЛО ДЛЯ AI-АГЕНТОВ (Gemini / Claude / Cursor):**
> 1. При создании или модификации любой структуры в `anet-auth/src/entities/` **ОБЯЗАТЕЛЬНО ПАРАЛЛЕЛЬНО** создавайте файл миграции в `anet-auth/src/migration/` (формат имени: `mYYYYMMDD_HHMMSS_<описание>.rs`).
> 2. Созданная миграция **ДОЛЖНА БЫТЬ СРАЗУ ЗАРЕГИСТРИРОВАНА** в векторе `Migrator::migrations()` внутри `anet-auth/src/migration/mod.rs`.
> 3. Миграции описываются строго через SeaQuery DSL (`Table::create()`, `Table::alter()`) либо через типизированный DDL. Никогда не оставляйте сущности без миграций!

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

/// Сетевые протоколы подключения клиентов к нодам
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Enum)]
pub enum TransportProtocol {
    #[oai(rename = "quic")]
    Quic,
    #[oai(rename = "ssh")]
    Ssh,
    #[oai(rename = "vnc")]
    Vnc,
    #[oai(rename = "ws")]
    Websocket,
    #[oai(rename = "ahttp")]
    Ahttp,
    #[oai(rename = "wrtc_ws")]
    WrtcWs,
    #[oai(rename = "wrtc_video")]
    WrtcVideo,
    #[oai(rename = "wrtc_dc")]
    WrtcDc,
    #[oai(rename = "wrtc_p2p")]
    WrtcDirectP2p,
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
    /// Уникальный идентификатор товара
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Витринное наименование товара
    pub name: String,
    /// Подробное описание тарифа для карточки в ЛК
    pub description: String,
    /// Стоимость товара
    pub price: f64,
    /// Валюта стоимости
    pub currency: Currency,
    /// Тип продукта (определяет логику начисления)
    pub product_type: ProductType,
    /// Идентификатор целевой группы (для GroupSubscription)
    pub target_id: Option<Uuid>,
    /// Порядок сортировки при выводе на витрине
    pub sort_order: i32,
    /// Маркетинговый бейдж ("Хит", "-20%", "VIP")
    pub badge: Option<String>,
    /// Дополнительные параметры продукта в формате JSONB
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub metadata: Option<serde_json::Value>,
    /// Доступен ли товар к покупке
    pub is_active: bool,
    /// Время создания товара
    pub created_at: DateTimeUtc,
    /// Время последнего обновления
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
    /// Внутренний уникальный идентификатор заказа
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Идентификатор покупателя
    pub user_id: Uuid,
    /// Идентификатор приобретаемого продукта
    pub product_id: Uuid,
    /// Зафиксированная сумма к оплате
    pub amount: f64,
    /// Валюта оплаты
    pub currency: Currency,
    /// Текущий статус заказа
    pub status: OrderStatus,
    /// Флаг покупки в подарок (генерация промокода Voucher)
    pub is_gift: bool,
    /// Параметры кастомных тарифов в формате JSONB
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub metadata: Option<serde_json::Value>,
    /// Время оформления заказа
    pub created_at: DateTimeUtc,
    /// Время изменения статуса заказа
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
    /// Внутренний ID записи аудита транзакции
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Ссылка на оплаченный заказ (если удалось сопоставить)
    pub order_id: Option<Uuid>,
    /// Платежный шлюз, обработавший перевод
    pub payment_system: PaymentSystem,
    /// Внешний ID платежа на стороне шлюза (intid)
    pub external_tx_id: String,
    /// Фактически зачисленная сумма
    pub amount_received: f64,
    /// Полный сырой дамп тела входящего вебхука для аудита
    #[sea_orm(column_type = "JsonBinary")]
    pub raw_request: serde_json::Value,
    /// Время получения уведомления от платежного шлюза
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
    /// Уникальный идентификатор ваучера
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Уникальный промокод для передачи (например, "ANET-GIFT-A8F2-99C1")
    #[sea_orm(unique)]
    pub code: String,
    /// Идентификатор продукта, который активирует ваучер
    pub product_id: Uuid,
    /// Пользователь, оплативший ваучер
    pub buyer_user_id: Option<Uuid>,
    /// Пользователь, активировавший ваучер на свой профиль
    pub claimed_by_user_id: Option<Uuid>,
    /// Текущее состояние ваучера
    pub status: VoucherStatus,
    /// Резервное поле для будущих кастомных тарифов (RateExtension в подарок)
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub metadata: Option<serde_json::Value>,
    /// Время фактической активации промокода
    pub claimed_at: Option<DateTimeUtc>,
    /// Время создания промокода
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

## 4. Конфигурация, Регистрация и Авторизация

### 4.1. Параметры конфигурации (`contrib/config/server.toml`)

Все таймауты, длительности токенов и ключи выносятся в конфигурационный файл сервера (никакого хардкода в коде):

```toml
[auth]
# Время жизни одноразового токена подтверждения Email (в минутах)
verification_token_ttl_mins = 15
# Минимальная длина пароля при регистрации
min_password_length = 5
# Публичный домен веб-кабинета для генерации ссылок в письмах
public_domain = "https://service.example.com"

[billing.freekassa]
# Интервал запуска фонового опроса незавершенных заказов (в секундах)
sync_interval_secs = 900
# Возраст заказа со статусом Pending для начала проверки через getOrders (в минутах)
pending_threshold_mins = 15

[telegram]
# Токен бота Telegram для валидации TMA
bot_token = ""
# Ключ для вычисления промежуточного HMAC по спецификации Telegram API
web_app_data_key = "WebAppData"
```

### 4.2. Авторизация по Email (Пароли и ссылки)

1. **Запрос ссылки:** Пользователь указывает Email на странице входа Личного Кабинета.
2. **Токен подтверждения:** Бэкенд генерирует одноразовый токен со временем жизни `verification_token_ttl_mins`, сохраняет его в таблице `verification_tokens` и отправляет письмо со ссылкой на публичный сервис:
   `https://service.example.com/auth/verify?token=XYZ`
3. **Установка пароля:** Пользователь вводит пароль (валидируется только длина $\ge min\_password\_length$).
4. **Создание профиля:**
   * Создается `UserModel`.
   * Генерируется ключевая пара ASTP и `fingerprint`.
   * Пользователю привязывается группа по умолчанию (`is_default = true`).
   * Поля `activated_at` и `expires_at` устанавливаются в `None` (ждет первого входа).
   * Возвращается сессионный JWT.

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
         return Err(poem::Error::from_string("Amount mismatch", StatusCode::BAD_REQUEST));
     }
     ```
   * **Атомарность (Database Transactions):** Обработка вебхука обязательно оборачивается в транзакцию БД (`let txn = self.db.begin().await? ... txn.commit().await?`). В рамках одной неделимой транзакции:
     1. Записывается аудит в таблицу `transactions` (включая `raw_request: JsonBinary`).
     2. Статус заказа в `orders` меняется на `Paid`.
     3. Начисляется услуга (назначается `user.group_id` с `activated_at = None`, либо продлевается срок `user.expires_at`).
     Если любая из операций завершилась с ошибкой, транзакция целиком откатывается, защищая БД от рассинхронизации.
   * Белый список IP-адресов FreeKassa: `168.119.157.136`, `168.119.60.227`, `138.201.88.124`, `178.154.197.79`.
   * Ответ шлюзу при успехе: строго строка `YES` с HTTP статусом 200.
3. **Фоновая проверка заказов через FreeKassa API v1 (`https://api.fk.life/v1/orders`):**
   * Согласно спецификации FreeKassa API (`getOrders`), подпись формируется по алгоритму **HMAC-SHA256**:
     1. Все поля запроса (кроме `signature`) сортируются в алфавитном порядке по ключам.
     2. Значения полей склеиваются через символ пайпа `|` (например: `nonce|orderId|shopId`).
     3. От полученной строки вычисляется `HMAC-SHA256` с использованием секретного `apiKey` (API-ключ из настроек ЛК FreeKassa).

### 5.2. Строго типизированный воркер FreeKassa

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sea_orm::{DatabaseConnection, EntityTrait, QueryFilter, ColumnTrait, ActiveModelTrait, Set};
use serde::{Deserialize, Serialize};
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

/// Статусы заказов по спецификации FreeKassa API v1 (getOrders)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum FkApiOrderStatus {
    /// Новый заказ (ожидает оплаты)
    New = 0,
    /// Успешно оплачен
    Paid = 1,
    /// Ошибка проведения платежа
    Error = 8,
    /// Заказ отменен
    Cancelled = 9,
}

#[derive(Deserialize, Debug)]
pub struct FkOrdersApiResponse {
    pub r#type: String,
    #[serde(default)]
    pub orders: Option<Vec<FkOrderRecord>>,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct FkOrderRecord {
    pub id: i64,
    pub merchant_order_id: String,
    pub status: i32,
    pub amount: f64,
}

pub async fn cron_sync_freekassa(db: DatabaseConnection) {
    let shop_id = std::env::var("FK_SHOP_ID").unwrap_or_default();
    let api_key = std::env::var("FK_API_KEY").unwrap_or_default();
    let sync_interval_secs: u64 = std::env::var("FK_SYNC_INTERVAL_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(900);
    let pending_threshold_mins: i64 = std::env::var("FK_PENDING_THRESHOLD_MINS").ok().and_then(|v| v.parse().ok()).unwrap_or(15);

    if shop_id.is_empty() || api_key.is_empty() {
        return;
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    loop {
        tokio::time::sleep(Duration::from_secs(sync_interval_secs)).await;

        let threshold = chrono::Utc::now() - chrono::Duration::minutes(pending_threshold_mins);
        
        let pending_orders = match crate::entities::orders::Entity::find()
            .filter(crate::entities::orders::Column::Status.eq(crate::entities::billing_enums::OrderStatus::Pending))
            .filter(crate::entities::orders::Column::CreatedAt.lt(threshold))
            .all(&db)
            .await 
        {
            Ok(orders) => orders,
            Err(e) => {
                tracing::error!("[FreeKassa Sync] DB error querying pending orders: {:?}", e);
                continue;
            }
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

            match resp {
                Ok(res) => {
                    let text = res.text().await.unwrap_or_default();
                    match serde_json::from_str::<FkOrdersApiResponse>(&text) {
                        Ok(parsed) if parsed.r#type == "success" => {
                            if let Some(records) = parsed.orders {
                                if let Some(record) = records.iter().find(|r| r.merchant_order_id == order_id_str) {
                                    if record.status == FkApiOrderStatus::Paid as i32 {
                                        tracing::info!("[FreeKassa Sync] Order {} confirmed paid", order.id);
                                        let raw_json = serde_json::to_value(record).unwrap_or_default();
                                        let _ = fulfill_order(&db, order.id, "CRON_SYNC", raw_json).await;
                                    } else if record.status == FkApiOrderStatus::Error as i32 || record.status == FkApiOrderStatus::Cancelled as i32 {
                                        tracing::warn!("[FreeKassa Sync] Order {} cancelled (status {})", order.id, record.status);
                                        let mut active: crate::entities::orders::ActiveModel = order.into();
                                        active.status = Set(crate::entities::billing_enums::OrderStatus::Cancelled);
                                        let _ = active.update(&db).await;
                                    }
                                }
                            }
                        }
                        Ok(parsed) => {
                            tracing::error!("[FreeKassa Sync] Gateway returned non-success response: {:?}", parsed.message);
                            // [AI-PROMPT / Phase 2 TODO]: Отправка алерта в Telegram/ELK админу при аномальных ответах шлюза
                        }
                        Err(e) => {
                            tracing::error!("[FreeKassa Sync] Deserialization failure! Body: {}. Error: {}", text, e);
                            // [AI-PROMPT / Phase 2 TODO]: Отправка алерта в Telegram/ELK админу при получении невалидного JSON
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("[FreeKassa Sync] Network error connecting to FreeKassa API: {}", e);
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

use poem::http::StatusCode;
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
    billing_enums::{Currency, LimitSource, OrderStatus, PaymentSystem, ProductType, TransportProtocol, VoucherStatus},
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
    pub transport: TransportProtocol,
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
pub struct TrafficHistoryPointDto {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
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
    db: DatabaseConnection,
}

impl UserCabinetApi {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[OpenApi]
impl UserCabinetApi {
    /// Получение профиля, баланса и действующих лимитов пользователя
    #[oai(path = "/api/v1/user/me", method = "get")]
    async fn get_me(&self, auth: UserAuth) -> poem::Result<Json<UserProfileResponse>> {
        let user = users::Entity::find_by_id(auth.0.user_id)
            .one(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or_else(|| poem::Error::from_string("User not found", StatusCode::NOT_FOUND))?;

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
                    source: LimitSource::Rates,
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
                        source: LimitSource::Groups,
                        sessions_limit: g.sessions_limit,
                        speed_limit_kbps: g.speed_limit,
                        traffic_limit_bytes: g.traffic_limit,
                    },
                    Some(g.name),
                )
            } else {
                (
                    EffectiveLimitsDto {
                        source: LimitSource::Default,
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
                    source: LimitSource::Unlimited,
                    sessions_limit: 0,
                    speed_limit_kbps: 0,
                    traffic_limit_bytes: 0,
                },
                None,
            )
        };

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
        }))
    }

    /// Активные сессии пользователя со всех серверов
    #[oai(path = "/api/v1/user/sessions", method = "get")]
    async fn get_active_sessions(&self, auth: UserAuth) -> poem::Result<Json<Vec<ActiveSessionDto>>> {
        // [AI-PROMPT]: Возвращает активные сессии пользователя по его fingerprint из ClientRegistry
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

    /// График потребления трафика пользователем (Rx / Tx по часам/дням)
    #[oai(path = "/api/v1/user/traffic-history", method = "get")]
    async fn get_traffic_history(&self, auth: UserAuth) -> poem::Result<Json<Vec<TrafficHistoryPointDto>>> {
        // [AI-PROMPT]: Агрегация данных потребления трафика из таблицы статистики за последние 30 дней
        Ok(Json(vec![]))
    }

    /// Получение client.toml и ссылки на QR-код
    #[oai(path = "/api/v1/user/config", method = "get")]
    async fn get_client_config(&self, auth: UserAuth) -> poem::Result<Json<ClientConfigResponse>> {
        let user = users::Entity::find_by_id(auth.0.user_id)
            .one(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or_else(|| poem::Error::from_string("User not found", StatusCode::NOT_FOUND))?;

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

use poem::http::StatusCode;
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
    db: DatabaseConnection,
}

impl AdminBillingApi {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
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
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;
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
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;
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
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or_else(|| poem::Error::from_string("Product not found", StatusCode::NOT_FOUND))?;

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
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;
        Ok(Json(updated))
    }

    #[oai(path = "/api/v1/admin/products/:id", method = "delete")]
    async fn delete_product(
        &self,
        _auth: AdminAuth,
        id: poem_openapi::param::Path<Uuid>,
    ) -> poem::Result<Json<bool>> {
        products::Entity::delete_by_id(id.0).exec(&self.db).await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;
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
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
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
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
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
}
```

---

## 8. Пользовательский интерфейс (User WebUI & Admin Panel)

### 8.1. Личный кабинет пользователя (User Dashboard) — Phase 1 MVP
* **Карточка активного тарифа:**
  * Название подключенной группы.
  * Индикатор срока действия: точная дата истечения (либо бейдж *«Активируется при первом подключении»*).
  * Статус профиля (Активен / Ожидает оплаты).
* **Конфигурация устройства:**
  * Кнопка *«Скачать client.toml»*.
  * Модальное окно с отображением QR-кода для мобильных клиентов.
* **Статистика и метрики:**
  * Количество активных сессий (например: `1 / 3 устройств онлайн`).
  * Потребление трафика: израсходовано из лимита (или отметка *«Безлимит»*).
  * Ограничение скорости (Мбит/с).
  * **Интерактивные графики трафика:** Визуализация объемов загрузки и отдачи (Rx / Tx) по часам за последние сутки и по дням за месяц.
* **Управление активными сессиями:**
  * Таблица подключенных устройств (IP клиента, протокол транспорта, объем переданных данных, время онлайн).
  * Кнопка *«Завершить сессию»* для принудительного разрыва конкретного туннеля.
* **Витрина тарифов:**
  * Карточки доступных базовых групп (`ProductType::GroupSubscription`) с перечнем включенных опций.
  * Кнопка *«Купить тариф»*, инициирующая создание заказа и переход на шлюз FreeKassa.

### 8.2. Панель управления администратора (Admin WebUI) — Phase 1 MVP
* **Раздел Products:** CRUD-интерфейс каталога тарифов. Настройка цен, валюты, бейджей и привязка к существующим `groups`.
* **Раздел Orders:** Журнал заказов с фильтрами по статусам (`Pending`, `Paid`, `Failed`, `Cancelled`) и поиском по ID пользователя.
* **Раздел Transactions:** Единый аудит-лог поступивших оплат. Возможность просмотра сырого тела запроса (`raw_request`) в формате JSONB для мгновенного разбора спорных ситуаций.

---

## 9. Функционал Phase 2 (Backlog / Дальнейшее развитие)

Следующие возможности заложены на уровне моделей базы данных, но сознательно вынесены за рамки Phase 1 MVP для скорейшего запуска базового биллинга:
1. **Индивидуальный конструктор тарифов (Subway sandwich):** Ползунки количества сессий, трафика и скорости с динамическим расчетом цены и записью в `rates`.
2. **Подарочные ваучеры (`is_gift`):** Покупка подарка в один клик, генерация промокодов `ANET-GIFT-...`, витрина неактивированных кодов и форма ввода ваучера в ЛК.
3. **Раздел Vouchers в панели администратора:** Учет выданных подарочных кодов.
4. **Telegram-бот и Mini App (TMA):** Вход без пароля через `initData` и оплата через Telegram Stars.