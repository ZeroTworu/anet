# Архитектура коммерческого модуля (Личный Кабинет, Биллинг, Лимиты)

Документация актуальна для ветки `master`.

## 1. Концептуальная модель: Единый Пользователь
Архитектура строится на принципе **«Один пользователь = Один криптографический ключ = Одна подписка»**. В системе нет привязки к оборудованию (HWID).

Сущность `User` (таблица `users`) объединяет в себе:
1.  **Сетевую идентичность:** Криптографические ключи, Fingerprint, выделенный IP.
2.  **Пользовательскую идентичность:** Email, Password, Telegram ID, Баланс.

Пользователь использует один и тот же конфигурационный файл (`client.toml` или QR-код) на всех своих устройствах. Ограничение потребления ресурсов строится **исключительно на количестве одновременных сессий**.

### 1.1. Иерархия лимитов (Groups vs Rates)
Лимиты применяются к Пользователю в момент подключения (в `anet-server/src/auth_provider.rs`).
1.  **Базовые лимиты (Group):** Определяются группой (`groups`), на которую у Пользователя есть активная подписка.
2.  **Индивидуальные расширения (Rates):** Если пользователь докупил индивидуальный пакет (сущность `rates`), эти лимиты **полностью переопределяют** (override) групповые лимиты.

### 1.2. Механизм вытеснения сессий (FIFO Disconnect)
Если Пользователь имеет лимит в $N$ сессий, и сервер фиксирует попытку установки $(N+1)$-й сессии:
1.  Новое подключение **одобряется**.
2.  Сервер (в `ClientRegistry`) находит самую старую активную сессию данного `fingerprint` (сортировка по `created_at`).
3.  Сервер принудительно разрывает старую сессию, отправляя в транспорт (QUIC/TCP/WS) команду закрытия со специфичной причиной: `"Session limit reached. Disconnected by newer connection."`.
4.  **Реакция клиентов (`anet-client-core`):** При получении этой причины разрыва, клиент **не пытается переподключиться**.
    *   В CLI: Выводится `ERROR: Сессия завершена. Выполнен вход с другого устройства.` и процесс завершается.
    *   В GUI / Android: Туннель останавливается, на экран выводится модальное окно с аналогичным текстом ошибки.

## 2. Модель монетизации и Товары (Products)
Архитектура биллинга строится вокруг единой сущности **Product (Товар)** — агрегатора всего, что можно продать.

### 2.1. Типы товаров (`ProductType`)
1.  **GroupSubscription:** Подписка на базовый тариф (ссылается на `groups`).
2.  **RateExtension:** Дополнительные пакеты (например, "+50 ГБ трафика" или "+1 одновременная сессия", ссылается на `rates`).
3.  **Feature:** Активация специфических функций (например, доступ к выделенному IP).

### 2.2. Подарки и Ваучеры (`is_gift`)
*   Если заказ оформлен с флагом `is_gift = false`, после оплаты товар немедленно конвертируется в **Подписку (Subscription)** в инвентаре покупателя.
*   Если заказ оформлен с флагом `is_gift = true`, генерируется **Ваучер (Voucher)** (промокод `ANET-GIFT-...`), который помещается в инвентарь покупателя. Ваучер можно передать другому человеку для активации.

### 2.3. Отложенная активация (Smart Activation)
Срок действия подписки (`duration_days`) начинает отсчет **не с момента покупки, а с момента первого использования**.
1.  После покупки подписка получает статус `Pending`.
2.  При первой успешной установке VPN-туннеля (ASTP Handshake) сервер переводит подписку в статус `Active` и устанавливает `expires_at = now() + duration_days`.

## 3. Схема Базы Данных (SeaORM Entities)

```rust
// --- ENUMS ---

/// Поддерживаемые платежные шлюзы
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "payment_system")]
pub enum PaymentSystem {
    #[sea_orm(string_value = "freekassa")] FreeKassa,
    #[sea_orm(string_value = "aaio")] Aaio,
    #[sea_orm(string_value = "yoomoney")] YooMoney,
    #[sea_orm(string_value = "telegram_stars")] TelegramStars,
}

/// Жизненный цикл заказа
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "order_status")]
pub enum OrderStatus {
    #[sea_orm(string_value = "pending")] Pending,     /// Ожидает оплаты
    #[sea_orm(string_value = "paid")] Paid,           /// Успешно оплачен и выдан
    #[sea_orm(string_value = "failed")] Failed,       /// Ошибка оплаты
    #[sea_orm(string_value = "cancelled")] Cancelled, /// Отменен пользователем
    #[sea_orm(string_value = "refunded")] Refunded,   /// Возврат средств (Чарджбэк)
}

/// Тип продаваемого продукта
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "product_type")]
pub enum ProductType {
    #[sea_orm(string_value = "group_subscription")] GroupSubscription, 
    #[sea_orm(string_value = "rate_extension")] RateExtension,     
    #[sea_orm(string_value = "feature")] Feature,           
}

// --- ENTITIES ---

/// Пользователи (Учетная запись + Профиль VPN)
pub struct UserModel {
    /// Внутренний уникальный идентификатор пользователя
    #[sea_orm(primary_key, auto_increment = false)] pub id: Uuid,
    /// Криптографический отпечаток публичного ключа (ASTP)
    pub fingerprint: String,
    /// Никнейм / Display Name для админки
    pub uid: Option<String>, 
    
    /// Email для входа в WebUI (уникальный)
    #[sea_orm(unique)] pub email: Option<String>,
    /// Хэш пароля (bcrypt)
    pub password_hash: Option<String>,
    /// Привязанный Telegram ID для авторизации через бота
    #[sea_orm(unique)] pub telegram_id: Option<i64>,
    /// Внутренний баланс кошелька (для рефералок/кешбэка)
    pub balance: f64,
    
    /// Статус блокировки
    pub is_active: bool,
    /// Дата регистрации
    pub created_at: DateTime,
    /// Дата обновления записи
    pub updated_at: DateTime,
    /* ... остальные крипто-поля (keys, static_ip) ... */
}

/// Каталог товаров (Агрегатор)
pub struct ProductModel {
    /// Уникальный идентификатор товара
    #[sea_orm(primary_key, auto_increment = false)] pub id: Uuid,
    /// Публичное название (например, "Тариф Бояре на 30 дней")
    pub name: String, 
    /// Описание товара для витрины
    pub description: String,
    /// Стоимость товара
    pub price: f64,
    /// Валюта (RUB, USD, STARS)
    pub currency: String, 
    /// Тип продукта (определяет логику выдачи)
    pub product_type: ProductType,
    /// Обязательная ссылка на целевую сущность (ID из таблицы groups или rates)
    pub target_id: Uuid, 
    /// Гибкие настройки фич в формате JSONB (например, {"enable_imap": true})
    pub metadata: Option<serde_json::Value>, 
    /// Доступен ли товар для покупки
    pub is_active: bool,
}

/// Заказы (Намерения покупки)
pub struct OrderModel {
    /// Внутренний системный ID заказа (передается в платежку как order_id)
    #[sea_orm(primary_key, auto_increment = false)] pub id: Uuid,
    /// ID пользователя, оформляющего заказ
    pub user_id: Uuid,
    /// ID покупаемого продукта
    pub product_id: Uuid,
    /// Сумма к оплате (фиксация цены на момент заказа)
    pub amount: f64,
    /// Текущий статус заказа
    pub status: OrderStatus,
    /// Флаг покупки в подарок (true -> генерируем Voucher, false -> Subscription)
    pub is_gift: bool, 
    /// Время создания заказа
    pub created_at: DateTime,
    /// Время последнего обновления статуса
    pub updated_at: DateTime,
}

/// Транзакции (Аудит фактических поступлений средств от шлюзов)
pub struct TransactionModel {
    /// Внутренний ID транзакции
    #[sea_orm(primary_key, auto_increment = false)] pub id: Uuid,
    /// Ссылка на заказ (может быть null, если шлюз прислал мусор, но мы обязаны его сохранить для аудита)
    pub order_id: Option<Uuid>, 
    /// Платежная система, обработавшая платеж
    pub payment_system: PaymentSystem,
    /// Идентификатор транзакции на стороне шлюза (например, intid во FreeKassa)
    pub external_tx_id: String, 
    /// Фактически зачисленная сумма
    pub amount_received: f64,
    /// JSONB: Полный дамп POST-запроса от шлюза "как есть" (для дебага и разбора полетов)
    #[sea_orm(column_type = "JsonBinary")]
    pub raw_request: serde_json::Value, 
    /// Время получения вебхука
    pub created_at: DateTime,
}

/// Очередь подписок пользователя
pub struct SubscriptionModel {
    /// Внутренний ID подписки
    #[sea_orm(primary_key, auto_increment = false)] pub id: Uuid,
    /// Владелец подписки
    pub user_id: Uuid,
    /// Купленный продукт
    pub product_id: Uuid,
    /// "pending", "active", "expired"
    pub status: String, 
    /// Дата фактической активации (первый коннект)
    pub activated_at: Option<DateTime>,
    /// Дата окончания
    pub expires_at: Option<DateTime>,
}

/// Подарочные ваучеры
pub struct VoucherModel {
    /// Внутренний ID ваучера
    #[sea_orm(primary_key, auto_increment = false)] pub id: Uuid,
    /// Уникальный промокод (например, "ANET-GIFT-8A4F")
    pub code: String, 
    /// Какой продукт дает этот ваучер
    pub product_id: Uuid,
    /// Кто купил
    pub buyer_user_id: Option<Uuid>,
    /// Кто активировал
    pub claimed_by_user_id: Option<Uuid>,
    /// "created", "claimed"
    pub status: String, 
}
```

## 4. Регистрация и Авторизация (WebUI)

### 4.1. Процесс регистрации по Email
Учитывая ограничения AWS SES в РФ, для отправки транзакционных писем используется крейт `lettre` в связке с российскими SMTP-провайдерами (VK WorkMail, Yandex 360 для бизнеса, Beget) или специализированными сервисами (RuSender, Unisender).

1.  **Запрос Email:** Пользователь вводит Email на сайте.
2.  **Генерация токена:** Бэкенд генерирует случайный токен (`verification_tokens`), сохраняет его в БД с привязкой к Email (TTL 15 минут) и отправляет письмо со ссылкой `https://cp.anet-project.org/auth/verify?token=XYZ`.
3.  **Переход по ссылке:** Пользователь кликает по ссылке, открывается страница задания пароля.
4.  **Установка пароля:** Пользователь вводит пароль. Бэкенд проверяет токен.
    *   *Требования к паролю:* Проверяется только минимальная длина (настраивается в `server.toml`, по умолчанию 5 символов). Никаких требований к спецсимволам или регистру.
5.  **Создание пользователя:** Бэкенд хэширует пароль (Bcrypt), создает сущность `User` (генерируя криптографические ключи VPN), удаляет токен и возвращает JWT для входа в ЛК.

### 4.2. API Авторизации (`anet-auth/src/api/auth.rs`)
```rust
// [AI-PROMPT] Реализовать эндпоинты:
// POST /api/v1/auth/register (Принимает email, шлет письмо)
// POST /api/v1/auth/verify (Принимает token и password, создает User, возвращает JWT)
// POST /api/v1/auth/login (Принимает email и password, возвращает JWT)
```

## 5. Спецификация API Биллинга (FreeKassa)

Интеграция реализует строгий паттерн: **Сначала аудит (Transaction), затем бизнес-логика (Order $\to$ Product)**. Все взаимодействия происходят строго через `POST`.

### 5.1. DTO (Data Transfer Objects)
```rust
use poem_openapi::{payload::{Form, Json, PlainText}, Object, OpenApi};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct CreateOrderRequest {
    pub product_id: Uuid,
    pub is_gift: bool,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct CreateOrderResponse {
    pub payment_url: String,
    pub order_id: Uuid,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct FkNotifyForm {
    #[oai(rename = "MERCHANT_ID")] pub merchant_id: String,
    #[oai(rename = "AMOUNT")] pub amount: String,
    #[oai(rename = "MERCHANT_ORDER_ID")] pub order_id: String,
    pub intid: String,
    #[oai(rename = "SIGN")] pub sign: String,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct FkResultForm {
    #[oai(rename = "MERCHANT_ORDER_ID")] pub order_id: String,
}
```

### 5.2. API Контроллер (`anet-auth/src/api/billing.rs`)
```rust
pub struct BillingApi {
    pub db: sea_orm::DatabaseConnection,
}

#[OpenApi]
impl BillingApi {
    /// 1. Создание заказа (Генерация ссылки на оплату)
    /// [AI-PROMPT] Извлечь UserID из JWT. Создать Order. Сгенерировать MD5 подпись.
    #[oai(path = "/billing/freekassa/create", method = "post")]
    async fn create_order(&self, req: Json<CreateOrderRequest>) -> poem::Result<Json<CreateOrderResponse>> {
        // ... логика создания заказа и генерации URL ...
        todo!()
    }

    /// 2. Webhook от FreeKassa об успешной оплате (Server-to-Server)
    /// [AI-PROMPT] Обязательно использовать транзакции БД (DatabaseTransaction).
    #[oai(path = "/billing/freekassa/notify", method = "post")]
    async fn fk_notify(&self, form: Form<FkNotifyForm>) -> poem::Result<PlainText<String>> {
        let merchant_id = std::env::var("FK_MERCHANT_ID").unwrap();
        let secret2 = std::env::var("FK_SECRET_2").unwrap();

        // 1. Валидация подписи
        let sign_str = format!("{}:{}:{}:{}", merchant_id, form.amount, secret2, form.order_id);
        let expected_sign = format!("{:x}", md5::Md5::digest(sign_str.as_bytes()));
        if form.sign != expected_sign {
            return Err(poem::Error::from_string("Invalid signature", poem::http::StatusCode::BAD_REQUEST));
        }

        let order_uuid = Uuid::parse_str(&form.order_id).unwrap();
        let txn = self.db.begin().await.unwrap();

        // 2. Аудит (Запись транзакции)
        let raw_json = serde_json::to_value(&form.0).unwrap();
        let new_tx = transactions::ActiveModel {
            id: Set(Uuid::new_v4()),
            order_id: Set(Some(order_uuid)),
            payment_system: Set(PaymentSystem::FreeKassa),
            external_tx_id: Set(form.intid.clone()),
            amount_received: Set(form.amount.parse().unwrap_or(0.0)),
            raw_request: Set(raw_json),
            ..Default::default()
        };
        new_tx.insert(&txn).await.unwrap();

        // 3. Бизнес-логика
        let order = orders::Entity::find_by_id(order_uuid).one(&txn).await.unwrap().unwrap();
        if order.status == OrderStatus::Paid {
            txn.commit().await.unwrap();
            return Ok(PlainText("YES".to_string()));
        }

        let product = products::Entity::find_by_id(order.product_id).one(&txn).await.unwrap().unwrap();

        if order.is_gift {
            // Создаем Voucher
        } else {
            // Создаем Pending Subscription
        }

        let mut active_order: orders::ActiveModel = order.into();
        active_order.status = Set(OrderStatus::Paid);
        active_order.update(&txn).await.unwrap();

        txn.commit().await.unwrap();
        Ok(PlainText("YES".to_string()))
    }

    /// 3. Возврат пользователя после успешной оплаты
    #[oai(path = "/billing/freekassa/success", method = "post")]
    async fn fk_success(&self, form: Form<FkResultForm>) -> poem::Result<poem::web::Redirect> {
        Ok(poem::web::Redirect::found(format!("/dashboard?payment=success&order={}", form.order_id)))
    }

    /// 4. Возврат пользователя после отмены
    #[oai(path = "/billing/freekassa/fail", method = "post")]
    async fn fk_fail(&self, form: Form<FkResultForm>) -> poem::Result<poem::web::Redirect> {
        Ok(poem::web::Redirect::found(format!("/dashboard?payment=fail&order={}", form.order_id)))
    }
}
```

### 4.3. Фоновая синхронизация (Cron Job / API `getOrders`)
Для фоновых задач в экосистеме Rust/Tokio нет необходимости использовать тяжеловесные решения вроде Python Celery (с Redis/RabbitMQ). Вся логика выполняется в изолированном асинхронном цикле (`tokio::spawn`), запущенном при старте сервера.

```rust
// [AI-PROMPT] Реализовать фоновый таск в anet-auth/src/main.rs
pub async fn cron_sync_freekassa(db: DatabaseConnection) {
    let shop_id = std::env::var("FK_SHOP_ID").unwrap();
    let api_key = std::env::var("FK_API_KEY").unwrap(); // API KEY из ЛК FreeKassa

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(900)).await; // Каждые 15 минут

        // 1. Ищем заказы в статусе Pending старше 15 минут
        // 2. Делаем POST https://api.freekassa.ru/v1/orders
        //    Payload: {"shopId": "<ID>", "nonce": <UNIX_TS>, "signature": "<SIGN>", "orderId": "<Наш UUID>"}
        //    Signature: md5(shopId+nonce+api_key)
        // 3. Анализируем ответ:
        //    - status == 1 (Paid) -> Форсированно выдаем товар (создаем Transaction "Sync" и Subscription/Voucher).
        //    - status == 8 (Error) | 9 (Cancelled) -> Переводим Order в Failed/Cancelled.
    }
}
```

## 5. Прототипы API Личного Кабинета (User WebUI)
Эндпоинты защищены JWT токеном пользователя.

```rust
// [AI-PROMPT] Реализовать эндпоинты в anet-auth/src/api/user_cabinet.rs:

/// GET /api/v1/user/me
/// Возвращает: Данные User, Баланс, Активную подписку (с лимитами), список Pending подписок, список купленных Ваучеров.

/// GET /api/v1/user/sessions
/// Возвращает: Список активных VPN-подключений текущего пользователя (IP, Транспорт, RX/TX).

/// POST /api/v1/user/sessions/disconnect
/// Принимает: server_id. Отправляет команду разрыва сессии на ноду.

/// POST /api/v1/user/vouchers/claim
/// Принимает: code (промокод). Переводит Voucher в статус Claimed, создает Pending Subscription.
```

## 6. Прототипы API Администратора (Admin WebUI)
Эндпоинты защищены JWT токеном администратора (сущность `admins`).

```rust
// [AI-PROMPT] Реализовать эндпоинты в anet-auth/src/api/admin_billing.rs:

/// CRUD для Products:
/// GET /api/v1/admin/products
/// POST /api/v1/admin/products
/// PATCH /api/v1/admin/products/:id
/// DELETE /api/v1/admin/products/:id

/// Просмотр заказов и транзакций:
/// GET /api/v1/admin/orders (с пагинацией и фильтрами по статусу)
/// GET /api/v1/admin/transactions (с пагинацией, возвращает raw_request для дебага)
/// GET /api/v1/admin/vouchers
```

## 7. Telegram Bot (Phase 2)
Разработка Telegram-бота начинается **только после** полной стабилизации WebUI и API биллинга.
Бот выступает как удобная надстройка, дублирующая функционал ЛК через **Telegram Web Apps (TMA)**.
При нажатии кнопки "Личный кабинет" в боте, пользователю открывается адаптированная мобильная версия WebUI внутри Telegram. Авторизация происходит прозрачно через передачу и криптографическую проверку `initData` (Telegram ID связывается с таблицей `users`). Внутри TMA пользователь может получить свой конфиг, управлять сессиями и приобретать товары (включая оплату через Telegram Stars) в формате бесшовного окна.

## 8. Личный Кабинет Пользователя (WebUI)
Приоритет №1 — полнофункциональный веб-кабинет для конечных пользователей.

**Функционал ЛК (User Dashboard):**
1.  **Авторизация:** Email/Пароль + кнопка "Войти через Telegram" (OAuth/Widget).
2.  **Главная страница:**
    *   Отображение активной подписки (Название, Лимиты, Дата окончания).
    *   **Инвентарь:** Список ожидающих активации подписок (`Pending`) и купленных подарочных ваучеров (с кнопкой "Скопировать код").
    *   **Активация ваучера:** Поле ввода кода (`ANET-GIFT-...`) для применения подарка к своему аккаунту.
3.  **Управление профилями (Ключами):**
    *   Список сгенерированных профилей.
    *   Кнопки "Скачать .toml" и "Показать QR-код".
    *   **Активные сессии:** Список текущих подключений с кнопкой **"Отключить (Disconnect)"** (отправляет команду `disconnect_user` на ноду).
4.  **Магазин (Тарифы):**
    *   Витрина доступных `Products`.
    *   Переключатель "Купить себе" / "Купить в подарок" (`is_gift`).

## 9. Интерфейс Администратора (Admin WebUI)
В боковое меню панели управления добавляется раздел **Billing & Commerce**:
*   **Accounts:** Список пользователей ЛК, их баланс, привязанные Telegram ID и список VPN-профилей.
*   **Products:** CRUD-интерфейс каталога товаров. Настройка цен, типов продуктов и привязка к `target_id`.
*   **Orders & Transactions:** Единый центр мониторинга платежей. Позволяет отслеживать конверсию заказов и просматривать сырые данные транзакций (JSONB) для отладки интеграций с платежными шлюзами.
*   **Vouchers:** Реестр подарочных кодов с отслеживанием статуса (кем куплен, кем активирован).
пки "Личный кабинет" в боте, пользователю открывается адаптированная мобильная версия WebUI внутри Telegram. Авторизация происходит прозрачно через передачу и криптографическую проверку `initData`. Внутри TMA пользователь может управлять профилями и приобретать товары (включая оплату через Telegram Stars) в формате бесшовного окна.