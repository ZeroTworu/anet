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
