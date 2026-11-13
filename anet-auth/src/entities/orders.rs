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
