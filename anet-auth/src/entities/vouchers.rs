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
