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
