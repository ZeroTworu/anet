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
