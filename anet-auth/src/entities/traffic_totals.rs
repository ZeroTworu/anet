//! Идемпотентные накопительные счётчики трафика по ноде, пользователю и протоколу.

use sea_orm::entity::prelude::*;
use super::ProtocolType;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "traffic_totals")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub server_id: Uuid,
    pub boot_id: String,
    pub user_id: Option<Uuid>,
    pub fingerprint: String,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
    pub updated_at: DateTime,
    pub protocol: ProtocolType,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::servers::Entity",
        from = "Column::ServerId",
        to = "super::servers::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Server,
    #[sea_orm(
        belongs_to = "super::users::Entity",
        from = "Column::UserId",
        to = "super::users::Column::Id",
        on_update = "Cascade",
        on_delete = "SetNull"
    )]
    User,
}

impl ActiveModelBehavior for ActiveModel {}
