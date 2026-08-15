//! Последнее фактическое состояние ноды, полученное через heartbeat.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "node_runtime_states")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub server_id: Uuid,
    /// Время последнего успешно проверенного heartbeat.
    pub last_seen_at: DateTime,
    pub version: String,
    pub uptime_seconds: i64,
    pub active_connections: i64,
    pub accepting_connections: bool,
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
}

impl Related<super::servers::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Server.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
