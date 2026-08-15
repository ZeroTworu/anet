//! Надёжная очередь команд от панели к ноде.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "node_commands")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub server_id: Uuid,
    pub command_type: String,
    pub accepting_connections: Option<bool>,
    pub status: String,
    pub created_at: DateTime,
    pub started_at: Option<DateTime>,
    pub completed_at: Option<DateTime>,
    pub error: Option<String>,
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
