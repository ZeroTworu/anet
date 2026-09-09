//! Связь pool ↔ node с весом участника, выбранным протоколом и кастомным портом/URL.

use super::protocol_type::ProtocolType;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "node_pool_members")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub pool_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub server_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub protocol: ProtocolType,
    pub weight: i32,
    pub port_or_url: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::node_pools::Entity",
        from = "Column::PoolId",
        to = "super::node_pools::Column::Id",
        on_delete = "Cascade"
    )]
    Pool,
    #[sea_orm(
        belongs_to = "super::servers::Entity",
        from = "Column::ServerId",
        to = "super::servers::Column::Id",
        on_delete = "Cascade"
    )]
    Server,
}

impl Related<super::node_pools::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Pool.def()
    }
}

impl Related<super::servers::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Server.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
