//! Связь pool ↔ node с весом участника.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "node_pool_members")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub pool_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub server_id: Uuid,
    pub weight: i32,
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

impl ActiveModelBehavior for ActiveModel {}
