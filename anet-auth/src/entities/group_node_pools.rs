//! Назначение одной или нескольких групп серверов (node pools) группе пользователей.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "group_node_pools")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub group_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub pool_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::groups::Entity",
        from = "Column::GroupId",
        to = "super::groups::Column::Id",
        on_delete = "Cascade"
    )]
    Group,
    #[sea_orm(
        belongs_to = "super::node_pools::Entity",
        from = "Column::PoolId",
        to = "super::node_pools::Column::Id",
        on_delete = "Cascade"
    )]
    Pool,
}

impl Related<super::groups::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Group.def()
    }
}

impl Related<super::node_pools::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Pool.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
