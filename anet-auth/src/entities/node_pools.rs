//! Сущность пула нод и его стратегия балансировки.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "node_pools")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub name: String,
    pub strategy: String,
    pub is_active: bool,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::node_pool_members::Entity")]
    Member,
    #[sea_orm(has_many = "super::group_node_pools::Entity")]
    GroupNodePool,
}

impl Related<super::groups::Entity> for Entity {
    fn to() -> RelationDef {
        super::group_node_pools::Relation::Group.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::group_node_pools::Relation::Pool.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {}
