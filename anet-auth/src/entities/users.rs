use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,

    #[sea_orm(unique, column_type = "Text")]
    pub fingerprint: String,

    #[sea_orm(column_type = "Text", nullable)]
    pub uid: Option<String>,

    pub is_active: bool,

    pub created_at: DateTime,
    pub updated_at: DateTime,

    pub static_ip: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_one = "super::rates::Entity")]
    Rate,
    #[sea_orm(has_one = "super::active_sessions::Entity")]
    ActiveSession,

}

impl Related<super::rates::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Rate.def()
    }
}

impl Related<super::active_sessions::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ActiveSession.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
