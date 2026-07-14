use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "servers")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub name: String,
    pub address: String,
    pub public_key: String,
    pub quic_port: Option<i32>,
    pub ssh_port: Option<i32>,
    pub vnc_port: Option<i32>,
    pub ssh_user: Option<String>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl Related<super::users::Entity> for Entity {
    fn to() -> RelationDef {
        super::user_servers::Relation::User.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::user_servers::Relation::Server.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {}
