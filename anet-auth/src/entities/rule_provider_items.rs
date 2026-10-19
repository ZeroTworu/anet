//! Сущность закэшированного элемента провайдера правил (rule_provider_items).
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "rule_provider_items")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub provider_id: Uuid,
    pub rule_value: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::rule_providers::Entity",
        from = "Column::ProviderId",
        to = "super::rule_providers::Column::Id",
        on_delete = "Cascade"
    )]
    RuleProvider,
}

impl ActiveModelBehavior for ActiveModel {}
