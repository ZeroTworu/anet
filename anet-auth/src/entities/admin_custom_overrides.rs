//! Сущность администраторских исключений (Custom Overrides) для доменов и IP.
use poem_openapi::Enum as OpenApiEnum;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize, OpenApiEnum,
)]
#[sea_orm(rs_type = "String", db_type = "Text")]
#[oai(rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum OverrideType {
    #[sea_orm(string_value = "domain")]
    Domain,
    #[sea_orm(string_value = "wildcard")]
    SubdomainWildcard,
    #[sea_orm(string_value = "cidr")]
    IpNet,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize, OpenApiEnum,
)]
#[sea_orm(rs_type = "String", db_type = "Text")]
#[oai(rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum OverrideCategory {
    #[sea_orm(string_value = "block")]
    CustomBlock,
    #[sea_orm(string_value = "direct")]
    CustomDirect,
    #[sea_orm(string_value = "proxy")]
    CustomProxy,
}

impl From<OverrideCategory> for anet_filter_core::RuleAction {
    fn from(cat: OverrideCategory) -> Self {
        match cat {
            OverrideCategory::CustomBlock => anet_filter_core::RuleAction::Block,
            OverrideCategory::CustomDirect => anet_filter_core::RuleAction::Direct,
            OverrideCategory::CustomProxy => anet_filter_core::RuleAction::Proxy,
        }
    }
}

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "admin_custom_overrides")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub route_map_id: Option<Uuid>, // None = глобально для всех профилей
    pub rule_type: OverrideType,
    pub pattern: String,
    pub category: OverrideCategory,
    pub comment: String,
    pub is_active: bool,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
