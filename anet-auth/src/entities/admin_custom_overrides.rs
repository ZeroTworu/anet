//! Сущность администраторских исключений (Custom Overrides) для доменов и IP.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "admin_custom_overrides")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub route_map_id: Option<Uuid>, // None = глобально для всех профилей
    pub rule_type: String,          // "domain" | "wildcard" | "cidr"
    pub pattern: String,            // например, "corp.internal", "192.168.0.0/16"
    pub category: String,           // "custom_block" | "custom_direct" | "custom_proxy"
    pub comment: String,
    pub is_active: bool,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
