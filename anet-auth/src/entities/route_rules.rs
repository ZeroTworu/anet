//! Упорядоченное правило route map: CIDR, домен или приложение и его действие.
use sea_orm::entity::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteMatchKind {
    Cidr,
    Domain,
    Application,
    RuleProvider,
}

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "route_rules")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub route_map_id: Uuid,
    pub position: i32,
    pub match_type: String,
    pub match_value: String,
    pub action: String,
}

impl Model {
    pub fn match_kind(&self) -> Option<RouteMatchKind> {
        match self.match_type.as_str() {
            "cidr" | "ip" => Some(RouteMatchKind::Cidr),
            "domain" => Some(RouteMatchKind::Domain),
            "application" | "app" => Some(RouteMatchKind::Application),
            "rule_provider" | "provider" => Some(RouteMatchKind::RuleProvider),
            _ => None,
        }
    }

    pub fn rule_action(&self) -> anet_filter_core::RuleAction {
        anet_filter_core::RuleAction::from_str_loose(&self.action).unwrap_or(anet_filter_core::RuleAction::Direct)
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::route_maps::Entity",
        from = "Column::RouteMapId",
        to = "super::route_maps::Column::Id",
        on_delete = "Cascade"
    )]
    RouteMap,
}

impl ActiveModelBehavior for ActiveModel {}
