//! Упорядоченное правило route map: CIDR или приложение и его действие.

use sea_orm::entity::prelude::*;

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
