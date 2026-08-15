//! Связь VPN-пользователя с применяемой route map.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "user_route_maps")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: Uuid,
    pub route_map_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::users::Entity",
        from = "Column::UserId",
        to = "super::users::Column::Id",
        on_delete = "Cascade"
    )]
    User,
    #[sea_orm(
        belongs_to = "super::route_maps::Entity",
        from = "Column::RouteMapId",
        to = "super::route_maps::Column::Id",
        on_delete = "Cascade"
    )]
    RouteMap,
}
impl ActiveModelBehavior for ActiveModel {}
