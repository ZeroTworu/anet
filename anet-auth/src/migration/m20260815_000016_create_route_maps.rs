//! Создаёт route maps, их правила и назначения пользователям.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(RouteMaps::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(RouteMaps::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(RouteMaps::Name)
                            .text()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(RouteMaps::Description)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(ColumnDef::new(RouteMaps::DefaultAction).text().not_null())
                    .col(
                        ColumnDef::new(RouteMaps::IsActive)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(RouteMaps::Revision)
                            .big_integer()
                            .not_null()
                            .default(1),
                    )
                    .col(ColumnDef::new(RouteMaps::CreatedAt).timestamp().not_null())
                    .col(ColumnDef::new(RouteMaps::UpdatedAt).timestamp().not_null())
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(RouteRules::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(RouteRules::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(RouteRules::RouteMapId).uuid().not_null())
                    .col(ColumnDef::new(RouteRules::Position).integer().not_null())
                    .col(ColumnDef::new(RouteRules::MatchType).text().not_null())
                    .col(ColumnDef::new(RouteRules::MatchValue).text().not_null())
                    .col(ColumnDef::new(RouteRules::Action).text().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-route-rule-map")
                            .from(RouteRules::Table, RouteRules::RouteMapId)
                            .to(RouteMaps::Table, RouteMaps::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("uq-route-rule-position")
                    .if_not_exists()
                    .table(RouteRules::Table)
                    .col(RouteRules::RouteMapId)
                    .col(RouteRules::Position)
                    .unique()
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(UserRouteMaps::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(UserRouteMaps::UserId)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(UserRouteMaps::RouteMapId).uuid().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-user-route-map-user")
                            .from(UserRouteMaps::Table, UserRouteMaps::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-user-route-map-map")
                            .from(UserRouteMaps::Table, UserRouteMaps::RouteMapId)
                            .to(RouteMaps::Table, RouteMaps::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UserRouteMaps::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(RouteRules::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(RouteMaps::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum RouteMaps {
    Table,
    Id,
    Name,
    Description,
    DefaultAction,
    IsActive,
    Revision,
    CreatedAt,
    UpdatedAt,
}
#[derive(Iden)]
enum RouteRules {
    Table,
    Id,
    RouteMapId,
    Position,
    MatchType,
    MatchValue,
    Action,
}
#[derive(Iden)]
enum UserRouteMaps {
    Table,
    UserId,
    RouteMapId,
}
#[derive(Iden)]
enum Users {
    Table,
    Id,
}
