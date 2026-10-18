//! Создаёт таблицы rule_providers и admin_custom_overrides для Smart DNS, Geo-Routing и AdBlock.
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. Таблица внешних провайдеров правил (rule_providers)
        manager
            .create_table(
                Table::create()
                    .table(RuleProviders::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(RuleProviders::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(RuleProviders::Name)
                            .text()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(RuleProviders::Description)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(RuleProviders::ProviderType)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(RuleProviders::Format)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(RuleProviders::Url)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(RuleProviders::UpdateIntervalHours)
                            .integer()
                            .not_null()
                            .default(24),
                    )
                    .col(ColumnDef::new(RuleProviders::LastFetchedAt).timestamp().null())
                    .col(ColumnDef::new(RuleProviders::LastEtag).text().null())
                    .col(
                        ColumnDef::new(RuleProviders::ItemCount)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(RuleProviders::IsActive)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(ColumnDef::new(RuleProviders::CreatedAt).timestamp().not_null())
                    .col(ColumnDef::new(RuleProviders::UpdatedAt).timestamp().not_null())
                    .to_owned(),
            )
            .await?;

        // 2. Таблица администраторских исключений (admin_custom_overrides)
        manager
            .create_table(
                Table::create()
                    .table(AdminCustomOverrides::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AdminCustomOverrides::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(AdminCustomOverrides::RouteMapId).uuid().null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_admin_overrides_route_map_id")
                            .from(AdminCustomOverrides::Table, AdminCustomOverrides::RouteMapId)
                            .to(RouteMaps::Table, RouteMaps::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .col(
                        ColumnDef::new(AdminCustomOverrides::RuleType)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AdminCustomOverrides::Pattern)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AdminCustomOverrides::Category)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AdminCustomOverrides::Comment)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(AdminCustomOverrides::IsActive)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(ColumnDef::new(AdminCustomOverrides::CreatedAt).timestamp().not_null())
                    .col(ColumnDef::new(AdminCustomOverrides::UpdatedAt).timestamp().not_null())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(AdminCustomOverrides::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(RuleProviders::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum RouteMaps {
    Table,
    Id,
}

#[derive(DeriveIden)]
pub enum RuleProviders {
    Table,
    Id,
    Name,
    Description,
    ProviderType,
    Format,
    Url,
    UpdateIntervalHours,
    LastFetchedAt,
    LastEtag,
    ItemCount,
    IsActive,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum AdminCustomOverrides {
    Table,
    Id,
    RouteMapId,
    RuleType,
    Pattern,
    Category,
    Comment,
    IsActive,
    CreatedAt,
    UpdatedAt,
}
