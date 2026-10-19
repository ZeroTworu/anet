//! Добавляет поля action и route_map_id в таблицу rule_providers,
//! а также создаёт таблицу rule_provider_items для хранения кэшированных правил провайдеров в БД.
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. Добавляем action и route_map_id в rule_providers
        manager
            .alter_table(
                Table::alter()
                    .table(RuleProviders::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(RuleProviders::Action)
                            .text()
                            .not_null()
                            .default("block"),
                    )
                    .add_column_if_not_exists(
                        ColumnDef::new(RuleProviders::RouteMapId)
                            .uuid()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        // 2. Создаём таблицу rule_provider_items для хранения загруженных правил в БД
        manager
            .create_table(
                Table::create()
                    .table(RuleProviderItems::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(RuleProviderItems::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(RuleProviderItems::ProviderId)
                            .uuid()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_rule_provider_items_provider_id")
                            .from(RuleProviderItems::Table, RuleProviderItems::ProviderId)
                            .to(RuleProviders::Table, RuleProviders::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .col(
                        ColumnDef::new(RuleProviderItems::RuleValue)
                            .text()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_rule_provider_items_provider_id")
                    .table(RuleProviderItems::Table)
                    .col(RuleProviderItems::ProviderId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(RuleProviderItems::Table).to_owned())
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(RuleProviders::Table)
                    .drop_column(RuleProviders::Action)
                    .drop_column(RuleProviders::RouteMapId)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum RuleProviders {
    Table,
    Id,
    Action,
    RouteMapId,
}

#[derive(DeriveIden)]
enum RuleProviderItems {
    Table,
    Id,
    ProviderId,
    RuleValue,
}
