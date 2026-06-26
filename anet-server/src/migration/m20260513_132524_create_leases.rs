use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {

        manager
        .create_table(
            Table::create()
                .table(Clients::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(Clients::Fingerprint)
                        .string()
                        .not_null()
                        .primary_key()
                )
                .col(
                    ColumnDef::new(Clients::Ip)
                        .big_integer()
                        .not_null()
                        .unique_key()
                )
                .col(
                    ColumnDef::new(Clients::CreatedAt)
                        .timestamp()
                        .not_null()
                        .default(Expr::current_timestamp())
                )
                .col(
                    ColumnDef::new(Clients::UpdatedAt)
                        .timestamp()
                        .not_null()
                        .default(Expr::current_timestamp())
                )
                .to_owned()
        )
        .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {

        manager
            .drop_table(Table::drop().table(Clients::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Clients {
    Table,
    Fingerprint,
    Ip,
    CreatedAt,
    UpdatedAt,
}
