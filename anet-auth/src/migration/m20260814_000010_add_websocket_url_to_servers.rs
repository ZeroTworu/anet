use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Servers::Table)
                    .add_column(ColumnDef::new(Servers::WebsocketUrl).text().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Servers::Table)
                    .drop_column(Servers::WebsocketUrl)
                    .to_owned(),
            )
            .await
    }
}

#[derive(Iden)]
enum Servers {
    Table,
    WebsocketUrl,
}
