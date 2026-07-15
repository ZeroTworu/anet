use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Server::Table)
                    .add_column(
                        ColumnDef::new(Server::IsActive)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Server::Table)
                    .drop_column(Server::IsActive)
                    .to_owned(),
            )
            .await
    }
}

#[derive(Iden)]
pub enum Server {
    #[iden = "servers"]
    Table,
    IsActive,
}
