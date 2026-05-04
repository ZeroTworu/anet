use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(User::Table)
                    .add_column(
                        ColumnDef::new(User::StaticIp)
                            .text()
                            .null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(User::Table)
                    .drop_column(User::StaticIp)
                    .to_owned(),
            )
            .await
    }
}


#[derive(Iden)]
pub enum User {
    #[iden = "users"]
    Table,
    Id,
    Fingerprint,
    Uid,
    IsActive,
    CreatedAt,
    UpdatedAt,
    StaticIp,
}
