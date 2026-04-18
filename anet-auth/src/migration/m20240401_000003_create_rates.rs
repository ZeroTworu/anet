use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Rate::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Rate::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Rate::UserId).uuid().not_null())
                    .col(ColumnDef::new(Rate::Sessions).integer().not_null())
                    .col(ColumnDef::new(Rate::DateEnd).timestamp().not_null())
                    .col(ColumnDef::new(Rate::CreatedAt).timestamp().not_null())
                    .col(ColumnDef::new(Rate::UpdatedAt).timestamp().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-rate-user")
                            .from(Rate::Table, Rate::UserId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Rate::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
pub enum Rate {
    #[iden = "rates"]
    Table,
    Id,
    UserId,
    Sessions,
    DateEnd,
    CreatedAt,
    UpdatedAt,
}

#[derive(Iden)]
pub enum User {
    #[iden = "users"]
    Table,
    Id,
}
