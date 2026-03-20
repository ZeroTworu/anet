use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Admin::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Admin::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Admin::Login).text().not_null().unique_key())
                    .col(ColumnDef::new(Admin::PassHash).text().not_null())
                    .col(ColumnDef::new(Admin::CreatedAt).timestamp().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Session::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Session::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Session::AdminId).uuid().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-session-admin")
                            .from(Session::Table, Session::AdminId)
                            .to(Admin::Table, Admin::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .col(ColumnDef::new(Session::ExpiresAt).timestamp().not_null())
                    .col(ColumnDef::new(Session::CreatedAt).timestamp().not_null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Session::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Admin::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
pub enum Admin {
    #[iden = "admins"]
    Table,
    Id,
    Login,
    PassHash,
    CreatedAt,
}
#[derive(Iden)]
pub enum Session {
    #[iden = "sessions"]
    Table,
    Id,
    AdminId,
    ExpiresAt,
    CreatedAt,
}
