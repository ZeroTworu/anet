use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ActiveSession::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(ActiveSession::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(ActiveSession::UserId).uuid().not_null().unique_key())
                    .col(ColumnDef::new(ActiveSession::Sessions).integer().not_null().default(0))
                    .col(ColumnDef::new(ActiveSession::CreatedAt).timestamp().not_null())
                    .col(ColumnDef::new(ActiveSession::UpdatedAt).timestamp().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-activesessions-user")
                            .from(ActiveSession::Table, ActiveSession::UserId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(ActiveSession::Table).to_owned()).await
    }
}

#[derive(Iden)]
pub enum ActiveSession { #[iden = "active_sessions"] Table, Id, UserId, Sessions, CreatedAt, UpdatedAt }
#[derive(Iden)]
pub enum User { #[iden = "users"] Table, Id }
