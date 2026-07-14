use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(UserServer::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(UserServer::UserId).uuid().not_null())
                    .col(ColumnDef::new(UserServer::ServerId).uuid().not_null())
                    // Составной первичный ключ
                    .primary_key(
                        Index::create()
                            .col(UserServer::UserId)
                            .col(UserServer::ServerId)
                    )
                    // Каскадная связь с пользователями
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-userservers-user")
                            .from(UserServer::Table, UserServer::UserId)
                            .to(Alias::new("users"), Alias::new("id"))
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade)
                    )
                    // Каскадная связь с серверами
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-userservers-server")
                            .from(UserServer::Table, UserServer::ServerId)
                            .to(Alias::new("servers"), Alias::new("id"))
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade)
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UserServer::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
pub enum UserServer {
    #[iden = "user_servers"]
    Table,
    UserId,
    ServerId,
}
