use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Server::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Server::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Server::Name).text().not_null())
                    .col(ColumnDef::new(Server::Address).text().not_null())
                    .col(ColumnDef::new(Server::PublicKey).text().not_null())
                    .col(ColumnDef::new(Server::QuicPort).integer().null())
                    .col(ColumnDef::new(Server::SshPort).integer().null())
                    .col(ColumnDef::new(Server::VncPort).integer().null())
                    .col(ColumnDef::new(Server::SshUser).text().null())
                    .col(ColumnDef::new(Server::CreatedAt).timestamp().not_null())
                    .col(ColumnDef::new(Server::UpdatedAt).timestamp().not_null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Server::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
pub enum Server {
    #[iden = "servers"]
    Table,
    Id,
    Name,
    Address,
    PublicKey,
    QuicPort,
    SshPort,
    VncPort,
    SshUser,
    CreatedAt,
    UpdatedAt,
}
