//! Создаёт очередь команд панели для исходящего polling со стороны ноды.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(NodeCommands::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(NodeCommands::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(NodeCommands::ServerId).uuid().not_null())
                    .col(ColumnDef::new(NodeCommands::CommandType).text().not_null())
                    .col(
                        ColumnDef::new(NodeCommands::AcceptingConnections)
                            .boolean()
                            .null(),
                    )
                    .col(ColumnDef::new(NodeCommands::Status).text().not_null())
                    .col(
                        ColumnDef::new(NodeCommands::CreatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .col(ColumnDef::new(NodeCommands::StartedAt).timestamp().null())
                    .col(ColumnDef::new(NodeCommands::CompletedAt).timestamp().null())
                    .col(ColumnDef::new(NodeCommands::Error).text().null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-node-command-server")
                            .from(NodeCommands::Table, NodeCommands::ServerId)
                            .to(Servers::Table, Servers::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Обычный индекс нельзя объявлять как table constraint: PostgreSQL
        // принимает внутри CREATE TABLE только PRIMARY KEY/UNIQUE/FOREIGN KEY.
        manager
            .create_index(
                Index::create()
                    .name("idx-node-command-pending")
                    .if_not_exists()
                    .table(NodeCommands::Table)
                    .col(NodeCommands::ServerId)
                    .col(NodeCommands::Status)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(NodeCommands::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum NodeCommands {
    Table,
    Id,
    ServerId,
    CommandType,
    AcceptingConnections,
    Status,
    CreatedAt,
    StartedAt,
    CompletedAt,
    Error,
}

#[derive(Iden)]
enum Servers {
    Table,
    Id,
}
