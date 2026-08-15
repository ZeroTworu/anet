//! Создаёт таблицу последнего heartbeat-состояния каждой ноды.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(NodeRuntimeStates::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(NodeRuntimeStates::ServerId)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(NodeRuntimeStates::LastSeenAt)
                            .timestamp()
                            .not_null(),
                    )
                    .col(ColumnDef::new(NodeRuntimeStates::Version).text().not_null())
                    .col(
                        ColumnDef::new(NodeRuntimeStates::UptimeSeconds)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(NodeRuntimeStates::ActiveConnections)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(NodeRuntimeStates::AcceptingConnections)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-node-runtime-server")
                            .from(NodeRuntimeStates::Table, NodeRuntimeStates::ServerId)
                            .to(Servers::Table, Servers::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(NodeRuntimeStates::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum NodeRuntimeStates {
    Table,
    ServerId,
    LastSeenAt,
    Version,
    UptimeSeconds,
    ActiveConnections,
    AcceptingConnections,
}

#[derive(Iden)]
enum Servers {
    Table,
    Id,
}
