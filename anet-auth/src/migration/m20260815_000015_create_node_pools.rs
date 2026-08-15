//! Создаёт пулы нод, их участников и назначения пулов пользователям.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(NodePools::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(NodePools::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(NodePools::Name)
                            .text()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(NodePools::Strategy).text().not_null())
                    .col(
                        ColumnDef::new(NodePools::IsActive)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(ColumnDef::new(NodePools::CreatedAt).timestamp().not_null())
                    .col(ColumnDef::new(NodePools::UpdatedAt).timestamp().not_null())
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(NodePoolMembers::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(NodePoolMembers::PoolId).uuid().not_null())
                    .col(ColumnDef::new(NodePoolMembers::ServerId).uuid().not_null())
                    .col(
                        ColumnDef::new(NodePoolMembers::Weight)
                            .integer()
                            .not_null()
                            .default(1),
                    )
                    .primary_key(
                        Index::create()
                            .col(NodePoolMembers::PoolId)
                            .col(NodePoolMembers::ServerId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-pool-member-pool")
                            .from(NodePoolMembers::Table, NodePoolMembers::PoolId)
                            .to(NodePools::Table, NodePools::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-pool-member-server")
                            .from(NodePoolMembers::Table, NodePoolMembers::ServerId)
                            .to(Servers::Table, Servers::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(UserNodePools::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(UserNodePools::UserId).uuid().not_null())
                    .col(ColumnDef::new(UserNodePools::PoolId).uuid().not_null())
                    .primary_key(
                        Index::create()
                            .col(UserNodePools::UserId)
                            .col(UserNodePools::PoolId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-user-pool-user")
                            .from(UserNodePools::Table, UserNodePools::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-user-pool-pool")
                            .from(UserNodePools::Table, UserNodePools::PoolId)
                            .to(NodePools::Table, NodePools::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UserNodePools::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(NodePoolMembers::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(NodePools::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum NodePools {
    Table,
    Id,
    Name,
    Strategy,
    IsActive,
    CreatedAt,
    UpdatedAt,
}
#[derive(Iden)]
enum NodePoolMembers {
    Table,
    PoolId,
    ServerId,
    Weight,
}
#[derive(Iden)]
enum UserNodePools {
    Table,
    UserId,
    PoolId,
}
#[derive(Iden)]
enum Servers {
    Table,
    Id,
}
#[derive(Iden)]
enum Users {
    Table,
    Id,
}
