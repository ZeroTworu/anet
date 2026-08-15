//! Создаёт lifetime-счётчики трафика с ключом `(node, boot_id, fingerprint)`.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(TrafficTotals::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(TrafficTotals::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(TrafficTotals::ServerId).uuid().not_null())
                    .col(ColumnDef::new(TrafficTotals::BootId).text().not_null())
                    .col(ColumnDef::new(TrafficTotals::UserId).uuid().null())
                    .col(ColumnDef::new(TrafficTotals::Fingerprint).text().not_null())
                    .col(
                        ColumnDef::new(TrafficTotals::RxBytes)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TrafficTotals::TxBytes)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TrafficTotals::UpdatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-traffic-total-server")
                            .from(TrafficTotals::Table, TrafficTotals::ServerId)
                            .to(Servers::Table, Servers::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-traffic-total-user")
                            .from(TrafficTotals::Table, TrafficTotals::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .to_owned(),
            )
            .await?;

        // Уникальный ключ делает cumulative report идемпотентным при повторах.
        manager
            .create_index(
                Index::create()
                    .name("uq-traffic-total-boot-identity")
                    .if_not_exists()
                    .table(TrafficTotals::Table)
                    .col(TrafficTotals::ServerId)
                    .col(TrafficTotals::BootId)
                    .col(TrafficTotals::Fingerprint)
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(TrafficTotals::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum TrafficTotals {
    Table,
    Id,
    ServerId,
    BootId,
    UserId,
    Fingerprint,
    RxBytes,
    TxBytes,
    UpdatedAt,
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
