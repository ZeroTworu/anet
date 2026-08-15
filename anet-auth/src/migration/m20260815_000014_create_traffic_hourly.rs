//! Создаёт почасовые агрегаты трафика для истории в админке.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(TrafficHourly::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(TrafficHourly::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(TrafficHourly::BucketStart)
                            .timestamp()
                            .not_null(),
                    )
                    .col(ColumnDef::new(TrafficHourly::ServerId).uuid().not_null())
                    .col(ColumnDef::new(TrafficHourly::UserId).uuid().null())
                    .col(ColumnDef::new(TrafficHourly::Fingerprint).text().not_null())
                    .col(
                        ColumnDef::new(TrafficHourly::RxBytes)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TrafficHourly::TxBytes)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TrafficHourly::UpdatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-traffic-hourly-server")
                            .from(TrafficHourly::Table, TrafficHourly::ServerId)
                            .to(Servers::Table, Servers::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-traffic-hourly-user")
                            .from(TrafficHourly::Table, TrafficHourly::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("uq-traffic-hourly-node-identity")
                    .if_not_exists()
                    .table(TrafficHourly::Table)
                    .col(TrafficHourly::BucketStart)
                    .col(TrafficHourly::ServerId)
                    .col(TrafficHourly::Fingerprint)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // Отдельный индекс ускоряет выбор диапазона для графика истории.
        manager
            .create_index(
                Index::create()
                    .name("idx-traffic-hourly-bucket")
                    .if_not_exists()
                    .table(TrafficHourly::Table)
                    .col(TrafficHourly::BucketStart)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(TrafficHourly::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum TrafficHourly {
    Table,
    Id,
    BucketStart,
    ServerId,
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
