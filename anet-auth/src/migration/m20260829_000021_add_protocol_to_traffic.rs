use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        // 1. Создаем тип ENUM в PostgreSQL
        let sql_create_enum = "CREATE TYPE protocol_type AS ENUM ('quic', 'ssh', 'vnc', 'ws');";
        db.execute_unprepared(sql_create_enum).await?;

        // 2. Добавляем колонку в traffic_totals с типом ENUM и значением по умолчанию 'quic'
        let sql_alter_totals = "ALTER TABLE traffic_totals ADD COLUMN protocol protocol_type NOT NULL DEFAULT 'quic';";
        db.execute_unprepared(sql_alter_totals).await?;

        // 3. Добавляем колонку в traffic_hourly с типом ENUM и значением по умолчанию 'quic'
        let sql_alter_hourly = "ALTER TABLE traffic_hourly ADD COLUMN protocol protocol_type NOT NULL DEFAULT 'quic';";
        db.execute_unprepared(sql_alter_hourly).await?;

        // 4. Пересоздаем уникальные составные индексы с учетом новой enum колонки
        // Для traffic_totals:
        manager.drop_index(Index::drop().name("uq-traffic-total-boot-identity").table(Alias::new("traffic_totals")).to_owned()).await?;
        manager.create_index(
            Index::create()
                .name("uq-traffic-total-boot-identity")
                .table(Alias::new("traffic_totals"))
                .col(Alias::new("server_id"))
                .col(Alias::new("boot_id"))
                .col(Alias::new("fingerprint"))
                .col(Alias::new("protocol"))
                .unique()
                .to_owned()
        ).await?;

        // Для traffic_hourly:
        manager.drop_index(Index::drop().name("uq-traffic-hourly-node-identity").table(Alias::new("traffic_hourly")).to_owned()).await?;
        manager.create_index(
            Index::create()
                .name("uq-traffic-hourly-node-identity")
                .table(Alias::new("traffic_hourly"))
                .col(Alias::new("bucket_start"))
                .col(Alias::new("server_id"))
                .col(Alias::new("fingerprint"))
                .col(Alias::new("protocol"))
                .unique()
                .to_owned()
        ).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let _ = manager.drop_index(Index::drop().name("uq-traffic-total-boot-identity").table(Alias::new("traffic_totals")).to_owned()).await;
        let _ = manager.drop_index(Index::drop().name("uq-traffic-hourly-node-identity").table(Alias::new("traffic_hourly")).to_owned()).await;

        let _ = db.execute_unprepared("ALTER TABLE traffic_totals DROP COLUMN IF EXISTS protocol;").await;
        let _ = db.execute_unprepared("ALTER TABLE traffic_hourly DROP COLUMN IF EXISTS protocol;").await;
        let _ = db.execute_unprepared("DROP TYPE IF EXISTS protocol_type;").await;
        Ok(())
    }
}
