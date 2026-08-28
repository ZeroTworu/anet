use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        // 1. Создаем таблицу groups без лишних extra-параметров
        manager
            .create_table(
                Table::create()
                    .table(Alias::new("groups"))
                    .if_not_exists()
                    .col(ColumnDef::new(Alias::new("id")).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Alias::new("name")).text().not_null().unique_key())
                    .col(ColumnDef::new(Alias::new("traffic_limit")).big_integer().not_null().default(0))
                    .col(ColumnDef::new(Alias::new("speed_limit")).integer().not_null().default(0))
                    .col(ColumnDef::new(Alias::new("sessions_limit")).integer().not_null().default(1))
                    .col(ColumnDef::new(Alias::new("duration_days")).integer().not_null().default(30))
                    .col(ColumnDef::new(Alias::new("created_at")).timestamp().not_null())
                    .col(ColumnDef::new(Alias::new("updated_at")).timestamp().not_null())
                    .to_owned(),
            )
            .await?;

        // Накатываем ограничения CHECK через нативные ALTER-запросы (гарантирует корректный SQL)
        db.execute_unprepared("ALTER TABLE groups ADD CONSTRAINT check_traffic_limit_positive CHECK (traffic_limit >= 0);").await?;
        db.execute_unprepared("ALTER TABLE groups ADD CONSTRAINT check_speed_limit_positive CHECK (speed_limit >= 0);").await?;
        db.execute_unprepared("ALTER TABLE groups ADD CONSTRAINT check_sessions_limit_positive CHECK (sessions_limit >= 0);").await?;
        db.execute_unprepared("ALTER TABLE groups ADD CONSTRAINT check_duration_days_positive CHECK (duration_days >= 0);").await?;

        // 2. Добавляем колонку group_id в таблицу пользователей users
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("users"))
                    .add_column(ColumnDef::new(Alias::new("group_id")).uuid().null())
                    .to_owned(),
            )
            .await?;

        // Создаем внешний ключ из users к groups
        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name("fk-users-group")
                    .from(Alias::new("users"), Alias::new("group_id"))
                    .to(Alias::new("groups"), Alias::new("id"))
                    .on_delete(ForeignKeyAction::SetNull)
                    .on_update(ForeignKeyAction::Cascade)
                    .to_owned(),
            )
            .await?;

        // 3. Расширяем таблицу rates новыми колонками трафика и скорости с ограничениями CHECK
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("rates"))
                    .add_column(ColumnDef::new(Alias::new("traffic_limit")).big_integer().not_null().default(0))
                    .add_column(ColumnDef::new(Alias::new("speed_limit")).integer().not_null().default(0))
                    .to_owned(),
            )
            .await?;

        // Добавляем ограничения CHECK в таблицу rates
        db.execute_unprepared("ALTER TABLE rates ADD CONSTRAINT check_rates_traffic CHECK (traffic_limit >= 0);").await?;
        db.execute_unprepared("ALTER TABLE rates ADD CONSTRAINT check_rates_speed CHECK (speed_limit >= 0);").await?;

        // 4. Сеем базовые группы (Standard и PowerUser)
        let now = chrono::Utc::now().naive_utc().to_string();

        // Группа Standard: Лимит 100 GB (107374182400 байт), Скорость 50 Mbps (51200 kbps), 1 сессия, доступ 30 дней
        let sql_standard = format!(
            "INSERT INTO groups (id, name, traffic_limit, speed_limit, sessions_limit, duration_days, created_at, updated_at) \
             VALUES ('00000000-0000-4000-c000-000000000001', 'Standard', 107374182400, 51200, 1, 30, '{now}', '{now}')"
        );
        db.execute_unprepared(&sql_standard).await?;

        // Группа VIP: Без лимита трафика (0), Без лимита скорости (0), 3 сессии, доступ 90 дней
        let sql_poweruser = format!(
            "INSERT INTO groups (id, name, traffic_limit, speed_limit, sessions_limit, duration_days, created_at, updated_at) \
             VALUES ('00000000-0000-4000-c000-000000000002', 'PowerUser', 0, 0, 3, 90, '{now}', '{now}')"
        );
        db.execute_unprepared(&sql_poweruser).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let _ = db.execute_unprepared("ALTER TABLE rates DROP CONSTRAINT IF EXISTS check_rates_traffic;").await;
        let _ = db.execute_unprepared("ALTER TABLE rates DROP CONSTRAINT IF EXISTS check_rates_speed;").await;
        let _ = manager.drop_foreign_key(ForeignKey::drop().name("fk-users-group").table(Alias::new("users")).to_owned()).await;
        let _ = manager.alter_table(Table::alter().table(Alias::new("users")).drop_column(Alias::new("group_id")).to_owned()).await;
        let _ = manager.alter_table(Table::alter().table(Alias::new("rates")).drop_column(Alias::new("traffic_limit")).drop_column(Alias::new("speed_limit")).to_owned()).await;

        let _ = db.execute_unprepared("ALTER TABLE groups DROP CONSTRAINT IF EXISTS check_traffic_limit_positive;").await;
        let _ = db.execute_unprepared("ALTER TABLE groups DROP CONSTRAINT IF EXISTS check_speed_limit_positive;").await;
        let _ = db.execute_unprepared("ALTER TABLE groups DROP CONSTRAINT IF EXISTS check_sessions_limit_positive;").await;
        let _ = db.execute_unprepared("ALTER TABLE groups DROP CONSTRAINT IF EXISTS check_duration_days_positive;").await;

        let _ = manager.drop_table(Table::drop().table(Alias::new("groups")).to_owned()).await;
        let _ = db.execute_unprepared("DROP TABLE IF EXISTS groups;").await;
        Ok(())
    }
}
