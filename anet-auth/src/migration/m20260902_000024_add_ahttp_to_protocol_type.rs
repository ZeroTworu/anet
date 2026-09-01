use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        // В PostgreSQL добавление значения в существующий ENUM выполняется через ALTER TYPE.
        // Используем 'ADD VALUE IF NOT EXISTS', что безопасно при повторных накатах (поддерживается в PG 13+).
        let sql = "ALTER TYPE protocol_type ADD VALUE IF NOT EXISTS 'ahttp';";

        db.execute_unprepared(sql).await.map(|_| ())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // В PostgreSQL операция удаления значения из типа ENUM (DROP VALUE) не поддерживается нативно.
        // Для отката потребовалось бы полностью пересоздавать тип и перезаписывать колонки таблиц,
        // что несет риски потери данных в продакшене.
        // Поэтому для отката этой миграции безопасно оставить тип как есть.
        Ok(())
    }
}
