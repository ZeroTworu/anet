use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        // В PostgreSQL добавление значения в существующий ENUM выполняется через ALTER TYPE.
        // Используем 'ADD VALUE IF NOT EXISTS', что безопасно при повторных накатах.
        let sql = "ALTER TYPE protocol_type ADD VALUE IF NOT EXISTS 'wrtc';";

        db.execute_unprepared(sql).await.map(|_| ())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // В PostgreSQL операция удаления значения из типа ENUM (DROP VALUE) не поддерживается нативно.
        // Оставляем тип без изменений для предотвращения потери данных.
        Ok(())
    }
}
