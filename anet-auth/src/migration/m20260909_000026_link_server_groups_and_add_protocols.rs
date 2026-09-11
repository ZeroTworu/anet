//! Миграция: привязка групп серверов к группам пользователей и поддержка протокола/порта/URL в пуле нод.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        // 1. Расширяем таблицу node_pool_members:
        // Добавляем тип протокола (используем уже существующий PostgreSQL ENUM 'protocol_type')
        // и кастомный порт/URL.
        db.execute_unprepared(
            "ALTER TABLE node_pool_members ADD COLUMN IF NOT EXISTS protocol protocol_type NOT NULL DEFAULT 'quic';",
        )
        .await?;

        db.execute_unprepared(
            "ALTER TABLE node_pool_members ADD COLUMN IF NOT EXISTS port_or_url TEXT;",
        )
        .await?;

        // Обновляем составной первичный ключ: теперь он (pool_id, server_id, protocol),
        // чтобы один и тот же сервер мог быть добавлен в группу с разными протоколами (например, QUIC и WS).
        db.execute_unprepared(
            "ALTER TABLE node_pool_members DROP CONSTRAINT IF EXISTS node_pool_members_pkey;",
        )
        .await?;

        db.execute_unprepared(
            "ALTER TABLE node_pool_members ADD PRIMARY KEY (pool_id, server_id, protocol);",
        )
        .await?;

        // 2. Создаем связующую таблицу group_node_pools (привязка групп серверов к группам пользователей)
        db.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS group_node_pools (
                group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
                pool_id UUID NOT NULL REFERENCES node_pools(id) ON DELETE CASCADE,
                PRIMARY KEY (group_id, pool_id)
            );
            "#,
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        let _ = db.execute_unprepared("DROP TABLE IF EXISTS group_node_pools;").await;

        let _ = db
            .execute_unprepared(
                "ALTER TABLE node_pool_members DROP CONSTRAINT IF EXISTS node_pool_members_pkey;",
            )
            .await;

        let _ = db
            .execute_unprepared("ALTER TABLE node_pool_members DROP COLUMN IF EXISTS port_or_url;")
            .await;

        let _ = db
            .execute_unprepared("ALTER TABLE node_pool_members DROP COLUMN IF EXISTS protocol;")
            .await;

        let _ = db
            .execute_unprepared(
                "ALTER TABLE node_pool_members ADD PRIMARY KEY (pool_id, server_id);",
            )
            .await;

        Ok(())
    }
}
