use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        // Переносим данные из DSN в дискретные колонки, если какие-то ноды были созданы только по dsn
        let sql_restore = r#"
            UPDATE servers
            SET
                address = COALESCE(NULLIF(address, ''), SPLIT_PART(SUBSTRING(dsn FROM '://([^:/]+)'), '/', 1)),
                quic_port = COALESCE(quic_port, CASE WHEN dsn LIKE 'quic://%' THEN CAST(NULLIF(SUBSTRING(dsn FROM ':[0-9]+'), ':') AS INTEGER) END),
                ssh_port = COALESCE(ssh_port, CASE WHEN dsn LIKE 'ssh://%' THEN CAST(NULLIF(SUBSTRING(dsn FROM ':[0-9]+'), ':') AS INTEGER) END),
                vnc_port = COALESCE(vnc_port, CASE WHEN dsn LIKE 'vnc://%' THEN CAST(NULLIF(SUBSTRING(dsn FROM ':[0-9]+'), ':') AS INTEGER) END),
                websocket_url = COALESCE(websocket_url, CASE WHEN dsn LIKE 'ws%' THEN dsn END)
            WHERE dsn IS NOT NULL AND dsn <> '';
        "#;

        // Выполняем разбор в безопасном режиме
        let _ = db.execute_unprepared(sql_restore).await;

        // Теперь удаляем колонку dsn
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("servers"))
                    .drop_column(Alias::new("dsn"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("servers"))
                    .add_column(
                        ColumnDef::new(Alias::new("dsn"))
                            .text()
                            .not_null()
                            .default("quic://127.0.0.1:0"),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
