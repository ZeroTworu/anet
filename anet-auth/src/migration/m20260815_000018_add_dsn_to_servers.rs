//! Перевод панели на единый DSN ноды.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Servers::Table)
                    .add_column(
                        ColumnDef::new(Servers::Dsn)
                            .text()
                            .not_null()
                            .default("quic://127.0.0.1:0"),
                    )
                    .to_owned(),
            )
            .await?;

        // Сохраняем работоспособность уже зарегистрированных нод. Старые
        // колонки не удаляем: они могут понадобиться для ручного перехода
        // оставшихся endpoint'ов в отдельные записи.
        let sql = r#"
            UPDATE servers
            SET dsn = CASE
                WHEN quic_port IS NOT NULL AND quic_port > 0
                    THEN 'quic://' || address || ':' || CAST(quic_port AS TEXT)
                WHEN ssh_port IS NOT NULL AND ssh_port > 0
                    THEN 'ssh://' || address || ':' || CAST(ssh_port AS TEXT)
                WHEN vnc_port IS NOT NULL AND vnc_port > 0
                    THEN 'vnc://' || address || ':' || CAST(vnc_port AS TEXT)
                WHEN websocket_url IS NOT NULL AND TRIM(websocket_url) <> ''
                    THEN websocket_url
                ELSE 'quic://' || address || ':0'
            END
        "#;

        manager
            .get_connection()
            .execute_unprepared(sql)
            .await
            .map(|_| ())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Servers::Table)
                    .drop_column(Servers::Dsn)
                    .to_owned(),
            )
            .await
    }
}

#[derive(Iden)]
enum Servers {
    Table,
    Dsn,
}
