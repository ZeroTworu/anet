use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Добавляем две новые колонки в таблицу users для хранения зашифрованных ключей
        manager
            .alter_table(
                Table::alter()
                    .table(User::Table)
                    .add_column(ColumnDef::new(User::PrivateKey).text().null())
                    .add_column(ColumnDef::new(User::PublicKey).text().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Логика отката миграции: удаляем добавленные колонки
        manager
            .alter_table(
                Table::alter()
                    .table(User::Table)
                    .drop_column(User::PrivateKey)
                    .drop_column(User::PublicKey)
                    .to_owned(),
            )
            .await
    }
}

#[derive(Iden)]
pub enum User {
    #[iden = "users"]
    Table,
    PrivateKey,
    PublicKey,
}
