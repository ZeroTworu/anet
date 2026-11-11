use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ImapMailboxes::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ImapMailboxes::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(ImapMailboxes::Host).string().not_null())
                    .col(ColumnDef::new(ImapMailboxes::Port).integer().not_null().default(993))
                    .col(ColumnDef::new(ImapMailboxes::Email).string().not_null().unique_key())
                    .col(ColumnDef::new(ImapMailboxes::ClientPasswordEncrypted).text().not_null())
                    .col(ColumnDef::new(ImapMailboxes::ServerPasswordEncrypted).text().null())
                    .col(
                        ColumnDef::new(ImapMailboxes::IsActive)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(ColumnDef::new(ImapMailboxes::CreatedAt).timestamp().not_null())
                    .col(ColumnDef::new(ImapMailboxes::UpdatedAt).timestamp().not_null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ImapMailboxes::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum ImapMailboxes {
    Table,
    Id,
    Host,
    Port,
    Email,
    ClientPasswordEncrypted,
    ServerPasswordEncrypted,
    IsActive,
    CreatedAt,
    UpdatedAt,
}
