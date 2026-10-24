//! Создаёт таблицу doh_resolvers для хранения и динамической настройки публичных DoH-резолверов через WebUI.
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(DohResolvers::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(DohResolvers::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(DohResolvers::Name)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(DohResolvers::Url)
                            .text()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(DohResolvers::IsDefault)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(DohResolvers::IsActive)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(ColumnDef::new(DohResolvers::CreatedAt).timestamp().not_null())
                    .col(ColumnDef::new(DohResolvers::UpdatedAt).timestamp().not_null())
                    .to_owned(),
            )
            .await?;

        // Заполняем базовыми резолверами при инициализации таблицы
        let db = manager.get_connection();
        db.execute_unprepared(
            r#"
            INSERT INTO doh_resolvers (id, name, url, is_default, is_active, created_at, updated_at)
            VALUES
                ('00000000-0000-0000-0000-000000000001', 'Yandex Safe DNS (77.88.8.7)', 'https://77.88.8.7/dns-query', true, true, NOW(), NOW()),
                ('00000000-0000-0000-0000-000000000002', 'AdGuard DNS', 'https://dns.adguard-dns.com/dns-query', true, true, NOW(), NOW()),
                ('00000000-0000-0000-0000-000000000003', 'Yandex Common DNS', 'https://common.dot.dns.yandex.net/dns-query', false, true, NOW(), NOW()),
                ('00000000-0000-0000-0000-000000000004', 'Cloudflare DNS (1.1.1.1)', 'https://1.1.1.1/dns-query', false, true, NOW(), NOW()),
                ('00000000-0000-0000-0000-000000000005', 'Google Public DNS (8.8.8.8)', 'https://8.8.8.8/dns-query', false, true, NOW(), NOW()),
                ('00000000-0000-0000-0000-000000000006', 'Quad9 DNS (9.9.9.9)', 'https://9.9.9.9/dns-query', false, true, NOW(), NOW())
            ON CONFLICT (url) DO NOTHING;
            "#,
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(DohResolvers::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum DohResolvers {
    Table,
    Id,
    Name,
    Url,
    IsDefault,
    IsActive,
    CreatedAt,
    UpdatedAt,
}
