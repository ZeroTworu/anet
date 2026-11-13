use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_query::Expr;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        // 0. Создание PostgreSQL ENUM типов для billing_enums.rs (идемпотентно)
        db.execute_unprepared(
            r#"
            DO $$ BEGIN
                CREATE TYPE currency AS ENUM ('RUB', 'USD', 'EUR', 'STARS');
            EXCEPTION WHEN duplicate_object THEN null;
            END $$;
            DO $$ BEGIN
                CREATE TYPE payment_system AS ENUM ('freekassa', 'aaio', 'yoomoney', 'telegram_stars');
            EXCEPTION WHEN duplicate_object THEN null;
            END $$;
            DO $$ BEGIN
                CREATE TYPE order_status AS ENUM ('pending', 'paid', 'failed', 'cancelled', 'refunded');
            EXCEPTION WHEN duplicate_object THEN null;
            END $$;
            DO $$ BEGIN
                CREATE TYPE product_type AS ENUM ('group_subscription', 'rate_extension', 'feature');
            EXCEPTION WHEN duplicate_object THEN null;
            END $$;
            DO $$ BEGIN
                CREATE TYPE voucher_status AS ENUM ('created', 'claimed', 'revoked');
            EXCEPTION WHEN duplicate_object THEN null;
            END $$;
            "#,
        )
        .await?;

        // 0.1. Добавляем флаг is_default в существующую таблицу groups (Раздел 1.1)
        manager
            .alter_table(
                Table::alter()
                    .table(Groups::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(Groups::IsDefault)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;

        // 1. Модификация существующей таблицы users
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(Users::Email).string().null().unique_key(),
                    )
                    .add_column_if_not_exists(
                        ColumnDef::new(Users::PasswordHash).text().null(),
                    )
                    .add_column_if_not_exists(
                        ColumnDef::new(Users::TelegramId)
                            .big_integer()
                            .null()
                            .unique_key(),
                    )
                    .add_column_if_not_exists(
                        ColumnDef::new(Users::Balance)
                            .double()
                            .not_null()
                            .default(0.0),
                    )
                    .add_column_if_not_exists(
                        ColumnDef::new(Users::ActivatedAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .add_column_if_not_exists(
                        ColumnDef::new(Users::ExpiresAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        // 2. Создание таблицы products
        manager
            .create_table(
                Table::create()
                    .table(Products::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Products::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Products::Name).string().not_null())
                    .col(ColumnDef::new(Products::Description).text().not_null())
                    .col(ColumnDef::new(Products::Price).double().not_null())
                    .col(
                        ColumnDef::new(Products::Currency)
                            .custom(Alias::new("currency"))
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Products::ProductType)
                            .custom(Alias::new("product_type"))
                            .not_null(),
                    )
                    .col(ColumnDef::new(Products::TargetId).uuid().null())
                    .col(
                        ColumnDef::new(Products::SortOrder)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(ColumnDef::new(Products::Badge).string().null())
                    .col(ColumnDef::new(Products::Metadata).json_binary().null())
                    .col(
                        ColumnDef::new(Products::IsActive)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(Products::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Products::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_products_target_group")
                            .from(Products::Table, Products::TargetId)
                            .to(Groups::Table, Groups::Id)
                            .on_delete(ForeignKeyAction::SetNull)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // 3. Создание таблицы orders
        manager
            .create_table(
                Table::create()
                    .table(Orders::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Orders::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Orders::UserId).uuid().not_null())
                    .col(ColumnDef::new(Orders::ProductId).uuid().not_null())
                    .col(ColumnDef::new(Orders::Amount).double().not_null())
                    .col(
                        ColumnDef::new(Orders::Currency)
                            .custom(Alias::new("currency"))
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Orders::Status)
                            .custom(Alias::new("order_status"))
                            .not_null()
                            .default(Expr::cust("'pending'::order_status")),
                    )
                    .col(
                        ColumnDef::new(Orders::IsGift)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(Orders::Metadata).json_binary().null())
                    .col(
                        ColumnDef::new(Orders::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Orders::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_orders_user")
                            .from(Orders::Table, Orders::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_orders_product")
                            .from(Orders::Table, Orders::ProductId)
                            .to(Products::Table, Products::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // 4. Создание таблицы transactions
        manager
            .create_table(
                Table::create()
                    .table(Transactions::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Transactions::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Transactions::OrderId).uuid().null())
                    .col(
                        ColumnDef::new(Transactions::PaymentSystem)
                            .custom(Alias::new("payment_system"))
                            .not_null(),
                    )
                    .col(ColumnDef::new(Transactions::ExternalTxId).string().not_null())
                    .col(ColumnDef::new(Transactions::AmountReceived).double().not_null())
                    .col(ColumnDef::new(Transactions::RawRequest).json_binary().not_null())
                    .col(
                        ColumnDef::new(Transactions::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_transactions_order")
                            .from(Transactions::Table, Transactions::OrderId)
                            .to(Orders::Table, Orders::Id)
                            .on_delete(ForeignKeyAction::SetNull)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // 5. Создание таблицы vouchers
        manager
            .create_table(
                Table::create()
                    .table(Vouchers::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Vouchers::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Vouchers::Code).string().not_null().unique_key())
                    .col(ColumnDef::new(Vouchers::ProductId).uuid().not_null())
                    .col(ColumnDef::new(Vouchers::BuyerUserId).uuid().null())
                    .col(ColumnDef::new(Vouchers::ClaimedByUserId).uuid().null())
                    .col(
                        ColumnDef::new(Vouchers::Status)
                            .custom(Alias::new("voucher_status"))
                            .not_null()
                            .default(Expr::cust("'created'::voucher_status")),
                    )
                    .col(ColumnDef::new(Vouchers::Metadata).json_binary().null())
                    .col(
                        ColumnDef::new(Vouchers::ClaimedAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(Vouchers::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_vouchers_product")
                            .from(Vouchers::Table, Vouchers::ProductId)
                            .to(Products::Table, Products::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_vouchers_buyer")
                            .from(Vouchers::Table, Vouchers::BuyerUserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::SetNull)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_vouchers_claimed_by")
                            .from(Vouchers::Table, Vouchers::ClaimedByUserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::SetNull)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Vouchers::Table).if_exists().to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Transactions::Table).if_exists().to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Orders::Table).if_exists().to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Products::Table).if_exists().to_owned())
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Groups::Table)
                    .drop_column(Groups::IsDefault)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::Email)
                    .drop_column(Users::PasswordHash)
                    .drop_column(Users::TelegramId)
                    .drop_column(Users::Balance)
                    .drop_column(Users::ActivatedAt)
                    .drop_column(Users::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        let db = manager.get_connection();
        db.execute_unprepared(
            r#"
            DROP TYPE IF EXISTS voucher_status;
            DROP TYPE IF EXISTS product_type;
            DROP TYPE IF EXISTS order_status;
            DROP TYPE IF EXISTS payment_system;
            DROP TYPE IF EXISTS currency;
            "#,
        )
        .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
    Email,
    PasswordHash,
    TelegramId,
    Balance,
    ActivatedAt,
    ExpiresAt,
}

#[derive(DeriveIden)]
enum Products {
    Table,
    Id,
    Name,
    Description,
    Price,
    Currency,
    ProductType,
    TargetId,
    SortOrder,
    Badge,
    Metadata,
    IsActive,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Groups {
    Table,
    Id,
    IsDefault,
}

#[derive(DeriveIden)]
enum Orders {
    Table,
    Id,
    UserId,
    ProductId,
    Amount,
    Currency,
    Status,
    IsGift,
    Metadata,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Transactions {
    Table,
    Id,
    OrderId,
    PaymentSystem,
    ExternalTxId,
    AmountReceived,
    RawRequest,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Vouchers {
    Table,
    Id,
    Code,
    ProductId,
    BuyerUserId,
    ClaimedByUserId,
    Status,
    Metadata,
    ClaimedAt,
    CreatedAt,
}
