use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("servers"))
                    .add_column(ColumnDef::new(Alias::new("wrtc_mode")).text().null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("node_pool_members"))
                    .add_column(ColumnDef::new(Alias::new("wrtc_mode")).text().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("node_pool_members"))
                    .drop_column(Alias::new("wrtc_mode"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("servers"))
                    .drop_column(Alias::new("wrtc_mode"))
                    .to_owned(),
            )
            .await
    }
}
