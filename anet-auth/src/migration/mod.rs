pub mod m20240101_000001_create_users;
pub mod m20240319_000002_create_admins;

use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20240101_000001_create_users::Migration),
            Box::new(m20240319_000002_create_admins::Migration),
        ]
    }
}
