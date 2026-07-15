pub mod m20240101_000001_create_users;
pub mod m20240319_000002_create_admins;
pub mod m20240401_000003_create_rates;
pub mod m20240501_000004_create_active_sessions;
pub mod m20260504_152844_add_ipv4_to_user;
pub mod m20260714_000007_create_servers;
pub mod m20260714_000006_add_keys_to_user;
pub mod m20260714_000008_create_user_servers;
pub mod m20260714_000009_add_is_active_to_servers;

use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20240101_000001_create_users::Migration),
            Box::new(m20240319_000002_create_admins::Migration),
            Box::new(m20240401_000003_create_rates::Migration),
            Box::new(m20240501_000004_create_active_sessions::Migration),
            Box::new(m20260504_152844_add_ipv4_to_user::Migration),
            Box::new(m20260714_000007_create_servers::Migration),
            Box::new(m20260714_000008_create_user_servers::Migration),
            Box::new(m20260714_000006_add_keys_to_user::Migration),
            Box::new(m20260714_000009_add_is_active_to_servers::Migration),
        ]
    }
}
