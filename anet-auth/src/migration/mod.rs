pub mod m20240101_000001_create_users;
pub mod m20240319_000002_create_admins;
pub mod m20240401_000003_create_rates;
pub mod m20240501_000004_create_active_sessions;
pub mod m20260504_152844_add_ipv4_to_user;
pub mod m20260714_000006_add_keys_to_user;
pub mod m20260714_000007_create_servers;
pub mod m20260714_000008_create_user_servers;
pub mod m20260714_000009_add_is_active_to_servers;
pub mod m20260814_000010_add_websocket_url_to_servers;
pub mod m20260815_000011_create_node_runtime_states;
pub mod m20260815_000012_create_node_commands;
pub mod m20260815_000013_create_traffic_totals;
pub mod m20260815_000014_create_traffic_hourly;
pub mod m20260815_000015_create_node_pools;
pub mod m20260815_000016_create_route_maps;
pub mod m20260815_000017_add_control_token_to_servers;
pub mod m20260815_000018_add_dsn_to_servers;
pub mod m20260820_000019_refactor_route_maps;
pub mod m20260828_000020_remove_dsn_from_servers;

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
            Box::new(m20260814_000010_add_websocket_url_to_servers::Migration),
            Box::new(m20260815_000011_create_node_runtime_states::Migration),
            Box::new(m20260815_000012_create_node_commands::Migration),
            Box::new(m20260815_000013_create_traffic_totals::Migration),
            Box::new(m20260815_000014_create_traffic_hourly::Migration),
            Box::new(m20260815_000015_create_node_pools::Migration),
            Box::new(m20260815_000016_create_route_maps::Migration),
            Box::new(m20260815_000017_add_control_token_to_servers::Migration),
            Box::new(m20260815_000018_add_dsn_to_servers::Migration),
            Box::new(m20260820_000019_refactor_route_maps::Migration),
            Box::new(m20260828_000020_remove_dsn_from_servers::Migration),
        ]
    }
}
