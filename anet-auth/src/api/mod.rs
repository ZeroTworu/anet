pub mod api;
pub mod auth;
pub mod compiled_rules;
pub mod custom_overrides;
pub mod dto;
pub mod groups;
pub mod pools;
pub mod route_maps;
pub mod rule_providers;
pub mod servers;
pub mod statistics;
pub mod users;

use poem_openapi::OpenApi;
use sea_orm::DatabaseConnection;

/// Собирает все доменные контроллеры API в единый кортеж для Poem OpenAPI
pub fn get_api(
    db: DatabaseConnection,
    client_template_path: String,
) -> impl OpenApi {
    (
        auth::AuthApi { db: db.clone() },
        users::UsersApi {
            db: db.clone(),
            client_template_path,
        },
        servers::ServersApi { db: db.clone() },
        pools::PoolsApi { db: db.clone() },
        route_maps::RouteMapsApi { db: db.clone() },
        groups::GroupsApi { db: db.clone() },
        statistics::StatisticsApi { db: db.clone() },
        compiled_rules::CompiledRulesApi { db: db.clone() },
        rule_providers::RuleProvidersApi { db: db.clone() },
        custom_overrides::CustomOverridesApi { db },
    )
}
