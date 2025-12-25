use anet_auth::api;
use anet_auth::middleware;
use anet_auth::migration;
use log::info;
use poem::{EndpointExt, Route, Server, listener::TcpListener};
use poem_openapi::OpenApiService;
use sea_orm::{Database, DatabaseConnection};
use sea_orm_migration::MigratorTrait;
use std::env;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // 1. Загрузка .env и логгера
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    dotenvy::dotenv().ok();

    // 2. Конфигурация
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let server_port = env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let api_key = env::var("AUTH_BACKEND_KEY").expect("AUTH_BACKEND_KEY must be set");

    info!("Connecting to database...");
    let db: DatabaseConnection = Database::connect(&db_url).await?;

    // 3. Миграции (создание таблиц)
    info!("Running migrations...");
    migration::Migrator::up(&db, None).await?;

    // 4. API Сервис
    let api_service = OpenApiService::new(api::VpnApi { db }, "ANet Auth API", "1.0")
        .server(format!("http://localhost:{}/api/v1", server_port));

    let ui = api_service.swagger_ui();
    let spec = api_service.spec_endpoint(); // JSON spec

    // Все API методы заворачиваем в Middleware проверки ключа
    let app = Route::new()
        .nest("/api/v1", api_service)
        .nest("/swagger", ui)
        .at("/spec", spec)
        .with(middleware::ApiKeyMiddleware { key: api_key });

    info!("ANet Auth started on 127.0.0.1:{}", server_port);
    Server::new(TcpListener::bind(format!("127.0.0.1:{}", server_port)))
        .run(app)
        .await?;

    Ok(())
}
