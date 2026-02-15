use anet_auth::api;
use anet_auth::entities::users;
use anet_auth::keygen;
use anet_auth::middleware;
use anet_auth::migration;
use clap::Parser;
use log::{error, info};
use poem::{EndpointExt, Route, Server, listener::TcpListener};
use poem_openapi::OpenApiService;
use sea_orm::{ActiveModelTrait, Database, DatabaseConnection, Set};
use sea_orm_migration::MigratorTrait;
use std::env;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Add a new user with the specified Name (UID) and generate keys
    #[arg(short = 'a', long = "add", value_name = "NAME")]
    add_user: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // 1. Инициализация окружения
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    dotenvy::dotenv().ok();

    // 2. Парсинг аргументов
    let args = Args::parse();

    // 3. Подключение к БД
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db: DatabaseConnection = Database::connect(&db_url).await?;

    // 4. Миграции (всегда полезно убедиться, что схема актуальна)
    if args.add_user.is_none() {
        info!("Running migrations...");
    }
    migration::Migrator::up(&db, None).await?;

    // 5. ЛОГИКА ВЕТВЛЕНИЯ
    if let Some(username) = args.add_user {
        handle_add_user(&db, username).await?;
    } else {
        run_server(db).await?;
    }

    Ok(())
}

/// Режим добавления пользователя (CLI Tool)
async fn handle_add_user(db: &DatabaseConnection, username: String) -> Result<(), anyhow::Error> {
    // 1. Генерируем ключи
    let identity = keygen::generate_identity();

    info!("Generating new identity for '{}'...", username);

    // 2. Создаем модель для БД
    let new_user = users::ActiveModel {
        id: Set(Uuid::new_v4()),
        fingerprint: Set(identity.fingerprint.clone()),
        uid: Set(Some(username.clone())),
        is_active: Set(true),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    };

    // 3. Сохраняем
    match new_user.insert(db).await {
        Ok(_) => {
            println!("\n=== User Created Successfully ===");
            println!("User (UID):  {}", username);
            println!("Fingerprint: {}", identity.fingerprint);
            println!("\n=== Client Configuration (client.toml) ===");
            println!("[keys]");
            println!("private_key = \"{}\"", identity.private_key);
            println!("\n=== Public Key (For reference) ===");
            println!("{}\n", identity.public_key);
        }
        Err(e) => {
            error!("Failed to insert user into database: {}", e);
            return Err(e.into());
        }
    }

    Ok(())
}

/// Режим сервера (Daemon)
async fn run_server(db: DatabaseConnection) -> Result<(), anyhow::Error> {
    let bind_to = env::var("BIND_TOT").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
    let api_key = env::var("AUTH_BACKEND_KEY").expect("AUTH_BACKEND_KEY must be set");

    let api_service = OpenApiService::new(api::VpnApi { db }, "ANet Auth API", "1.0")
        .server(format!("http://{}/api/v1", bind_to));

    let ui = api_service.swagger_ui();
    let spec = api_service.spec_endpoint();

    let app = Route::new()
        .nest("/api/v1", api_service)
        .nest("/swagger", ui)
        .at("/spec", spec)
        .with(middleware::ApiKeyMiddleware { key: api_key });

    info!("ANet Auth started on {}", bind_to);
    Server::new(TcpListener::bind(format!("{}", bind_to)))
        .run(app)
        .await?;

    Ok(())
}
