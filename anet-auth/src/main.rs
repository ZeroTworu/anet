use anet_auth::api;
use anet_auth::entities::{admins, users};
use anet_auth::keygen;
use anet_auth::middleware;
use anet_auth::migration;
use bcrypt::{DEFAULT_COST, hash};
use clap::Parser;
use log::{error, info};
use poem::{EndpointExt, Route, Server, listener::TcpListener};
use poem_openapi::OpenApiService;
use sea_orm::{ActiveModelTrait, Database, DatabaseConnection, Set, EntityTrait};
use sea_orm_migration::MigratorTrait;
use std::env;
use std::io::Write;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Add a new user with the specified Name (UID) and generate keys
    #[arg(short = 'a', long = "add", value_name = "NAME")]
    add_user: Option<String>,

    /// Количество разрешенных сессий (Опционально)
    #[arg(short = 's', long = "sessions")]
    sessions: Option<u32>,

    /// Дата окончания доступа в формате YYYY-MM-DD-HH:MM (Опционально)
    #[arg(short = 'd', long = "date-end")]
    date_end: Option<String>,

    /// Добавление Администратора Системы (interactive pass entry)
    #[arg(long = "add-su", value_name = "LOGIN")]
    add_su: Option<String>,
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

    if args.add_user.is_none() && args.add_su.is_none() {
        info!("Resetting all active sessions to 0...");
        if let Err(e) = anet_auth::entities::active_sessions::Entity::update_many()
            .col_expr(anet_auth::entities::active_sessions::Column::Sessions, sea_orm::sea_query::Expr::value(0))
            .exec(&db).await
        {
            error!("Failed to reset sessions: {}", e);
        }
        else {
            info!("Session counters reset successfully.");
        }
    }

    // 5. ЛОГИКА ВЕТВЛЕНИЯ
    if let Some(username) = args.add_user {
        handle_add_user(&db, username, args.sessions, args.date_end).await?;
    } else if let Some(admin_login) = args.add_su {
        handle_add_admin(&db, admin_login).await?;
    } else {
        run_server(db).await?;
    }

    Ok(())
}

/// Режим добавления пользователя (CLI Tool)
async fn handle_add_user(
    db: &DatabaseConnection,
    username: String,
    sessions: Option<u32>,
    date_end_str: Option<String>,
) -> Result<(), anyhow::Error> {
    let identity = keygen::generate_identity();
    info!("Generating new identity for '{}'...", username);

    let user_id = Uuid::new_v4();

    // 1. Проверяем и парсим дату если переданы параметры тарифа
    let mut parsed_date = None;
    if let Some(d_str) = &date_end_str {
        parsed_date = Some(
            chrono::NaiveDateTime::parse_from_str(d_str, "%Y-%m-%d-%H:%M")
                .map_err(|_| anyhow::anyhow!("Неверный формат даты. Ожидается: YYYY-MM-DD-HH:MM"))?,
        );
    }

    if (sessions.is_some() && date_end_str.is_none()) || (sessions.is_none() && date_end_str.is_some()) {
        return Err(anyhow::anyhow!("ОШИБКА: Для привязки тарифа необходимо указать И --sessions И --date-end"));
    }

    // 2. Создаем модель для БД
    let new_user = users::ActiveModel {
        id: Set(user_id),
        fingerprint: Set(identity.fingerprint.clone()),
        uid: Set(Some(username.clone())),
        is_active: Set(true),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
        static_ip: Set(None),
    };

    // 3. Сохраняем
    match new_user.insert(db).await {
        Ok(_) => {
            // Если передан лимит (Rate) — пишем в базу
            if let (Some(sess), Some(date)) = (sessions, parsed_date) {
                let new_rate = anet_auth::entities::rates::ActiveModel {
                    id: Set(Uuid::new_v4()),
                    user_id: Set(user_id),
                    sessions: Set(sess as i32),
                    date_end: Set(date),
                    created_at: Set(chrono::Utc::now().naive_utc()),
                    updated_at: Set(chrono::Utc::now().naive_utc()),
                };

                if let Err(e) = new_rate.insert(db).await {
                    error!("Failed to insert rate config into database: {}", e);
                } else {
                    println!("\n[✔] Тариф установлен: Сессий: {}, Истекает: {}", sess, date_end_str.unwrap());
                }
            }

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

async fn handle_add_admin(db: &DatabaseConnection, login: String) -> Result<(), anyhow::Error> {
    info!("Initialize SuperUser terminal builder for: '{}'", login);

    // Магически-Слепое приглашение для пароля
    print!("🔑 Password for [{}]: ", login);
    std::io::stdout().flush()?;

    // Перехват символов терминалом
    let password = rpassword::read_password()?;

    if password.len() < 1 {
        error!("Пароль слишком короткий");
        return Ok(());
    }

    // Хешируем Bcrypt'ом солью
    let hashed = match hash(&password, DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            error!("CryptoHash Error: {}", e);
            return Err(e.into());
        }
    };

    let new_admin = admins::ActiveModel {
        id: Set(Uuid::new_v4()),
        login: Set(login.clone()),
        pass_hash: Set(hashed),
        created_at: Set(chrono::Utc::now().naive_utc()),
    };

    match new_admin.insert(db).await {
        Ok(_) => {
            println!("  LOGIN :  {} created", login);
        }
        Err(e) => {
            error!("БД отказала в записи: {}", e);
            return Err(e.into());
        }
    }

    Ok(())
}

/// Режим сервера (Daemon)
async fn run_server(db: DatabaseConnection) -> Result<(), anyhow::Error> {
    let bind_to = env::var("BIND_TO").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
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
