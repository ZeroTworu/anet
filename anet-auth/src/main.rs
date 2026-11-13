use anet_auth::api;
use anet_auth::entities::{admins, users};
use anet_auth::keygen;
use anet_auth::middleware;
use anet_auth::migration;
use anet_auth::crypto::DbEncryptor; // Подключаем наш шифратор базы данных
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

    /// Путь к .env / EnvironmentFile с секретами биллинга и ЛК (опционально)
    #[arg(long = "env-file", value_name = "PATH")]
    env_file: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // 1. Инициализация окружения
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .filter(Some("sqlx"), log::LevelFilter::Warn) // Игнорировать INFO-логи от sqlx
        .init();
    // 2. Парсинг аргументов и загрузка .env / systemd EnvironmentFile
    let args = Args::parse();
    if let Some(ref env_path) = args.env_file {
        dotenvy::from_path(env_path)
            .map_err(|e| anyhow::anyhow!("Failed to load env file '{}': {}", env_path, e))?;
    } else if let Ok(env_path) = env::var("ANET_ENV_FILE") {
        if !env_path.trim().is_empty() {
            dotenvy::from_path(env_path.trim())
                .map_err(|e| anyhow::anyhow!("Failed to load ANET_ENV_FILE '{}': {}", env_path, e))?;
        } else {
            dotenvy::dotenv().ok();
        }
    } else {
        dotenvy::dotenv().ok();
    }
    anet_auth::config::init_config();

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

    // Инициализируем шифратор БД
    let encryptor = DbEncryptor::new();

    // Зашифровываем сгенерированные ключи перед записью в Postgres
    let encrypted_private_key = encryptor.encrypt(&identity.private_key)
        .map_err(|e| anyhow::anyhow!("Failed to encrypt user private key: {}", e))?;
    let encrypted_public_key = encryptor.encrypt(&identity.public_key)
        .map_err(|e| anyhow::anyhow!("Failed to encrypt user public key: {}", e))?;

    // 2. Создаем модель для БД с поддержкой новых зашифрованных полей
    let new_user = users::ActiveModel {
        id: Set(user_id),
        fingerprint: Set(identity.fingerprint.clone()),
        uid: Set(Some(username.clone())),
        is_active: Set(true),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
        static_ip: Set(None),
        private_key: Set(Some(encrypted_private_key)),
        public_key: Set(Some(encrypted_public_key)),
        route_map_id: Set(None),
        group_id: Set(None),
        email: Set(None),
        password_hash: Set(None),
        telegram_id: Set(None),
        balance: Set(0.0),
        activated_at: Set(None),
        expires_at: Set(None),
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
                    traffic_limit: Set(0),
                    speed_limit: Set(0),
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
    // Запускаем фоновый воркер загрузки списков и компиляции правил
    tokio::spawn(anet_auth::compiler_worker::run_worker(db.clone()));
    // Запускаем фоновый воркер сверки зависших заказов FreeKassa (HMAC-SHA256 getOrders)
    tokio::spawn(anet_auth::api::freekassa::cron_sync_freekassa(db.clone()));

    let bind_to = env::var("BIND_TO").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
    let api_key = env::var("AUTH_BACKEND_KEY").expect("AUTH_BACKEND_KEY must be set");
    let client_template_path = env::var("CLIENT_TEMPLATE_PATH")
        .unwrap_or_else(|_| "/opt/anet/client_template.toml".to_string());

    let server_url = env::var("PUBLIC_API_URL").unwrap_or_else(|_| "/api/v1".to_string());
    let api_service = OpenApiService::new(
        api::get_api(db.clone(), client_template_path),
        "ANet Auth API",
        "1.0"
    )
        .server(server_url);

    let ui = api_service.swagger_ui();
    let spec = api_service.spec_endpoint();

    // Защищенные маршруты OpenAPI (проверка X-Auth-Key для /check_access и /session/*)
    let protected_api = Route::new()
        .nest("/api/v1", api_service)
        .nest("/swagger", ui)
        .at("/spec", spec)
        .with(middleware::ApiKeyMiddleware { key: api_key });

    // Открытый маршрут для входящих вебхуков FreeKassa (IP whitelist + MD5 SIGN проверяются внутри)
    let app = Route::new()
        .at(
            "/billing/freekassa/notify",
            poem::post(anet_auth::api::freekassa::freekassa_notify_handler).data(db),
        )
        .nest("/", protected_api)
        .with(poem::middleware::Cors::new());

    info!("ANet Auth started on {}", bind_to);
    Server::new(TcpListener::bind(format!("{}", bind_to)))
        .run(app)
        .await?;

    Ok(())
}
