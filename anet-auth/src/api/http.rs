use crate::api::dto::*;
use crate::entities::{admins, sessions, users, users::Entity as User};
use jsonwebtoken::{EncodingKey, Header, encode};
use log::error;
use poem::Result;
use poem_openapi::{OpenApi, param::Query, payload::Json};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel,
    PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, Set,
};
use std::env;
use uuid::Uuid;

pub struct VpnApi {
    pub db: DatabaseConnection,
}

#[OpenApi]
impl VpnApi {
    /// Внутренний механизм верификации
    async fn validate_admin_session(&self, token_str: &str) -> std::result::Result<Uuid, String> {
        let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "secret_na_chushpana".to_string());

        let token_data = jsonwebtoken::decode::<Claims>(
            token_str,
            &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
            &jsonwebtoken::Validation::default(),
        )
        .map_err(|_| "Сломанный или протухший JWT")?;

        let jti = Uuid::parse_str(&token_data.claims.jti).map_err(|_| "Invalid JTI Format")?;

        let session_in_db = sessions::Entity::find_by_id(jti)
            .one(&self.db)
            .await
            .map_err(|_| "Database Exception")?;

        match session_in_db {
            Some(sess) => {
                if sess.expires_at < chrono::Utc::now().naive_utc() {
                    return Err("Сессия в БД истекла".to_string());
                }
                Ok(sess.admin_id)
            }
            None => Err("Отказ! Сессия отозвана".to_string()),
        }
    }

    /// Проверка VPN Сервера при Handshake
    #[oai(path = "/check_access", method = "post")]
    async fn check_access(
        &self,
        req: Json<CheckAccessRequest>,
    ) -> Result<Json<CheckAccessResponse>> {
        let fingerprint = &req.0.fingerprint;
        let user = users::Entity::find()
            .filter(users::Column::Fingerprint.eq(fingerprint))
            .one(&self.db)
            .await
            .map_err(poem::error::InternalServerError)?;

        if let Some(u) = user {
            let res = if u.is_active {
                CheckAccessResponse {
                    allowed: true,
                    message: "OK".into(),
                }
            } else {
                CheckAccessResponse {
                    allowed: false,
                    message: "Banned".into(),
                }
            };
            Ok(Json(res))
        } else {
            Ok(Json(CheckAccessResponse {
                allowed: false,
                message: "Not found".into(),
            }))
        }
    }

    /// Логин в панель Админа
    #[oai(path = "/login", method = "post")]
    async fn admin_login(&self, req: Json<LoginRequest>) -> LoginResponse {
        let admin_entry = match admins::Entity::find()
            .filter(admins::Column::Login.eq(&req.0.login))
            .one(&self.db)
            .await
        {
            Ok(Some(a)) => a,
            _ => return LoginResponse::Unauthorized(Json("Invalid login".into())),
        };

        if !bcrypt::verify(&req.0.password, &admin_entry.pass_hash).unwrap_or(false) {
            return LoginResponse::Unauthorized(Json("Invalid pass".into()));
        }

        let token_id = Uuid::new_v4();
        let expiration = chrono::Utc::now() + chrono::Duration::hours(12);

        let new_session = sessions::ActiveModel {
            id: Set(token_id),
            admin_id: Set(admin_entry.id),
            expires_at: Set(expiration.naive_utc()),
            created_at: Set(chrono::Utc::now().naive_utc()),
        };

        if let Err(_) = new_session.insert(&self.db).await {
            return LoginResponse::Error;
        }

        let claims = Claims {
            jti: token_id.to_string(),
            sub: admin_entry.id.to_string(),
            exp: expiration.timestamp() as usize,
        };
        let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "secret_na_chushpana".into());
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap_or_default();

        LoginResponse::Ok(Json(AuthTokens {
            access_token: token,
        }))
    }

    /// Список юзеров в Панели (С ЗАМКОМ JWT)
    #[oai(path = "/users", method = "get")]
    async fn get_users(
        &self,
        auth: AdminToken,
        from: Query<Option<u64>>,
        limit: Query<Option<u64>>,
    ) -> GetUsersResponse {
        if let Err(deny_reason) = self.validate_admin_session(&auth.0.token).await {
            return GetUsersResponse::Unauthorized(Json(deny_reason));
        }

        let offset = from.0.unwrap_or(0);
        let page_size = limit.0.unwrap_or(50);

        let users = users::Entity::find()
            .order_by_desc(users::Column::CreatedAt)
            .offset(offset)
            .limit(page_size)
            .all(&self.db)
            .await;
        let count = users::Entity::find().count(&self.db).await;

        if users.is_err() || count.is_err() {
            return GetUsersResponse::Error(Json("DB Fetch Error".into()));
        }

        let dto_list = users
            .unwrap()
            .into_iter()
            .map(|m| VpnUserDto {
                id: m.id,
                fingerprint: m.fingerprint,
                uid: m.uid,
                is_active: m.is_active,
                created_at: m.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            })
            .collect();

        GetUsersResponse::Ok(Json(PaginatedUsers {
            total: count.unwrap(),
            items: dto_list,
        }))
    }

    /// Создание нового VPN-Клиента (API-альтернатива команде -a)
    ///
    /// Генерирует новую крипто-пару и добавляет слепок в Белый Список БД.
    #[oai(path = "/add", method = "post")]
    async fn add_user(&self, auth: AdminToken, req: Json<AddUserRequest>) -> AddUserApiResult {
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return AddUserApiResult::Unauthorized(Json(err));
        }

        let identity = crate::keygen::generate_identity();

        let new_user = users::ActiveModel {
            id: Set(Uuid::new_v4()),
            fingerprint: Set(identity.fingerprint.clone()),
            uid: Set(Some(req.0.uid.clone())),
            is_active: Set(true),
            created_at: Set(chrono::Utc::now().naive_utc()),
            updated_at: Set(chrono::Utc::now().naive_utc()),
        };

        if let Err(e) = new_user.insert(&self.db).await {
            error!("Failed to create user: {}", e);
            return AddUserApiResult::Error(Json("Ошибка записи в БД".to_string()));
        }

        AddUserApiResult::Ok(Json(AddUserResponse {
            uid: req.0.uid,
            fingerprint: identity.fingerprint,
            private_key: identity.private_key,
            public_key: identity.public_key,
        }))
    }

    /// Настройки профиля: Ренейминг и Бан. (PATCH запрос по ID клиента).
    ///
    /// Полное отключение узла (`is_active: false`) перекрывает доступ для `CheckAccess`.
    #[oai(path = "/user/:id", method = "patch")]
    async fn update_user(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
        req: Json<UpdateUserRequest>,
    ) -> UpdateUserApiResult {
        // Проверяем админа
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return UpdateUserApiResult::Unauthorized(Json(err));
        }

        // 1. Пытаемся поймать юзера с таким UUID
        let user_model = match User::find_by_id(id.0).one(&self.db).await {
            Ok(Some(u)) => u,
            Ok(None) => {
                return UpdateUserApiResult::NotFound(Json(
                    "VPN клиент не найден в базе!".to_string(),
                ));
            }
            Err(e) => {
                error!("[DB CRASH] Searching user by ID: {}", e);
                return UpdateUserApiResult::Error(Json("Ошибка поиска (DB Fallback)".to_string()));
            }
        };

        // 2. Раскручиваем модель из Read-Only в Режим Редактирования (ActiveModel)
        let mut editable_user = user_model.into_active_model();

        let mut something_changed = false;

        // Если нам кинули сменить имя - переименовываем
        if let Some(new_uid) = req.0.uid {
            editable_user.uid = Set(Some(new_uid.clone()));
            something_changed = true;
        }

        // Если дёргают рубильник доступа:
        if let Some(activation_flag) = req.0.is_active {
            editable_user.is_active = Set(activation_flag);
            something_changed = true;
        }

        // 3. Завершаем работу!
        if something_changed {
            editable_user.updated_at = Set(chrono::Utc::now().naive_utc());

            match editable_user.update(&self.db).await {
                Ok(updated_data) => {
                    return UpdateUserApiResult::Ok(Json(VpnUserDto {
                        id: updated_data.id,
                        fingerprint: updated_data.fingerprint,
                        uid: updated_data.uid,
                        is_active: updated_data.is_active,
                        created_at: updated_data
                            .created_at
                            .format("%Y-%m-%d %H:%M:%S")
                            .to_string(),
                    }));
                }
                Err(e) => {
                    error!("[DB CRASH] Editing user payload: {}", e);
                    return UpdateUserApiResult::Error(Json(
                        "Обновление сорвано на фазе базы данных!".to_string(),
                    ));
                }
            }
        }

        // Если передали абсолютно пустой JSON (Не меняли ни Имя ни Статус) — отдадим старое.
        // Дабы Сваггер или ВебМорда не ругались и не висли
        UpdateUserApiResult::Ok(Json(VpnUserDto {
            id: editable_user.id.unwrap(),
            fingerprint: editable_user.fingerprint.unwrap(),
            uid: editable_user.uid.unwrap(),
            is_active: editable_user.is_active.unwrap(),
            created_at: editable_user
                .created_at
                .unwrap()
                .format("%Y-%m-%d %H:%M:%S")
                .to_string(),
        }))
    }

    /// Обнулить конфиг: (Удаление старых ключей) по ID клиента.
    ///
    /// Намертво лишает клиента возможности законнектиться по старым файлам, выдавая новую чистую связку.
    #[oai(path = "/regenerate/:id", method = "post")]
    async fn regenerate_keys(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
    ) -> RegenerateUserApiResult {
        // Прогоняем токен
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return RegenerateUserApiResult::Unauthorized(Json(err));
        }

        let user_model = match User::find_by_id(id.0).one(&self.db).await {
            Ok(Some(u)) => u,
            Ok(None) => {
                return RegenerateUserApiResult::NotFound(Json(
                    "Клиент с таким ID не обнаружен.".to_string(),
                ));
            }
            Err(e) => {
                log::error!("[REGEN FAIL] {}", e);
                return RegenerateUserApiResult::Error(Json("Ошибка поиска".to_string()));
            }
        };

        let new_crypto_core = crate::keygen::generate_identity();

        // 3. ПЕРЕСБОРКА В ТИПЕ ActiveModel (Разбираем-Собираем)
        let mut updated_usr = user_model.into_active_model();

        // ВАЖНО: Мы перебиваем ему в базе только `fingerprint`, и ставим дату
        updated_usr.fingerprint = Set(new_crypto_core.fingerprint.clone());
        updated_usr.updated_at = Set(chrono::Utc::now().naive_utc());

        let final_model = match updated_usr.update(&self.db).await {
            Ok(saved) => saved,
            Err(e) => {
                error!("[REGEN DB ERROR]: {}", e);
                return RegenerateUserApiResult::Error(Json(
                    "Ошибка базы данных, операция отменена.".to_string(),
                ));
            }
        };

        RegenerateUserApiResult::Ok(Json(RegenerateUserResponse {
            id: final_model.id,
            uid: final_model.uid,
            fingerprint: new_crypto_core.fingerprint,
            private_key: new_crypto_core.private_key,
            public_key: new_crypto_core.public_key,
        }))
    }
}
