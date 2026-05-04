use crate::api::dto::*;
use crate::entities::{admins, sessions, users, users::Entity as User};
use jsonwebtoken::{EncodingKey, Header, encode};
use log::error;
use poem::Result;
use poem_openapi::{OpenApi, param::Query, payload::Json};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel,
    PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, Set, TransactionTrait,
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
    /// Настройки тарифа: Обновление количества сессий и даты окончания. (PATCH запрос по ID тарифа).
    #[oai(path = "/rate/:id", method = "patch")]
    async fn update_rate(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
        req: Json<UpdateRateRequest>,
    ) -> UpdateRateApiResult {
        // Проверяем админа
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return UpdateRateApiResult::Unauthorized(Json(err));
        }

        // 1. Пытаемся поймать тариф с таким UUID
        let rate_model = match crate::entities::rates::Entity::find_by_id(id.0).one(&self.db).await {
            Ok(Some(r)) => r,
            Ok(None) => {
                return UpdateRateApiResult::NotFound(Json("Тариф не найден в базе!".to_string()));
            }
            Err(e) => {
                error!("[DB CRASH] Searching rate by ID: {}", e);
                return UpdateRateApiResult::Error(Json("Ошибка поиска тарифа".to_string()));
            }
        };

        // 2. Раскручиваем модель в режим редактирования
        let mut editable_rate = rate_model.into_active_model();
        let mut something_changed = false;

        // Если передано новое количество сессий
        if let Some(new_sessions) = req.0.sessions {
            editable_rate.sessions = Set(new_sessions as i32);
            something_changed = true;
        }

        // Если передана новая дата окончания
        if let Some(new_date_str) = &req.0.date_end {
            let date_parsed = match chrono::NaiveDateTime::parse_from_str(new_date_str, "%Y-%m-%d-%H:%M") {
                Ok(d) => d,
                Err(_) => return UpdateRateApiResult::BadRequest(Json("Неверный формат даты. Ожидается YYYY-MM-DD-HH:MM".to_string())),
            };
            editable_rate.date_end = Set(date_parsed);
            something_changed = true;
        }

        // 3. Сохраняем, если были изменения
        if something_changed {
            editable_rate.updated_at = Set(chrono::Utc::now().naive_utc());

            match editable_rate.update(&self.db).await {
                Ok(updated_data) => {
                    return UpdateRateApiResult::Ok(Json(RateDto {
                        id: updated_data.id,
                        sessions: updated_data.sessions as u32,
                        date_end: updated_data.date_end.format("%Y-%m-%d-%H:%M").to_string(),
                    }));
                }
                Err(e) => {
                    error!("[DB CRASH] Editing rate payload: {}", e);
                    return UpdateRateApiResult::Error(Json("Ошибка обновления тарифа в БД!".to_string()));
                }
            }
        }

        // Если передан пустой JSON, возвращаем старые данные
        UpdateRateApiResult::Ok(Json(RateDto {
            id: editable_rate.id.unwrap(),
            sessions: editable_rate.sessions.unwrap() as u32,
            date_end: editable_rate.date_end.unwrap().format("%Y-%m-%d-%H:%M").to_string(),
        }))
    }

    /// Проверка VPN Сервера при Handshake
    #[oai(path = "/check_access", method = "post")]
    async fn check_access(&self, req: Json<CheckAccessRequest>) -> Result<Json<CheckAccessResponse>> {
        let fingerprint = &req.0.fingerprint;

        let result = users::Entity::find()
            .filter(users::Column::Fingerprint.eq(fingerprint))
            .find_also_related(crate::entities::rates::Entity)
            .one(&self.db)
            .await
            .map_err(poem::error::InternalServerError)?;

        if let Some((user, rate_opt)) = result {
            if !user.is_active {
                return Ok(Json(CheckAccessResponse { allowed: false, message: "Banned".into() }));
            }

            if let Some(rate) = rate_opt {
                if chrono::Utc::now().naive_utc() > rate.date_end {
                    return Ok(Json(CheckAccessResponse { allowed: false, message: "Время действия ключа истекло".into() }));
                }

                let current_sessions = match crate::entities::active_sessions::Entity::find()
                    .filter(crate::entities::active_sessions::Column::UserId.eq(user.id))
                    .one(&self.db)
                    .await
                {
                    Ok(Some(session_model)) => session_model.sessions,
                    _ => 0,
                };

                if current_sessions >= (rate.sessions as i32) {
                    return Ok(Json(CheckAccessResponse { allowed: false, message: "Кол-во сессий для ключа достигло максимума".into() }));
                }
            }
            Ok(Json(CheckAccessResponse { allowed: true, message: "OK".into() }))
        } else {
            Ok(Json(CheckAccessResponse { allowed: false, message: "Not found".into() }))
        }
    }

    #[oai(path = "/session/start", method = "post")]
    async fn session_start(&self, req: Json<SessionEventRequest>) -> SessionEventResponse {
        let txn = match self.db.begin().await {
            Ok(t) => t,
            Err(_) => return SessionEventResponse::Error,
        };

        let user = match users::Entity::find().filter(users::Column::Fingerprint.eq(&req.0.fingerprint)).one(&txn).await {
            Ok(Some(u)) => u,
            _ => { let _ = txn.rollback().await; return SessionEventResponse::NotFound; }
        };

        let existing_session = crate::entities::active_sessions::Entity::find()
            .filter(crate::entities::active_sessions::Column::UserId.eq(user.id))
            .one(&txn).await.unwrap_or(None);

        match existing_session {
            Some(sess) => {
                let mut editable = sess.into_active_model();
                editable.sessions = Set(editable.sessions.unwrap() + 1);
                editable.updated_at = Set(chrono::Utc::now().naive_utc());
                if editable.update(&txn).await.is_err() { let _ = txn.rollback().await; return SessionEventResponse::Error; }
            }
            None => {
                let new_sess = crate::entities::active_sessions::ActiveModel {
                    id: Set(Uuid::new_v4()),
                    user_id: Set(user.id),
                    sessions: Set(1),
                    created_at: Set(chrono::Utc::now().naive_utc()),
                    updated_at: Set(chrono::Utc::now().naive_utc()),
                };
                if new_sess.insert(&txn).await.is_err() { let _ = txn.rollback().await; return SessionEventResponse::Error; }
            }
        }
        if txn.commit().await.is_err() { return SessionEventResponse::Error; }
        SessionEventResponse::Ok
    }

    #[oai(path = "/session/stop", method = "post")]
    async fn session_stop(&self, req: Json<SessionEventRequest>) -> SessionEventResponse {
        let txn = match self.db.begin().await {
            Ok(t) => t,
            Err(_) => return SessionEventResponse::Error,
        };

        let user = match users::Entity::find().filter(users::Column::Fingerprint.eq(&req.0.fingerprint)).one(&txn).await {
            Ok(Some(u)) => u,
            _ => { let _ = txn.rollback().await; return SessionEventResponse::NotFound; }
        };

        if let Ok(Some(sess)) = crate::entities::active_sessions::Entity::find()
            .filter(crate::entities::active_sessions::Column::UserId.eq(user.id))
            .one(&txn).await
        {
            let mut editable = sess.into_active_model();
            let current = editable.sessions.unwrap();
            if current > 0 {
                editable.sessions = Set(current - 1);
                editable.updated_at = Set(chrono::Utc::now().naive_utc());
                if editable.update(&txn).await.is_err() { let _ = txn.rollback().await; return SessionEventResponse::Error; }
            }
        }
        if txn.commit().await.is_err() { return SessionEventResponse::Error; }
        SessionEventResponse::Ok
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
            .find_also_related(crate::entities::rates::Entity)
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
            .map(|(m, r)| VpnUserDto {
                id: m.id,
                fingerprint: m.fingerprint,
                uid: m.uid,
                is_active: m.is_active,
                created_at: m.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
                rate: r.map(|rate_model| RateDto {
                    id: rate_model.id,
                    sessions: rate_model.sessions as u32,
                    date_end: rate_model.date_end.format("%Y-%m-%d-%H:%M").to_string(),
                }),
                static_ip: m.static_ip.map(|ip| ip.parse().ok()).flatten(),
            })
            .collect();

        GetUsersResponse::Ok(Json(PaginatedUsers {
            total: count.unwrap(),
            items: dto_list,
        }))
    }

    /// Получение профиля пользователя по ID (Вместе с тарифом Rate)
    #[oai(path = "/user/:id", method = "get")]
    async fn get_user(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
    ) -> GetUserApiResult {
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return GetUserApiResult::Unauthorized(Json(err));
        }

        let result = match users::Entity::find_by_id(id.0)
            .find_also_related(crate::entities::rates::Entity)
            .one(&self.db)
            .await
        {
            Ok(Some((u, r))) => {
                let rate_dto = r.map(|rate_model| RateDto {
                    id: rate_model.id,
                    sessions: rate_model.sessions as u32,
                    date_end: rate_model.date_end.format("%Y-%m-%d-%H:%M").to_string(),
                });

                VpnUserDto {
                    id: u.id,
                    fingerprint: u.fingerprint,
                    uid: u.uid,
                    is_active: u.is_active,
                    created_at: u.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
                    rate: rate_dto,
                    static_ip: u.static_ip.map(|ip| ip.parse().ok()).flatten(),
                }
            }
            Ok(None) => return GetUserApiResult::NotFound(Json("VPN клиент не найден".to_string())),
            Err(e) => {
                error!("[DB ERROR] Get User By ID: {}", e);
                return GetUserApiResult::Error(Json("Ошибка поиска".to_string()));
            }
        };

        GetUserApiResult::Ok(Json(result))
    }

    /// Создание нового VPN-Клиента (API-альтернатива команде -a)
    ///
    /// Генерирует новую крипто-пару и добавляет слепок в Белый Список БД.
    /// Создание нового VPN-Клиента (API-альтернатива команде -a)
    ///
    /// Генерирует новую крипто-пару и добавляет слепок в Белый Список БД.
    #[oai(path = "/add", method = "post")]
    async fn add_user(&self, auth: AdminToken, req: Json<AddUserRequest>) -> AddUserApiResult {
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return AddUserApiResult::Unauthorized(Json(err));
        }

        let identity = crate::keygen::generate_identity();
        let user_id = Uuid::new_v4();

        let new_user = users::ActiveModel {
            id: Set(user_id),
            fingerprint: Set(identity.fingerprint.clone()),
            uid: Set(Some(req.0.uid.clone())),
            is_active: Set(true),
            created_at: Set(chrono::Utc::now().naive_utc()),
            updated_at: Set(chrono::Utc::now().naive_utc()),
            static_ip: Set(None),
        };

        if let Err(e) = new_user.insert(&self.db).await {
            error!("Failed to create user: {}", e);
            return AddUserApiResult::Error(Json("Ошибка записи в БД".to_string()));
        }

        // --- ЛОГИКА СОЗДАНИЯ ТАРИФА (RATE) ---
        let mut saved_rate_dto = None;

        if let Some(rate_req) = &req.0.rate {
            let date_parsed = match chrono::NaiveDateTime::parse_from_str(&rate_req.date_end, "%Y-%m-%d-%H:%M") {
                Ok(d) => d,
                Err(_) => return AddUserApiResult::Error(Json("Неверный формат даты. Ожидается YYYY-MM-DD-HH:MM".to_string())),
            };

            let rate_id = Uuid::new_v4(); // Генерируем UUID тарифа

            let new_rate = crate::entities::rates::ActiveModel {
                id: Set(rate_id),
                user_id: Set(user_id),
                sessions: Set(rate_req.sessions as i32),
                date_end: Set(date_parsed),
                created_at: Set(chrono::Utc::now().naive_utc()),
                updated_at: Set(chrono::Utc::now().naive_utc()),
            };

            if let Err(e) = new_rate.insert(&self.db).await {
                error!("Failed to insert rate: {}", e);
                return AddUserApiResult::Error(Json("Ошибка записи тарифа в БД".to_string()));
            }

            // Собираем DTO для ответа (включая только что созданный ID тарифа)
            saved_rate_dto = Some(RateDto {
                id: rate_id,
                sessions: rate_req.sessions,
                date_end: rate_req.date_end.clone(),
            });
        }

        // Возвращаем финальный JSON, в котором есть оба ID
        AddUserApiResult::Ok(Json(AddUserResponse {
            id: user_id, // <--- ID созданного пользователя
            uid: req.0.uid.clone(),
            fingerprint: identity.fingerprint,
            private_key: identity.private_key,
            public_key: identity.public_key,
            rate: saved_rate_dto, // <--- Тариф (внутри будет свой id)
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

        // 1. Пытаемся поймать юзера с таким UUID (Сразу тянем rate для ответа)
        let (user_model, rate_model) = match User::find_by_id(id.0)
            .find_also_related(crate::entities::rates::Entity)
            .one(&self.db)
            .await
        {
            Ok(Some((u, r))) => (u, r),
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

        // Подготавливаем Rate DTO, чтобы вернуть его в любом случае
        let rate_dto = rate_model.map(|r_model| RateDto {
            id: r_model.id,
            sessions: r_model.sessions as u32,
            date_end: r_model.date_end.format("%Y-%m-%d-%H:%M").to_string(),
        });

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
                        rate: rate_dto,
                        static_ip: updated_data.static_ip.map(|ip| ip.parse().ok()).flatten(),
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
            rate: rate_dto,
            static_ip: editable_user.static_ip.unwrap().map(|ip| ip.parse().ok()).flatten(),
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