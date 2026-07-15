use crate::api::dto::*;
use crate::entities::{admins, sessions, users, servers, user_servers, users::Entity as User};
use crate::crypto::DbEncryptor;
use chrono::NaiveDateTime;
use jsonwebtoken::{EncodingKey, Header, encode};
use log::{error, info, warn};
use poem::Result;
use poem_openapi::{OpenApi, param::Query, payload::Json, payload::PlainText};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel,
    PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, Set, TransactionTrait,
};
use std::env;
use uuid::Uuid;

pub struct VpnApi {
    pub db: DatabaseConnection,
    pub client_template_path: String,
}

#[OpenApi]
impl VpnApi {
    /// Внутренний механизм верификации токена администратора
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

    /// Регистрация нового физического VPN-сервера (ноды) в системе
    #[oai(path = "/servers", method = "post")]
    async fn create_server(&self, auth: AdminToken, req: Json<CreateServerRequest>) -> Result<Json<ServerDto>, poem::Error> {
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return Err(poem::Error::from_string(err, poem::http::StatusCode::UNAUTHORIZED));
        }

        let server_id = Uuid::new_v4();
        let new_server = servers::ActiveModel {
            id: Set(server_id),
            name: Set(req.0.name.clone()),
            address: Set(req.0.address.clone()),
            public_key: Set(req.0.public_key.clone()),
            quic_port: Set(req.0.quic_port),
            ssh_port: Set(req.0.ssh_port),
            vnc_port: Set(req.0.vnc_port),
            ssh_user: Set(req.0.ssh_user.clone()),
            is_active: Set(req.0.is_active.unwrap_or(true)),
            created_at: Set(chrono::Utc::now().naive_utc()),
            updated_at: Set(chrono::Utc::now().naive_utc()),
        };

        match new_server.insert(&self.db).await {
            Ok(saved) => Ok(Json(ServerDto {
                id: saved.id,
                name: saved.name,
                address: saved.address,
                public_key: saved.public_key,
                quic_port: saved.quic_port,
                ssh_port: saved.ssh_port,
                vnc_port: saved.vnc_port,
                ssh_user: saved.ssh_user,
                is_active: saved.is_active,
            })),
            Err(e) => Err(poem::error::InternalServerError(e)),
        }
    }

    /// Настройки сервера: Обновление параметров, портов и статуса активности (PATCH)
    #[oai(path = "/servers/:id", method = "patch")]
    async fn update_server(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
        req: Json<UpdateServerRequest>,
    ) -> UpdateServerApiResult {
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return UpdateServerApiResult::Unauthorized(Json(err));
        }

        let server_model = match servers::Entity::find_by_id(id.0).one(&self.db).await {
            Ok(Some(s)) => s,
            Ok(None) => return UpdateServerApiResult::NotFound(Json("Сервер не найден".to_string())),
            Err(e) => return UpdateServerApiResult::Error(Json(e.to_string())),
        };

        let mut active_model = server_model.clone().into_active_model();
        let mut changed = false;

        if let Some(name) = req.0.name {
            active_model.name = Set(name);
            changed = true;
        }
        if let Some(address) = req.0.address {
            active_model.address = Set(address);
            changed = true;
        }
        if let Some(pub_key) = req.0.public_key {
            active_model.public_key = Set(pub_key);
            changed = true;
        }
        if let Some(port) = req.0.quic_port {
            active_model.quic_port = Set(port);
            changed = true;
        }
        if let Some(port) = req.0.ssh_port {
            active_model.ssh_port = Set(port);
            changed = true;
        }
        if let Some(port) = req.0.vnc_port {
            active_model.vnc_port = Set(port);
            changed = true;
        }
        if let Some(user) = req.0.ssh_user {
            active_model.ssh_user = Set(user);
            changed = true;
        }
        if let Some(is_active) = req.0.is_active {
            active_model.is_active = Set(is_active);
            changed = true;
        }

        if changed {
            active_model.updated_at = Set(chrono::Utc::now().naive_utc());
            match active_model.update(&self.db).await {
                Ok(saved) => UpdateServerApiResult::Ok(Json(ServerDto {
                    id: saved.id,
                    name: saved.name,
                    address: saved.address,
                    public_key: saved.public_key,
                    quic_port: saved.quic_port,
                    ssh_port: saved.ssh_port,
                    vnc_port: saved.vnc_port,
                    ssh_user: saved.ssh_user,
                    is_active: saved.is_active,
                })),
                Err(e) => UpdateServerApiResult::Error(Json(e.to_string())),
            }
        } else {
            UpdateServerApiResult::Ok(Json(ServerDto {
                id: server_model.id,
                name: server_model.name,
                address: server_model.address,
                public_key: server_model.public_key,
                quic_port: server_model.quic_port,
                ssh_port: server_model.ssh_port,
                vnc_port: server_model.vnc_port,
                ssh_user: server_model.ssh_user,
                is_active: server_model.is_active,
            }))
        }
    }

    /// Получить список всех зарегистрированных VPN-нод
    #[oai(path = "/servers", method = "get")]
    async fn get_servers(&self, auth: AdminToken) -> GetServersResponse {
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return GetServersResponse::Unauthorized(Json(err));
        }

        match servers::Entity::find().all(&self.db).await {
            Ok(list) => {
                let dtos = list.into_iter().map(|s| ServerDto {
                    id: s.id,
                    name: s.name,
                    address: s.address,
                    public_key: s.public_key,
                    quic_port: s.quic_port,
                    ssh_port: s.ssh_port,
                    vnc_port: s.vnc_port,
                    ssh_user: s.ssh_user,
                    is_active: s.is_active,
                }).collect();
                GetServersResponse::Ok(Json(dtos))
            }
            Err(e) => GetServersResponse::Error(Json(e.to_string())),
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
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return UpdateRateApiResult::Unauthorized(Json(err));
        }

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

        let mut editable_rate = rate_model.into_active_model();
        let mut something_changed = false;

        if let Some(new_sessions) = req.0.sessions {
            editable_rate.sessions = Set(new_sessions as i32);
            something_changed = true;
        }

        if let Some(new_date_str) = &req.0.date_end {
            let date_parsed = match chrono::NaiveDateTime::parse_from_str(new_date_str, "%Y-%m-%d-%H:%M") {
                Ok(d) => d,
                Err(_) => return UpdateRateApiResult::BadRequest(Json("Неверный формат даты. Ожидается YYYY-MM-DD-HH:MM".to_string())),
            };
            editable_rate.date_end = Set(date_parsed);
            something_changed = true;
        }

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

        UpdateRateApiResult::Ok(Json(RateDto {
            id: editable_rate.id.unwrap(),
            sessions: editable_rate.sessions.unwrap() as u32,
            date_end: editable_rate.date_end.unwrap().format("%Y-%m-%d-%H:%M").to_string(),
        }))
    }

    /// Добавление тарифа
    #[oai(path = "/addrate", method = "post")]
    async fn add_rate(&self, auth: AdminToken,
                      user_id: Query<Uuid>,
                      req: Json<AddRateRequest>,) -> AddRateApiResult {
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return AddRateApiResult::Unauthorized(Json(err));
        }

        match users::Entity::find_by_id(user_id.0)
            .one(&self.db)
            .await
        {
            Ok(Some(_)) => {}

            Ok(None) => {
                return AddRateApiResult::BadRequest(
                    Json("Пользователь не найден".to_string())
                );
            }

            Err(e) => {
                error!("[DB ERROR] Get User By ID: {}", e);

                return AddRateApiResult::Error(
                    Json("Ошибка поиска пользователя".to_string())
                );
            }
        }

        let rate_id = Uuid::new_v4();

        let date_parsed: NaiveDateTime = if let Some(new_date_str) = &req.0.date_end {
            let date_parsed = match chrono::NaiveDateTime::parse_from_str(new_date_str, "%Y-%m-%d-%H:%M") {
                Ok(d) => d,
                Err(_) => return AddRateApiResult::BadRequest(Json("Неверный формат даты. Ожидается YYYY-MM-DD-HH:MM".to_string())),
            };
            date_parsed
        } else {
            return AddRateApiResult::BadRequest(Json("Нету даты".to_string()))
        };

        let new_sessions = req.0.sessions.unwrap_or(0);

        let new_rate= crate::entities::rates::ActiveModel  {
            id: Set(rate_id),
            user_id: Set(user_id.0),
            sessions: Set(new_sessions as i32),
            date_end: Set(date_parsed),
            created_at: Set(chrono::Utc::now().naive_utc()),
            updated_at: Set(chrono::Utc::now().naive_utc()),
        };

        match new_rate.insert(&self.db).await {
            Ok(added_data) => {
                return AddRateApiResult::Ok(Json(RateDto {
                    id: added_data.id,
                    sessions: added_data.sessions as u32,
                    date_end: added_data.date_end.format("%Y-%m-%d-%H:%M").to_string(),
                }));
            }
            Err(e) => {
                error!("[DB ERROR] Add rate failed: {}", e);
                return AddRateApiResult::Error(Json("Ошибка добавления тарифа в БД!".to_string()));
            }
        }
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
                return Ok(Json(CheckAccessResponse { allowed: false, message: "Banned".into(), static_ip: None }));
            }

            if let Some(rate) = rate_opt {
                if chrono::Utc::now().naive_utc() > rate.date_end {
                    return Ok(Json(CheckAccessResponse { allowed: false, message: "Время действия ключа истекло".into(), static_ip: None }));
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
                    return Ok(Json(CheckAccessResponse { allowed: false, message: "Кол-во сессий для ключа достигло максимума".into(), static_ip: None }));
                }
            }

            // Отдаем привязанный статический IP обратно серверу для аллокации
            let static_ip = user.static_ip.clone();

            Ok(Json(CheckAccessResponse { allowed: true, message: "OK".into(), static_ip }))
        } else {
            Ok(Json(CheckAccessResponse { allowed: false, message: "Not found".into(), static_ip: None }))
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

    /// Список юзеров в Панели (Заполняем массивы server_ids для каждого)
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

        let users = match users::Entity::find()
            .find_also_related(crate::entities::rates::Entity)
            .order_by_desc(users::Column::CreatedAt)
            .offset(offset)
            .limit(page_size)
            .all(&self.db)
            .await
        {
            Ok(list) => list,
            Err(e) => return GetUsersResponse::Error(Json(e.to_string())),
        };

        let count = match users::Entity::find().count(&self.db).await {
            Ok(c) => c,
            Err(e) => return GetUsersResponse::Error(Json(e.to_string())),
        };

        let mut dto_list = Vec::new();
        for (m, r) in users {
            // Забираем связи многие-ко-многим для каждого пользователя
            let s_ids = user_servers::Entity::find()
                .filter(user_servers::Column::UserId.eq(m.id))
                .all(&self.db)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|us| us.server_id)
                .collect();

            dto_list.push(VpnUserDto {
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
                server_ids: s_ids,
            });
        }

        GetUsersResponse::Ok(Json(PaginatedUsers {
            total: count,
            items: dto_list,
        }))
    }

    /// Получение профиля пользователя по ID
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
            Ok(Some((u, r))) => (u, r),
            Ok(None) => return GetUserApiResult::NotFound(Json("VPN клиент не найден".to_string())),
            Err(e) => return GetUserApiResult::Error(Json(e.to_string())),
        };

        let s_ids = user_servers::Entity::find()
            .filter(user_servers::Column::UserId.eq(result.0.id))
            .all(&self.db)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|us| us.server_id)
            .collect();

        let rate_dto = result.1.map(|rate_model| RateDto {
            id: rate_model.id,
            sessions: rate_model.sessions as u32,
            date_end: rate_model.date_end.format("%Y-%m-%d-%H:%M").to_string(),
        });

        GetUserApiResult::Ok(Json(VpnUserDto {
            id: result.0.id,
            fingerprint: result.0.fingerprint,
            uid: result.0.uid,
            is_active: result.0.is_active,
            created_at: result.0.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            rate: rate_dto,
            static_ip: result.0.static_ip.map(|ip| ip.parse().ok()).flatten(),
            server_ids: s_ids,
        }))
    }

    /// Создание нового VPN-Клиента (API-альтернатива команде -a)
    ///
    /// Генерирует новую крипто-пару и добавляет слепок в Белый Список БД.
    /// Создание нового VPN-Клиента (запись связей в user_servers)
    #[oai(path = "/add", method = "post")]
    async fn add_user(&self, auth: AdminToken, req: Json<AddUserRequest>) -> AddUserApiResult {
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return AddUserApiResult::Unauthorized(Json(err));
        }

        let identity = crate::keygen::generate_identity();
        let user_id = Uuid::new_v4();
        let encryptor = DbEncryptor::new();

        let encrypted_private_key = match encryptor.encrypt(&identity.private_key) {
            Ok(k) => k,
            Err(e) => return AddUserApiResult::Error(Json(e.to_string())),
        };
        let encrypted_public_key = match encryptor.encrypt(&identity.public_key) {
            Ok(k) => k,
            Err(e) => return AddUserApiResult::Error(Json(e.to_string())),
        };

        let new_user = users::ActiveModel {
            id: Set(user_id),
            fingerprint: Set(identity.fingerprint.clone()),
            uid: Set(Some(req.0.uid.clone())),
            is_active: Set(true),
            created_at: Set(chrono::Utc::now().naive_utc()),
            updated_at: Set(chrono::Utc::now().naive_utc()),
            static_ip: Set(None),
            private_key: Set(Some(encrypted_private_key)),
            public_key: Set(Some(encrypted_public_key)),
        };

        if let Err(e) = new_user.insert(&self.db).await {
            error!("Failed to create user: {}", e);
            return AddUserApiResult::Error(Json("Ошибка записи в БД".to_string()));
        }

        // Записываем привязку ко всем выбранным серверам (нодам)
        if let Some(ids) = &req.0.server_ids {
            for sid in ids {
                let link = user_servers::ActiveModel {
                    user_id: Set(user_id),
                    server_id: Set(*sid),
                };
                if let Err(e) = link.insert(&self.db).await {
                    error!("Failed to bind server to user: {}", e);
                }
            }
        }

        AddUserApiResult::Ok(Json(AddUserResponse {
            id: user_id,
            uid: req.0.uid.clone(),
            fingerprint: identity.fingerprint,
            private_key: identity.private_key,
            public_key: identity.public_key,
            rate: None,
        }))
    }

    /// Настройки профиля: Ренейминг, Бан и обновление списка серверов
    #[oai(path = "/user/:id", method = "patch")]
    async fn update_user(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
        req: Json<UpdateUserRequest>,
    ) -> UpdateUserApiResult {
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return UpdateUserApiResult::Unauthorized(Json(err));
        }

        let (user_model, rate_model) = match User::find_by_id(id.0).find_also_related(crate::entities::rates::Entity).one(&self.db).await {
            Ok(Some((u, r))) => (u, r),
            Ok(None) => return UpdateUserApiResult::NotFound(Json("VPN клиент не найден".to_string())),
            Err(e) => return UpdateUserApiResult::Error(Json(e.to_string())),
        };

        let rate_dto = rate_model.map(|r_model| RateDto {
            id: r_model.id,
            sessions: r_model.sessions as u32,
            date_end: r_model.date_end.format("%Y-%m-%d-%H:%M").to_string(),
        });

        let mut editable_user = user_model.into_active_model();
        let mut something_changed = false;

        if let Some(new_uid) = req.0.uid {
            editable_user.uid = Set(Some(new_uid));
            something_changed = true;
        }
        if let Some(activation_flag) = req.0.is_active {
            editable_user.is_active = Set(activation_flag);
            something_changed = true;
        }
        if let Some(static_ip) = req.0.static_ip {
            editable_user.static_ip = Set(Some(static_ip));
            something_changed = true;
        }

        // Обновляем связи со списком серверов в СУБД
        if let Some(ref ids) = req.0.server_ids {
            // Удаляем старые связи
            let _ = user_servers::Entity::delete_many()
                .filter(user_servers::Column::UserId.eq(id.0))
                .exec(&self.db)
                .await;

            // Записываем новые связи
            for sid in ids {
                let link = user_servers::ActiveModel {
                    user_id: Set(id.0),
                    server_id: Set(*sid),
                };
                let _ = link.insert(&self.db).await;
            }
            something_changed = true;
        }

        if something_changed {
            editable_user.updated_at = Set(chrono::Utc::now().naive_utc());

            match editable_user.update(&self.db).await {
                Ok(updated_data) => {
                    let s_ids = user_servers::Entity::find()
                        .filter(user_servers::Column::UserId.eq(updated_data.id))
                        .all(&self.db)
                        .await
                        .unwrap_or_default()
                        .into_iter()
                        .map(|us| us.server_id)
                        .collect();

                    return UpdateUserApiResult::Ok(Json(VpnUserDto {
                        id: updated_data.id,
                        fingerprint: updated_data.fingerprint,
                        uid: updated_data.uid,
                        is_active: updated_data.is_active,
                        created_at: updated_data.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
                        rate: rate_dto,
                        static_ip: updated_data.static_ip.map(|ip| ip.parse().ok()).flatten(),
                        server_ids: s_ids,
                    }));
                }
                Err(e) => {
                    error!("[DB CRASH] Editing user payload: {}", e);
                    return UpdateUserApiResult::Error(Json("DB Update failed".to_string()));
                }
            }
        }

        let s_ids = user_servers::Entity::find()
            .filter(user_servers::Column::UserId.eq(editable_user.id.clone().unwrap()))
            .all(&self.db)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|us| us.server_id)
            .collect();

        UpdateUserApiResult::Ok(Json(VpnUserDto {
            id: editable_user.id.unwrap(),
            fingerprint: editable_user.fingerprint.unwrap(),
            uid: editable_user.uid.unwrap(),
            is_active: editable_user.is_active.unwrap(),
            created_at: editable_user.created_at.unwrap().format("%Y-%m-%d %H:%M:%S").to_string(),
            rate: rate_dto,
            static_ip: editable_user.static_ip.unwrap().map(|ip| ip.parse().ok()).flatten(),
            server_ids: s_ids,
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
        let encryptor = DbEncryptor::new();

        // Шифруем новые ключи перед перезаписью
        let encrypted_private_key = match encryptor.encrypt(&new_crypto_core.private_key) {
            Ok(k) => k,
            Err(_) => return RegenerateUserApiResult::Error(Json("Encryption error".to_string())),
        };
        let encrypted_public_key = match encryptor.encrypt(&new_crypto_core.public_key) {
            Ok(k) => k,
            Err(_) => return RegenerateUserApiResult::Error(Json("Encryption error".to_string())),
        };

        // 3. ПЕРЕСБОРКА В ТИПЕ ActiveModel (Разбираем-Собираем)
        let mut updated_usr = user_model.into_active_model();

        // ВАЖНО: Мы перебиваем ему в базе только `fingerprint`, и ставим дату
        updated_usr.fingerprint = Set(new_crypto_core.fingerprint.clone());
        updated_usr.private_key = Set(Some(encrypted_private_key));
        updated_usr.public_key = Set(Some(encrypted_public_key));
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

    /// ПУБЛИЧНЫЙ ЭНДПОИНТ: Скачать готовый client.toml для конкретного пользователя по его UUID
    /// ПУБЛИЧНЫЙ ЭНДПОИНТ: Скачать готовый файл конфигурации client.toml для конкретного пользователя по его UUID
    #[oai(path = "/config/:id", method = "get")]
    async fn download_config(&self, id: poem_openapi::param::Path<Uuid>) -> DownloadConfigResponse {
        // 1. ЗА ОДИН ЗАПРОС тянем пользователя и ВСЕ связанные с ним ноды (Many-to-Many) из базы данных
        let (user_opt, assigned_servers) = match User::find_by_id(id.0)
            .find_with_related(servers::Entity)
            .all(&self.db)
            .await
        {
            Ok(mut list) => {
                if list.is_empty() {
                    warn!("[CONFIG] Client download failed: ID {} not found", id.0);
                    return DownloadConfigResponse::NotFound(Json("Client not found".to_string()));
                }
                list.remove(0) // Забираем единственный кортеж (users::Model, Vec<servers::Model>)
            }
            Err(e) => {
                error!("[DB ERROR] Failed to fetch user and assigned servers: {}", e);
                return DownloadConfigResponse::Error(Json("Database error".to_string()));
            }
        };

        // 2. Если пользователь забанен или неактивен — прерываем операцию
        if !user_opt.is_active {
            warn!("[CONFIG] Blocked download attempt for inactive/banned client: {}", id.0);
            return DownloadConfigResponse::NotFound(Json("Client is inactive or banned".to_string()));
        }

        // 3. Если у пользователя нет привязанных серверов — ругаемся
        if assigned_servers.is_empty() {
            warn!("[CONFIG] Download cancelled: No servers assigned to user {}", id.0);
            return DownloadConfigResponse::Error(Json("No servers assigned to this user".to_string()));
        }

        // 4. Инициализируем дешифратор базы данных
        let encryptor = DbEncryptor::new();

        // 5. Расшифровываем приватный ключ пользователя на лету
        let decrypted_private_key = match user_opt.private_key {
            Some(ref enc_pk) => match encryptor.decrypt(enc_pk) {
                Ok(pk) => pk,
                Err(e) => {
                    error!("[DECRYPTION ERROR] Failed to decrypt user private key for {}: {}", id.0, e);
                    return DownloadConfigResponse::Error(Json("Failed to decrypt user credentials".to_string()));
                }
            },
            None => {
                error!("[CONFIG ERROR] Private key is missing in database for user {}", id.0);
                return DownloadConfigResponse::Error(Json("Private key is missing in DB".to_string()));
            }
        };

        // 6. Динамически генерируем каскадный массив [[servers]]
        let mut servers_toml = String::new();
        servers_toml.push_str("\n# =========================================================================\n");
        servers_toml.push_str("# ANET Client: Dynamic Failover Servers (Multi-Node)\n");
        servers_toml.push_str("# =========================================================================\n");

        let mut fallback_pub_key = String::new();

        // Пробегаемся по уже загруженному в память массиву серверов без единого запроса к СУБД!
        for server in assigned_servers {

            if !server.is_active {
                continue;
            }

            if fallback_pub_key.is_empty() {
                fallback_pub_key = server.public_key.clone();
            }

            if let Some(port) = server.quic_port {
                servers_toml.push_str(&format!(
                    "[[servers]]\nname = \"{}\"\naddress = \"{}:{}\"\nmode = \"quic\"\ntimeout_secs = 5\nserver_pub_key = \"{}\"\n\n",
                    format!("{} [QUIC]", server.name), server.address, port, server.public_key
                ));
            }

            if let Some(port) = server.ssh_port {
                let user_name = server.ssh_user.as_deref().unwrap_or("hanyuu");
                servers_toml.push_str(&format!(
                    "[[servers]]\nname = \"{}\"\naddress = \"{}:{}\"\nmode = \"ssh\"\nssh_user = \"{}\"\ntimeout_secs = 6\nserver_pub_key = \"{}\"\n\n",
                    format!("{} [SSH]", server.name), server.address, port, user_name, server.public_key
                ));
            }

            if let Some(port) = server.vnc_port {
                servers_toml.push_str(&format!(
                    "[[servers]]\nname = \"{}\"\naddress = \"{}:{}\"\nmode = \"vnc\"\ntimeout_secs = 8\nserver_pub_key = \"{}\"\n\n",
                    format!("{} [VNC]", server.name), server.address, port, server.public_key
                ));
            }
        }

        // 7. Читаем базовый шаблон client_template.toml с диска сервера
        let template_content = match tokio::fs::read_to_string(&self.client_template_path).await {
            Ok(content) => content,
            Err(e) => {
                error!("[CONFIG TEMPLATE ERROR] Failed to read {}: {}", self.client_template_path, e);
                return DownloadConfigResponse::Error(Json("Base configuration template is missing on server".to_string()));
            }
        };

        // 8. Сливаем базовый конфиг и сгенерированный блок серверов в один контент
        let mut config_output = template_content;
        config_output.push_str(&servers_toml);

        // 9. Заменяем плейсхолдеры на расшифрованный приватный ключ юзера и ключ сервера
        let final_output = config_output
            .replace("{{PRIVATE_KEY}}", &decrypted_private_key)
            .replace("{{SERVER_PUB_KEY}}", &fallback_pub_key);

        // 10. Настраиваем заголовки скачивания
        let client_name = user_opt.uid.unwrap_or_else(|| "client".to_string());
        let filename_header = format!("attachment; filename=\"{}.toml\"", client_name);

        info!("[CONFIG] Successfully generated and served client.toml for user: {}", client_name);

        DownloadConfigResponse::Ok(PlainText(final_output), filename_header)
    }

    /// ПУБЛИЧНЫЙ ЭНДПОИНТ: Получить HTML-страницу с QR-кодом и прямой ссылкой на скачивание конфига
    #[oai(path = "/config/qr/:id", method = "get")]
    async fn download_config_qr(
        &self,
        id: poem_openapi::param::Path<Uuid>,
        #[oai(name = "Host")] host: poem_openapi::param::Header<Option<String>>,
    ) -> QrPageResponse {
        let user_opt = match User::find_by_id(id.0).one(&self.db).await {
            Ok(Some(u)) => u,
            Ok(None) => {
                warn!("[QR] Download failed: ID {} not found", id.0);
                return QrPageResponse::NotFound(Json("Client not found".to_string()));
            }
            Err(e) => {
                error!("[DB ERROR] Failed to fetch user for QR config: {}", e);
                return QrPageResponse::Error(Json("Database error".to_string()));
            }
        };

        if !user_opt.is_active {
            warn!("[QR] Blocked download attempt for inactive/banned client: {}", id.0);
            return QrPageResponse::NotFound(Json("Client is inactive or banned".to_string()));
        }

        // Автоматически строим абсолютную ссылку на скачивание на основе хоста запроса
        let host_str = host.0.unwrap_or_else(|| "127.0.0.1:3000".to_string());
        let config_url = format!("http://{}/api/v1/config/{}", host_str, id.0);

        // Рендерим наш стильный OLED-Black HTML-шаблон на лету
        let html_page = get_qr_html_page(&config_url, user_opt.uid.unwrap_or_else(|| "client".to_string()).as_str());

        info!("[QR] Successfully served QR setup page for user ID: {}", id.0);

        QrPageResponse::Ok(PlainText(html_page))
    }
}


/// Генератор стильной консольной OLED-Black HTML страницы для скачивания конфига клиентом
fn get_qr_html_page(config_url: &str, user_name: &str) -> String {
    format!(r#"<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ANet VPN Connection</title>
    <style>
        body {{
            background-color: #050505;
            color: #e2e8f0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            padding: 16px;
            box-sizing: border-box;
        }}
        .card {{
            background: #0a0a0a;
            border: 1px solid #1f1f23;
            border-radius: 12px;
            padding: 32px;
            text-align: center;
            max-width: 420px;
            width: 100%;
            box-shadow: 0 8px 32px rgba(0,0,0,0.5);
        }}
        h1 {{
            color: #18a058;
            font-size: 24px;
            margin-top: 0;
            margin-bottom: 8px;
            font-family: monospace;
            letter-spacing: 0.5px;
        }}
        p {{
            color: #94a3b8;
            font-size: 14px;
            line-height: 1.5;
            margin-bottom: 24px;
        }}
        .qr-container {{
            background: white;
            padding: 16px;
            border-radius: 8px;
            display: inline-block;
            margin-bottom: 24px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }}
        .qr-container img {{
            display: block;
            width: 200px;
            height: 200px;
        }}
        .btn {{
            display: block;
            background-color: #18a058;
            color: white;
            text-decoration: none;
            padding: 12px 24px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 15px;
            transition: background-color 0.15s ease-in-out;
            margin-bottom: 16px;
            border: none;
            cursor: pointer;
            width: 100%;
            box-sizing: border-box;
        }}
        .btn:hover {{
            background-color: #148043;
        }}
        .input-group {{
            display: flex;
            background: #121214;
            border: 1px solid #1f1f23;
            border-radius: 6px;
            padding: 4px;
            margin-top: 16px;
        }}
        .input-group input {{
            flex: 1;
            background: transparent;
            border: none;
            color: #cbd5e1;
            font-family: monospace;
            font-size: 12px;
            padding: 8px;
            outline: none;
            width: 100%;
        }}
        .btn-copy {{
            background: #222;
            border: 1px solid #333;
            color: #cbd5e1;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            transition: all 0.1s;
        }}
        .btn-copy:hover {{
            background: #333;
            color: white;
        }}
    </style>
</head>
<body>
    <div class="card">
        <h1>ANet VPN for {user_name}</h1>
        <p>Отсканируй QR-код приложением ANet, или скачай файл конфигурации прямо на свой компьютер.</p>

        <div class="qr-container">
            <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={config_url}" alt="Config QR" />
        </div>

        <a href="{config_url}" class="btn">Download client.toml</a>

        <div class="input-group">
            <input type="text" readonly id="link-input" value="{config_url}" />
            <button class="btn-copy" onclick="copyLink()">Copy</button>
        </div>
    </div>
    <script>
        function copyLink() {{
            var copyText = document.getElementById("link-input");
            copyText.select();
            copyText.setSelectionRange(0, 99999);
            navigator.clipboard.writeText(copyText.value);

            var btn = document.querySelector(".btn-copy");
            btn.textContent = "Copied!";
            setTimeout(function() {{
                btn.textContent = "Copy";
            }}, 2000);
        }}
    </script>
</body>
</html>"#, config_url = config_url)
}
