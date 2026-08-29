use crate::api::api::{
    compiled_routes_for_user, resolve_client_servers, user_pool_ids, user_route_map_id,
    validate_admin_session,
};
use crate::api::dto::{
    AddRateApiResult, AddRateRequest, AddUserApiResult, AddUserRequest, AddUserResponse,
    AdminToken, DownloadConfigResponse, GetUserApiResult, GetUsersResponse, PaginatedUsers,
    QrPageResponse, RateDto, RegenerateUserApiResult, RegenerateUserResponse, UpdateRateApiResult,
    UpdateRateRequest, UpdateUserApiResult, UpdateUserRequest, VpnUserDto,
};
use crate::crypto::DbEncryptor;
use crate::entities::{groups, servers, user_node_pools, user_servers, users};
use crate::route_compiler::toml_string_array;
use chrono::{NaiveDateTime, Utc};
use log::{error, info, warn};
use poem_openapi::{param::Query, payload::Json, payload::PlainText, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, Set,
    QueryFilter, QueryOrder, PaginatorTrait, QuerySelect
};
use uuid::Uuid;

pub struct UsersApi {
    pub db: DatabaseConnection,
    pub client_template_path: String,
}

#[OpenApi]
impl UsersApi {
    /// Получить список всех пользователей (с поиском по LIKE)
    #[oai(path = "/users", method = "get")]
    async fn get_users(
        &self,
        auth: AdminToken,
        from: Query<Option<i64>>,
        limit: Query<Option<i64>>,
        search: Query<Option<String>>,
    ) -> GetUsersResponse {
        if let Err(deny_reason) = validate_admin_session(&self.db, &auth.0.token).await {
            return GetUsersResponse::Unauthorized(Json(deny_reason));
        }

        let offset = from.0.unwrap_or(0) as u64;
        let page_size = limit.0.unwrap_or(50) as u64;

        let mut query = users::Entity::find()
            .find_also_related(crate::entities::rates::Entity);

        if let Some(ref s) = search.0 {
            if !s.trim().is_empty() {
                let pattern = format!("%{}%", s.trim());
                query = query.filter(
                    users::Column::Uid.like(&pattern)
                        .or(users::Column::Fingerprint.like(&pattern))
                );
            }
        }

        let count = match query.clone().count(&self.db).await {
            Ok(c) => c as i64,
            Err(e) => return GetUsersResponse::Error(Json(e.to_string())),
        };

        let users = match query
            .order_by_desc(users::Column::CreatedAt)
            .offset(offset)
            .limit(page_size)
            .all(&self.db)
            .await
        {
            Ok(list) => list,
            Err(e) => return GetUsersResponse::Error(Json(e.to_string())),
        };

        let mut dto_list = Vec::new();
        for (m, r) in users {
            let p_ids = user_pool_ids(&self.db, m.id).await;
            let route_map_id = user_route_map_id(&self.db, m.id).await;
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
                    sessions: rate_model.sessions as i32,
                    date_end: rate_model.date_end.format("%Y-%m-%d-%H:%M").to_string(),
                }),
                static_ip: m.static_ip.map(|ip| ip.parse().ok()).flatten(),
                server_ids: s_ids,
                pool_ids: p_ids,
                route_map_id,
                group_id: m.group_id,
            });
        }

        GetUsersResponse::Ok(Json(PaginatedUsers {
            total: count,
            items: dto_list,
        }))
    }

    /// Получение профиля пользователя по ID
    #[oai(path = "/user/:id", method = "get")]
    async fn get_user(&self, auth: AdminToken, id: poem_openapi::param::Path<Uuid>) -> GetUserApiResult {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return GetUserApiResult::Unauthorized(Json(err));
        }

        let result = match users::Entity::find_by_id(id.0)
            .find_also_related(crate::entities::rates::Entity)
            .one(&self.db)
            .await
        {
            Ok(Some((u, r))) => (u, r),
            Ok(None) => {
                return GetUserApiResult::NotFound(Json("VPN клиент не найден".to_string()));
            }
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
        let p_ids = user_pool_ids(&self.db, result.0.id).await;
        let route_map_id = user_route_map_id(&self.db, result.0.id).await;

        let rate_dto = result.1.map(|rate_model| RateDto {
            id: rate_model.id,
            sessions: rate_model.sessions as i32,
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
            pool_ids: p_ids,
            route_map_id,
            group_id: result.0.group_id,
        }))
    }

    /// Создание нового VPN-Клиента
    #[oai(path = "/add", method = "post")]
    async fn add_user(&self, auth: AdminToken, req: Json<AddUserRequest>) -> AddUserApiResult {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
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
            created_at: Set(Utc::now().naive_utc()),
            updated_at: Set(Utc::now().naive_utc()),
            static_ip: Set(None),
            private_key: Set(Some(encrypted_private_key)),
            public_key: Set(Some(encrypted_public_key)),
            route_map_id: Set(req.0.route_map_id),
            group_id: Set(req.0.group_id),
        };

        if let Err(e) = new_user.insert(&self.db).await {
            error!("Failed to create user: {}", e);
            return AddUserApiResult::Error(Json("Ошибка записи в БД".to_string()));
        }

        if let Some(group_id) = req.0.group_id {
            if let Ok(Some(group)) = groups::Entity::find_by_id(group_id).one(&self.db).await {
                let now = Utc::now().naive_utc();
                let date_end = now + chrono::Duration::days(group.duration_days as i64);

                let new_rate = crate::entities::rates::ActiveModel {
                    id: Set(Uuid::new_v4()),
                    user_id: Set(user_id),
                    sessions: Set(group.sessions_limit),
                    traffic_limit: Set(group.traffic_limit),
                    speed_limit: Set(group.speed_limit),
                    date_end: Set(date_end),
                    created_at: Set(now),
                    updated_at: Set(now),
                };
                let _ = new_rate.insert(&self.db).await;
            }
        }

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
        if let Some(ids) = &req.0.pool_ids {
            for pool_id in ids {
                if let Err(e) = (user_node_pools::ActiveModel {
                    user_id: Set(user_id),
                    pool_id: Set(*pool_id),
                })
                    .insert(&self.db)
                    .await
                {
                    error!("Failed to bind pool to user: {}", e);
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

    /// Редактировать настройки профиля (PATCH)
    #[oai(path = "/user/:id", method = "patch")]
    async fn update_user(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
        req: Json<UpdateUserRequest>,
    ) -> UpdateUserApiResult {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return UpdateUserApiResult::Unauthorized(Json(err));
        }

        let (user_model, rate_model) = match users::Entity::find_by_id(id.0)
            .find_also_related(crate::entities::rates::Entity)
            .one(&self.db)
            .await
        {
            Ok(Some((u, r))) => (u, r),
            Ok(None) => {
                return UpdateUserApiResult::NotFound(Json("VPN клиент не найден".to_string()));
            }
            Err(e) => return UpdateUserApiResult::Error(Json(e.to_string())),
        };

        let rate_dto = rate_model.map(|r_model| RateDto {
            id: r_model.id,
            sessions: r_model.sessions as i32,
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

        if let Some(ref ids) = req.0.server_ids {
            let _ = user_servers::Entity::delete_many()
                .filter(user_servers::Column::UserId.eq(id.0))
                .exec(&self.db)
                .await;

            for sid in ids {
                let link = user_servers::ActiveModel {
                    user_id: Set(id.0),
                    server_id: Set(*sid),
                };
                let _ = link.insert(&self.db).await;
            }
            something_changed = true;
        }
        if let Some(ref ids) = req.0.pool_ids {
            let _ = user_node_pools::Entity::delete_many()
                .filter(user_node_pools::Column::UserId.eq(id.0))
                .exec(&self.db)
                .await;
            for pool_id in ids {
                let _ = (user_node_pools::ActiveModel {
                    user_id: Set(id.0),
                    pool_id: Set(*pool_id),
                })
                    .insert(&self.db)
                    .await;
            }
            something_changed = true;
        }

        if req.0.clear_route_map.unwrap_or(false) {
            editable_user.route_map_id = Set(None);
            something_changed = true;
        } else if let Some(route_map_id) = req.0.route_map_id {
            editable_user.route_map_id = Set(Some(route_map_id));
            something_changed = true;
        }

        if something_changed {
            editable_user.updated_at = Set(Utc::now().naive_utc());

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
                    let p_ids = user_pool_ids(&self.db, updated_data.id).await;
                    let route_map_id = user_route_map_id(&self.db, updated_data.id).await;

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
                        server_ids: s_ids,
                        pool_ids: p_ids,
                        route_map_id,
                        group_id: updated_data.group_id,
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
        let editable_user_id = editable_user.id.clone().unwrap();
        let p_ids = user_pool_ids(&self.db, editable_user_id).await;
        let route_map_id = user_route_map_id(&self.db, editable_user_id).await;

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
            static_ip: editable_user
                .static_ip
                .unwrap()
                .map(|ip| ip.parse().ok())
                .flatten(),
            server_ids: s_ids,
            pool_ids: p_ids,
            route_map_id,
            group_id: editable_user.group_id.unwrap(),
        }))
    }

    /// Обнулить конфиг: (Удаление старых ключей) по ID клиента
    #[oai(path = "/regenerate/:id", method = "post")]
    async fn regenerate_keys(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
    ) -> RegenerateUserApiResult {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return RegenerateUserApiResult::Unauthorized(Json(err));
        }

        let user_model = match users::Entity::find_by_id(id.0).one(&self.db).await {
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

        let encrypted_private_key = match encryptor.encrypt(&new_crypto_core.private_key) {
            Ok(k) => k,
            Err(_) => return RegenerateUserApiResult::Error(Json("Encryption error".to_string())),
        };
        let encrypted_public_key = match encryptor.encrypt(&new_crypto_core.public_key) {
            Ok(k) => k,
            Err(_) => return RegenerateUserApiResult::Error(Json("Encryption error".to_string())),
        };

        let mut updated_usr = user_model.into_active_model();
        updated_usr.fingerprint = Set(new_crypto_core.fingerprint.clone());
        updated_usr.private_key = Set(Some(encrypted_private_key));
        updated_usr.public_key = Set(Some(encrypted_public_key));
        updated_usr.updated_at = Set(Utc::now().naive_utc());

        let final_model = match updated_usr.update(&self.db).await {
            Ok(saved) => saved,
            Err(e) => {
                error!("[REGEN DB ERROR]: {}", e);
                return RegenerateUserApiResult::Error(Json(
                    "Ошибка базы данных, operation aborted.".to_string(),
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

    /// Настройки тарифа: Обновление количества сессий и даты окончания.
    #[oai(path = "/rate/:id", method = "patch")]
    async fn update_rate(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
        req: Json<UpdateRateRequest>,
    ) -> UpdateRateApiResult {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return UpdateRateApiResult::Unauthorized(Json(err));
        }

        let rate_model = match crate::entities::rates::Entity::find_by_id(id.0)
            .one(&self.db)
            .await
        {
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
            editable_rate.sessions = Set(new_sessions);
            something_changed = true;
        }

        if let Some(new_date_str) = &req.0.date_end {
            let date_parsed =
                match chrono::NaiveDateTime::parse_from_str(new_date_str, "%Y-%m-%d-%H:%M") {
                    Ok(d) => d,
                    Err(_) => {
                        return UpdateRateApiResult::BadRequest(Json(
                            "Неверный формат даты. Ожидается YYYY-MM-DD-HH:MM".to_string(),
                        ));
                    }
                };
            editable_rate.date_end = Set(date_parsed);
            something_changed = true;
        }

        if something_changed {
            editable_rate.updated_at = Set(Utc::now().naive_utc());

            match editable_rate.update(&self.db).await {
                Ok(updated_data) => {
                    return UpdateRateApiResult::Ok(Json(RateDto {
                        id: updated_data.id,
                        sessions: updated_data.sessions as i32,
                        date_end: updated_data.date_end.format("%Y-%m-%d-%H:%M").to_string(),
                    }));
                }
                Err(e) => {
                    error!("[DB CRASH] Editing rate payload: {}", e);
                    return UpdateRateApiResult::Error(Json(
                        "Ошибка обновления тарифа в БД!".to_string(),
                    ));
                }
            }
        }

        UpdateRateApiResult::Ok(Json(RateDto {
            id: editable_rate.id.unwrap(),
            sessions: editable_rate.sessions.unwrap() as i32,
            date_end: editable_rate
                .date_end
                .unwrap()
                .format("%Y-%m-%d-%H:%M")
                .to_string(),
        }))
    }

    /// Добавление тарифа
    #[oai(path = "/addrate", method = "post")]
    async fn add_rate(
        &self,
        auth: AdminToken,
        user_id: Query<Uuid>,
        req: Json<AddRateRequest>,
    ) -> AddRateApiResult {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return AddRateApiResult::Unauthorized(Json(err));
        }

        match users::Entity::find_by_id(user_id.0).one(&self.db).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return AddRateApiResult::BadRequest(Json("Пользователь не найден".to_string()));
            }
            Err(e) => {
                error!("[DB ERROR] Get User By ID: {}", e);
                return AddRateApiResult::Error(Json("Ошибка поиска пользователя".to_string()));
            }
        }

        let rate_id = Uuid::new_v4();

        let date_parsed: NaiveDateTime = if let Some(new_date_str) = &req.0.date_end {
            let date_parsed =
                match chrono::NaiveDateTime::parse_from_str(new_date_str, "%Y-%m-%d-%H:%M") {
                    Ok(d) => d,
                    Err(_) => {
                        return AddRateApiResult::BadRequest(Json(
                            "Неверный формат даты. Ожидается YYYY-MM-DD-HH:MM".to_string(),
                        ));
                    }
                };
            date_parsed
        } else {
            return AddRateApiResult::BadRequest(Json("Нет даты".to_string()));
        };

        let new_sessions = req.0.sessions.unwrap_or(0);

        let new_rate = crate::entities::rates::ActiveModel {
            id: Set(rate_id),
            user_id: Set(user_id.0),
            sessions: Set(new_sessions),
            date_end: Set(date_parsed),
            traffic_limit: Set(req.0.traffic_limit.unwrap_or(0)),
            speed_limit: Set(req.0.speed_limit.unwrap_or(0)),
            created_at: Set(Utc::now().naive_utc()),
            updated_at: Set(Utc::now().naive_utc()),
        };

        match new_rate.insert(&self.db).await {
            Ok(added_data) => {
                AddRateApiResult::Ok(Json(RateDto {
                    id: added_data.id,
                    sessions: added_data.sessions as i32,
                    date_end: added_data.date_end.format("%Y-%m-%d-%H:%M").to_string(),
                }))
            }
            Err(e) => {
                error!("[DB ERROR] Add rate failed: {}", e);
                AddRateApiResult::Error(Json("Ошибка добавления тарифа в БД!".to_string()))
            }
        }
    }

    /// ПУБЛИЧНЫЙ ЭНДПОИНТ: Скачать готовый client.toml
    #[oai(path = "/config/:id", method = "get")]
    async fn download_config(&self, id: poem_openapi::param::Path<Uuid>) -> DownloadConfigResponse {
        let (user_opt, assigned_servers) = match users::Entity::find_by_id(id.0)
            .find_with_related(servers::Entity)
            .all(&self.db)
            .await
        {
            Ok(mut list) => {
                if list.is_empty() {
                    warn!("[CONFIG] Client download failed: ID {} not found", id.0);
                    return DownloadConfigResponse::NotFound(Json("Client not found".to_string()));
                }
                list.remove(0)
            }
            Err(e) => {
                error!(
                    "[DB ERROR] Failed to fetch user and assigned servers: {}",
                    e
                );
                return DownloadConfigResponse::Error(Json("Database error".to_string()));
            }
        };

        if !user_opt.is_active {
            warn!(
                "[CONFIG] Blocked download attempt for inactive/banned client: {}",
                id.0
            );
            return DownloadConfigResponse::NotFound(Json(
                "Client is inactive or banned".to_string(),
            ));
        }

        let assigned_servers =
            match resolve_client_servers(&self.db, user_opt.id, assigned_servers).await {
                Ok(servers) => servers,
                Err(e) => {
                    error!(
                        "[CONFIG] Failed to resolve node pools for user {}: {}",
                        id.0, e
                    );
                    return DownloadConfigResponse::Error(Json(
                        "Failed to resolve node pools".to_string(),
                    ));
                }
            };

        if assigned_servers.is_empty() {
            warn!(
                "[CONFIG] Download cancelled: No servers assigned to user {}",
                id.0
            );
            return DownloadConfigResponse::Error(Json(
                "No available servers for this user".to_string(),
            ));
        }

        let compiled_routes = match compiled_routes_for_user(&self.db, user_opt.id).await {
            Ok(routes) => routes,
            Err(e) => {
                error!(
                    "[CONFIG] Failed to compile route map for user {}: {}",
                    id.0, e
                );
                return DownloadConfigResponse::Error(Json(
                    "Failed to compile route map".to_string(),
                ));
            }
        };

        let encryptor = DbEncryptor::new();

        let decrypted_private_key = match user_opt.private_key {
            Some(ref enc_pk) => match encryptor.decrypt(enc_pk) {
                Ok(pk) => pk,
                Err(e) => {
                    error!(
                        "[DECRYPTION ERROR] Failed to decrypt user private key for {}: {}",
                        id.0, e
                    );
                    return DownloadConfigResponse::Error(Json(
                        "Failed to decrypt user credentials".to_string(),
                    ));
                }
            },
            None => {
                error!(
                    "[CONFIG ERROR] Private key is missing in database for user {}",
                    id.0
                );
                return DownloadConfigResponse::Error(Json(
                    "Private key is missing in DB".to_string(),
                ));
            }
        };

        let mut servers_toml = String::new();
        servers_toml.push_str(
            "\n# =========================================================================\n",
        );
        servers_toml.push_str("# ANET Client: Load-balanced Entry Point + Failover Nodes\n");
        servers_toml.push_str(
            "# =========================================================================\n",
        );

        let mut fallback_pub_key = String::new();

        for server in assigned_servers {
            if !server.is_active {
                continue;
            }

            if fallback_pub_key.is_empty() {
                fallback_pub_key = server.public_key.clone();
            }

            if server.address.trim().is_empty() {
                continue;
            }

            let ssh_user = server
                .ssh_user
                .as_deref()
                .map(|user| format!("ssh_user = \"{}\"\n", user))
                .unwrap_or_default();

            let mut write_server_block = |protocol: &str, port_or_url: &str| {
                let dsn = if port_or_url.contains("://") {
                    port_or_url.to_string()
                } else {
                    format!("{}://{}:{}", protocol, server.address, port_or_url)
                };

                let display_name = format!("{} [{}]", server.name.trim(), protocol.to_uppercase());

                servers_toml.push_str(&format!(
                    "[[servers]]\nname = \"{}\"\ndsn = \"{}\"\n{}timeout_secs = 8\nserver_pub_key = \"{}\"\n\n",
                    display_name, dsn, ssh_user, server.public_key
                ));
            };

            if let Some(quic) = server.quic_port {
                if quic > 0 {
                    write_server_block("quic", &quic.to_string());
                }
            }

            if let Some(ref ws) = server.websocket_url {
                if !ws.trim().is_empty() {
                    let proto = if ws.starts_with("ws://") { "ws" } else { "wss" };
                    write_server_block(proto, ws);
                }
            }

            if let Some(ssh) = server.ssh_port {
                if ssh > 0 {
                    write_server_block("ssh", &ssh.to_string());
                }
            }

            if let Some(vnc) = server.vnc_port {
                if vnc > 0 {
                    write_server_block("vnc", &vnc.to_string());
                }
            }
        }

        let template_content = match tokio::fs::read_to_string(&self.client_template_path).await {
            Ok(content) => content,
            Err(e) => {
                error!(
                    "[CONFIG TEMPLATE ERROR] Failed to read {}: {}",
                    self.client_template_path, e
                );
                return DownloadConfigResponse::Error(Json(
                    "Base configuration template is missing on server".to_string(),
                ));
            }
        };

        let mut config_output = template_content;
        config_output.push_str(&servers_toml);

        let final_output = config_output
            .replace("{{PRIVATE_KEY}}", &decrypted_private_key)
            .replace("{{SERVER_PUB_KEY}}", &fallback_pub_key);
        let final_output = if let Some(routes) = compiled_routes {
            final_output
                .replace("{{ROUTE_FOR}}", &toml_string_array(&routes.route_for))
                .replace(
                    "{{EXCLUDE_ROUTE_FOR}}",
                    &toml_string_array(&routes.exclude_route_for),
                )
                .replace("{{PER_APP}}", &toml_string_array(&routes.per_app))
                .replace("{{PER_APP_MODE}}", &routes.per_app_mode)
        } else {
            final_output
                .replace("{{ROUTE_FOR}}", "[]")
                .replace("{{EXCLUDE_ROUTE_FOR}}", "[\"192.168.1.0/24\"]")
                .replace("{{PER_APP}}", "[]")
                .replace("{{PER_APP_MODE}}", "all")
        };

        let client_name = user_opt.uid.unwrap_or_else(|| "client".to_string());
        let filename_header = format!("attachment; filename=\"{}.toml\"", client_name);

        info!(
            "[CONFIG] Successfully generated and served client.toml for user: {}",
            client_name
        );

        DownloadConfigResponse::Ok(PlainText(final_output), filename_header)
    }

    /// ПУБЛИЧНЫЙ ЭНДПОИНТ: QR-код для настройки мобильного
    #[oai(path = "/config/qr/:id", method = "get")]
    async fn download_config_qr(
        &self,
        id: poem_openapi::param::Path<Uuid>,
        #[oai(name = "Host")] host: poem_openapi::param::Header<Option<String>>,
    ) -> QrPageResponse {
        let user_opt = match users::Entity::find_by_id(id.0).one(&self.db).await {
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
            warn!(
                "[QR] Blocked download attempt for inactive/banned client: {}",
                id.0
            );
            return QrPageResponse::NotFound(Json("Client is inactive or banned".to_string()));
        }

        let host_str = host.0.unwrap_or_else(|| "127.0.0.1:3000".to_string());
        let config_url = format!("http://{}/api/v1/config/{}", host_str, id.0);

        let html_page = crate::api::api::get_qr_html_page(
            &config_url,
            user_opt
                .uid
                .unwrap_or_else(|| "client".to_string())
                .as_str(),
        );

        info!(
            "[QR] Successfully served QR setup page for user ID: {}",
            id.0
        );

        QrPageResponse::Ok(PlainText(html_page))
    }
}
