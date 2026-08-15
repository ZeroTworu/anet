use crate::api::dto::*;
use crate::balancer::{BalanceCandidate, order_candidates};
use crate::crypto::DbEncryptor;
use crate::entities::{
    admins, node_commands, node_pool_members, node_pools, node_runtime_states, route_maps,
    route_rules, servers, sessions, traffic_hourly, traffic_totals, user_node_pools,
    user_route_maps, user_servers, users, users::Entity as User,
};
use crate::route_compiler::{
    CompiledRouteConfig, RouteRuleSpec, compile_route_map, toml_string_array,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{NaiveDateTime, Timelike};
use jsonwebtoken::{EncodingKey, Header, encode};
use log::{error, info, warn};
use poem::Result;
use poem_openapi::{OpenApi, param::Query, payload::Json, payload::PlainText};
use rand::{RngCore, rngs::OsRng};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel,
    PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, Set, TransactionTrait,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    env,
};
use uuid::Uuid;

pub struct VpnApi {
    pub db: DatabaseConnection,
    pub client_template_path: String,
}

fn cumulative_delta(previous: i64, current: i64) -> i64 {
    if current >= previous {
        current - previous
    } else {
        current
    }
}

// Credential ноды не хранится в открытом виде. Случайный token генерируется
// только при выпуске/перевыпуске, а для каждого control-plane запроса сравнивается
// его SHA-256 отпечаток с записью в таблице servers.
fn hash_node_token(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

fn generate_node_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

async fn node_token_is_valid(
    db: &DatabaseConnection,
    node_id: Uuid,
    token: &str,
) -> std::result::Result<bool, sea_orm::DbErr> {
    Ok(servers::Entity::find_by_id(node_id)
        .one(db)
        .await?
        .and_then(|node| node.control_token_hash)
        .is_some_and(|expected| expected == hash_node_token(token)))
}

async fn load_pool_dto(
    db: &DatabaseConnection,
    pool: node_pools::Model,
) -> std::result::Result<NodePoolDto, sea_orm::DbErr> {
    let members = node_pool_members::Entity::find()
        .filter(node_pool_members::Column::PoolId.eq(pool.id))
        .all(db)
        .await?
        .into_iter()
        .map(|member| NodePoolMemberDto {
            server_id: member.server_id,
            weight: member.weight.max(1) as u32,
        })
        .collect();
    Ok(NodePoolDto {
        id: pool.id,
        name: pool.name,
        strategy: pool.strategy,
        is_active: pool.is_active,
        members,
    })
}

fn validate_pool_request(req: &SaveNodePoolRequest) -> std::result::Result<(), String> {
    if req.name.trim().is_empty() {
        return Err("Pool name cannot be empty".to_string());
    }
    if req.strategy != "weighted" && req.strategy != "least_connections" {
        return Err("Strategy must be weighted or least_connections".to_string());
    }
    if req
        .members
        .iter()
        .any(|member| member.weight == 0 || member.weight > 10_000)
    {
        return Err("Member weight must be between 1 and 10000".to_string());
    }
    let unique: HashSet<_> = req.members.iter().map(|member| member.server_id).collect();
    if unique.len() != req.members.len() {
        return Err("Pool contains duplicate nodes".to_string());
    }
    Ok(())
}

async fn user_pool_ids(db: &DatabaseConnection, user_id: Uuid) -> Vec<Uuid> {
    user_node_pools::Entity::find()
        .filter(user_node_pools::Column::UserId.eq(user_id))
        .all(db)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|link| link.pool_id)
        .collect()
}

async fn user_route_map_id(db: &DatabaseConnection, user_id: Uuid) -> Option<Uuid> {
    user_route_maps::Entity::find_by_id(user_id)
        .one(db)
        .await
        .ok()
        .flatten()
        .map(|link| link.route_map_id)
}

async fn load_route_map_dto(
    db: &DatabaseConnection,
    map: route_maps::Model,
) -> std::result::Result<RouteMapDto, sea_orm::DbErr> {
    let rules = route_rules::Entity::find()
        .filter(route_rules::Column::RouteMapId.eq(map.id))
        .order_by_asc(route_rules::Column::Position)
        .all(db)
        .await?
        .into_iter()
        .map(|rule| RouteRuleDto {
            id: Some(rule.id),
            position: rule.position.max(0) as u32,
            match_type: rule.match_type,
            match_value: rule.match_value,
            action: rule.action,
        })
        .collect();
    Ok(RouteMapDto {
        id: map.id,
        name: map.name,
        description: map.description,
        default_action: map.default_action,
        is_active: map.is_active,
        revision: map.revision.max(0) as u64,
        rules,
    })
}

fn validate_route_map_request(req: &SaveRouteMapRequest) -> std::result::Result<(), String> {
    if req.name.trim().is_empty() {
        return Err("Route map name cannot be empty".to_string());
    }
    let specs: Vec<_> = req
        .rules
        .iter()
        .map(|rule| RouteRuleSpec {
            match_type: rule.match_type.clone(),
            match_value: rule.match_value.clone(),
            action: rule.action.clone(),
        })
        .collect();
    compile_route_map(&req.default_action, &specs).map(|_| ())
}

async fn resolve_client_servers(
    db: &DatabaseConnection,
    user_id: Uuid,
    direct_servers: Vec<servers::Model>,
) -> std::result::Result<Vec<servers::Model>, sea_orm::DbErr> {
    // Порядок результата важен: клиент подключается к первому узлу, а
    // последующие использует как failover. Поэтому resolver фильтрует offline/
    // admission-closed ноды до сортировки по стратегии пула.
    let links = user_node_pools::Entity::find()
        .filter(user_node_pools::Column::UserId.eq(user_id))
        .order_by_asc(user_node_pools::Column::PoolId)
        .all(db)
        .await?;
    let mut resolved = Vec::new();
    let mut included = HashSet::new();
    let now = chrono::Utc::now().naive_utc();

    for link in links {
        let Some(pool) = node_pools::Entity::find_by_id(link.pool_id).one(db).await? else {
            continue;
        };
        if !pool.is_active {
            continue;
        }
        let members = node_pool_members::Entity::find()
            .filter(node_pool_members::Column::PoolId.eq(pool.id))
            .all(db)
            .await?;
        let member_ids: Vec<_> = members.iter().map(|member| member.server_id).collect();
        if member_ids.is_empty() {
            continue;
        }
        let pool_servers = servers::Entity::find()
            .filter(servers::Column::Id.is_in(member_ids.clone()))
            .all(db)
            .await?;
        let runtime_by_id: HashMap<_, _> = node_runtime_states::Entity::find()
            .filter(node_runtime_states::Column::ServerId.is_in(member_ids))
            .all(db)
            .await?
            .into_iter()
            .map(|runtime| (runtime.server_id, runtime))
            .collect();
        let weight_by_id: HashMap<_, _> = members
            .into_iter()
            .map(|member| (member.server_id, member.weight.max(1) as u32))
            .collect();
        let mut server_by_id: HashMap<_, _> = pool_servers
            .into_iter()
            .filter(|server| server.is_active)
            .filter(|server| {
                runtime_by_id.get(&server.id).is_some_and(|runtime| {
                    runtime.accepting_connections
                        && now
                            .signed_duration_since(runtime.last_seen_at)
                            .num_seconds()
                            <= 45
                })
            })
            .map(|server| (server.id, server))
            .collect();
        let mut candidates: Vec<_> = server_by_id
            .keys()
            .map(|server_id| BalanceCandidate {
                server_id: *server_id,
                weight: weight_by_id.get(server_id).copied().unwrap_or(1),
                active_connections: runtime_by_id
                    .get(server_id)
                    .map(|runtime| runtime.active_connections.max(0) as u64)
                    .unwrap_or_default(),
            })
            .collect();
        order_candidates(&pool.strategy, user_id, pool.id, &mut candidates);
        for candidate in candidates {
            if included.insert(candidate.server_id) {
                if let Some(server) = server_by_id.remove(&candidate.server_id) {
                    resolved.push(server);
                }
            }
        }
    }

    // Explicit assignments remain fallback-compatible and do not require heartbeat.
    for server in direct_servers {
        if server.is_active && included.insert(server.id) {
            resolved.push(server);
        }
    }
    Ok(resolved)
}

async fn compiled_routes_for_user(
    db: &DatabaseConnection,
    user_id: Uuid,
) -> std::result::Result<Option<CompiledRouteConfig>, String> {
    // Route map компилируется в момент выдачи client.toml, чтобы сам клиент
    // не зависел от REST-доступа к панели во время работы туннеля.
    let Some(link) = user_route_maps::Entity::find_by_id(user_id)
        .one(db)
        .await
        .map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    let Some(map) = route_maps::Entity::find_by_id(link.route_map_id)
        .one(db)
        .await
        .map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    if !map.is_active {
        return Ok(None);
    }
    let rules = route_rules::Entity::find()
        .filter(route_rules::Column::RouteMapId.eq(map.id))
        .order_by_asc(route_rules::Column::Position)
        .all(db)
        .await
        .map_err(|e| e.to_string())?;
    let specs: Vec<_> = rules
        .into_iter()
        .map(|rule| RouteRuleSpec {
            match_type: rule.match_type,
            match_value: rule.match_value,
            action: rule.action,
        })
        .collect();
    compile_route_map(&map.default_action, &specs).map(Some)
}

#[cfg(test)]
mod traffic_tests {
    use super::{cumulative_delta, generate_node_token, hash_node_token};

    #[test]
    fn repeated_cumulative_report_has_zero_delta() {
        assert_eq!(cumulative_delta(4096, 4096), 0);
    }

    #[test]
    fn counter_reset_starts_a_new_delta() {
        assert_eq!(cumulative_delta(4096, 512), 512);
    }

    #[test]
    fn node_credentials_are_random_and_only_the_hash_is_stored() {
        let first = generate_node_token();
        let second = generate_node_token();
        assert_ne!(first, second);
        assert_ne!(first, hash_node_token(&first));
        assert_eq!(hash_node_token(&first), hash_node_token(&first));
        assert_ne!(hash_node_token(&first), hash_node_token(&second));
    }
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
    async fn create_server(
        &self,
        auth: AdminToken,
        req: Json<CreateServerRequest>,
    ) -> Result<Json<ServerDto>, poem::Error> {
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return Err(poem::Error::from_string(
                err,
                poem::http::StatusCode::UNAUTHORIZED,
            ));
        }

        let server_id = Uuid::new_v4();
        let new_server = servers::ActiveModel {
            id: Set(server_id),
            name: Set(req.0.name.clone()),
            address: Set(String::new()),
            dsn: Set(req.0.dsn.clone()),
            public_key: Set(req.0.public_key.clone()),
            quic_port: Set(None),
            ssh_port: Set(None),
            vnc_port: Set(None),
            websocket_url: Set(None),
            ssh_user: Set(req.0.ssh_user.clone()),
            is_active: Set(req.0.is_active.unwrap_or(true)),
            control_token_hash: Set(None),
            created_at: Set(chrono::Utc::now().naive_utc()),
            updated_at: Set(chrono::Utc::now().naive_utc()),
        };

        match new_server.insert(&self.db).await {
            Ok(saved) => Ok(Json(ServerDto {
                id: saved.id,
                name: saved.name,
                dsn: saved.dsn,
                public_key: saved.public_key,
                ssh_user: saved.ssh_user,
                is_active: saved.is_active,
                has_control_credential: saved.control_token_hash.is_some(),
                runtime: None,
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
            Ok(None) => {
                return UpdateServerApiResult::NotFound(Json("Сервер не найден".to_string()));
            }
            Err(e) => return UpdateServerApiResult::Error(Json(e.to_string())),
        };

        let mut active_model = server_model.clone().into_active_model();
        let mut changed = false;

        if let Some(name) = req.0.name {
            active_model.name = Set(name);
            changed = true;
        }
        if let Some(dsn) = req.0.dsn {
            active_model.dsn = Set(dsn);
            changed = true;
        }
        if let Some(pub_key) = req.0.public_key {
            active_model.public_key = Set(pub_key);
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
                    dsn: saved.dsn,
                    public_key: saved.public_key,
                    ssh_user: saved.ssh_user,
                    is_active: saved.is_active,
                    has_control_credential: saved.control_token_hash.is_some(),
                    runtime: None,
                })),
                Err(e) => UpdateServerApiResult::Error(Json(e.to_string())),
            }
        } else {
            UpdateServerApiResult::Ok(Json(ServerDto {
                id: server_model.id,
                name: server_model.name,
                dsn: server_model.dsn,
                public_key: server_model.public_key,
                ssh_user: server_model.ssh_user,
                is_active: server_model.is_active,
                has_control_credential: server_model.control_token_hash.is_some(),
                runtime: None,
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
                let runtime_by_server: HashMap<Uuid, node_runtime_states::Model> =
                    match node_runtime_states::Entity::find().all(&self.db).await {
                        Ok(states) => states
                            .into_iter()
                            .map(|state| (state.server_id, state))
                            .collect(),
                        Err(e) => return GetServersResponse::Error(Json(e.to_string())),
                    };
                let now = chrono::Utc::now().naive_utc();
                let dtos = list
                    .into_iter()
                    .map(|s| ServerDto {
                        runtime: runtime_by_server.get(&s.id).map(|state| NodeRuntimeDto {
                            status: if now.signed_duration_since(state.last_seen_at).num_seconds()
                                <= 45
                            {
                                "online".to_string()
                            } else {
                                "offline".to_string()
                            },
                            last_seen_at: state.last_seen_at.and_utc().to_rfc3339(),
                            version: state.version.clone(),
                            uptime_seconds: state.uptime_seconds.max(0) as u64,
                            active_connections: state.active_connections.max(0) as u64,
                            accepting_connections: state.accepting_connections,
                        }),
                        id: s.id,
                        name: s.name,
                        dsn: s.dsn,
                        public_key: s.public_key,
                        ssh_user: s.ssh_user,
                        is_active: s.is_active,
                        has_control_credential: s.control_token_hash.is_some(),
                    })
                    .collect();
                GetServersResponse::Ok(Json(dtos))
            }
            Err(e) => GetServersResponse::Error(Json(e.to_string())),
        }
    }

    #[oai(path = "/pools", method = "get")]
    async fn get_node_pools(&self, auth: AdminToken) -> GetNodePoolsResponse {
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return GetNodePoolsResponse::Unauthorized(Json(err));
        }
        let pools = match node_pools::Entity::find()
            .order_by_asc(node_pools::Column::Name)
            .all(&self.db)
            .await
        {
            Ok(pools) => pools,
            Err(e) => return GetNodePoolsResponse::Error(Json(e.to_string())),
        };
        let mut result = Vec::with_capacity(pools.len());
        for pool in pools {
            match load_pool_dto(&self.db, pool).await {
                Ok(pool) => result.push(pool),
                Err(e) => return GetNodePoolsResponse::Error(Json(e.to_string())),
            }
        }
        GetNodePoolsResponse::Ok(Json(result))
    }

    #[oai(path = "/pools", method = "post")]
    async fn create_node_pool(
        &self,
        auth: AdminToken,
        req: Json<SaveNodePoolRequest>,
    ) -> SaveNodePoolResponse {
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return SaveNodePoolResponse::Unauthorized(Json(err));
        }
        if let Err(error) = validate_pool_request(&req.0) {
            return SaveNodePoolResponse::BadRequest(Json(error));
        }
        let txn = match self.db.begin().await {
            Ok(txn) => txn,
            Err(e) => return SaveNodePoolResponse::Error(Json(e.to_string())),
        };
        let now = chrono::Utc::now().naive_utc();
        let pool = match (node_pools::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(req.0.name.trim().to_string()),
            strategy: Set(req.0.strategy.clone()),
            is_active: Set(req.0.is_active.unwrap_or(true)),
            created_at: Set(now),
            updated_at: Set(now),
        })
        .insert(&txn)
        .await
        {
            Ok(pool) => pool,
            Err(e) => return SaveNodePoolResponse::Error(Json(e.to_string())),
        };
        for member in &req.0.members {
            if let Err(e) = (node_pool_members::ActiveModel {
                pool_id: Set(pool.id),
                server_id: Set(member.server_id),
                weight: Set(member.weight as i32),
            })
            .insert(&txn)
            .await
            {
                return SaveNodePoolResponse::Error(Json(e.to_string()));
            }
        }
        if let Err(e) = txn.commit().await {
            return SaveNodePoolResponse::Error(Json(e.to_string()));
        }
        match load_pool_dto(&self.db, pool).await {
            Ok(pool) => SaveNodePoolResponse::Ok(Json(pool)),
            Err(e) => SaveNodePoolResponse::Error(Json(e.to_string())),
        }
    }

    #[oai(path = "/pools/:id", method = "patch")]
    async fn update_node_pool(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
        req: Json<SaveNodePoolRequest>,
    ) -> SaveNodePoolResponse {
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return SaveNodePoolResponse::Unauthorized(Json(err));
        }
        if let Err(error) = validate_pool_request(&req.0) {
            return SaveNodePoolResponse::BadRequest(Json(error));
        }
        let existing = match node_pools::Entity::find_by_id(id.0).one(&self.db).await {
            Ok(Some(pool)) => pool,
            Ok(None) => return SaveNodePoolResponse::NotFound(Json("Pool not found".to_string())),
            Err(e) => return SaveNodePoolResponse::Error(Json(e.to_string())),
        };
        let txn = match self.db.begin().await {
            Ok(txn) => txn,
            Err(e) => return SaveNodePoolResponse::Error(Json(e.to_string())),
        };
        let mut pool = existing.into_active_model();
        pool.name = Set(req.0.name.trim().to_string());
        pool.strategy = Set(req.0.strategy.clone());
        pool.is_active = Set(req.0.is_active.unwrap_or(true));
        pool.updated_at = Set(chrono::Utc::now().naive_utc());
        let saved = match pool.update(&txn).await {
            Ok(pool) => pool,
            Err(e) => return SaveNodePoolResponse::Error(Json(e.to_string())),
        };
        if let Err(e) = node_pool_members::Entity::delete_many()
            .filter(node_pool_members::Column::PoolId.eq(id.0))
            .exec(&txn)
            .await
        {
            return SaveNodePoolResponse::Error(Json(e.to_string()));
        }
        for member in &req.0.members {
            if let Err(e) = (node_pool_members::ActiveModel {
                pool_id: Set(id.0),
                server_id: Set(member.server_id),
                weight: Set(member.weight as i32),
            })
            .insert(&txn)
            .await
            {
                return SaveNodePoolResponse::Error(Json(e.to_string()));
            }
        }
        if let Err(e) = txn.commit().await {
            return SaveNodePoolResponse::Error(Json(e.to_string()));
        }
        match load_pool_dto(&self.db, saved).await {
            Ok(pool) => SaveNodePoolResponse::Ok(Json(pool)),
            Err(e) => SaveNodePoolResponse::Error(Json(e.to_string())),
        }
    }

    #[oai(path = "/pools/:id", method = "delete")]
    async fn delete_node_pool(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
    ) -> DeleteNodePoolResponse {
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return DeleteNodePoolResponse::Unauthorized(Json(err));
        }
        match node_pools::Entity::delete_by_id(id.0).exec(&self.db).await {
            Ok(result) if result.rows_affected > 0 => DeleteNodePoolResponse::Deleted,
            Ok(_) => DeleteNodePoolResponse::NotFound(Json("Pool not found".to_string())),
            Err(e) => DeleteNodePoolResponse::Error(Json(e.to_string())),
        }
    }

    #[oai(path = "/route-maps", method = "get")]
    async fn get_route_maps(&self, auth: AdminToken) -> GetRouteMapsResponse {
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return GetRouteMapsResponse::Unauthorized(Json(err));
        }
        let maps = match route_maps::Entity::find()
            .order_by_asc(route_maps::Column::Name)
            .all(&self.db)
            .await
        {
            Ok(maps) => maps,
            Err(e) => return GetRouteMapsResponse::Error(Json(e.to_string())),
        };
        let mut result = Vec::with_capacity(maps.len());
        for map in maps {
            match load_route_map_dto(&self.db, map).await {
                Ok(map) => result.push(map),
                Err(e) => return GetRouteMapsResponse::Error(Json(e.to_string())),
            }
        }
        GetRouteMapsResponse::Ok(Json(result))
    }

    #[oai(path = "/route-maps", method = "post")]
    async fn create_route_map(
        &self,
        auth: AdminToken,
        req: Json<SaveRouteMapRequest>,
    ) -> SaveRouteMapResponse {
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return SaveRouteMapResponse::Unauthorized(Json(err));
        }
        if let Err(error) = validate_route_map_request(&req.0) {
            return SaveRouteMapResponse::BadRequest(Json(error));
        }
        let txn = match self.db.begin().await {
            Ok(txn) => txn,
            Err(e) => return SaveRouteMapResponse::Error(Json(e.to_string())),
        };
        let now = chrono::Utc::now().naive_utc();
        let map = match (route_maps::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(req.0.name.trim().to_string()),
            description: Set(req.0.description.clone()),
            default_action: Set(req.0.default_action.clone()),
            is_active: Set(req.0.is_active.unwrap_or(true)),
            revision: Set(1),
            created_at: Set(now),
            updated_at: Set(now),
        })
        .insert(&txn)
        .await
        {
            Ok(map) => map,
            Err(e) => return SaveRouteMapResponse::Error(Json(e.to_string())),
        };
        for (position, rule) in req.0.rules.iter().enumerate() {
            if let Err(e) = (route_rules::ActiveModel {
                id: Set(Uuid::new_v4()),
                route_map_id: Set(map.id),
                position: Set(position as i32),
                match_type: Set(rule.match_type.clone()),
                match_value: Set(rule.match_value.clone()),
                action: Set(rule.action.clone()),
            })
            .insert(&txn)
            .await
            {
                return SaveRouteMapResponse::Error(Json(e.to_string()));
            }
        }
        if let Err(e) = txn.commit().await {
            return SaveRouteMapResponse::Error(Json(e.to_string()));
        }
        match load_route_map_dto(&self.db, map).await {
            Ok(map) => SaveRouteMapResponse::Ok(Json(map)),
            Err(e) => SaveRouteMapResponse::Error(Json(e.to_string())),
        }
    }

    #[oai(path = "/route-maps/:id", method = "patch")]
    async fn update_route_map(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
        req: Json<SaveRouteMapRequest>,
    ) -> SaveRouteMapResponse {
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return SaveRouteMapResponse::Unauthorized(Json(err));
        }
        if let Err(error) = validate_route_map_request(&req.0) {
            return SaveRouteMapResponse::BadRequest(Json(error));
        }
        let existing = match route_maps::Entity::find_by_id(id.0).one(&self.db).await {
            Ok(Some(map)) => map,
            Ok(None) => {
                return SaveRouteMapResponse::NotFound(Json("Route map not found".to_string()));
            }
            Err(e) => return SaveRouteMapResponse::Error(Json(e.to_string())),
        };
        let txn = match self.db.begin().await {
            Ok(txn) => txn,
            Err(e) => return SaveRouteMapResponse::Error(Json(e.to_string())),
        };
        let mut map = existing.into_active_model();
        map.name = Set(req.0.name.trim().to_string());
        map.description = Set(req.0.description.clone());
        map.default_action = Set(req.0.default_action.clone());
        map.is_active = Set(req.0.is_active.unwrap_or(true));
        map.revision = Set(map.revision.as_ref().saturating_add(1));
        map.updated_at = Set(chrono::Utc::now().naive_utc());
        let saved = match map.update(&txn).await {
            Ok(map) => map,
            Err(e) => return SaveRouteMapResponse::Error(Json(e.to_string())),
        };
        if let Err(e) = route_rules::Entity::delete_many()
            .filter(route_rules::Column::RouteMapId.eq(id.0))
            .exec(&txn)
            .await
        {
            return SaveRouteMapResponse::Error(Json(e.to_string()));
        }
        for (position, rule) in req.0.rules.iter().enumerate() {
            if let Err(e) = (route_rules::ActiveModel {
                id: Set(Uuid::new_v4()),
                route_map_id: Set(id.0),
                position: Set(position as i32),
                match_type: Set(rule.match_type.clone()),
                match_value: Set(rule.match_value.clone()),
                action: Set(rule.action.clone()),
            })
            .insert(&txn)
            .await
            {
                return SaveRouteMapResponse::Error(Json(e.to_string()));
            }
        }
        if let Err(e) = txn.commit().await {
            return SaveRouteMapResponse::Error(Json(e.to_string()));
        }
        match load_route_map_dto(&self.db, saved).await {
            Ok(map) => SaveRouteMapResponse::Ok(Json(map)),
            Err(e) => SaveRouteMapResponse::Error(Json(e.to_string())),
        }
    }

    #[oai(path = "/route-maps/:id", method = "delete")]
    async fn delete_route_map(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
    ) -> DeleteRouteMapResponse {
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return DeleteRouteMapResponse::Unauthorized(Json(err));
        }
        match route_maps::Entity::delete_by_id(id.0).exec(&self.db).await {
            Ok(result) if result.rows_affected > 0 => DeleteRouteMapResponse::Deleted,
            Ok(_) => DeleteRouteMapResponse::NotFound(Json("Route map not found".to_string())),
            Err(e) => DeleteRouteMapResponse::Error(Json(e.to_string())),
        }
    }

    /// Принять фактическое состояние VPN-ноды.
    #[oai(path = "/control/nodes/heartbeat", method = "post")]
    async fn node_heartbeat(
        &self,
        #[oai(name = "X-Node-Token")] node_token: poem_openapi::param::Header<String>,
        req: Json<NodeHeartbeatRequest>,
    ) -> NodeHeartbeatResponse {
        let node_id = match Uuid::parse_str(&req.0.node_id) {
            Ok(id) => id,
            Err(_) => {
                return NodeHeartbeatResponse::BadRequest(Json("Invalid node_id".to_string()));
            }
        };

        match node_token_is_valid(&self.db, node_id, &node_token.0).await {
            Ok(true) => {}
            Ok(false) => {
                return NodeHeartbeatResponse::Unauthorized(Json(
                    "Invalid node credential".to_string(),
                ));
            }
            Err(e) => return NodeHeartbeatResponse::Error(Json(e.to_string())),
        }

        match servers::Entity::find_by_id(node_id).one(&self.db).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return NodeHeartbeatResponse::NotFound(Json("Node is not registered".to_string()));
            }
            Err(e) => return NodeHeartbeatResponse::Error(Json(e.to_string())),
        }

        let now = chrono::Utc::now().naive_utc();
        let uptime_seconds = req.0.uptime_seconds.min(i64::MAX as u64) as i64;
        let active_connections = req.0.active_connections.min(i64::MAX as u64) as i64;
        let result = match node_runtime_states::Entity::find_by_id(node_id)
            .one(&self.db)
            .await
        {
            Ok(Some(existing)) => {
                let mut state = existing.into_active_model();
                state.last_seen_at = Set(now);
                state.version = Set(req.0.version);
                state.uptime_seconds = Set(uptime_seconds);
                state.active_connections = Set(active_connections);
                state.accepting_connections = Set(req.0.accepting_connections);
                state.update(&self.db).await.map(|_| ())
            }
            Ok(None) => node_runtime_states::ActiveModel {
                server_id: Set(node_id),
                last_seen_at: Set(now),
                version: Set(req.0.version),
                uptime_seconds: Set(uptime_seconds),
                active_connections: Set(active_connections),
                accepting_connections: Set(req.0.accepting_connections),
            }
            .insert(&self.db)
            .await
            .map(|_| ()),
            Err(e) => Err(e),
        };

        match result {
            Ok(()) => NodeHeartbeatResponse::Accepted,
            Err(e) => NodeHeartbeatResponse::Error(Json(e.to_string())),
        }
    }

    /// Поставить в очередь команду включения или выключения новых подключений.
    #[oai(path = "/servers/:id/commands/admission", method = "post")]
    async fn create_admission_command(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
        req: Json<CreateAdmissionCommandRequest>,
    ) -> CreateNodeCommandResponse {
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return CreateNodeCommandResponse::Unauthorized(Json(err));
        }
        match servers::Entity::find_by_id(id.0).one(&self.db).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return CreateNodeCommandResponse::NotFound(Json("Node not found".to_string()));
            }
            Err(e) => return CreateNodeCommandResponse::Error(Json(e.to_string())),
        }

        let command_id = Uuid::new_v4();
        let command = node_commands::ActiveModel {
            id: Set(command_id),
            server_id: Set(id.0),
            command_type: Set("set_accepting_connections".to_string()),
            accepting_connections: Set(Some(req.0.accepting_connections)),
            status: Set("pending".to_string()),
            created_at: Set(chrono::Utc::now().naive_utc()),
            started_at: Set(None),
            completed_at: Set(None),
            error: Set(None),
        };
        match command.insert(&self.db).await {
            Ok(saved) => CreateNodeCommandResponse::Created(Json(NodeCommand {
                command_id: saved.id.to_string(),
                command_type: saved.command_type,
                accepting_connections: saved.accepting_connections,
            })),
            Err(e) => CreateNodeCommandResponse::Error(Json(e.to_string())),
        }
    }

    /// Получить состояние ранее поставленной управляющей команды.
    #[oai(path = "/servers/:server_id/commands/:command_id", method = "get")]
    async fn get_node_command_status(
        &self,
        auth: AdminToken,
        server_id: poem_openapi::param::Path<Uuid>,
        command_id: poem_openapi::param::Path<Uuid>,
    ) -> GetNodeCommandStatusResponse {
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return GetNodeCommandStatusResponse::Unauthorized(Json(err));
        }

        match node_commands::Entity::find_by_id(command_id.0)
            .one(&self.db)
            .await
        {
            Ok(Some(command)) if command.server_id == server_id.0 => {
                GetNodeCommandStatusResponse::Ok(Json(NodeCommandStatusDto {
                    command_id: command.id,
                    server_id: command.server_id,
                    command_type: command.command_type,
                    status: command.status,
                    accepting_connections: command.accepting_connections,
                    created_at: command.created_at.and_utc().to_rfc3339(),
                    started_at: command.started_at.map(|value| value.and_utc().to_rfc3339()),
                    completed_at: command
                        .completed_at
                        .map(|value| value.and_utc().to_rfc3339()),
                    error: command.error,
                }))
            }
            Ok(Some(_)) | Ok(None) => {
                GetNodeCommandStatusResponse::NotFound(Json("Command not found".to_string()))
            }
            Err(e) => GetNodeCommandStatusResponse::Error(Json(e.to_string())),
        }
    }

    /// Выпустить новый индивидуальный credential ноды. Секрет возвращается только один раз.
    #[oai(path = "/servers/:id/credentials", method = "post")]
    async fn rotate_node_credential(
        &self,
        auth: AdminToken,
        id: poem_openapi::param::Path<Uuid>,
    ) -> RotateNodeCredentialResponse {
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return RotateNodeCredentialResponse::Unauthorized(Json(err));
        }

        let node = match servers::Entity::find_by_id(id.0).one(&self.db).await {
            Ok(Some(node)) => node,
            Ok(None) => {
                return RotateNodeCredentialResponse::NotFound(Json("Node not found".to_string()));
            }
            Err(e) => return RotateNodeCredentialResponse::Error(Json(e.to_string())),
        };
        let token = generate_node_token();
        let mut active = node.into_active_model();
        active.control_token_hash = Set(Some(hash_node_token(&token)));
        active.updated_at = Set(chrono::Utc::now().naive_utc());
        match active.update(&self.db).await {
            Ok(_) => RotateNodeCredentialResponse::Ok(Json(NodeCredentialDto {
                node_id: id.0,
                token,
            })),
            Err(e) => RotateNodeCredentialResponse::Error(Json(e.to_string())),
        }
    }

    /// Забрать следующую ожидающую команду. Вызов выполняется самой нодой.
    #[oai(path = "/control/nodes/commands", method = "get")]
    async fn get_node_commands(
        &self,
        #[oai(name = "X-Node-Token")] node_token: poem_openapi::param::Header<String>,
        node_id: Query<String>,
    ) -> GetNodeCommandsResponse {
        let node_id = match Uuid::parse_str(&node_id.0) {
            Ok(id) => id,
            Err(_) => {
                return GetNodeCommandsResponse::BadRequest(Json("Invalid node_id".to_string()));
            }
        };
        match node_token_is_valid(&self.db, node_id, &node_token.0).await {
            Ok(true) => {}
            Ok(false) => {
                return GetNodeCommandsResponse::Unauthorized(Json(
                    "Invalid node credential".to_string(),
                ));
            }
            Err(e) => return GetNodeCommandsResponse::Error(Json(e.to_string())),
        }
        match servers::Entity::find_by_id(node_id).one(&self.db).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return GetNodeCommandsResponse::NotFound(Json("Node not found".to_string()));
            }
            Err(e) => return GetNodeCommandsResponse::Error(Json(e.to_string())),
        }

        let stale_before = chrono::Utc::now().naive_utc() - chrono::Duration::seconds(60);
        if let Err(e) = node_commands::Entity::update_many()
            .col_expr(
                node_commands::Column::Status,
                sea_orm::sea_query::Expr::value("pending"),
            )
            .col_expr(
                node_commands::Column::StartedAt,
                sea_orm::sea_query::Expr::value(Option::<NaiveDateTime>::None),
            )
            .filter(node_commands::Column::ServerId.eq(node_id))
            .filter(node_commands::Column::Status.eq("running"))
            .filter(node_commands::Column::StartedAt.lt(stale_before))
            .exec(&self.db)
            .await
        {
            return GetNodeCommandsResponse::Error(Json(e.to_string()));
        }

        let pending = match node_commands::Entity::find()
            .filter(node_commands::Column::ServerId.eq(node_id))
            .filter(node_commands::Column::Status.eq("pending"))
            .order_by_asc(node_commands::Column::CreatedAt)
            .one(&self.db)
            .await
        {
            Ok(command) => command,
            Err(e) => return GetNodeCommandsResponse::Error(Json(e.to_string())),
        };

        let Some(command) = pending else {
            return GetNodeCommandsResponse::Ok(Json(Vec::new()));
        };
        let mut claimed = command.into_active_model();
        claimed.status = Set("running".to_string());
        claimed.started_at = Set(Some(chrono::Utc::now().naive_utc()));
        match claimed.update(&self.db).await {
            Ok(saved) => GetNodeCommandsResponse::Ok(Json(vec![NodeCommand {
                command_id: saved.id.to_string(),
                command_type: saved.command_type,
                accepting_connections: saved.accepting_connections,
            }])),
            Err(e) => GetNodeCommandsResponse::Error(Json(e.to_string())),
        }
    }

    /// Зафиксировать результат выполнения команды нодой.
    #[oai(path = "/control/nodes/commands/:id/result", method = "post")]
    async fn complete_node_command(
        &self,
        #[oai(name = "X-Node-Token")] node_token: poem_openapi::param::Header<String>,
        id: poem_openapi::param::Path<Uuid>,
        req: Json<NodeCommandResultRequest>,
    ) -> NodeCommandResultResponse {
        let node_id = match Uuid::parse_str(&req.0.node_id) {
            Ok(id) => id,
            Err(_) => {
                return NodeCommandResultResponse::BadRequest(Json("Invalid node_id".to_string()));
            }
        };
        match node_token_is_valid(&self.db, node_id, &node_token.0).await {
            Ok(true) => {}
            Ok(false) => {
                return NodeCommandResultResponse::Unauthorized(Json(
                    "Invalid node credential".to_string(),
                ));
            }
            Err(e) => return NodeCommandResultResponse::Error(Json(e.to_string())),
        }
        let command = match node_commands::Entity::find_by_id(id.0).one(&self.db).await {
            Ok(Some(command)) => command,
            Ok(None) => {
                return NodeCommandResultResponse::NotFound(Json("Command not found".to_string()));
            }
            Err(e) => return NodeCommandResultResponse::Error(Json(e.to_string())),
        };
        if command.server_id != node_id {
            return NodeCommandResultResponse::Conflict(Json(
                "Command belongs to another node".to_string(),
            ));
        }
        if command.status == "succeeded" || command.status == "failed" {
            return NodeCommandResultResponse::Accepted;
        }

        let mut completed = command.into_active_model();
        completed.status = Set(if req.0.succeeded {
            "succeeded"
        } else {
            "failed"
        }
        .to_string());
        completed.completed_at = Set(Some(chrono::Utc::now().naive_utc()));
        completed.error = Set(req.0.error);
        match completed.update(&self.db).await {
            Ok(_) => NodeCommandResultResponse::Accepted,
            Err(e) => NodeCommandResultResponse::Error(Json(e.to_string())),
        }
    }

    /// Принять накопительные счётчики полезного VPN-трафика от ноды.
    #[oai(path = "/control/nodes/traffic", method = "post")]
    async fn report_node_traffic(
        &self,
        #[oai(name = "X-Node-Token")] node_token: poem_openapi::param::Header<String>,
        req: Json<NodeTrafficReport>,
    ) -> TrafficReportResponse {
        let node_id = match Uuid::parse_str(&req.0.node_id) {
            Ok(id) => id,
            Err(_) => {
                return TrafficReportResponse::BadRequest(Json("Invalid node_id".to_string()));
            }
        };
        match node_token_is_valid(&self.db, node_id, &node_token.0).await {
            Ok(true) => {}
            Ok(false) => {
                return TrafficReportResponse::Unauthorized(Json(
                    "Invalid node credential".to_string(),
                ));
            }
            Err(e) => return TrafficReportResponse::Error(Json(e.to_string())),
        }
        if req.0.boot_id.is_empty() || req.0.boot_id.len() > 128 || req.0.samples.len() > 10_000 {
            return TrafficReportResponse::BadRequest(Json("Invalid traffic report".to_string()));
        }
        match servers::Entity::find_by_id(node_id).one(&self.db).await {
            Ok(Some(_)) => {}
            Ok(None) => return TrafficReportResponse::NotFound(Json("Node not found".to_string())),
            Err(e) => return TrafficReportResponse::Error(Json(e.to_string())),
        }

        let txn = match self.db.begin().await {
            Ok(txn) => txn,
            Err(e) => return TrafficReportResponse::Error(Json(e.to_string())),
        };
        let now = chrono::Utc::now().naive_utc();
        let bucket_start = now
            .date()
            .and_hms_opt(now.hour(), 0, 0)
            .expect("valid hour");

        for sample in req.0.samples {
            if sample.fingerprint.is_empty() {
                return TrafficReportResponse::BadRequest(Json("Empty fingerprint".to_string()));
            }
            let user_id = match sample.user_id {
                Some(id) => match Uuid::parse_str(&id) {
                    Ok(id) => Some(id),
                    Err(_) => {
                        return TrafficReportResponse::BadRequest(Json(
                            "Invalid user_id".to_string(),
                        ));
                    }
                },
                None => None,
            };
            let rx_bytes = sample.rx_bytes.min(i64::MAX as u64) as i64;
            let tx_bytes = sample.tx_bytes.min(i64::MAX as u64) as i64;
            let existing = match traffic_totals::Entity::find()
                .filter(traffic_totals::Column::ServerId.eq(node_id))
                .filter(traffic_totals::Column::BootId.eq(&req.0.boot_id))
                .filter(traffic_totals::Column::Fingerprint.eq(&sample.fingerprint))
                .one(&txn)
                .await
            {
                Ok(existing) => existing,
                Err(e) => return TrafficReportResponse::Error(Json(e.to_string())),
            };
            let (rx_delta, tx_delta, total_result) = if let Some(existing) = existing {
                let rx_delta = cumulative_delta(existing.rx_bytes, rx_bytes);
                let tx_delta = cumulative_delta(existing.tx_bytes, tx_bytes);
                let mut total = existing.into_active_model();
                // Reports are cumulative for a node boot, so retries cannot double count.
                total.rx_bytes = Set(rx_bytes);
                total.tx_bytes = Set(tx_bytes);
                total.user_id = Set(user_id);
                total.updated_at = Set(now);
                (rx_delta, tx_delta, total.update(&txn).await.map(|_| ()))
            } else {
                let result = traffic_totals::ActiveModel {
                    id: Set(Uuid::new_v4()),
                    server_id: Set(node_id),
                    boot_id: Set(req.0.boot_id.clone()),
                    user_id: Set(user_id),
                    fingerprint: Set(sample.fingerprint.clone()),
                    rx_bytes: Set(rx_bytes),
                    tx_bytes: Set(tx_bytes),
                    updated_at: Set(now),
                }
                .insert(&txn)
                .await
                .map(|_| ());
                (rx_bytes, tx_bytes, result)
            };
            if let Err(e) = total_result {
                return TrafficReportResponse::Error(Json(e.to_string()));
            }

            if rx_delta == 0 && tx_delta == 0 {
                continue;
            }
            let hourly = match traffic_hourly::Entity::find()
                .filter(traffic_hourly::Column::BucketStart.eq(bucket_start))
                .filter(traffic_hourly::Column::ServerId.eq(node_id))
                .filter(traffic_hourly::Column::Fingerprint.eq(&sample.fingerprint))
                .one(&txn)
                .await
            {
                Ok(hourly) => hourly,
                Err(e) => return TrafficReportResponse::Error(Json(e.to_string())),
            };
            let hourly_result = if let Some(hourly) = hourly {
                let mut aggregate = hourly.into_active_model();
                aggregate.rx_bytes = Set(aggregate.rx_bytes.as_ref().saturating_add(rx_delta));
                aggregate.tx_bytes = Set(aggregate.tx_bytes.as_ref().saturating_add(tx_delta));
                aggregate.user_id = Set(user_id);
                aggregate.updated_at = Set(now);
                aggregate.update(&txn).await.map(|_| ())
            } else {
                traffic_hourly::ActiveModel {
                    id: Set(Uuid::new_v4()),
                    bucket_start: Set(bucket_start),
                    server_id: Set(node_id),
                    user_id: Set(user_id),
                    fingerprint: Set(sample.fingerprint),
                    rx_bytes: Set(rx_delta),
                    tx_bytes: Set(tx_delta),
                    updated_at: Set(now),
                }
                .insert(&txn)
                .await
                .map(|_| ())
            };
            if let Err(e) = hourly_result {
                return TrafficReportResponse::Error(Json(e.to_string()));
            }
        }
        match txn.commit().await {
            Ok(()) => TrafficReportResponse::Accepted,
            Err(e) => TrafficReportResponse::Error(Json(e.to_string())),
        }
    }

    #[oai(path = "/statistics/nodes", method = "get")]
    async fn get_node_traffic_stats(&self, auth: AdminToken) -> GetNodeTrafficStatsResponse {
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return GetNodeTrafficStatsResponse::Unauthorized(Json(err));
        }
        let nodes = match servers::Entity::find().all(&self.db).await {
            Ok(nodes) => nodes,
            Err(e) => return GetNodeTrafficStatsResponse::Error(Json(e.to_string())),
        };
        let totals = match traffic_totals::Entity::find().all(&self.db).await {
            Ok(totals) => totals,
            Err(e) => return GetNodeTrafficStatsResponse::Error(Json(e.to_string())),
        };
        let mut aggregate: HashMap<Uuid, (u64, u64)> = HashMap::new();
        for total in totals {
            let entry = aggregate.entry(total.server_id).or_default();
            entry.0 = entry.0.saturating_add(total.rx_bytes.max(0) as u64);
            entry.1 = entry.1.saturating_add(total.tx_bytes.max(0) as u64);
        }
        GetNodeTrafficStatsResponse::Ok(Json(
            nodes
                .into_iter()
                .map(|node| {
                    let (rx_bytes, tx_bytes) = aggregate.get(&node.id).copied().unwrap_or_default();
                    NodeTrafficStatDto {
                        node_id: node.id,
                        name: node.name,
                        rx_bytes,
                        tx_bytes,
                    }
                })
                .collect(),
        ))
    }

    #[oai(path = "/statistics/users", method = "get")]
    async fn get_user_traffic_stats(&self, auth: AdminToken) -> GetUserTrafficStatsResponse {
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return GetUserTrafficStatsResponse::Unauthorized(Json(err));
        }
        let user_models = match users::Entity::find().all(&self.db).await {
            Ok(users) => users,
            Err(e) => return GetUserTrafficStatsResponse::Error(Json(e.to_string())),
        };
        let users_by_id: HashMap<Uuid, users::Model> =
            user_models.into_iter().map(|u| (u.id, u)).collect();
        let totals = match traffic_totals::Entity::find().all(&self.db).await {
            Ok(totals) => totals,
            Err(e) => return GetUserTrafficStatsResponse::Error(Json(e.to_string())),
        };
        let mut aggregate: HashMap<String, UserTrafficStatDto> = HashMap::new();
        for total in totals {
            let entry = aggregate
                .entry(total.fingerprint.clone())
                .or_insert_with(|| {
                    let user = total.user_id.and_then(|id| users_by_id.get(&id));
                    UserTrafficStatDto {
                        user_id: total.user_id,
                        uid: user.and_then(|u| u.uid.clone()),
                        fingerprint: total.fingerprint.clone(),
                        rx_bytes: 0,
                        tx_bytes: 0,
                    }
                });
            entry.rx_bytes = entry.rx_bytes.saturating_add(total.rx_bytes.max(0) as u64);
            entry.tx_bytes = entry.tx_bytes.saturating_add(total.tx_bytes.max(0) as u64);
        }
        let mut stats: Vec<_> = aggregate.into_values().collect();
        stats.sort_by_key(|item| std::cmp::Reverse(item.rx_bytes.saturating_add(item.tx_bytes)));
        GetUserTrafficStatsResponse::Ok(Json(stats))
    }

    #[oai(path = "/statistics/traffic/history", method = "get")]
    async fn get_traffic_history(
        &self,
        auth: AdminToken,
        hours: Query<Option<u32>>,
    ) -> GetTrafficHistoryResponse {
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
            return GetTrafficHistoryResponse::Unauthorized(Json(err));
        }
        let hours = hours.0.unwrap_or(24).clamp(1, 24 * 90);
        let now = chrono::Utc::now().naive_utc();
        let current_bucket = now
            .date()
            .and_hms_opt(now.hour(), 0, 0)
            .expect("valid hour");
        let first_bucket = current_bucket - chrono::Duration::hours((hours - 1) as i64);
        let rows = match traffic_hourly::Entity::find()
            .filter(traffic_hourly::Column::BucketStart.gte(first_bucket))
            .order_by_asc(traffic_hourly::Column::BucketStart)
            .all(&self.db)
            .await
        {
            Ok(rows) => rows,
            Err(e) => return GetTrafficHistoryResponse::Error(Json(e.to_string())),
        };
        let mut aggregate: HashMap<NaiveDateTime, (u64, u64)> = HashMap::new();
        for row in rows {
            let entry = aggregate.entry(row.bucket_start).or_default();
            entry.0 = entry.0.saturating_add(row.rx_bytes.max(0) as u64);
            entry.1 = entry.1.saturating_add(row.tx_bytes.max(0) as u64);
        }
        let points = (0..hours)
            .map(|offset| {
                let bucket = first_bucket + chrono::Duration::hours(offset as i64);
                let (rx_bytes, tx_bytes) = aggregate.get(&bucket).copied().unwrap_or_default();
                TrafficHistoryPointDto {
                    bucket_start: bucket.and_utc().to_rfc3339(),
                    rx_bytes,
                    tx_bytes,
                }
            })
            .collect();
        GetTrafficHistoryResponse::Ok(Json(points))
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
            editable_rate.sessions = Set(new_sessions as i32);
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
                    return UpdateRateApiResult::Error(Json(
                        "Ошибка обновления тарифа в БД!".to_string(),
                    ));
                }
            }
        }

        UpdateRateApiResult::Ok(Json(RateDto {
            id: editable_rate.id.unwrap(),
            sessions: editable_rate.sessions.unwrap() as u32,
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
        if let Err(err) = self.validate_admin_session(&auth.0.token).await {
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
            return AddRateApiResult::BadRequest(Json("Нету даты".to_string()));
        };

        let new_sessions = req.0.sessions.unwrap_or(0);

        let new_rate = crate::entities::rates::ActiveModel {
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
    async fn check_access(
        &self,
        req: Json<CheckAccessRequest>,
    ) -> Result<Json<CheckAccessResponse>> {
        let fingerprint = &req.0.fingerprint;

        let result = users::Entity::find()
            .filter(users::Column::Fingerprint.eq(fingerprint))
            .find_also_related(crate::entities::rates::Entity)
            .one(&self.db)
            .await
            .map_err(poem::error::InternalServerError)?;

        if let Some((user, rate_opt)) = result {
            if !user.is_active {
                return Ok(Json(CheckAccessResponse {
                    allowed: false,
                    message: "Banned".into(),
                    static_ip: None,
                    user_id: None,
                }));
            }

            if let Some(rate) = rate_opt {
                if chrono::Utc::now().naive_utc() > rate.date_end {
                    return Ok(Json(CheckAccessResponse {
                        allowed: false,
                        message: "Время действия ключа истекло".into(),
                        static_ip: None,
                        user_id: None,
                    }));
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
                    return Ok(Json(CheckAccessResponse {
                        allowed: false,
                        message: "Кол-во сессий для ключа достигло максимума".into(),
                        static_ip: None,
                        user_id: None,
                    }));
                }
            }

            // Отдаем привязанный статический IP обратно серверу для аллокации
            let static_ip = user.static_ip.clone();

            Ok(Json(CheckAccessResponse {
                allowed: true,
                message: "OK".into(),
                static_ip,
                user_id: Some(user.id.to_string()),
            }))
        } else {
            Ok(Json(CheckAccessResponse {
                allowed: false,
                message: "Not found".into(),
                static_ip: None,
                user_id: None,
            }))
        }
    }

    #[oai(path = "/session/start", method = "post")]
    async fn session_start(&self, req: Json<SessionEventRequest>) -> SessionEventResponse {
        let txn = match self.db.begin().await {
            Ok(t) => t,
            Err(_) => return SessionEventResponse::Error,
        };

        let user = match users::Entity::find()
            .filter(users::Column::Fingerprint.eq(&req.0.fingerprint))
            .one(&txn)
            .await
        {
            Ok(Some(u)) => u,
            _ => {
                let _ = txn.rollback().await;
                return SessionEventResponse::NotFound;
            }
        };

        let existing_session = crate::entities::active_sessions::Entity::find()
            .filter(crate::entities::active_sessions::Column::UserId.eq(user.id))
            .one(&txn)
            .await
            .unwrap_or(None);

        match existing_session {
            Some(sess) => {
                let mut editable = sess.into_active_model();
                editable.sessions = Set(editable.sessions.unwrap() + 1);
                editable.updated_at = Set(chrono::Utc::now().naive_utc());
                if editable.update(&txn).await.is_err() {
                    let _ = txn.rollback().await;
                    return SessionEventResponse::Error;
                }
            }
            None => {
                let new_sess = crate::entities::active_sessions::ActiveModel {
                    id: Set(Uuid::new_v4()),
                    user_id: Set(user.id),
                    sessions: Set(1),
                    created_at: Set(chrono::Utc::now().naive_utc()),
                    updated_at: Set(chrono::Utc::now().naive_utc()),
                };
                if new_sess.insert(&txn).await.is_err() {
                    let _ = txn.rollback().await;
                    return SessionEventResponse::Error;
                }
            }
        }
        if txn.commit().await.is_err() {
            return SessionEventResponse::Error;
        }
        SessionEventResponse::Ok
    }

    #[oai(path = "/session/stop", method = "post")]
    async fn session_stop(&self, req: Json<SessionEventRequest>) -> SessionEventResponse {
        let txn = match self.db.begin().await {
            Ok(t) => t,
            Err(_) => return SessionEventResponse::Error,
        };

        let user = match users::Entity::find()
            .filter(users::Column::Fingerprint.eq(&req.0.fingerprint))
            .one(&txn)
            .await
        {
            Ok(Some(u)) => u,
            _ => {
                let _ = txn.rollback().await;
                return SessionEventResponse::NotFound;
            }
        };

        if let Ok(Some(sess)) = crate::entities::active_sessions::Entity::find()
            .filter(crate::entities::active_sessions::Column::UserId.eq(user.id))
            .one(&txn)
            .await
        {
            let mut editable = sess.into_active_model();
            let current = editable.sessions.unwrap();
            if current > 0 {
                editable.sessions = Set(current - 1);
                editable.updated_at = Set(chrono::Utc::now().naive_utc());
                if editable.update(&txn).await.is_err() {
                    let _ = txn.rollback().await;
                    return SessionEventResponse::Error;
                }
            }
        }
        if txn.commit().await.is_err() {
            return SessionEventResponse::Error;
        }
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
            let p_ids = user_pool_ids(&self.db, m.id).await;
            let route_map_id = user_route_map_id(&self.db, m.id).await;
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
                pool_ids: p_ids,
                route_map_id,
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
            pool_ids: p_ids,
            route_map_id,
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
        if let Some(route_map_id) = req.0.route_map_id {
            if let Err(e) = (user_route_maps::ActiveModel {
                user_id: Set(user_id),
                route_map_id: Set(route_map_id),
            })
            .insert(&self.db)
            .await
            {
                error!("Failed to bind route map to user: {}", e);
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

        let (user_model, rate_model) = match User::find_by_id(id.0)
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
        if req.0.clear_route_map.unwrap_or(false) || req.0.route_map_id.is_some() {
            let _ = user_route_maps::Entity::delete_by_id(id.0)
                .exec(&self.db)
                .await;
            if let Some(route_map_id) = req.0.route_map_id {
                let _ = (user_route_maps::ActiveModel {
                    user_id: Set(id.0),
                    route_map_id: Set(route_map_id),
                })
                .insert(&self.db)
                .await;
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
                error!(
                    "[DB ERROR] Failed to fetch user and assigned servers: {}",
                    e
                );
                return DownloadConfigResponse::Error(Json("Database error".to_string()));
            }
        };

        // 2. Если пользователь забанен или неактивен — прерываем операцию
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

        // 3. Если нет доступных прямых назначений или здоровых pool-нод — ругаемся
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

        // 4. Инициализируем дешифратор базы данных
        let encryptor = DbEncryptor::new();

        // 5. Расшифровываем приватный ключ пользователя на лету
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

        // 6. Генерируем массив [[servers]]: первый элемент — выбранный pool entry point,
        // последующие элементы — failover-кандидаты в том же рассчитанном порядке.
        let mut servers_toml = String::new();
        servers_toml.push_str(
            "\n# =========================================================================\n",
        );
        servers_toml.push_str("# ANET Client: Load-balanced Entry Point + Failover Nodes\n");
        servers_toml.push_str(
            "# =========================================================================\n",
        );

        let mut fallback_pub_key = String::new();

        // Пробегаемся по уже загруженному в память массиву серверов без единого запроса к СУБД!
        for server in assigned_servers {
            if !server.is_active {
                continue;
            }

            if fallback_pub_key.is_empty() {
                fallback_pub_key = server.public_key.clone();
            }

            if server.dsn.trim().is_empty() {
                continue;
            }

            let ssh_user = server
                .ssh_user
                .as_deref()
                .map(|user| format!("ssh_user = \"{}\"\n", user))
                .unwrap_or_default();
            servers_toml.push_str(&format!(
                "[[servers]]\nname = \"{}\"\ndsn = \"{}\"\n{}timeout_secs = 8\nserver_pub_key = \"{}\"\n\n",
                server.name, server.dsn, ssh_user, server.public_key
            ));
        }

        // 7. Читаем базовый шаблон client_template.toml с диска сервера
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

        // 8. Сливаем базовый конфиг и сгенерированный блок серверов в один контент
        let mut config_output = template_content;
        config_output.push_str(&servers_toml);

        // 9. Заменяем плейсхолдеры на расшифрованный приватный ключ юзера и ключ сервера
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

        // 10. Настраиваем заголовки скачивания
        let client_name = user_opt.uid.unwrap_or_else(|| "client".to_string());
        let filename_header = format!("attachment; filename=\"{}.toml\"", client_name);

        info!(
            "[CONFIG] Successfully generated and served client.toml for user: {}",
            client_name
        );

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
            warn!(
                "[QR] Blocked download attempt for inactive/banned client: {}",
                id.0
            );
            return QrPageResponse::NotFound(Json("Client is inactive or banned".to_string()));
        }

        // Автоматически строим абсолютную ссылку на скачивание на основе хоста запроса
        let host_str = host.0.unwrap_or_else(|| "127.0.0.1:3000".to_string());
        let config_url = format!("http://{}/api/v1/config/{}", host_str, id.0);

        // Рендерим наш стильный OLED-Black HTML-шаблон на лету
        let html_page = get_qr_html_page(
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

/// Генератор стильной консольной OLED-Black HTML страницы для скачивания конфига клиентом
fn get_qr_html_page(config_url: &str, user_name: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
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
</html>"#,
        config_url = config_url
    )
}
