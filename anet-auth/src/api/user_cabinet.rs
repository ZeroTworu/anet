use chrono::{DateTime, Datelike, Duration as ChronoDuration, NaiveDateTime, Timelike, Utc};
use poem::http::StatusCode;
use poem_openapi::{
    auth::Bearer,
    param::Query,
    payload::Json,
    Object, OpenApi, SecurityScheme,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect, Set,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use uuid::Uuid;

use crate::entities::{
    active_sessions,
    billing_enums::{Currency, LimitSource, OrderStatus, ProductType},
    groups, node_commands, orders, products, rates, servers, traffic_hourly, traffic_totals,
    users, ProtocolType,
};

#[derive(SecurityScheme)]
#[oai(ty = "bearer", bearer_format = "jwt")]
pub struct UserAuth(pub Bearer);

#[derive(Clone, Debug)]
pub struct UserClaims {
    pub user_id: Uuid,
    pub fingerprint: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct UserJwtClaims {
    pub sub: String,
    #[serde(default)]
    pub fp: String,
    pub iat: usize,
    pub exp: usize,
}

/// Выпуск пользовательского JWT для Личного Кабинета / TMA
pub(crate) fn issue_user_jwt(user_id: Uuid, fingerprint: &str) -> poem::Result<(String, i64)> {
    let secret = crate::config::jwt_secret();
    let ttl_hours = crate::config::get().cabinet.web.user_jwt_ttl_hours.max(1);
    let now = Utc::now();
    let exp_dt = now + ChronoDuration::hours(ttl_hours);

    let claims = UserJwtClaims {
        sub: user_id.to_string(),
        fp: fingerprint.to_string(),
        iat: now.timestamp() as usize,
        exp: exp_dt.timestamp() as usize,
    };

    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

    Ok((token, ttl_hours * 3600))
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct UserProfileResponse {
    pub id: Uuid,
    pub email: Option<String>,
    pub telegram_id: Option<i64>,
    pub fingerprint: String,
    pub balance: f64,
    pub is_active: bool,
    pub group_name: Option<String>,
    pub activated_at: Option<String>,
    pub expires_at: Option<String>,
    pub is_smart_activation_pending: bool,
    pub active_sessions_count: i32,
    pub traffic_used_bytes: i64,
    pub effective_limits: EffectiveLimitsDto,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct EffectiveLimitsDto {
    pub source: LimitSource,
    pub sessions_limit: i32,
    pub speed_limit_kbps: i32,
    pub traffic_limit_bytes: i64,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct ActiveSessionDto {
    pub session_id: String,
    pub server_id: Uuid,
    pub server_name: String,
    pub client_ip: String,
    pub protocol: ProtocolType,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
    pub connection_count: i32,
    pub connected_at: String,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct DisconnectSessionRequest {
    pub server_id: Uuid,
    pub session_id: String,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct CabinetTrafficHistoryPointDto {
    pub timestamp: String,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct ClientConfigResponse {
    pub client_toml: String,
    pub qr_code_url: String,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct PublicProductDto {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub price: f64,
    pub currency: Currency,
    pub product_type: ProductType,
    pub target_id: Option<Uuid>,
    pub sort_order: i32,
    pub badge: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct CreateOrderRequest {
    pub product_id: Uuid,
    #[oai(default)]
    pub is_gift: bool,
    pub payment_system_id: Option<i32>,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct CreateOrderResponse {
    pub order_id: Uuid,
    pub amount: f64,
    pub currency: Currency,
    pub payment_url: String,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct UserOrderDto {
    pub id: Uuid,
    pub product_id: Uuid,
    pub amount: f64,
    pub currency: Currency,
    pub status: OrderStatus,
    pub is_gift: bool,
    pub created_at: String,
    pub updated_at: String,
}

pub struct UserCabinetApi {
    db: DatabaseConnection,
    client_template_path: String,
}

impl UserCabinetApi {
    pub fn new(db: DatabaseConnection, client_template_path: String) -> Self {
        Self {
            db,
            client_template_path,
        }
    }

    pub(crate) async fn ensure_user(&self, auth: &UserAuth) -> poem::Result<UserClaims> {
        let secret = crate::config::jwt_secret();
        let mut validation = jsonwebtoken::Validation::default();
        validation.validate_exp = true;

        let token_data = jsonwebtoken::decode::<UserJwtClaims>(
            &auth.0.token,
            &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )
        .map_err(|_| {
            poem::Error::from_string("Invalid or expired user token", StatusCode::UNAUTHORIZED)
        })?;

        let user_id = Uuid::parse_str(&token_data.claims.sub).map_err(|_| {
            poem::Error::from_string("Invalid token subject", StatusCode::UNAUTHORIZED)
        })?;

        let user = users::Entity::find_by_id(user_id)
            .one(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or_else(|| poem::Error::from_string("User not found", StatusCode::UNAUTHORIZED))?;

        if !user.is_active {
            return Err(poem::Error::from_string(
                "User account is disabled",
                StatusCode::FORBIDDEN,
            ));
        }

        Ok(UserClaims {
            user_id: user.id,
            fingerprint: user.fingerprint,
        })
    }
}

fn extract_header_ip(real_ip: Option<&str>, xff: Option<&str>) -> String {
    if let Some(ip) = real_ip.map(str::trim).filter(|s| !s.is_empty()) {
        return ip.to_string();
    }
    if let Some(chain) = xff {
        if let Some(first) = chain.split(',').next().map(str::trim).filter(|s| !s.is_empty()) {
            return first.to_string();
        }
    }
    "127.0.0.1".to_string()
}

#[OpenApi]
impl UserCabinetApi {
    /// Получение профиля, баланса, статистики и действующих лимитов пользователя
    #[oai(path = "/user/me", method = "get")]
    async fn get_me(&self, auth: UserAuth) -> poem::Result<Json<UserProfileResponse>> {
        let claims = self.ensure_user(&auth).await?;

        let user = users::Entity::find_by_id(claims.user_id)
            .one(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or_else(|| poem::Error::from_string("User not found", StatusCode::NOT_FOUND))?;

        // 1. Проверяем наличие индивидуального тарифа rates (Приоритет 1: Override)
        let user_rate = rates::Entity::find()
            .filter(rates::Column::UserId.eq(user.id))
            .one(&self.db)
            .await
            .unwrap_or(None);

        let now = Utc::now().naive_utc();
        let first_day_current_month =
            chrono::NaiveDate::from_ymd_opt(now.year(), now.month(), 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap();

        let group_opt = if let Some(group_id) = user.group_id {
            groups::Entity::find_by_id(group_id)
                .one(&self.db)
                .await
                .unwrap_or(None)
        } else {
            None
        };

        let (effective_limits, group_name, cycle_start) =
            if let Some(rate) = user_rate.filter(|r| r.date_end > now) {
                let duration_days = group_opt
                    .as_ref()
                    .map(|g| g.duration_days)
                    .filter(|&d| d > 0)
                    .unwrap_or(30) as i64;
                let c_start = rate.date_end - ChronoDuration::days(duration_days);
                (
                    EffectiveLimitsDto {
                        source: LimitSource::Rates,
                        sessions_limit: rate.sessions,
                        speed_limit_kbps: rate.speed_limit,
                        traffic_limit_bytes: rate.traffic_limit,
                    },
                    Some("Индивидуальный тариф".into()),
                    c_start,
                )
            } else if let Some(ref g) = group_opt {
                let c_start = if user.expires_at.is_some() || g.duration_days > 0 {
                    user.activated_at
                        .map(|d| d.naive_utc())
                        .unwrap_or(first_day_current_month)
                } else {
                    first_day_current_month
                };
                (
                    EffectiveLimitsDto {
                        source: LimitSource::Groups,
                        sessions_limit: g.sessions_limit,
                        speed_limit_kbps: g.speed_limit,
                        traffic_limit_bytes: g.traffic_limit,
                    },
                    Some(g.name.clone()),
                    c_start,
                )
            } else {
                (
                    EffectiveLimitsDto {
                        source: LimitSource::Unlimited,
                        sessions_limit: 0,
                        speed_limit_kbps: 0,
                        traffic_limit_bytes: 0,
                    },
                    None,
                    first_day_current_month,
                )
            };

        let db_sessions = active_sessions::Entity::find()
            .filter(active_sessions::Column::UserId.eq(user.id))
            .one(&self.db)
            .await
            .ok()
            .flatten()
            .map(|s| s.sessions.max(0))
            .unwrap_or(0);

        let active_sessions_count =
            crate::api::api::get_live_sessions_for_fingerprint(&user.fingerprint)
                .unwrap_or(db_sessions);

        let sum_result = traffic_hourly::Entity::find()
            .filter(
                sea_orm::Condition::any()
                    .add(traffic_hourly::Column::UserId.eq(user.id))
                    .add(traffic_hourly::Column::Fingerprint.eq(&user.fingerprint)),
            )
            .filter(traffic_hourly::Column::BucketStart.gte(cycle_start))
            .select_only()
            .column_as(
                sea_orm::sea_query::Expr::cust(
                    "CAST(COALESCE(SUM(rx_bytes), 0) + COALESCE(SUM(tx_bytes), 0) AS BIGINT)",
                ),
                "total",
            )
            .into_tuple::<Option<i64>>()
            .one(&self.db)
            .await;

        let traffic_used_bytes = match sum_result {
            Ok(Some(Some(total_bytes))) => total_bytes.max(0),
            _ => 0,
        };

        let is_pending = user.activated_at.is_none() && user.group_id.is_some();

        Ok(Json(UserProfileResponse {
            id: user.id,
            email: user.email,
            telegram_id: user.telegram_id,
            fingerprint: user.fingerprint,
            balance: user.balance,
            is_active: user.is_active,
            group_name,
            activated_at: user.activated_at.map(|dt| dt.to_rfc3339()),
            expires_at: user.expires_at.map(|dt| dt.to_rfc3339()),
            is_smart_activation_pending: is_pending,
            active_sessions_count,
            traffic_used_bytes,
            effective_limits,
        }))
    }

    /// Витрина активных тарифов для Личного Кабинета
    #[oai(path = "/user/products", method = "get")]
    async fn list_public_products(&self, auth: UserAuth) -> poem::Result<Json<Vec<PublicProductDto>>> {
        let _claims = self.ensure_user(&auth).await?;

        let items = products::Entity::find()
            .filter(products::Column::IsActive.eq(true))
            .order_by_asc(products::Column::SortOrder)
            .all(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

        Ok(Json(
            items
                .into_iter()
                .map(|p| PublicProductDto {
                    id: p.id,
                    name: p.name,
                    description: p.description,
                    price: p.price,
                    currency: p.currency,
                    product_type: p.product_type,
                    target_id: p.target_id,
                    sort_order: p.sort_order,
                    badge: p.badge,
                    metadata: p.metadata,
                })
                .collect(),
        ))
    }

    /// История заказов текущего пользователя (для проверки статуса оплаты в ЛК)
    #[oai(path = "/user/orders", method = "get")]
    async fn list_my_orders(&self, auth: UserAuth) -> poem::Result<Json<Vec<UserOrderDto>>> {
        let claims = self.ensure_user(&auth).await?;

        let list = orders::Entity::find()
            .filter(orders::Column::UserId.eq(claims.user_id))
            .order_by_desc(orders::Column::CreatedAt)
            .limit(50)
            .all(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

        Ok(Json(
            list.into_iter()
                .map(|o| UserOrderDto {
                    id: o.id,
                    product_id: o.product_id,
                    amount: o.amount,
                    currency: o.currency,
                    status: o.status,
                    is_gift: o.is_gift,
                    created_at: o.created_at.to_rfc3339(),
                    updated_at: o.updated_at.to_rfc3339(),
                })
                .collect(),
        ))
    }

    /// Создание заказа на оплату тарифа через FreeKassa
    #[oai(path = "/user/orders", method = "post")]
    async fn create_order(
        &self,
        auth: UserAuth,
        #[oai(name = "X-Real-IP")] real_ip: poem_openapi::param::Header<Option<String>>,
        #[oai(name = "X-Forwarded-For")] xff: poem_openapi::param::Header<Option<String>>,
        req: Json<CreateOrderRequest>,
    ) -> poem::Result<Json<CreateOrderResponse>> {
        let claims = self.ensure_user(&auth).await?;

        let user = users::Entity::find_by_id(claims.user_id)
            .one(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or_else(|| poem::Error::from_string("User not found", StatusCode::NOT_FOUND))?;

        let product = products::Entity::find_by_id(req.product_id)
            .filter(products::Column::IsActive.eq(true))
            .one(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or_else(|| poem::Error::from_string("Product not found or inactive", StatusCode::NOT_FOUND))?;

        let now = Utc::now();
        let order_id = Uuid::new_v4();

        let new_order = orders::ActiveModel {
            id: Set(order_id),
            user_id: Set(user.id),
            product_id: Set(product.id),
            amount: Set(product.price),
            currency: Set(product.currency),
            status: Set(OrderStatus::Pending),
            is_gift: Set(req.is_gift),
            metadata: Set(product.metadata.clone()),
            created_at: Set(now),
            updated_at: Set(now),
        };

        let inserted = new_order
            .insert(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

        let client_ip = extract_header_ip(real_ip.0.as_deref(), xff.0.as_deref());

        let payment_url = if let Some(ps_id) = req.payment_system_id {
            let email = user
                .email
                .as_deref()
                .unwrap_or("noreply@service.example.com");
            crate::api::freekassa::create_fk_api_order(
                inserted.id,
                inserted.amount,
                inserted.currency,
                ps_id,
                email,
                &client_ip,
            )
            .await
            .map_err(|e| poem::Error::from_string(e, StatusCode::BAD_GATEWAY))?
        } else {
            crate::api::freekassa::build_sci_payment_url(
                inserted.id,
                inserted.amount,
                inserted.currency,
            )
            .map_err(|e| poem::Error::from_string(e, StatusCode::INTERNAL_SERVER_ERROR))?
        };

        Ok(Json(CreateOrderResponse {
            order_id: inserted.id,
            amount: inserted.amount,
            currency: inserted.currency,
            payment_url,
        }))
    }

    /// Активные сессии пользователя со всех VPN-нод (из LIVE_NODE_SESSIONS + traffic_totals)
    #[oai(path = "/user/sessions", method = "get")]
    async fn get_active_sessions(&self, auth: UserAuth) -> poem::Result<Json<Vec<ActiveSessionDto>>> {
        let claims = self.ensure_user(&auth).await?;

        let user = users::Entity::find_by_id(claims.user_id)
            .one(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or_else(|| poem::Error::from_string("User not found", StatusCode::NOT_FOUND))?;

        let live_nodes =
            crate::api::api::get_live_node_sessions_detail_for_fingerprint(&claims.fingerprint);
        if live_nodes.is_empty() {
            return Ok(Json(vec![]));
        }

        let node_ids: Vec<Uuid> = live_nodes.iter().map(|(id, _, _)| *id).collect();
        let server_rows = servers::Entity::find()
            .filter(servers::Column::Id.is_in(node_ids.clone()))
            .all(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;
        let server_map: HashMap<Uuid, servers::Model> =
            server_rows.into_iter().map(|s| (s.id, s)).collect();

        let recent_threshold = Utc::now().naive_utc() - ChronoDuration::seconds(120);
        let recent_totals = traffic_totals::Entity::find()
            .filter(traffic_totals::Column::Fingerprint.eq(&claims.fingerprint))
            .filter(traffic_totals::Column::ServerId.is_in(node_ids))
            .filter(traffic_totals::Column::UpdatedAt.gte(recent_threshold))
            .all(&self.db)
            .await
            .unwrap_or_default();

        let mut totals_by_server: HashMap<Uuid, Vec<traffic_totals::Model>> = HashMap::new();
        for t in recent_totals {
            totals_by_server.entry(t.server_id).or_default().push(t);
        }

        let mut sessions = Vec::new();
        let fallback_now_iso = Utc::now().to_rfc3339();

        for (server_id, count, oldest_ts) in live_nodes {
            let server_opt = server_map.get(&server_id);
            let server_name = server_opt
                .map(|s| s.name.clone())
                .unwrap_or_else(|| "VPN Node".to_string());
            let client_ip = user
                .static_ip
                .clone()
                .or_else(|| server_opt.map(|s| s.address.clone()))
                .unwrap_or_else(|| "-".to_string());

            let connected_at = if oldest_ts > 0 {
                DateTime::from_timestamp(oldest_ts as i64, 0)
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_else(|| fallback_now_iso.clone())
            } else {
                fallback_now_iso.clone()
            };

            if let Some(proto_rows) = totals_by_server.get(&server_id) {
                for row in proto_rows {
                    sessions.push(ActiveSessionDto {
                        session_id: format!("{}:{}", server_id, row.protocol.as_str()),
                        server_id,
                        server_name: server_name.clone(),
                        client_ip: client_ip.clone(),
                        protocol: row.protocol,
                        rx_bytes: row.rx_bytes.max(0),
                        tx_bytes: row.tx_bytes.max(0),
                        connection_count: count as i32,
                        connected_at: connected_at.clone(),
                    });
                }
            } else {
                sessions.push(ActiveSessionDto {
                    session_id: server_id.to_string(),
                    server_id,
                    server_name,
                    client_ip,
                    protocol: ProtocolType::Quic,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    connection_count: count as i32,
                    connected_at,
                });
            }
        }

        Ok(Json(sessions))
    }

    /// Принудительный сброс сессии пользователя на выбранной ноде через node_commands
    #[oai(path = "/user/sessions/disconnect", method = "post")]
    async fn disconnect_session(
        &self,
        auth: UserAuth,
        req: Json<DisconnectSessionRequest>,
    ) -> poem::Result<Json<bool>> {
        let claims = self.ensure_user(&auth).await?;

        let server_exists = servers::Entity::find_by_id(req.server_id)
            .one(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

        if server_exists.is_none() {
            return Err(poem::Error::from_string(
                "Target VPN server not found",
                StatusCode::NOT_FOUND,
            ));
        }

        let cmd = node_commands::ActiveModel {
            id: Set(Uuid::new_v4()),
            server_id: Set(req.server_id),
            command_type: Set("disconnect_user".to_string()),
            accepting_connections: Set(None),
            target_fingerprint: Set(Some(claims.fingerprint)),
            status: Set("pending".to_string()),
            created_at: Set(Utc::now().naive_utc()),
            started_at: Set(None),
            completed_at: Set(None),
            error: Set(None),
        };

        cmd.insert(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

        Ok(Json(true))
    }

    /// График потребления трафика пользователем (Rx / Tx по часам за сутки или по дням за 30 дней)
    #[oai(path = "/user/traffic-history", method = "get")]
    async fn get_traffic_history(
        &self,
        auth: UserAuth,
        hours: Query<Option<u32>>,
        bucket_hours: Query<Option<u32>>,
    ) -> poem::Result<Json<Vec<CabinetTrafficHistoryPointDto>>> {
        let claims = self.ensure_user(&auth).await?;

        let hours = hours.0.unwrap_or(24).clamp(1, 24 * 90);
        let group_hours = bucket_hours.0.unwrap_or(1).clamp(1, 24) as i64;
        let now = Utc::now().naive_utc();
        let current_hour = now
            .date()
            .and_hms_opt(now.hour(), 0, 0)
            .expect("valid hour");
        let first_bucket = current_hour - ChronoDuration::hours(hours as i64);

        let rows = traffic_hourly::Entity::find()
            .filter(traffic_hourly::Column::BucketStart.gte(first_bucket))
            .filter(
                sea_orm::Condition::any()
                    .add(traffic_hourly::Column::UserId.eq(claims.user_id))
                    .add(traffic_hourly::Column::Fingerprint.eq(&claims.fingerprint)),
            )
            .order_by_asc(traffic_hourly::Column::BucketStart)
            .all(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

        let mut aggregate: BTreeMap<NaiveDateTime, (i64, i64)> = BTreeMap::new();
        for row in rows {
            let bucket = if group_hours >= 24 {
                row.bucket_start
                    .date()
                    .and_hms_opt(0, 0, 0)
                    .unwrap_or(row.bucket_start)
            } else {
                let floored_hour = (row.bucket_start.hour() as i64 / group_hours) * group_hours;
                row.bucket_start
                    .date()
                    .and_hms_opt(floored_hour as u32, 0, 0)
                    .unwrap_or(row.bucket_start)
            };
            let entry = aggregate.entry(bucket).or_insert((0, 0));
            entry.0 = entry.0.saturating_add(row.rx_bytes.max(0));
            entry.1 = entry.1.saturating_add(row.tx_bytes.max(0));
        }

        let mut points = Vec::new();
        if group_hours >= 24 {
            let total_days = ((hours as i64) + 23) / 24;
            let start_day = (now - ChronoDuration::days((total_days - 1).max(0)))
                .date()
                .and_hms_opt(0, 0, 0)
                .unwrap();
            for day_offset in 0..total_days {
                let bucket = start_day + ChronoDuration::days(day_offset);
                let (rx_bytes, tx_bytes) = aggregate.get(&bucket).copied().unwrap_or((0, 0));
                points.push(CabinetTrafficHistoryPointDto {
                    timestamp: bucket.and_utc().to_rfc3339(),
                    rx_bytes,
                    tx_bytes,
                });
            }
        } else {
            let step_count = ((hours as i64) + group_hours - 1) / group_hours;
            let start_bucket = current_hour - ChronoDuration::hours((step_count - 1).max(0) * group_hours);
            let aligned_start_hour = (start_bucket.hour() as i64 / group_hours) * group_hours;
            let aligned_start = start_bucket
                .date()
                .and_hms_opt(aligned_start_hour as u32, 0, 0)
                .unwrap_or(start_bucket);
            for step in 0..step_count {
                let bucket = aligned_start + ChronoDuration::hours(step * group_hours);
                let (rx_bytes, tx_bytes) = aggregate.get(&bucket).copied().unwrap_or((0, 0));
                points.push(CabinetTrafficHistoryPointDto {
                    timestamp: bucket.and_utc().to_rfc3339(),
                    rx_bytes,
                    tx_bytes,
                });
            }
        }

        Ok(Json(points))
    }

    /// Получение полноценного client.toml и ссылки на QR-код для мобильных клиентов
    #[oai(path = "/user/config", method = "get")]
    async fn get_client_config(
        &self,
        auth: UserAuth,
        #[oai(name = "Host")] host: poem_openapi::param::Header<Option<String>>,
        #[oai(name = "X-Forwarded-Proto")] forwarded_proto: poem_openapi::param::Header<Option<String>>,
        #[oai(name = "X-Forwarded-Host")] forwarded_host: poem_openapi::param::Header<Option<String>>,
    ) -> poem::Result<Json<ClientConfigResponse>> {
        let claims = self.ensure_user(&auth).await?;

        let effective_host = forwarded_host
            .0
            .filter(|h| !h.trim().is_empty())
            .or_else(|| host.0.filter(|h| !h.trim().is_empty()));
        let scheme = forwarded_proto
            .0
            .filter(|p| !p.trim().is_empty())
            .unwrap_or_else(|| "https".to_string());

        let (client_toml, _) = crate::api::users::build_client_toml_for_user(
            &self.db,
            &self.client_template_path,
            claims.user_id,
            effective_host.as_deref(),
            &scheme,
        )
        .await
        .map_err(|(code, msg)| poem::Error::from_string(msg, code))?;

        let auth_host = crate::config::get()
            .cabinet
            .web
            .public_domain
            .trim_end_matches('/');

        Ok(Json(ClientConfigResponse {
            client_toml,
            qr_code_url: format!("{}/api/v1/config/qr/{}", auth_host, claims.user_id),
        }))
    }
}
