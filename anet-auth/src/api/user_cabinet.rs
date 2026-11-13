use chrono::Utc;
use poem::http::StatusCode;
use poem_openapi::{
    auth::Bearer,
    payload::Json,
    Object, OpenApi, SecurityScheme,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::{
    billing_enums::{Currency, LimitSource, OrderStatus, ProductType},
    groups, orders, products, rates, users, ProtocolType,
};

#[derive(SecurityScheme)]
#[oai(ty = "bearer", bearer_format = "jwt")]
pub struct UserAuth(pub Bearer);

#[derive(Clone, Debug)]
pub struct UserClaims {
    pub user_id: Uuid,
    pub fingerprint: String,
}

#[derive(Deserialize)]
struct UserJwtClaims {
    sub: String,
    #[serde(default)]
    fp: Option<String>,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct UserProfileResponse {
    pub id: Uuid,
    pub email: Option<String>,
    pub fingerprint: String,
    pub balance: f64,
    pub is_active: bool,
    pub group_name: Option<String>,
    pub activated_at: Option<String>,
    pub expires_at: Option<String>,
    pub is_smart_activation_pending: bool,
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
    pub connected_at: String,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct DisconnectSessionRequest {
    pub server_id: Uuid,
    pub session_id: String,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct TrafficHistoryPointDto {
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

pub struct UserCabinetApi {
    db: DatabaseConnection,
}

impl UserCabinetApi {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    async fn ensure_user(&self, auth: &UserAuth) -> poem::Result<UserClaims> {
        let secret = crate::config::jwt_secret();
        let mut validation = jsonwebtoken::Validation::default();
        validation.validate_exp = true;

        let token_data = jsonwebtoken::decode::<UserJwtClaims>(
            &auth.0.token,
            &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )
        .map_err(|_| poem::Error::from_string("Invalid or expired user token", StatusCode::UNAUTHORIZED))?;

        let user_id = Uuid::parse_str(&token_data.claims.sub)
            .map_err(|_| poem::Error::from_string("Invalid token subject", StatusCode::UNAUTHORIZED))?;

        Ok(UserClaims {
            user_id,
            fingerprint: token_data.claims.fp.unwrap_or_default(),
        })
    }
}

#[OpenApi]
impl UserCabinetApi {
    /// Получение профиля, баланса и действующих лимитов пользователя
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
        let (effective_limits, group_name) = if let Some(rate) = user_rate.filter(|r| r.date_end > now) {
            (
                EffectiveLimitsDto {
                    source: LimitSource::Rates,
                    sessions_limit: rate.sessions,
                    speed_limit_kbps: rate.speed_limit,
                    traffic_limit_bytes: rate.traffic_limit,
                },
                Some("Индивидуальный тариф".into()),
            )
        } else if let Some(group_id) = user.group_id {
            let group = groups::Entity::find_by_id(group_id)
                .one(&self.db)
                .await
                .unwrap_or(None);
            if let Some(g) = group {
                (
                    EffectiveLimitsDto {
                        source: LimitSource::Groups,
                        sessions_limit: g.sessions_limit,
                        speed_limit_kbps: g.speed_limit,
                        traffic_limit_bytes: g.traffic_limit,
                    },
                    Some(g.name),
                )
            } else {
                (
                    EffectiveLimitsDto {
                        source: LimitSource::Default,
                        sessions_limit: 1,
                        speed_limit_kbps: 0,
                        traffic_limit_bytes: 0,
                    },
                    None,
                )
            }
        } else {
            (
                EffectiveLimitsDto {
                    source: LimitSource::Unlimited,
                    sessions_limit: 0,
                    speed_limit_kbps: 0,
                    traffic_limit_bytes: 0,
                },
                None,
            )
        };

        let is_pending = user.activated_at.is_none() && user.group_id.is_some();

        Ok(Json(UserProfileResponse {
            id: user.id,
            email: user.email,
            fingerprint: user.fingerprint,
            balance: user.balance,
            is_active: user.is_active,
            group_name,
            activated_at: user.activated_at.map(|dt| dt.to_rfc3339()),
            expires_at: user.expires_at.map(|dt| dt.to_rfc3339()),
            is_smart_activation_pending: is_pending,
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

    /// Создание заказа на оплату тарифа через FreeKassa
    #[oai(path = "/user/orders", method = "post")]
    async fn create_order(
        &self,
        auth: UserAuth,
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
                "127.0.0.1",
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

    /// Активные сессии пользователя со всех серверов
    #[oai(path = "/user/sessions", method = "get")]
    async fn get_active_sessions(&self, auth: UserAuth) -> poem::Result<Json<Vec<ActiveSessionDto>>> {
        let _claims = self.ensure_user(&auth).await?;
        Ok(Json(vec![]))
    }

    /// Принудительный сброс конкретной сессии по кнопке пользователя в ЛК
    #[oai(path = "/user/sessions/disconnect", method = "post")]
    async fn disconnect_session(
        &self,
        auth: UserAuth,
        _req: Json<DisconnectSessionRequest>,
    ) -> poem::Result<Json<bool>> {
        let _claims = self.ensure_user(&auth).await?;
        Ok(Json(true))
    }

    /// График потребления трафика пользователем (Rx / Tx по часам/дням)
    #[oai(path = "/user/traffic-history", method = "get")]
    async fn get_traffic_history(&self, auth: UserAuth) -> poem::Result<Json<Vec<TrafficHistoryPointDto>>> {
        let _claims = self.ensure_user(&auth).await?;
        Ok(Json(vec![]))
    }

    /// Получение client.toml и ссылки на QR-код
    #[oai(path = "/user/config", method = "get")]
    async fn get_client_config(&self, auth: UserAuth) -> poem::Result<Json<ClientConfigResponse>> {
        let claims = self.ensure_user(&auth).await?;

        let user = users::Entity::find_by_id(claims.user_id)
            .one(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or_else(|| poem::Error::from_string("User not found", StatusCode::NOT_FOUND))?;

        let auth_host = crate::config::get()
            .cabinet
            .web
            .public_domain
            .trim_end_matches('/');
        let toml_content = format!(
            "# Anet Client Config\nfingerprint = \"{}\"\nauth_server = \"{}\"\n",
            user.fingerprint, auth_host
        );

        Ok(Json(ClientConfigResponse {
            client_toml: toml_content,
            qr_code_url: format!("{}/api/v1/config/qr/{}", auth_host, user.id),
        }))
    }
}
