use crate::api::dto::{
   AuthTokens, CheckAccessRequest, CheckAccessResponse, Claims, LoginRequest,
    LoginResponse, SessionEventRequest, SessionEventResponse,
};
use crate::entities::{admins, sessions, users};
use anet_common::dto::BillingType;
use bcrypt::verify;
use jsonwebtoken::{encode, EncodingKey, Header};
use poem::Result;
use poem_openapi::{payload::Json, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, Set,
    QueryFilter, TransactionTrait, QuerySelect
};
use std::env;
use uuid::Uuid;
use chrono::Datelike;
use log::info;

pub struct AuthApi {
    pub db: DatabaseConnection,
}

#[OpenApi]
impl AuthApi {
    /// Логин в панель Администратора
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

        if !verify(&req.0.password, &admin_entry.pass_hash).unwrap_or(false) {
            return LoginResponse::Unauthorized(Json("Invalid pass".into()))
        }

        let token_id = Uuid::new_v4();
        let expiration = chrono::Utc::now() + chrono::Duration::hours(12);

        let new_session = sessions::ActiveModel {
            id: Set(token_id),
            admin_id: Set(admin_entry.id),
            expires_at: Set(expiration.naive_utc()),
            created_at: Set(chrono::Utc::now().naive_utc()),
        };

        if new_session.insert(&self.db).await.is_err() {
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

    /// Проверка VPN Сервера при Handshake
    #[oai(path = "/check_access", method = "post")]
    async fn check_access(
        &self,
        req: Json<CheckAccessRequest>,
    ) -> Result<Json<CheckAccessResponse>> {
        let fingerprint = &req.0.fingerprint;

        let user = match users::Entity::find()
            .filter(users::Column::Fingerprint.eq(fingerprint))
            .one(&self.db)
            .await
            .map_err(poem::error::InternalServerError)?
        {
            Some(u) => u,
            None => {
                return Ok(Json(CheckAccessResponse {
                    allowed: false,
                    message: "Not found".into(),
                    static_ip: None,
                    user_id: None,
                    speed_limit_kbps: None,
                    billing_type: None,
                    group_name: None,
                    traffic_limit: None,
                    traffic_consumed: None,
                    active_sessions: None,
                    allowed_sessions: None,
                    expires_at: None,
                }))
            }
        };

        if !user.is_active {
            return Ok(Json(CheckAccessResponse {
                allowed: false,
                message: "Учетная запись заблокирована".into(),
                static_ip: None,
                user_id: None,
                speed_limit_kbps: None,
                billing_type: None,
                group_name: None,
                traffic_limit: None,
                traffic_consumed: None,
                active_sessions: None,
                allowed_sessions: None,
                expires_at: None,
            }));
        }

        // Загружаем индивидуальный тариф (если есть)
        let rate_opt = crate::entities::rates::Entity::find()
            .filter(crate::entities::rates::Column::UserId.eq(user.id))
            .one(&self.db)
            .await
            .unwrap_or(None);

        // Загружаем группу с логированием ошибок вместо тихого unwrap_or(None)
        let group_opt = if let Some(group_id) = user.group_id {
            match crate::entities::groups::Entity::find_by_id(group_id).one(&self.db).await {
                Ok(g) => g,
                Err(e) => {
                    log::error!("[check_access] Ошибка загрузки группы {}: {}", group_id, e);
                    None
                }
            }
        } else {
            None
        };

        info!(
            "[check_access] Авторизован UID='{}', ID={}, group_id={:?}, группа найдена={}",
            user.uid.as_deref().unwrap_or("none"),
            user.id,
            user.group_id,
            group_opt.is_some()
        );

        let now = chrono::Utc::now().naive_utc();

        // 1. Границы расчетного месяца
        let first_day_current_month = chrono::NaiveDate::from_ymd_opt(now.year(), now.month(), 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();

        let (next_year, next_month) = if now.month() == 12 {
            (now.year() + 1, 1)
        } else {
            (now.year(), now.month() + 1)
        };
        let first_day_next_month = chrono::NaiveDate::from_ymd_opt(next_year, next_month, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();

        let mut expiration_date = first_day_next_month;
        let mut cycle_start = first_day_current_month;
        let mut check_expiration = false;

        if let Some(ref rate) = rate_opt {
            expiration_date = rate.date_end;
            check_expiration = true;

            let duration_days = group_opt.as_ref().map(|g| g.duration_days).unwrap_or(30).max(1) as i64;
            cycle_start = expiration_date - chrono::Duration::days(duration_days);
        }

        // 2. Определение значений лимитов
        let mut allowed_sessions = 0;
        let mut max_traffic: i64 = 0;
        let mut speed_limit = 0;
        let mut has_limits = false;

        let rate_has_limits = rate_opt.as_ref().is_some_and(|r| r.sessions > 0 || r.traffic_limit > 0 || r.speed_limit > 0);

        if rate_has_limits {
            let rate = rate_opt.as_ref().unwrap();
            max_traffic = rate.traffic_limit;
            allowed_sessions = rate.sessions as i32;
            speed_limit = rate.speed_limit;
            has_limits = true;
        } else if let Some(ref group) = group_opt {
            max_traffic = group.traffic_limit;
            allowed_sessions = group.sessions_limit;
            speed_limit = group.speed_limit;
            has_limits = true;
        }

        let billing_type = match (&rate_opt, &group_opt) {
            (None, None) => BillingType::NoTariffNoGroup,
            (None, Some(_)) => BillingType::Group,
            (Some(_), None) => BillingType::Individual,
            (Some(_), Some(_)) => BillingType::GroupAndIndividual,
        };

        let group_name = group_opt.as_ref().map(|g| g.name.clone());

        // Активные сессии
        let current_sessions = crate::entities::active_sessions::Entity::find()
            .filter(crate::entities::active_sessions::Column::UserId.eq(user.id))
            .one(&self.db)
            .await
            .ok()
            .flatten()
            .map(|s| s.sessions)
            .unwrap_or(0);

        // Расход трафика
        let mut traffic_consumed: Option<i64> = Some(0);
        let sum_result = crate::entities::traffic_totals::Entity::find()
            .filter(crate::entities::traffic_totals::Column::UserId.eq(user.id))
            .filter(crate::entities::traffic_totals::Column::UpdatedAt.gte(cycle_start))
            .select_only()
            .column_as(sea_orm::sea_query::Expr::cust("CAST(SUM(rx_bytes) + SUM(tx_bytes) AS BIGINT)"), "total")
            .into_tuple::<Option<i64>>()
            .one(&self.db)
            .await;

        if let Ok(Some(Some(total_bytes))) = sum_result {
            traffic_consumed = Some(total_bytes);
        }

        // 3. Проверка лимитов
        if has_limits {
            if check_expiration && chrono::Utc::now().naive_utc() > expiration_date {
                return Ok(Json(CheckAccessResponse {
                    allowed: false,
                    message: "Время действия подписки истекло".into(),
                    static_ip: None,
                    user_id: None,
                    speed_limit_kbps: None,
                    billing_type: Some(billing_type),
                    group_name,
                    traffic_limit: None,
                    traffic_consumed,
                    active_sessions: Some(current_sessions),
                    allowed_sessions: Some(allowed_sessions),
                    expires_at: None,
                }));
            }

            if allowed_sessions > 0 && current_sessions >= allowed_sessions {
                return Ok(Json(CheckAccessResponse {
                    allowed: false,
                    message: "Достигнут лимит одновременных подключений".into(),
                    static_ip: None,
                    user_id: None,
                    speed_limit_kbps: None,
                    billing_type: Some(billing_type),
                    group_name,
                    traffic_limit: None,
                    traffic_consumed,
                    active_sessions: Some(current_sessions),
                    allowed_sessions: Some(allowed_sessions),
                    expires_at: None,
                }));
            }

            if max_traffic > 0 {
                if let Some(total_bytes) = traffic_consumed {
                    if total_bytes >= max_traffic {
                        return Ok(Json(CheckAccessResponse {
                            allowed: false,
                            message: "Лимит трафика на этот период исчерпан".into(),
                            static_ip: None,
                            user_id: None,
                            speed_limit_kbps: None,
                            billing_type: Some(billing_type),
                            group_name,
                            traffic_limit: Some(max_traffic),
                            traffic_consumed,
                            active_sessions: Some(current_sessions),
                            allowed_sessions: Some(allowed_sessions),
                            expires_at: None
                        }));
                    }
                }
            }
        }

        let reported_active = current_sessions + 1;
        let expires_at = if check_expiration {
            Some(expiration_date.format("%Y-%m-%d %H:%M").to_string())
        } else {
            None
        };

        Ok(Json(CheckAccessResponse {
            allowed: true,
            message: "OK".into(),
            static_ip: user.static_ip.clone(),
            user_id: Some(user.id.to_string()),
            speed_limit_kbps: Some(speed_limit),
            billing_type: Some(billing_type),
            group_name,
            traffic_limit: if max_traffic > 0 { Some(max_traffic) } else { None },
            traffic_consumed,
            active_sessions: Some(reported_active),
            allowed_sessions: Some(allowed_sessions),
            expires_at,
        }))
    }

    /// Старт сессии
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

    /// Стоп сессии
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
}
