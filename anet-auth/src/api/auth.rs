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

        // Загружаем группу (если привязана)
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

        let now = chrono::Utc::now().naive_utc();

        // 1. Дефолтные границы по календарному месяцу
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

        // Объявляем переменные без холостой инициализации — компилятор проверит,
        // что каждая из них гарантированно заполнится в ветках if / else
        let expiration_date: chrono::NaiveDateTime;
        let cycle_start: chrono::NaiveDateTime;
        let check_expiration: bool;
        let allowed_sessions: i32;
        let max_traffic: i64;
        let speed_limit: i32;
        let has_limits: bool;
        let billing_type: BillingType;

        let group_name = group_opt.as_ref().map(|g| g.name.clone());

        // =========================================================================
        // ЛЕСТНИЦА ПРИОРИТЕТОВ: Рейт -> Группа -> Анлим
        // =========================================================================
        if let Some(ref rate) = rate_opt {
            // --- ПРИОРИТЕТ 1: Персональный тариф ---
            billing_type = if group_opt.is_some() {
                BillingType::GroupAndIndividual
            } else {
                BillingType::Individual
            };

            expiration_date = rate.date_end;
            check_expiration = true;

            let duration_days = group_opt
                .as_ref()
                .map(|g| g.duration_days)
                .filter(|&d| d > 0)
                .unwrap_or(30) as i64;
            cycle_start = expiration_date - chrono::Duration::days(duration_days);

            allowed_sessions = rate.sessions;
            max_traffic = rate.traffic_limit;
            speed_limit = rate.speed_limit;
            has_limits = true;
        } else if let Some(ref group) = group_opt {
            // --- ПРИОРИТЕТ 2: Группа (без персонального тарифа) ---
            billing_type = BillingType::Group;

            if group.duration_days > 0 {
                check_expiration = true;
                let duration = chrono::Duration::days(group.duration_days as i64);

                cycle_start = user.updated_at;
                expiration_date = user.updated_at + duration;
            } else {
                check_expiration = false;
                cycle_start = first_day_current_month;
                expiration_date = first_day_next_month;
            }

            allowed_sessions = group.sessions_limit;
            max_traffic = group.traffic_limit;
            speed_limit = group.speed_limit;
            has_limits = true;
        } else {
            // --- ПРИОРИТЕТ 3: Нет ни тарифа, ни группы (Полный анлим) ---
            billing_type = BillingType::NoTariffNoGroup;
            check_expiration = false;
            has_limits = false;
            cycle_start = first_day_current_month;
            expiration_date = first_day_next_month;
            allowed_sessions = 0;
            max_traffic = 0;
            speed_limit = 0;
        }

        // Подсчет активных сессий пользователя
        let current_sessions = crate::entities::active_sessions::Entity::find()
            .filter(crate::entities::active_sessions::Column::UserId.eq(user.id))
            .one(&self.db)
            .await
            .ok()
            .flatten()
            .map(|s| s.sessions)
            .unwrap_or(0);

        // Корректный подсчет израсходованного трафика:
        // Суммируем почасовые дельты из traffic_hourly strictly начиная с cycle_start
        let mut traffic_consumed: Option<i64> = Some(0);
        let sum_result = crate::entities::traffic_hourly::Entity::find()
            .filter(
                sea_orm::Condition::any()
                    .add(crate::entities::traffic_hourly::Column::UserId.eq(user.id))
                    .add(crate::entities::traffic_hourly::Column::Fingerprint.eq(&user.fingerprint))
            )
            .filter(crate::entities::traffic_hourly::Column::BucketStart.gte(cycle_start))
            .select_only()
            .column_as(sea_orm::sea_query::Expr::cust("CAST(COALESCE(SUM(rx_bytes), 0) + COALESCE(SUM(tx_bytes), 0) AS BIGINT)"), "total")
            .into_tuple::<Option<i64>>()
            .one(&self.db)
            .await;

        if let Ok(Some(Some(total_bytes))) = sum_result {
            traffic_consumed = Some(total_bytes);
        }

        // Форматируем дату окончания для передачи клиенту
        let expires_at = if check_expiration {
            Some(expiration_date.format("%Y-%m-%d %H:%M").to_string())
        } else {
            None
        };

        // 4. Проверка ограничений (если есть лимиты)
        if has_limits {
            // Проверка срока действия
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
                    expires_at,
                }));
            }

            // Проверка лимита сессий
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
                    expires_at,
                }));
            }

            // Проверка исчерпания трафика
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
                            expires_at,
                        }));
                    }
                }
            }
        }

        let reported_active = current_sessions + 1;

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
