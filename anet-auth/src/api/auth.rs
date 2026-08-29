use crate::api::dto::{
   AuthTokens, CheckAccessRequest, CheckAccessResponse, Claims, LoginRequest,
    LoginResponse, SessionEventRequest, SessionEventResponse,
};
use crate::entities::{admins, sessions, users};
use bcrypt::verify;
use jsonwebtoken::{encode, EncodingKey, Header};
use poem::Result;
use poem_openapi::{payload::Json, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, Set,
    QueryFilter, TransactionTrait,
};
use std::env;
use uuid::Uuid;

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
