use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration as ChronoDuration, Utc};
use poem::http::StatusCode;
use poem_openapi::{payload::Json, Object, OpenApi};
use rand::{rngs::OsRng, RngCore};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set,
    TransactionTrait,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::Duration;
use uuid::Uuid;

use crate::api::freekassa::{hex_encode, hmac_sha256_bytes, hmac_sha256_hex};
use crate::api::user_cabinet::{issue_user_jwt, UserAuth, UserCabinetApi};
use crate::crypto::DbEncryptor;
use crate::entities::{groups, users, verification_tokens};

#[derive(Object, Debug, Deserialize)]
pub struct RequestEmailLinkRequest {
    pub email: String,
}

#[derive(Object, Debug, Serialize)]
pub struct RequestEmailLinkResponse {
    pub sent: bool,
    pub expires_in_mins: u64,
    /// Заполняется ТОЛЬКО при APP_ENV=development, если не настроен EMAIL_WEBHOOK_URL
    pub dev_verify_url: Option<String>,
}

#[derive(Object, Debug, Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
    pub password: String,
}

#[derive(Object, Debug, Deserialize)]
pub struct UserLoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Object, Debug, Deserialize)]
pub struct TelegramAuthRequest {
    pub init_data: String,
}

#[derive(Object, Debug, Serialize)]
pub struct UserAuthTokenResponse {
    pub token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub user_id: Uuid,
    pub email: Option<String>,
    pub fingerprint: String,
}

pub struct UserAuthApi {
    pub db: DatabaseConnection,
}

fn normalize_email(raw: &str) -> Result<String, poem::Error> {
    let email = raw.trim().to_lowercase();
    if email.len() < 5 || !email.contains('@') || !email.contains('.') || email.contains(' ') {
        return Err(poem::Error::from_string(
            "Некорректный формат Email",
            StatusCode::BAD_REQUEST,
        ));
    }
    Ok(email)
}

fn generate_verification_token() -> (String, String) {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let raw_token = URL_SAFE_NO_PAD.encode(bytes);
    let token_hash = hex_encode(&Sha256::digest(raw_token.as_bytes()));
    (raw_token, token_hash)
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h1 = (bytes[i + 1] as char).to_digit(16);
            let h2 = (bytes[i + 2] as char).to_digit(16);
            if let (Some(a), Some(b)) = (h1, h2) {
                out.push(((a << 4) | b) as u8);
                i += 3;
                continue;
            }
            out.push(bytes[i]);
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn parse_form_urlencoded(raw: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(percent_decode(k), percent_decode(v));
        } else {
            map.insert(percent_decode(pair), String::new());
        }
    }
    map
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn dispatch_verification_email(
    email: &str,
    verify_url: &str,
    expires_mins: u64,
) -> Result<Option<String>, poem::Error> {
    let cfg = crate::config::get();
    let webhook_url = cfg.cabinet.web.email_webhook_url.trim();

    if !webhook_url.is_empty() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

        let payload = serde_json::json!({
            "to": email,
            "subject": "Подтверждение входа и установка пароля — ANet",
            "verify_url": verify_url,
            "expires_in_mins": expires_mins,
            "text": format!(
                "Для завершения регистрации или привязки Email перейдите по ссылке (действует {} мин.): {}",
                expires_mins, verify_url
            ),
        });

        let mut req = client
            .post(webhook_url)
            .header("Content-Type", "application/json")
            .body(payload.to_string());
        let token = cfg.cabinet.web.email_webhook_token.trim();
        if !token.is_empty() {
            req = req.bearer_auth(token);
        }

        let resp = req.send().await.map_err(|e| {
            log::error!("[UserAuth] Email webhook request failed: {}", e);
            poem::Error::from_string("Failed to send verification email", StatusCode::BAD_GATEWAY)
        })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            log::error!(
                "[UserAuth] Email webhook returned non-2xx ({}): {}",
                status,
                body
            );
            return Err(poem::Error::from_string(
                "Email provider rejected request",
                StatusCode::BAD_GATEWAY,
            ));
        }

        return Ok(None);
    }

    log::warn!(
        "[UserAuth] EMAIL_WEBHOOK_URL не настроен. Ссылка подтверждения для {}: {}",
        email,
        verify_url
    );
    if cfg.app_env == "development" {
        Ok(Some(verify_url.to_string()))
    } else {
        Ok(None)
    }
}

async fn create_new_user_with_default_group<C: sea_orm::ConnectionTrait>(
    txn: &C,
    email: Option<String>,
    password_hash: Option<String>,
    telegram_id: Option<i64>,
    uid_hint: Option<String>,
) -> Result<users::Model, poem::Error> {
    let identity = crate::keygen::generate_identity();
    let encryptor = DbEncryptor::new();
    let enc_priv = encryptor
        .encrypt(&identity.private_key)
        .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;
    let enc_pub = encryptor
        .encrypt(&identity.public_key)
        .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

    let default_group = groups::Entity::find()
        .filter(groups::Column::IsDefault.eq(true))
        .one(txn)
        .await
        .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

    let now_naive = Utc::now().naive_utc();
    let user_id = Uuid::new_v4();
    let uid = uid_hint.or_else(|| email.clone()).unwrap_or_else(|| {
        if let Some(tg) = telegram_id {
            format!("tg_{}", tg)
        } else {
            format!("user_{}", &user_id.to_string()[..8])
        }
    });

    let model = users::ActiveModel {
        id: Set(user_id),
        fingerprint: Set(identity.fingerprint),
        uid: Set(Some(uid)),
        is_active: Set(true),
        created_at: Set(now_naive),
        updated_at: Set(now_naive),
        static_ip: Set(None),
        private_key: Set(Some(enc_priv)),
        public_key: Set(Some(enc_pub)),
        route_map_id: Set(None),
        group_id: Set(default_group.map(|g| g.id)),
        email: Set(email),
        password_hash: Set(password_hash),
        telegram_id: Set(telegram_id),
        balance: Set(0.0),
        activated_at: Set(None),
        expires_at: Set(None),
    };

    model
        .insert(txn)
        .await
        .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))
}

#[OpenApi]
impl UserAuthApi {
    /// Запрос одноразовой ссылки подтверждения Email (регистрация или сброс/установка пароля)
    #[oai(path = "/user/auth/request-link", method = "post")]
    async fn request_email_link(
        &self,
        req: Json<RequestEmailLinkRequest>,
    ) -> poem::Result<Json<RequestEmailLinkResponse>> {
        let email = normalize_email(&req.email)?;
        let cfg = crate::config::get();
        let ttl_mins = cfg.cabinet.web.verification_token_ttl_mins;
        let now = Utc::now();
        let (raw_token, token_hash) = generate_verification_token();

        let existing_user = users::Entity::find()
            .filter(users::Column::Email.eq(&email))
            .one(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

        if let Some(ref existing) = existing_user {
            if !existing.is_active {
                return Err(poem::Error::from_string(
                    "Учетная запись заблокирована",
                    StatusCode::FORBIDDEN,
                ));
            }
        }

        let token_row = verification_tokens::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(existing_user.map(|u| u.id)),
            email: Set(email.clone()),
            token_hash: Set(token_hash),
            expires_at: Set(now + ChronoDuration::minutes(ttl_mins as i64)),
            used_at: Set(None),
            created_at: Set(now),
        };

        token_row
            .insert(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

        let domain = cfg.cabinet.web.public_domain.trim_end_matches('/');
        let verify_url = format!("{}/auth/verify?token={}", domain, raw_token);
        let dev_verify_url = dispatch_verification_email(&email, &verify_url, ttl_mins).await?;

        Ok(Json(RequestEmailLinkResponse {
            sent: true,
            expires_in_mins: ttl_mins,
            dev_verify_url,
        }))
    }

    /// Привязка Email к существующему аккаунту (сценарий Telegram TMA -> Web-кабинет)
    #[oai(path = "/user/auth/link-email", method = "post")]
    async fn link_email(
        &self,
        auth: UserAuth,
        req: Json<RequestEmailLinkRequest>,
    ) -> poem::Result<Json<RequestEmailLinkResponse>> {
        let claims = UserCabinetApi::new(self.db.clone(), String::new())
            .ensure_user(&auth)
            .await?;
        let email = normalize_email(&req.email)?;

        if let Some(other) = users::Entity::find()
            .filter(users::Column::Email.eq(&email))
            .one(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
        {
            if other.id != claims.user_id {
                return Err(poem::Error::from_string(
                    "Этот Email уже привязан к другому аккаунту",
                    StatusCode::CONFLICT,
                ));
            }
        }

        let cfg = crate::config::get();
        let ttl_mins = cfg.cabinet.web.verification_token_ttl_mins;
        let now = Utc::now();
        let (raw_token, token_hash) = generate_verification_token();

        let token_row = verification_tokens::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(Some(claims.user_id)),
            email: Set(email.clone()),
            token_hash: Set(token_hash),
            expires_at: Set(now + ChronoDuration::minutes(ttl_mins as i64)),
            used_at: Set(None),
            created_at: Set(now),
        };

        token_row
            .insert(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

        let domain = cfg.cabinet.web.public_domain.trim_end_matches('/');
        let verify_url = format!("{}/auth/verify?token={}", domain, raw_token);
        let dev_verify_url = dispatch_verification_email(&email, &verify_url, ttl_mins).await?;

        Ok(Json(RequestEmailLinkResponse {
            sent: true,
            expires_in_mins: ttl_mins,
            dev_verify_url,
        }))
    }

    /// Подтверждение одноразового токена из письма, установка пароля и выдача JWT
    #[oai(path = "/user/auth/verify", method = "post")]
    async fn verify_email_and_set_password(
        &self,
        req: Json<VerifyEmailRequest>,
    ) -> poem::Result<Json<UserAuthTokenResponse>> {
        let min_len = crate::config::get().cabinet.web.min_password_length;
        if req.password.chars().count() < min_len {
            return Err(poem::Error::from_string(
                format!("Минимальная длина пароля: {} символов", min_len),
                StatusCode::BAD_REQUEST,
            ));
        }

        let raw_token = req.token.trim();
        if raw_token.is_empty() {
            return Err(poem::Error::from_string(
                "Отсутствует токен подтверждения",
                StatusCode::BAD_REQUEST,
            ));
        }

        let token_hash = hex_encode(&Sha256::digest(raw_token.as_bytes()));
        let txn = self
            .db
            .begin()
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

        let token_model = verification_tokens::Entity::find()
            .filter(verification_tokens::Column::TokenHash.eq(&token_hash))
            .one(&txn)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or_else(|| {
                poem::Error::from_string("Неверный токен подтверждения", StatusCode::BAD_REQUEST)
            })?;

        let now = Utc::now();
        if token_model.used_at.is_some() {
            return Err(poem::Error::from_string(
                "Ссылка подтверждения уже была использована",
                StatusCode::BAD_REQUEST,
            ));
        }
        if now > token_model.expires_at {
            return Err(poem::Error::from_string(
                "Срок действия ссылки подтверждения истек",
                StatusCode::BAD_REQUEST,
            ));
        }

        let email = token_model.email.clone();
        let target_user_id = token_model.user_id;

        let mut token_active: verification_tokens::ActiveModel = token_model.into();
        token_active.used_at = Set(Some(now));
        token_active
            .update(&txn)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

        let password_hash = hash(&req.password, DEFAULT_COST)
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

        let user = if let Some(uid) = target_user_id {
            let existing = users::Entity::find_by_id(uid)
                .one(&txn)
                .await
                .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
                .ok_or_else(|| poem::Error::from_string("User not found", StatusCode::NOT_FOUND))?;

            if !existing.is_active {
                return Err(poem::Error::from_string(
                    "Учетная запись заблокирована",
                    StatusCode::FORBIDDEN,
                ));
            }

            if let Some(conflict) = users::Entity::find()
                .filter(users::Column::Email.eq(&email))
                .one(&txn)
                .await
                .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
            {
                if conflict.id != existing.id {
                    return Err(poem::Error::from_string(
                        "Email уже используется другим пользователем",
                        StatusCode::CONFLICT,
                    ));
                }
            }

            let mut active: users::ActiveModel = existing.into();
            active.email = Set(Some(email.clone()));
            active.password_hash = Set(Some(password_hash));
            active.updated_at = Set(now.naive_utc());
            active
                .update(&txn)
                .await
                .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
        } else if let Some(existing) = users::Entity::find()
            .filter(users::Column::Email.eq(&email))
            .one(&txn)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
        {
            if !existing.is_active {
                return Err(poem::Error::from_string(
                    "Учетная запись заблокирована",
                    StatusCode::FORBIDDEN,
                ));
            }
            let mut active: users::ActiveModel = existing.into();
            active.password_hash = Set(Some(password_hash));
            active.updated_at = Set(now.naive_utc());
            active
                .update(&txn)
                .await
                .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
        } else {
            create_new_user_with_default_group(&txn, Some(email.clone()), Some(password_hash), None, None).await?
        };

        txn.commit()
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

        let (jwt, expires_in) = issue_user_jwt(user.id, &user.fingerprint)?;
        Ok(Json(UserAuthTokenResponse {
            token: jwt,
            token_type: "Bearer".to_string(),
            expires_in,
            user_id: user.id,
            email: user.email,
            fingerprint: user.fingerprint,
        }))
    }

    /// Вход в Личный Кабинет по Email и паролю
    #[oai(path = "/user/auth/login", method = "post")]
    async fn login(&self, req: Json<UserLoginRequest>) -> poem::Result<Json<UserAuthTokenResponse>> {
        let email = normalize_email(&req.email)?;
        let user = users::Entity::find()
            .filter(users::Column::Email.eq(&email))
            .one(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or_else(|| {
                poem::Error::from_string("Неверный Email или пароль", StatusCode::UNAUTHORIZED)
            })?;

        if !user.is_active {
            return Err(poem::Error::from_string(
                "Учетная запись заблокирована",
                StatusCode::FORBIDDEN,
            ));
        }

        let Some(ref stored_hash) = user.password_hash else {
            return Err(poem::Error::from_string(
                "Для этого Email пароль еще не установлен — запросите ссылку входа",
                StatusCode::UNAUTHORIZED,
            ));
        };

        let valid = verify(&req.password, stored_hash).unwrap_or(false);
        if !valid {
            return Err(poem::Error::from_string(
                "Неверный Email или пароль",
                StatusCode::UNAUTHORIZED,
            ));
        }

        let (jwt, expires_in) = issue_user_jwt(user.id, &user.fingerprint)?;
        Ok(Json(UserAuthTokenResponse {
            token: jwt,
            token_type: "Bearer".to_string(),
            expires_in,
            user_id: user.id,
            email: user.email,
            fingerprint: user.fingerprint,
        }))
    }

    /// Вход / авторегистрация через Telegram Mini App (строгая проверка HMAC-SHA256 initData)
    #[oai(path = "/user/auth/telegram", method = "post")]
    async fn telegram_auth(
        &self,
        req: Json<TelegramAuthRequest>,
    ) -> poem::Result<Json<UserAuthTokenResponse>> {
        let tg_cfg = &crate::config::get().cabinet.telegram;
        let bot_token = tg_cfg.bot_token.trim();
        if bot_token.is_empty() {
            return Err(poem::Error::from_string(
                "TELEGRAM_BOT_TOKEN не настроен на сервере",
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }

        let mut params = parse_form_urlencoded(req.init_data.trim());
        let received_hash = params
            .remove("hash")
            .ok_or_else(|| poem::Error::from_string("Missing hash in initData", StatusCode::BAD_REQUEST))?
            .to_lowercase();

        if let Some(auth_date_str) = params.get("auth_date") {
            if let Ok(auth_ts) = auth_date_str.parse::<i64>() {
                let age_secs = Utc::now().timestamp() - auth_ts;
                if age_secs > 86_400 {
                    return Err(poem::Error::from_string(
                        "Telegram initData expired",
                        StatusCode::UNAUTHORIZED,
                    ));
                }
            }
        }

        let data_check_string = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("\n");

        let secret_key = hmac_sha256_bytes(tg_cfg.web_app_data_key.as_bytes(), bot_token.as_bytes());
        let expected_hash = hmac_sha256_hex(&secret_key, data_check_string.as_bytes());

        if !constant_time_eq(expected_hash.as_bytes(), received_hash.as_bytes()) {
            return Err(poem::Error::from_string(
                "Invalid Telegram initData signature",
                StatusCode::UNAUTHORIZED,
            ));
        }

        let user_json_str = params
            .get("user")
            .ok_or_else(|| poem::Error::from_string("Missing user field in initData", StatusCode::BAD_REQUEST))?;
        let user_json: serde_json::Value = serde_json::from_str(user_json_str)
            .map_err(|_| poem::Error::from_string("Invalid Telegram user JSON", StatusCode::BAD_REQUEST))?;

        let tg_id = user_json
            .get("id")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| poem::Error::from_string("Missing Telegram user id", StatusCode::BAD_REQUEST))?;
        let username_hint = user_json
            .get("username")
            .and_then(|v| v.as_str())
            .map(|u| format!("tg_{}", u));

        let txn = self
            .db
            .begin()
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

        let user = if let Some(existing) = users::Entity::find()
            .filter(users::Column::TelegramId.eq(tg_id))
            .one(&txn)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
        {
            if !existing.is_active {
                return Err(poem::Error::from_string(
                    "Учетная запись заблокирована",
                    StatusCode::FORBIDDEN,
                ));
            }
            existing
        } else {
            create_new_user_with_default_group(&txn, None, None, Some(tg_id), username_hint).await?
        };

        txn.commit()
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

        let (jwt, expires_in) = issue_user_jwt(user.id, &user.fingerprint)?;
        Ok(Json(UserAuthTokenResponse {
            token: jwt,
            token_type: "Bearer".to_string(),
            expires_in,
            user_id: user.id,
            email: user.email,
            fingerprint: user.fingerprint,
        }))
    }
}
