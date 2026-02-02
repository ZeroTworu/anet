use crate::entities::users::{self, Entity as User};
use log::error;
use poem::Result;
use poem_openapi::{Object, OpenApi, payload::Json};
use sea_orm::*;

// DTO

#[derive(Object)]
pub struct CheckAccessRequest {
    #[oai(validator(min_length = 10))]
    pub fingerprint: String,
}

#[derive(Object)]
pub struct CheckAccessResponse {
    pub allowed: bool,
    pub message: String,
}

pub struct VpnApi {
    pub db: DatabaseConnection,
}

#[OpenApi]
impl VpnApi {
    /// Проверка доступа для VPN-сервера
    ///
    /// Этот эндпоинт вызывается ANet Server при хендшейке.
    #[oai(path = "/check_access", method = "post")]
    async fn check_access(
        &self,
        req: Json<CheckAccessRequest>,
    ) -> Result<Json<CheckAccessResponse>> {
        let fingerprint = &req.0.fingerprint;

        // Ищем пользователя в БД
        let user = User::find()
            .filter(users::Column::Fingerprint.eq(fingerprint))
            .one(&self.db)
            .await
            .map_err(|e| {
                error!("Error DB {}", e);
                poem::error::InternalServerError(e)
            })?;

        if let Some(u) = user {
            if u.is_active {
                Ok(Json(CheckAccessResponse {
                    allowed: true,
                    message: "Access granted".to_string(),
                }))
            } else {
                Ok(Json(CheckAccessResponse {
                    allowed: false,
                    message: "Account is banned or inactive".to_string(),
                }))
            }
        } else {
            // Если пользователя нет в базе - доступ запрещен
            // (В будущем здесь можно сделать авто-регистрацию триалов, если нужно)
            Ok(Json(CheckAccessResponse {
                allowed: false,
                message: "User not found".to_string(),
            }))
        }
    }
}
