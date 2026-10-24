//! API управления списком публичных DoH-резолверов в БД для WebUI.

use chrono::Utc;
use poem_openapi::{param::Path, payload::Json, ApiResponse, Object, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set,
};
use uuid::Uuid;

use crate::api::api::validate_admin_session;
use crate::api::dto::AdminToken;
use crate::entities::doh_resolvers;

#[derive(Object, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DohResolverDto {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    pub is_default: bool,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl From<doh_resolvers::Model> for DohResolverDto {
    fn from(m: doh_resolvers::Model) -> Self {
        Self {
            id: m.id,
            name: m.name,
            url: m.url,
            is_default: m.is_default,
            is_active: m.is_active,
            created_at: m.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            updated_at: m.updated_at.format("%Y-%m-%d %H:%M:%S").to_string(),
        }
    }
}

#[derive(Object, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SaveDohResolverRequest {
    pub name: String,
    pub url: String,
    pub is_default: bool,
    pub is_active: bool,
}

#[derive(ApiResponse)]
pub enum GetDohResolversResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<DohResolverDto>>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(ApiResponse)]
pub enum SaveDohResolverResponse {
    #[oai(status = 200)]
    Ok(Json<DohResolverDto>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(ApiResponse)]
pub enum DeleteDohResolverResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

/// Возвращает список активных дефолтных DoH-резолверов из БД (или всех активных, если ни один не помечен is_default).
pub async fn get_default_doh_resolver_urls(db: &DatabaseConnection) -> Vec<String> {
    let active = doh_resolvers::Entity::find()
        .filter(doh_resolvers::Column::IsActive.eq(true))
        .order_by_desc(doh_resolvers::Column::IsDefault)
        .order_by_asc(doh_resolvers::Column::CreatedAt)
        .all(db)
        .await
        .unwrap_or_default();

    let defaults: Vec<String> = active
        .iter()
        .filter(|r| r.is_default)
        .map(|r| r.url.clone())
        .collect();

    if !defaults.is_empty() {
        defaults
    } else {
        active.into_iter().map(|r| r.url).collect()
    }
}

/// Дополняет `doh://...` DSN параметрами `?resolver=...` из БД, если в DSN ещё не указан ни один `resolver=`.
pub fn ensure_doh_dsn_has_resolvers(raw_dsn: &str, default_resolvers: &[String]) -> String {
    let base = if raw_dsn.contains("://") {
        raw_dsn.to_string()
    } else {
        format!("doh://{}", raw_dsn)
    };

    if base.contains("resolver=") || default_resolvers.is_empty() {
        return base;
    }

    let resolver_params: Vec<String> = default_resolvers
        .iter()
        .map(|r| format!("resolver={}", r.trim()))
        .collect();
    let sep = if base.contains('?') { '&' } else { '?' };
    format!("{}{}{}", base, sep, resolver_params.join("&"))
}

pub struct DohResolversApi {
    pub db: DatabaseConnection,
}

#[OpenApi]
impl DohResolversApi {
    /// Получение списка публичных DoH-резолверов
    #[oai(path = "/doh-resolvers", method = "get")]
    async fn get_doh_resolvers(&self, auth: AdminToken) -> GetDohResolversResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return GetDohResolversResponse::Unauthorized(Json(err));
        }

        match doh_resolvers::Entity::find()
            .order_by_desc(doh_resolvers::Column::IsDefault)
            .order_by_asc(doh_resolvers::Column::CreatedAt)
            .all(&self.db)
            .await
        {
            Ok(list) => {
                GetDohResolversResponse::Ok(Json(list.into_iter().map(Into::into).collect()))
            }
            Err(e) => GetDohResolversResponse::Error(Json(e.to_string())),
        }
    }

    /// Добавление нового DoH-резолвера
    #[oai(path = "/doh-resolvers", method = "post")]
    async fn create_doh_resolver(
        &self,
        auth: AdminToken,
        body: Json<SaveDohResolverRequest>,
    ) -> SaveDohResolverResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return SaveDohResolverResponse::Unauthorized(Json(err));
        }

        let url = body.0.url.trim().to_string();
        if url.is_empty() || (!url.starts_with("https://") && !url.starts_with("http://")) {
            return SaveDohResolverResponse::BadRequest(Json(
                "URL резолвера должен начинаться с https:// или http://".into(),
            ));
        }

        let name = if body.0.name.trim().is_empty() {
            url.clone()
        } else {
            body.0.name.trim().to_string()
        };

        let now = Utc::now().naive_utc();
        let new_model = doh_resolvers::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(name),
            url: Set(url),
            is_default: Set(body.0.is_default),
            is_active: Set(body.0.is_active),
            created_at: Set(now),
            updated_at: Set(now),
        };

        match new_model.insert(&self.db).await {
            Ok(saved) => SaveDohResolverResponse::Ok(Json(saved.into())),
            Err(e) => SaveDohResolverResponse::Error(Json(e.to_string())),
        }
    }

    /// Обновление существующего DoH-резолвера
    #[oai(path = "/doh-resolvers/:id", method = "put")]
    async fn update_doh_resolver(
        &self,
        auth: AdminToken,
        id: Path<Uuid>,
        body: Json<SaveDohResolverRequest>,
    ) -> SaveDohResolverResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return SaveDohResolverResponse::Unauthorized(Json(err));
        }

        let existing = match doh_resolvers::Entity::find_by_id(id.0).one(&self.db).await {
            Ok(Some(m)) => m,
            Ok(None) => {
                return SaveDohResolverResponse::NotFound(Json("DoH resolver not found".into()))
            }
            Err(e) => return SaveDohResolverResponse::Error(Json(e.to_string())),
        };

        let url = body.0.url.trim().to_string();
        if url.is_empty() || (!url.starts_with("https://") && !url.starts_with("http://")) {
            return SaveDohResolverResponse::BadRequest(Json(
                "URL резолвера должен начинаться с https:// или http://".into(),
            ));
        }

        let name = if body.0.name.trim().is_empty() {
            url.clone()
        } else {
            body.0.name.trim().to_string()
        };

        let mut active: doh_resolvers::ActiveModel = existing.into();
        active.name = Set(name);
        active.url = Set(url);
        active.is_default = Set(body.0.is_default);
        active.is_active = Set(body.0.is_active);
        active.updated_at = Set(Utc::now().naive_utc());

        match active.update(&self.db).await {
            Ok(saved) => SaveDohResolverResponse::Ok(Json(saved.into())),
            Err(e) => SaveDohResolverResponse::Error(Json(e.to_string())),
        }
    }

    /// Удаление DoH-резолвера
    #[oai(path = "/doh-resolvers/:id", method = "delete")]
    async fn delete_doh_resolver(
        &self,
        auth: AdminToken,
        id: Path<Uuid>,
    ) -> DeleteDohResolverResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return DeleteDohResolverResponse::Unauthorized(Json(err));
        }

        match doh_resolvers::Entity::delete_by_id(id.0)
            .exec(&self.db)
            .await
        {
            Ok(res) if res.rows_affected > 0 => DeleteDohResolverResponse::Deleted,
            Ok(_) => DeleteDohResolverResponse::NotFound(Json("DoH resolver not found".into())),
            Err(e) => DeleteDohResolverResponse::Error(Json(e.to_string())),
        }
    }
}
