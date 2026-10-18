//! API управления внешними провайдерами списков (Rule Providers) для WebUI.

use chrono::Utc;
use poem_openapi::{
    param::Path, payload::Json, ApiResponse, Object, OpenApi,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, QueryFilter,
    QueryOrder, Set,
};
use uuid::Uuid;

use crate::api::api::validate_admin_session;
use crate::api::dto::AdminToken;
use crate::compiler_worker::fetch_and_cache_provider;
use crate::entities::rule_providers::{self, ProviderFormat, ProviderType};

#[derive(Object, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuleProviderDto {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub provider_type: ProviderType,
    pub format: ProviderFormat,
    pub url: String,
    pub update_interval_hours: i32,
    pub last_fetched_at: Option<String>,
    pub last_etag: Option<String>,
    pub item_count: i64,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl From<rule_providers::Model> for RuleProviderDto {
    fn from(m: rule_providers::Model) -> Self {
        Self {
            id: m.id,
            name: m.name,
            description: m.description,
            provider_type: m.provider_type,
            format: m.format,
            url: m.url,
            update_interval_hours: m.update_interval_hours,
            last_fetched_at: m.last_fetched_at.map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string()),
            last_etag: m.last_etag,
            item_count: m.item_count,
            is_active: m.is_active,
            created_at: m.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            updated_at: m.updated_at.format("%Y-%m-%d %H:%M:%S").to_string(),
        }
    }
}

#[derive(Object, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SaveRuleProviderRequest {
    pub name: String,
    pub description: String,
    pub provider_type: ProviderType,
    pub format: ProviderFormat,
    pub url: String,
    pub update_interval_hours: i32,
    pub is_active: bool,
}

#[derive(ApiResponse)]
pub enum GetRuleProvidersResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<RuleProviderDto>>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(ApiResponse)]
pub enum SaveRuleProviderResponse {
    #[oai(status = 200)]
    Ok(Json<RuleProviderDto>),
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
pub enum DeleteRuleProviderResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(ApiResponse)]
pub enum FetchRuleProviderResponse {
    #[oai(status = 200)]
    Ok(Json<RuleProviderDto>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

pub struct RuleProvidersApi {
    pub db: DatabaseConnection,
}

#[OpenApi]
impl RuleProvidersApi {
    /// Получение списка всех провайдеров правил
    #[oai(path = "/routing/rule-providers", method = "get")]
    async fn get_rule_providers(&self, auth: AdminToken) -> GetRuleProvidersResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return GetRuleProvidersResponse::Unauthorized(Json(err));
        }

        match rule_providers::Entity::find()
            .order_by_asc(rule_providers::Column::Name)
            .all(&self.db)
            .await
        {
            Ok(list) => GetRuleProvidersResponse::Ok(Json(list.into_iter().map(Into::into).collect())),
            Err(e) => GetRuleProvidersResponse::Error(Json(e.to_string())),
        }
    }

    /// Создание нового провайдера правил
    #[oai(path = "/routing/rule-providers", method = "post")]
    async fn create_rule_provider(
        &self,
        auth: AdminToken,
        body: Json<SaveRuleProviderRequest>,
    ) -> SaveRuleProviderResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return SaveRuleProviderResponse::Unauthorized(Json(err));
        }

        let now = Utc::now().naive_utc();
        let new_model = rule_providers::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(body.0.name.trim().to_string()),
            description: Set(body.0.description.trim().to_string()),
            provider_type: Set(body.0.provider_type),
            format: Set(body.0.format),
            url: Set(body.0.url.trim().to_string()),
            update_interval_hours: Set(body.0.update_interval_hours.max(1)),
            last_fetched_at: Set(None),
            last_etag: Set(None),
            item_count: Set(0),
            is_active: Set(body.0.is_active),
            created_at: Set(now),
            updated_at: Set(now),
        };

        match new_model.insert(&self.db).await {
            Ok(saved) => SaveRuleProviderResponse::Ok(Json(saved.into())),
            Err(e) => SaveRuleProviderResponse::Error(Json(e.to_string())),
        }
    }

    /// Обновление существующего провайдера
    #[oai(path = "/routing/rule-providers/:id", method = "put")]
    async fn update_rule_provider(
        &self,
        auth: AdminToken,
        id: Path<Uuid>,
        body: Json<SaveRuleProviderRequest>,
    ) -> SaveRuleProviderResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return SaveRuleProviderResponse::Unauthorized(Json(err));
        }

        let existing = match rule_providers::Entity::find_by_id(id.0).one(&self.db).await {
            Ok(Some(m)) => m,
            Ok(None) => return SaveRuleProviderResponse::NotFound(Json("Provider not found".into())),
            Err(e) => return SaveRuleProviderResponse::Error(Json(e.to_string())),
        };

        let mut active: rule_providers::ActiveModel = existing.into();
        active.name = Set(body.0.name.trim().to_string());
        active.description = Set(body.0.description.trim().to_string());
        active.provider_type = Set(body.0.provider_type);
        active.format = Set(body.0.format);
        active.url = Set(body.0.url.trim().to_string());
        active.update_interval_hours = Set(body.0.update_interval_hours.max(1));
        active.is_active = Set(body.0.is_active);
        active.updated_at = Set(Utc::now().naive_utc());

        match active.update(&self.db).await {
            Ok(saved) => SaveRuleProviderResponse::Ok(Json(saved.into())),
            Err(e) => SaveRuleProviderResponse::Error(Json(e.to_string())),
        }
    }

    /// Удаление провайдера
    #[oai(path = "/routing/rule-providers/:id", method = "delete")]
    async fn delete_rule_provider(
        &self,
        auth: AdminToken,
        id: Path<Uuid>,
    ) -> DeleteRuleProviderResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return DeleteRuleProviderResponse::Unauthorized(Json(err));
        }

        match rule_providers::Entity::delete_by_id(id.0).exec(&self.db).await {
            Ok(res) if res.rows_affected > 0 => DeleteRuleProviderResponse::Deleted,
            Ok(_) => DeleteRuleProviderResponse::NotFound(Json("Provider not found".into())),
            Err(e) => DeleteRuleProviderResponse::Error(Json(e.to_string())),
        }
    }

    /// Принудительное скачивание и обновление правил провайдера
    #[oai(path = "/routing/rule-providers/:id/fetch", method = "post")]
    async fn fetch_rule_provider_now(
        &self,
        auth: AdminToken,
        id: Path<Uuid>,
    ) -> FetchRuleProviderResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return FetchRuleProviderResponse::Unauthorized(Json(err));
        }

        let provider = match rule_providers::Entity::find_by_id(id.0).one(&self.db).await {
            Ok(Some(m)) => m,
            Ok(None) => return FetchRuleProviderResponse::NotFound(Json("Provider not found".into())),
            Err(e) => return FetchRuleProviderResponse::Error(Json(e.to_string())),
        };

        if let Err(e) = fetch_and_cache_provider(&self.db, &provider).await {
            return FetchRuleProviderResponse::Error(Json(format!("Fetch failed: {e}")));
        }

        match rule_providers::Entity::find_by_id(id.0).one(&self.db).await {
            Ok(Some(updated)) => FetchRuleProviderResponse::Ok(Json(updated.into())),
            _ => FetchRuleProviderResponse::Error(Json("Failed to reload provider".into())),
        }
    }
}
