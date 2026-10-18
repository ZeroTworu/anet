//! API управления административными исключениями (Custom Overrides) для WebUI.

use chrono::Utc;
use poem_openapi::{
    param::Path, param::Query, payload::Json, ApiResponse, Object, OpenApi,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set,
};
use uuid::Uuid;

use crate::api::api::validate_admin_session;
use crate::api::dto::AdminToken;
use crate::entities::admin_custom_overrides::{self, OverrideCategory, OverrideType};

#[derive(Object, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CustomOverrideDto {
    pub id: Uuid,
    pub route_map_id: Option<Uuid>,
    pub rule_type: OverrideType,
    pub pattern: String,
    pub category: OverrideCategory,
    pub comment: String,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl From<admin_custom_overrides::Model> for CustomOverrideDto {
    fn from(m: admin_custom_overrides::Model) -> Self {
        Self {
            id: m.id,
            route_map_id: m.route_map_id,
            rule_type: m.rule_type,
            pattern: m.pattern,
            category: m.category,
            comment: m.comment,
            is_active: m.is_active,
            created_at: m.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            updated_at: m.updated_at.format("%Y-%m-%d %H:%M:%S").to_string(),
        }
    }
}

#[derive(Object, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SaveCustomOverrideRequest {
    pub route_map_id: Option<Uuid>,
    pub rule_type: OverrideType,
    pub pattern: String,
    pub category: OverrideCategory,
    pub comment: String,
    pub is_active: bool,
}

#[derive(ApiResponse)]
pub enum GetCustomOverridesResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<CustomOverrideDto>>),
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

#[derive(ApiResponse)]
pub enum SaveCustomOverrideResponse {
    #[oai(status = 200)]
    Ok(Json<CustomOverrideDto>),
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
pub enum DeleteCustomOverrideResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 401)]
    Unauthorized(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 500)]
    Error(Json<String>),
}

pub struct CustomOverridesApi {
    pub db: DatabaseConnection,
}

#[OpenApi]
impl CustomOverridesApi {
    /// Получение списка административных исключений
    #[oai(path = "/routing/custom-overrides", method = "get")]
    async fn get_custom_overrides(
        &self,
        auth: AdminToken,
        route_map_id: Query<Option<Uuid>>,
    ) -> GetCustomOverridesResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return GetCustomOverridesResponse::Unauthorized(Json(err));
        }

        let mut query = admin_custom_overrides::Entity::find();
        if let Some(map_id) = route_map_id.0 {
            let cond = Condition::any()
                .add(admin_custom_overrides::Column::RouteMapId.eq(map_id))
                .add(admin_custom_overrides::Column::RouteMapId.is_null());
            query = query.filter(cond);
        }

        match query
            .order_by_desc(admin_custom_overrides::Column::CreatedAt)
            .all(&self.db)
            .await
        {
            Ok(list) => GetCustomOverridesResponse::Ok(Json(list.into_iter().map(Into::into).collect())),
            Err(e) => GetCustomOverridesResponse::Error(Json(e.to_string())),
        }
    }

    /// Создание нового административного правила исключения
    #[oai(path = "/routing/custom-overrides", method = "post")]
    async fn create_custom_override(
        &self,
        auth: AdminToken,
        body: Json<SaveCustomOverrideRequest>,
    ) -> SaveCustomOverrideResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return SaveCustomOverrideResponse::Unauthorized(Json(err));
        }

        let pattern = body.0.pattern.trim().to_string();
        if pattern.is_empty() {
            return SaveCustomOverrideResponse::BadRequest(Json("Pattern cannot be empty".into()));
        }

        let now = Utc::now().naive_utc();
        let new_model = admin_custom_overrides::ActiveModel {
            id: Set(Uuid::new_v4()),
            route_map_id: Set(body.0.route_map_id),
            rule_type: Set(body.0.rule_type),
            pattern: Set(pattern),
            category: Set(body.0.category),
            comment: Set(body.0.comment.trim().to_string()),
            is_active: Set(body.0.is_active),
            created_at: Set(now),
            updated_at: Set(now),
        };

        match new_model.insert(&self.db).await {
            Ok(saved) => SaveCustomOverrideResponse::Ok(Json(saved.into())),
            Err(e) => SaveCustomOverrideResponse::Error(Json(e.to_string())),
        }
    }

    /// Обновление существующего исключения
    #[oai(path = "/routing/custom-overrides/:id", method = "put")]
    async fn update_custom_override(
        &self,
        auth: AdminToken,
        id: Path<Uuid>,
        body: Json<SaveCustomOverrideRequest>,
    ) -> SaveCustomOverrideResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return SaveCustomOverrideResponse::Unauthorized(Json(err));
        }

        let existing = match admin_custom_overrides::Entity::find_by_id(id.0).one(&self.db).await {
            Ok(Some(m)) => m,
            Ok(None) => return SaveCustomOverrideResponse::NotFound(Json("Override not found".into())),
            Err(e) => return SaveCustomOverrideResponse::Error(Json(e.to_string())),
        };

        let mut active: admin_custom_overrides::ActiveModel = existing.into();
        active.route_map_id = Set(body.0.route_map_id);
        active.rule_type = Set(body.0.rule_type);
        active.pattern = Set(body.0.pattern.trim().to_string());
        active.category = Set(body.0.category);
        active.comment = Set(body.0.comment.trim().to_string());
        active.is_active = Set(body.0.is_active);
        active.updated_at = Set(Utc::now().naive_utc());

        match active.update(&self.db).await {
            Ok(saved) => SaveCustomOverrideResponse::Ok(Json(saved.into())),
            Err(e) => SaveCustomOverrideResponse::Error(Json(e.to_string())),
        }
    }

    /// Удаление исключения
    #[oai(path = "/routing/custom-overrides/:id", method = "delete")]
    async fn delete_custom_override(
        &self,
        auth: AdminToken,
        id: Path<Uuid>,
    ) -> DeleteCustomOverrideResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return DeleteCustomOverrideResponse::Unauthorized(Json(err));
        }

        match admin_custom_overrides::Entity::delete_by_id(id.0).exec(&self.db).await {
            Ok(res) if res.rows_affected > 0 => DeleteCustomOverrideResponse::Deleted,
            Ok(_) => DeleteCustomOverrideResponse::NotFound(Json("Override not found".into())),
            Err(e) => DeleteCustomOverrideResponse::Error(Json(e.to_string())),
        }
    }
}
