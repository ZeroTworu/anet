//! API управления внешними провайдерами списков (Rule Providers) и просмотра кэша правил для WebUI.

use chrono::Utc;
use poem_openapi::{
    param::Path, param::Query, payload::Json, ApiResponse, Object, OpenApi,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, Set,
};
use uuid::Uuid;

use crate::api::api::validate_admin_session;
use crate::api::dto::AdminToken;
use crate::compiler_worker::{
    fetch_and_cache_provider, get_provider_cache_dir, invalidate_compiled_rules_cache,
    parse_provider_lines,
};
use crate::entities::admin_custom_overrides::OverrideCategory;
use crate::entities::rule_provider_items;
use crate::entities::rule_providers::{self, ProviderFormat, ProviderType};

#[derive(Object, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuleProviderDto {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub provider_type: ProviderType,
    pub format: ProviderFormat,
    pub action: OverrideCategory,
    pub route_map_id: Option<Uuid>,
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
            action: m.action,
            route_map_id: m.route_map_id,
            url: m.url,
            update_interval_hours: m.update_interval_hours,
            last_fetched_at: m
                .last_fetched_at
                .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string()),
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
    #[serde(default = "default_provider_action")]
    pub action: OverrideCategory,
    pub route_map_id: Option<Uuid>,
    pub url: String,
    pub update_interval_hours: i32,
    pub is_active: bool,
}

fn default_provider_action() -> OverrideCategory {
    OverrideCategory::CustomBlock
}

#[derive(Object, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProviderItemDto {
    pub id: i64,
    pub rule_value: String,
}

#[derive(Object, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuleProviderItemsPageDto {
    pub provider_id: Uuid,
    pub provider_name: String,
    pub total: u64,
    pub page: u64,
    pub per_page: u64,
    pub items: Vec<ProviderItemDto>,
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

#[derive(ApiResponse)]
pub enum GetRuleProviderItemsResponse {
    #[oai(status = 200)]
    Ok(Json<RuleProviderItemsPageDto>),
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
            Ok(list) => GetRuleProvidersResponse::Ok(Json(
                list.into_iter().map(Into::into).collect(),
            )),
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
            action: Set(body.0.action),
            route_map_id: Set(body.0.route_map_id),
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
            Ok(saved) => {
                invalidate_compiled_rules_cache();
                SaveRuleProviderResponse::Ok(Json(saved.into()))
            }
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
        active.action = Set(body.0.action);
        active.route_map_id = Set(body.0.route_map_id);
        active.url = Set(body.0.url.trim().to_string());
        active.update_interval_hours = Set(body.0.update_interval_hours.max(1));
        active.is_active = Set(body.0.is_active);
        active.updated_at = Set(Utc::now().naive_utc());

        match active.update(&self.db).await {
            Ok(saved) => {
                invalidate_compiled_rules_cache();
                SaveRuleProviderResponse::Ok(Json(saved.into()))
            }
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
            Ok(res) if res.rows_affected > 0 => {
                invalidate_compiled_rules_cache();
                DeleteRuleProviderResponse::Deleted
            }
            Ok(_) => DeleteRuleProviderResponse::NotFound(Json("Provider not found".into())),
            Err(e) => DeleteRuleProviderResponse::Error(Json(e.to_string())),
        }
    }

    /// Принудительное скачивание и обновление правил провайдера с сохранением в таблицу БД
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

        if let Err(e) = fetch_and_cache_provider(&self.db, &provider, true).await {
            return FetchRuleProviderResponse::Error(Json(format!("Fetch failed: {e}")));
        }

        match rule_providers::Entity::find_by_id(id.0).one(&self.db).await {
            Ok(Some(updated)) => FetchRuleProviderResponse::Ok(Json(updated.into())),
            _ => FetchRuleProviderResponse::Error(Json("Failed to reload provider".into())),
        }
    }

    /// Просмотр закэшированных элементов провайдера из таблицы `rule_provider_items` с поиском и пагинацией
    #[oai(path = "/routing/rule-providers/:id/items", method = "get")]
    async fn get_rule_provider_items(
        &self,
        auth: AdminToken,
        id: Path<Uuid>,
        search: Query<Option<String>>,
        page: Query<Option<u64>>,
        per_page: Query<Option<u64>>,
    ) -> GetRuleProviderItemsResponse {
        if let Err(err) = validate_admin_session(&self.db, &auth.0.token).await {
            return GetRuleProviderItemsResponse::Unauthorized(Json(err));
        }

        let provider = match rule_providers::Entity::find_by_id(id.0).one(&self.db).await {
            Ok(Some(m)) => m,
            Ok(None) => {
                return GetRuleProviderItemsResponse::NotFound(Json("Provider not found".into()));
            }
            Err(e) => return GetRuleProviderItemsResponse::Error(Json(e.to_string())),
        };

        // Если таблица rule_provider_items ещё пуста, но есть локальный файл /tmp/anet_providers/{id}.txt,
        // автоматически переносим элементы в БД без лишнего сетевого запроса.
        let existing_db_count = rule_provider_items::Entity::find()
            .filter(rule_provider_items::Column::ProviderId.eq(provider.id))
            .count(&self.db)
            .await
            .unwrap_or(0);

        if existing_db_count == 0 {
            let fallback_file = get_provider_cache_dir().join(format!("{}.txt", provider.id));
            if let Ok(content) = std::fs::read_to_string(&fallback_file) {
                let parsed = parse_provider_lines(&content);
                for chunk in parsed.chunks(1000) {
                    let models: Vec<rule_provider_items::ActiveModel> = chunk
                        .iter()
                        .map(|val| rule_provider_items::ActiveModel {
                            provider_id: Set(provider.id),
                            rule_value: Set(val.clone()),
                            ..Default::default()
                        })
                        .collect();
                    let _ = rule_provider_items::Entity::insert_many(models)
                        .exec(&self.db)
                        .await;
                }
            }
        }

        let page_num = page.0.unwrap_or(1).max(1);
        let page_size = per_page.0.unwrap_or(50).clamp(1, 500);

        let mut query = rule_provider_items::Entity::find()
            .filter(rule_provider_items::Column::ProviderId.eq(provider.id));

        if let Some(q) = search.0 {
            let trimmed = q.trim();
            if !trimmed.is_empty() {
                query = query.filter(rule_provider_items::Column::RuleValue.contains(trimmed));
            }
        }

        let paginator = query
            .order_by_asc(rule_provider_items::Column::Id)
            .paginate(&self.db, page_size);

        let total = match paginator.num_items().await {
            Ok(t) => t,
            Err(e) => return GetRuleProviderItemsResponse::Error(Json(e.to_string())),
        };

        let rows = match paginator.fetch_page(page_num - 1).await {
            Ok(r) => r,
            Err(e) => return GetRuleProviderItemsResponse::Error(Json(e.to_string())),
        };

        let items = rows
            .into_iter()
            .map(|r| ProviderItemDto {
                id: r.id,
                rule_value: r.rule_value,
            })
            .collect();

        GetRuleProviderItemsResponse::Ok(Json(RuleProviderItemsPageDto {
            provider_id: provider.id,
            provider_name: provider.name,
            total,
            page: page_num,
            per_page: page_size,
            items,
        }))
    }
}
